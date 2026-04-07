# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Batch export tools for disassembly and pseudocode."""

from __future__ import annotations

import contextlib
import os
import re
from collections.abc import Iterator

import ida_fpro
import ida_funcs
import ida_hexrays
import ida_ida
import ida_lines
import ida_loader
import idautils
from fastmcp import FastMCP
from fastmcp.dependencies import CurrentContext
from fastmcp.server.context import Context
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    META_BATCH,
    META_DECOMPILER,
    META_WRITES_FILES,
    Address,
    FilterPattern,
    IDAError,
    Limit,
    Offset,
    call_ida,
    check_cancelled,
    clean_disasm_line,
    compile_filter,
    format_address,
    get_func_name,
    is_cancelled,
    paginate,
    resolve_address,
)
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ExportedPseudocode(BaseModel):
    """Exported pseudocode for a function."""

    name: str = Field(description="Function name.")
    address: str = Field(description="Function address (hex).")
    pseudocode: str = Field(description="Decompiled pseudocode.")


class ExportError(BaseModel):
    """An error during batch export."""

    name: str = Field(description="Function name.")
    address: str = Field(description="Function address (hex).")
    error: str = Field(description="Error message.")


class ExportPseudocodeResult(BaseModel):
    """Result of batch pseudocode export."""

    functions: list[ExportedPseudocode] = Field(description="Exported functions.")
    errors: list[ExportError] = Field(description="Functions that failed.")
    total: int = Field(description="Total matching functions.")
    offset: int = Field(description="Starting offset.")
    limit: int = Field(description="Maximum functions per page.")
    has_more: bool = Field(description="Whether more functions exist.")


class ExportedDisassembly(BaseModel):
    """Exported disassembly for a function."""

    name: str = Field(description="Function name.")
    address: str = Field(description="Function address (hex).")
    instruction_count: int = Field(description="Number of instructions.")
    disassembly: str = Field(description="Disassembly text.")


class ExportDisassemblyResult(BaseModel):
    """Result of batch disassembly export."""

    functions: list[ExportedDisassembly] = Field(description="Exported functions.")
    total: int = Field(description="Total matching functions.")
    offset: int = Field(description="Starting offset.")
    limit: int = Field(description="Maximum functions per page.")
    has_more: bool = Field(description="Whether more functions exist.")


class GenerateOutputFileResult(BaseModel):
    """Result of generating an output file."""

    output_path: str = Field(description="Output file path.")
    output_type: str = Field(description="Output file type.")
    start_address: str = Field(description="Start address (hex).")
    end_address: str = Field(description="End address (hex).")
    lines_generated: int = Field(description="Number of lines generated.")


class GenerateExeFileResult(BaseModel):
    """Result of generating an executable file."""

    output_path: str = Field(description="Output file path.")
    status: str = Field(description="Status message.")


_OUTPUT_TYPE_MAP = {
    "map": ida_loader.OFILE_MAP,
    "idc": ida_loader.OFILE_IDC,
    "lst": ida_loader.OFILE_LST,
    "asm": ida_loader.OFILE_ASM,
    "dif": ida_loader.OFILE_DIF,
}


def _matching_functions(
    pattern: re.Pattern | None,
) -> Iterator[tuple[int, str]]:
    """Yield (start_ea, name) for functions matching *pattern*."""
    for i in range(ida_funcs.get_func_qty()):
        if is_cancelled():
            return
        func = ida_funcs.getn_func(i)
        if func is None:
            continue
        name = get_func_name(func.start_ea)
        if pattern and not pattern.search(name):
            continue
        yield func.start_ea, name


def _prepare_candidates(filter_pattern: str, offset: int, limit: int) -> dict:
    """Collect and paginate matching functions (runs on main thread)."""
    pattern = compile_filter(filter_pattern)
    candidates = list(_matching_functions(pattern))
    return paginate(candidates, offset, limit)


def _decompile_one(func_ea: int, name: str) -> tuple[ExportedPseudocode | None, ExportError | None]:
    """Decompile a single function (runs on main thread).

    Returns ``(ExportedPseudocode, None)`` on success or
    ``(None, ExportError)`` on failure.
    """
    check_cancelled()
    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception as e:
        return None, ExportError(name=name, address=format_address(func_ea), error=str(e))

    if cfunc is None:
        return None, ExportError(
            name=name, address=format_address(func_ea), error="decompilation returned no result"
        )

    sv = cfunc.get_pseudocode()
    lines = [ida_lines.tag_remove(sv[j].line) for j in range(sv.size())]
    return ExportedPseudocode(
        name=name, address=format_address(func_ea), pseudocode="\n".join(lines)
    ), None


def _disassemble_one(func_ea: int, name: str) -> ExportedDisassembly:
    """Disassemble a single function (runs on main thread)."""
    check_cancelled()
    lines = [
        f"{format_address(item_ea)}  {clean_disasm_line(item_ea)}"
        for item_ea in idautils.FuncItems(func_ea)
    ]
    return ExportedDisassembly(
        name=name,
        address=format_address(func_ea),
        instruction_count=len(lines),
        disassembly="\n".join(lines),
    )


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"export", "decompiler"},
        meta={**META_DECOMPILER, **META_BATCH},
    )
    @session.require_open
    async def export_all_pseudocode(
        filter_pattern: FilterPattern = "",
        offset: Offset = 0,
        limit: Limit = 50,
        ctx: Context = CurrentContext(),  # noqa: B008
    ) -> ExportPseudocodeResult:
        """Batch decompile multiple functions and return their pseudocode.

        Expensive: decompiles functions sequentially — each may take seconds.
        A request for 50 functions can take minutes. Prefer using
        list_functions with filter_pattern to identify targets, then call
        decompile_function individually on functions of interest. Use
        filter_pattern here to restrict output to relevant functions (e.g.
        "crypto|decrypt") rather than decompiling everything.

        Args:
            filter_pattern: Optional regex to filter function names.
            offset: Pagination offset (by function index).
            limit: Maximum number of functions to decompile.
        """
        page = await call_ida(_prepare_candidates, filter_pattern, offset, limit)

        items = page["items"]
        total_items = len(items)
        results = []
        errors = []
        for i, (func_ea, name) in enumerate(items):
            await ctx.report_progress(i, total_items)
            pseudocode, error = await call_ida(_decompile_one, func_ea, name)
            if error is not None:
                errors.append(error)
            elif pseudocode is not None:
                results.append(pseudocode)
        await ctx.report_progress(total_items, total_items)

        return ExportPseudocodeResult(
            functions=results,
            errors=errors,
            total=page["total"],
            offset=page["offset"],
            limit=page["limit"],
            has_more=page["has_more"],
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"export", "disassembly"},
        meta=META_BATCH,
    )
    @session.require_open
    async def export_all_disassembly(
        filter_pattern: FilterPattern = "",
        offset: Offset = 0,
        limit: Limit = 50,
        ctx: Context = CurrentContext(),  # noqa: B008
    ) -> ExportDisassemblyResult:
        """Batch export disassembly for multiple functions.

        Much faster than export_all_pseudocode (no decompilation needed),
        but still processes multiple functions. Use filter_pattern to
        restrict output to relevant function groups.

        Args:
            filter_pattern: Optional regex to filter function names.
            offset: Pagination offset (by function index).
            limit: Maximum number of functions to export.
        """
        page = await call_ida(_prepare_candidates, filter_pattern, offset, limit)

        items = page["items"]
        total_items = len(items)
        results = []
        for i, (func_ea, name) in enumerate(items):
            await ctx.report_progress(i, total_items)
            result = await call_ida(_disassemble_one, func_ea, name)
            results.append(result)
        await ctx.report_progress(total_items, total_items)

        return ExportDisassemblyResult(
            functions=results,
            total=page["total"],
            offset=page["offset"],
            limit=page["limit"],
            has_more=page["has_more"],
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"export"},
        meta=META_WRITES_FILES,
    )
    @session.require_open
    def generate_output_file(
        output_path: str,
        output_type: str,
        start_address: Address = "",
        end_address: Address = "",
        flags: int = 0,
    ) -> GenerateOutputFileResult:
        """Generate an IDA output file using IDA's native formatting.

        Produces files with full IDA formatting including comments,
        cross-references, and segment information. Omitting start/end
        addresses exports the entire database, which can be slow and
        produce very large files on big binaries. Specify a function
        or segment range for targeted exports.

        Args:
            output_path: Path where the output file will be written.
            output_type: Type of output — "asm" (assembly), "lst" (listing
                with metadata), "map" (segment map), "dif" (diff format),
                or "idc" (IDC script).
            start_address: Start address of range (empty = entire database).
            end_address: End address of range (empty = entire database).
            flags: Output generation flags (GENFLG_*).
        """
        otype = _OUTPUT_TYPE_MAP.get(output_type.lower())
        if otype is None:
            raise IDAError(
                f"Unknown output type: {output_type!r}. Valid: {', '.join(_OUTPUT_TYPE_MAP)}",
                error_type="InvalidArgument",
            )

        ea1 = resolve_address(start_address) if start_address else ida_ida.inf_get_min_ea()
        ea2 = resolve_address(end_address) if end_address else ida_ida.inf_get_max_ea()

        path = os.path.abspath(os.path.expanduser(output_path))
        fp = ida_fpro.qfile_t()
        if not fp.open(path, "w"):
            raise IDAError(f"Failed to open output file: {path}", error_type="OpenFailed")

        try:
            result = ida_loader.gen_file(otype, fp.get_fp(), ea1, ea2, flags)
        finally:
            fp.close()

        if result < 0:
            raise IDAError("Failed to generate output", error_type="GenerateFailed")

        return GenerateOutputFileResult(
            output_path=path,
            output_type=output_type,
            start_address=format_address(ea1),
            end_address=format_address(ea2),
            lines_generated=result,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"export"},
        meta=META_WRITES_FILES,
    )
    @session.require_open
    def generate_exe_file(output_path: str) -> GenerateExeFileResult:
        """Generate (rebuild) an executable file from the database.

        Reconstructs a binary file from the current database state,
        including any patches applied. Not all loaders support this —
        will return an error for unsupported formats. Primarily useful
        for applying patches to simple binaries.

        Args:
            output_path: Path where the executable will be written.
        """
        path = os.path.abspath(os.path.expanduser(output_path))
        fp = ida_fpro.qfile_t()
        if not fp.open(path, "wb"):
            raise IDAError(f"Failed to open output file: {path}", error_type="OpenFailed")

        try:
            result = ida_loader.gen_exe_file(fp.get_fp())
        finally:
            fp.close()

        if result == 0:
            # Clean up empty file on failure
            with contextlib.suppress(OSError):
                os.unlink(path)
            raise IDAError(
                "Cannot generate executable — loader may not support it", error_type="NotSupported"
            )

        return GenerateExeFileResult(output_path=path, status="generated")
