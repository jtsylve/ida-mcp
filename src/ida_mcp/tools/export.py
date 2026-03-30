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
from fastmcp import Context, FastMCP

from ida_mcp.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    FilterPattern,
    IDAError,
    Limit,
    Offset,
    check_cancelled,
    clean_disasm_line,
    compile_filter,
    format_address,
    get_func_name,
    is_cancelled,
    paginate,
    resolve_address,
    tool_timeout,
)
from ida_mcp.session import session

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


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"export"},
        timeout=tool_timeout("export_all_pseudocode"),
    )
    @session.require_open
    async def export_all_pseudocode(
        filter_pattern: FilterPattern = "",
        offset: Offset = 0,
        limit: Limit = 50,
        *,
        ctx: Context,
    ) -> dict:
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
        pattern = compile_filter(filter_pattern)

        candidates = list(_matching_functions(pattern))
        page = paginate(candidates, offset, limit)

        items = page["items"]
        total_items = len(items)
        results = []
        errors = []
        for i, (func_ea, name) in enumerate(items):
            check_cancelled()
            await ctx.report_progress(i, total_items)
            try:
                cfunc = ida_hexrays.decompile(func_ea)
            except Exception as e:
                errors.append({"name": name, "address": format_address(func_ea), "error": str(e)})
                continue

            if cfunc is None:
                errors.append(
                    {
                        "name": name,
                        "address": format_address(func_ea),
                        "error": "decompilation returned no result",
                    }
                )
                continue

            sv = cfunc.get_pseudocode()
            lines = [ida_lines.tag_remove(sv[j].line) for j in range(sv.size())]

            results.append(
                {
                    "name": name,
                    "address": format_address(func_ea),
                    "pseudocode": "\n".join(lines),
                }
            )
        await ctx.report_progress(total_items, total_items)

        return {
            "functions": results,
            "errors": errors,
            "total": page["total"],
            "offset": page["offset"],
            "limit": page["limit"],
            "has_more": page["has_more"],
        }

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"export"},
        timeout=tool_timeout("export_all_disassembly"),
    )
    @session.require_open
    async def export_all_disassembly(
        filter_pattern: FilterPattern = "",
        offset: Offset = 0,
        limit: Limit = 50,
        *,
        ctx: Context,
    ) -> dict:
        """Batch export disassembly for multiple functions.

        Much faster than export_all_pseudocode (no decompilation needed),
        but still processes multiple functions. Use filter_pattern to
        restrict output to relevant function groups.

        Args:
            filter_pattern: Optional regex to filter function names.
            offset: Pagination offset (by function index).
            limit: Maximum number of functions to export.
        """
        pattern = compile_filter(filter_pattern)

        candidates = list(_matching_functions(pattern))
        page = paginate(candidates, offset, limit)

        items = page["items"]
        total_items = len(items)
        results = []
        for i, (func_ea, name) in enumerate(items):
            if is_cancelled():
                break
            await ctx.report_progress(i, total_items)

            lines = [
                f"{format_address(item_ea)}  {clean_disasm_line(item_ea)}"
                for item_ea in idautils.FuncItems(func_ea)
            ]

            results.append(
                {
                    "name": name,
                    "address": format_address(func_ea),
                    "instruction_count": len(lines),
                    "disassembly": "\n".join(lines),
                }
            )
        await ctx.report_progress(total_items, total_items)

        return {
            "functions": results,
            "total": page["total"],
            "offset": page["offset"],
            "limit": page["limit"],
            "has_more": page["has_more"],
        }

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"export"},
    )
    @session.require_open
    def generate_output_file(
        output_path: str,
        output_type: str,
        start_address: Address = "",
        end_address: Address = "",
        flags: int = 0,
    ) -> dict:
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

        return {
            "output_path": path,
            "output_type": output_type,
            "start_address": format_address(ea1),
            "end_address": format_address(ea2),
            "lines_generated": result,
        }

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"export"},
    )
    @session.require_open
    def generate_exe_file(output_path: str) -> dict:
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

        return {"output_path": path, "status": "generated"}
