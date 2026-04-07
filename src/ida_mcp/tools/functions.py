# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Function analysis tools — listing, querying, decompilation, and disassembly."""

from __future__ import annotations

import ida_funcs
import ida_lines
import ida_name
import idautils
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    META_BATCH,
    META_DECOMPILER,
    Address,
    FilterPattern,
    IDAError,
    Limit,
    Offset,
    async_paginate_iter,
    clean_disasm_line,
    compile_filter,
    decompile_at,
    format_address,
    get_func_name,
    is_cancelled,
    resolve_address,
    resolve_function,
)
from ida_mcp.models import FunctionChunk, FunctionSummary, PaginatedResult, RenameResult
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class FunctionListResult(PaginatedResult[FunctionSummary]):
    """Paginated list of functions."""

    items: list[FunctionSummary] = Field(description="Page of function summaries.")


class FunctionDetail(BaseModel):
    """Detailed function information."""

    name: str = Field(description="Function name.")
    start: str = Field(description="Start address (hex).")
    end: str = Field(description="End address (hex, exclusive).")
    size: int = Field(description="Function size in bytes.")
    flags: int = Field(description="IDA function flags bitmask.")
    does_return: bool = Field(description="Whether the function returns.")
    is_library: bool = Field(description="Whether this is a library function.")
    is_thunk: bool = Field(description="Whether this is a thunk function.")
    comment: str = Field(description="Regular comment.")
    repeatable_comment: str = Field(description="Repeatable comment.")
    chunks: list[FunctionChunk] | None = Field(
        default=None,
        description="Non-contiguous chunks if function has multiple ranges.",
    )


class DecompilationResult(BaseModel):
    """Decompiled function pseudocode."""

    address: str = Field(description="Function start address (hex).")
    name: str = Field(description="Function name.")
    pseudocode: str = Field(description="Decompiled C pseudocode.")


class DisassemblyInstruction(BaseModel):
    """Single disassembled instruction."""

    address: str = Field(description="Instruction address (hex).")
    disasm: str = Field(description="Disassembly text.")


class DisassemblyResult(BaseModel):
    """Disassembled function listing."""

    address: str = Field(description="Function start address (hex).")
    name: str = Field(description="Function name.")
    instruction_count: int = Field(description="Number of instructions.")
    instructions: list[DisassemblyInstruction] = Field(description="Instruction listing.")


class DeleteFunctionResult(BaseModel):
    """Result of deleting a function."""

    address: str = Field(description="Deleted function start address (hex).")
    name: str = Field(description="Deleted function name.")
    old_end: str = Field(description="Previous end address of the deleted function (hex).")


class SetFunctionBoundsResult(BaseModel):
    """Result of setting function bounds."""

    address: str = Field(description="Function start address (hex).")
    name: str = Field(description="Function name.")
    old_end: str = Field(description="Previous end address (hex).")
    end: str = Field(description="New end address (hex).")


_VALID_FILTER_TYPES = {"thunk", "library", "noreturn", "user", ""}


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"functions"},
        meta=META_BATCH,
    )
    @session.require_open
    async def list_functions(
        offset: Offset = 0,
        limit: Limit = 100,
        filter_pattern: FilterPattern = "",
        filter_type: str = "",
    ) -> FunctionListResult:
        """List functions in the binary with optional filtering.

        Use filter_pattern with a regex to find functions by name.
        Combine filter_type="user" to exclude library stubs and thunks
        for more targeted results.

        Args:
            offset: Starting index for pagination.
            limit: Maximum number of results.
            filter_pattern: Optional regex pattern to filter function names.
            filter_type: Optional filter by function type — "thunk" (thunks only),
                "library" (library functions), "noreturn" (non-returning),
                "user" (exclude library and thunk functions).
        """
        pattern = compile_filter(filter_pattern)

        if filter_type not in _VALID_FILTER_TYPES:
            raise IDAError(
                f"Invalid filter_type: {filter_type!r}",
                error_type="InvalidArgument",
                valid_types=sorted(_VALID_FILTER_TYPES - {""}),
            )

        def _iter():
            for i in range(ida_funcs.get_func_qty()):
                if is_cancelled():
                    return
                func = ida_funcs.getn_func(i)
                if func is None:
                    continue

                if filter_type:
                    is_thunk = bool(func.flags & ida_funcs.FUNC_THUNK)
                    is_lib = bool(func.flags & ida_funcs.FUNC_LIB)
                    is_noret = bool(func.flags & ida_funcs.FUNC_NORET)
                    if (
                        (filter_type == "thunk" and not is_thunk)
                        or (filter_type == "library" and not is_lib)
                        or (filter_type == "noreturn" and not is_noret)
                        or (filter_type == "user" and (is_thunk or is_lib))
                    ):
                        continue

                name = get_func_name(func.start_ea)
                if pattern and not pattern.search(name):
                    continue
                yield {
                    "name": name,
                    "start": format_address(func.start_ea),
                    "end": format_address(func.end_ea),
                    "size": func.size(),
                }

        return FunctionListResult(
            **await async_paginate_iter(_iter(), offset, limit, progress_label="Listing functions")
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"functions"},
    )
    @session.require_open
    def get_function(
        address: Address,
    ) -> FunctionDetail:
        """Get detailed information about a function at the given address.

        Args:
            address: Address or symbol name of the function.
        """
        func = resolve_function(address)

        name = get_func_name(func.start_ea)
        regular_cmt = ida_funcs.get_func_cmt(func, False) or ""
        repeatable_cmt = ida_funcs.get_func_cmt(func, True) or ""

        chunks = list(idautils.Chunks(func.start_ea))
        return FunctionDetail(
            name=name,
            start=format_address(func.start_ea),
            end=format_address(func.end_ea),
            size=func.size(),
            flags=func.flags,
            does_return=not (func.flags & ida_funcs.FUNC_NORET),
            is_library=bool(func.flags & ida_funcs.FUNC_LIB),
            is_thunk=bool(func.flags & ida_funcs.FUNC_THUNK),
            comment=regular_cmt,
            repeatable_comment=repeatable_cmt,
            chunks=[
                {"start": format_address(s), "end": format_address(e), "size": e - s}
                for s, e in chunks
            ]
            if len(chunks) > 1
            else None,
        )

    def _decompile_one(target: str) -> DecompilationResult:
        """Decompile a single function and return its pseudocode."""
        cfunc, func = decompile_at(target)
        sv = cfunc.get_pseudocode()
        lines = [ida_lines.tag_remove(sv[i].line) for i in range(sv.size())]
        return DecompilationResult(
            address=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            pseudocode="\n".join(lines),
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"functions", "decompiler"},
        meta=META_DECOMPILER,
    )
    @session.require_open
    def decompile_function(
        address: Address = "",
        name: str = "",
    ) -> DecompilationResult:
        """Decompile a function to pseudocode using Hex-Rays.

        Requires a Hex-Rays decompiler license. For quick inspection without
        decompilation, use disassemble_function instead (faster, no license
        needed). For multiple functions, use the batch meta-tool.

        Args:
            address: Address of the function (hex string or symbol).
            name: Name of the function to decompile.
        """
        if not address and not name:
            raise IDAError("Provide either address or name", error_type="InvalidArgument")
        return _decompile_one(address or name)

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"functions"},
    )
    @session.require_open
    def disassemble_function(
        address: Address,
    ) -> DisassemblyResult:
        """Get the disassembly listing of a function.

        Faster than decompile_function and does not require Hex-Rays.
        Use this for quick inspection of function logic or when only
        assembly-level detail is needed. For readable C-like pseudocode
        (decompilation), use decompile_function instead — it requires a
        Hex-Rays decompiler license.

        Args:
            address: Address or symbol name of the function.
        """
        func = resolve_function(address)

        instructions = [
            {
                "address": format_address(item_ea),
                "disasm": clean_disasm_line(item_ea),
            }
            for item_ea in idautils.FuncItems(func.start_ea)
        ]

        func_name = get_func_name(func.start_ea)
        return DisassemblyResult(
            address=format_address(func.start_ea),
            name=func_name,
            instruction_count=len(instructions),
            instructions=instructions,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"functions"},
    )
    @session.require_open
    def rename_function(
        address: Address,
        new_name: str,
    ) -> RenameResult:
        """Rename a function.

        Args:
            address: Address or current name of the function.
            new_name: The new name to assign.
        """
        func = resolve_function(address)

        old_name = get_func_name(func.start_ea)
        success = ida_name.set_name(func.start_ea, new_name, ida_name.SN_CHECK)
        if not success:
            raise IDAError(f"Failed to rename function to {new_name!r}", error_type="RenameFailed")

        return RenameResult(
            address=format_address(func.start_ea),
            old_name=old_name,
            new_name=new_name,
        )

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"functions"},
    )
    @session.require_open
    def delete_function(
        address: Address,
    ) -> DeleteFunctionResult:
        """Delete a function definition (does not delete the code).

        The instructions remain but are no longer grouped as a function.

        Args:
            address: Address or name of the function to delete.
        """
        func = resolve_function(address)

        start_ea = func.start_ea
        end_ea = func.end_ea
        name = get_func_name(start_ea)
        success = ida_funcs.del_func(start_ea)
        if not success:
            raise IDAError(
                f"Failed to delete function {name} at {format_address(start_ea)}",
                error_type="DeleteFailed",
            )
        return DeleteFunctionResult(
            address=format_address(start_ea),
            name=name,
            old_end=format_address(end_ea),
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"functions"},
    )
    @session.require_open
    def set_function_bounds(
        address: Address,
        new_end: Address,
    ) -> SetFunctionBoundsResult:
        """Change the end address of a function.

        Useful for fixing function boundaries when IDA guesses wrong.

        Args:
            address: Address or name of the function.
            new_end: New end address (exclusive).
        """
        func = resolve_function(address)
        end_ea = resolve_address(new_end)

        old_end = func.end_ea
        success = ida_funcs.set_func_end(func.start_ea, end_ea)
        if not success:
            raise IDAError(
                f"Failed to set function end to {format_address(end_ea)}",
                error_type="SetBoundsFailed",
            )
        return SetFunctionBoundsResult(
            address=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            old_end=format_address(old_end),
            end=format_address(end_ea),
        )
