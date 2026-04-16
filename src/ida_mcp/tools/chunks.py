# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Function chunk/tail management tools."""

from __future__ import annotations

import ida_funcs
import idautils
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    IDAError,
    format_address,
    resolve_address,
    resolve_function,
)
from ida_mcp.models import FunctionChunk
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ListFunctionChunksResult(BaseModel):
    """Function chunks."""

    function: str = Field(description="Function address (hex).")
    chunk_count: int = Field(description="Number of chunks.")
    chunks: list[FunctionChunk] = Field(description="Function chunks.")


class AppendFunctionTailResult(BaseModel):
    """Result of appending a function tail."""

    function: str = Field(description="Function address (hex).")
    tail_start: str = Field(description="Tail start address (hex).")
    tail_end: str = Field(description="Tail end address (hex).")


class RemoveFunctionTailResult(BaseModel):
    """Result of removing a function tail."""

    function: str = Field(description="Function address (hex).")
    removed_tail_at: str = Field(description="Removed tail address (hex).")


class SetTailOwnerResult(BaseModel):
    """Result of setting a tail owner."""

    tail_address: str = Field(description="Tail address (hex).")
    old_owner: str | None = Field(description="Previous owner (hex).")
    new_owner: str = Field(description="New owner (hex).")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"functions"},
    )
    @session.require_open
    def list_function_chunks(
        address: Address,
    ) -> ListFunctionChunksResult:
        """List all chunks (contiguous regions) of a function.

        Non-contiguous functions have multiple chunks due to compiler optimizations
        like basic block reordering or hot/cold splitting.

        Args:
            address: Address or symbol name of the function.
        """
        func = resolve_function(address)

        chunks = []
        for start, end in idautils.Chunks(func.start_ea):
            chunks.append(
                {
                    "start": format_address(start),
                    "end": format_address(end),
                    "size": end - start,
                }
            )

        return ListFunctionChunksResult(
            function=format_address(func.start_ea),
            chunk_count=len(chunks),
            chunks=chunks,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"functions"},
    )
    @session.require_open
    def append_function_tail(
        function_address: Address,
        start: Address,
        end: Address,
    ) -> AppendFunctionTailResult:
        """Append a tail (non-contiguous chunk) to a function.

        Args:
            function_address: Address or name of the owning function.
            start: Start address of the tail region.
            end: End address of the tail region (exclusive).
        """
        func = resolve_function(function_address)
        ea1 = resolve_address(start)
        ea2 = resolve_address(end)

        success = ida_funcs.append_func_tail(func, ea1, ea2)
        if not success:
            raise IDAError(
                f"Failed to append tail [{format_address(ea1)}, {format_address(ea2)}) "
                f"to function at {format_address(func.start_ea)}",
                error_type="AppendFailed",
            )

        return AppendFunctionTailResult(
            function=format_address(func.start_ea),
            tail_start=format_address(ea1),
            tail_end=format_address(ea2),
        )

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"functions"},
    )
    @session.require_open
    def remove_function_tail(
        function_address: Address,
        tail_address: Address,
    ) -> RemoveFunctionTailResult:
        """Remove a tail (non-contiguous chunk) from a function.

        Args:
            function_address: Address or name of the owning function.
            tail_address: Any address within the tail chunk to remove.
        """
        func = resolve_function(function_address)
        tail_ea = resolve_address(tail_address)

        success = ida_funcs.remove_func_tail(func, tail_ea)
        if not success:
            raise IDAError(
                f"Failed to remove tail at {format_address(tail_ea)} "
                f"from function at {format_address(func.start_ea)}",
                error_type="RemoveFailed",
            )

        return RemoveFunctionTailResult(
            function=format_address(func.start_ea),
            removed_tail_at=format_address(tail_ea),
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"functions"},
    )
    @session.require_open
    def set_tail_owner(
        tail_address: Address,
        new_owner_address: Address,
    ) -> SetTailOwnerResult:
        """Reassign a function tail chunk to a different owning function.

        Args:
            tail_address: Any address within the tail chunk.
            new_owner_address: Address or name of the new owning function.
        """
        tail_ea = resolve_address(tail_address)
        owner_ea = resolve_address(new_owner_address)

        fnt = ida_funcs.get_fchunk(tail_ea)
        if fnt is None:
            raise IDAError(f"No function chunk at {format_address(tail_ea)}", error_type="NotFound")

        old_owner_func = ida_funcs.get_func(tail_ea)
        old_owner = format_address(old_owner_func.start_ea) if old_owner_func else None
        success = ida_funcs.set_tail_owner(fnt, owner_ea)
        if not success:
            raise IDAError(
                f"Failed to set tail owner at {format_address(tail_ea)} "
                f"to {format_address(owner_ea)}",
                error_type="SetOwnerFailed",
            )

        return SetTailOwnerResult(
            tail_address=format_address(tail_ea),
            old_owner=old_owner,
            new_owner=format_address(owner_ea),
        )
