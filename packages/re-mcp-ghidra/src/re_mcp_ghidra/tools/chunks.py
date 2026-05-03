# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Function chunk/body management tools."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    format_address,
    resolve_address,
    resolve_function,
)
from re_mcp_ghidra.models import FunctionChunk
from re_mcp_ghidra.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ListFunctionChunksResult(BaseModel):
    """Function chunks (address ranges)."""

    function: str = Field(description="Function address (hex).")
    function_name: str = Field(description="Function name.")
    chunk_count: int = Field(description="Number of address ranges.")
    chunks: list[FunctionChunk] = Field(description="Address ranges in the function body.")


class AppendFunctionTailResult(BaseModel):
    """Result of appending a function tail."""

    function: str = Field(description="Function address (hex).")
    tail_start: str = Field(description="Tail start address (hex).")
    tail_end: str = Field(description="Tail end address (hex, exclusive).")


class RemoveFunctionTailResult(BaseModel):
    """Result of removing a function tail."""

    function: str = Field(description="Function address (hex).")
    removed_tail_start: str = Field(description="Removed range start (hex).")
    removed_tail_end: str = Field(description="Removed range end (hex, exclusive).")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions"})
    @session.require_open
    def list_function_chunks(
        address: Address,
    ) -> ListFunctionChunksResult:
        """List all address ranges (chunks) in a function body.

        Non-contiguous functions have multiple ranges due to compiler
        optimizations like basic block reordering or hot/cold splitting.

        Args:
            address: Address or symbol name of the function.
        """
        func = resolve_function(address)
        body = func.getBody()

        chunks = []
        ranges = body.iterator()
        while ranges.hasNext():
            addr_range = ranges.next()
            start = addr_range.getMinAddress().getOffset()
            end = addr_range.getMaxAddress().getOffset() + 1
            chunks.append(
                FunctionChunk(
                    start=format_address(start),
                    end=format_address(end),
                    size=end - start,
                )
            )

        return ListFunctionChunksResult(
            function=format_address(func.getEntryPoint().getOffset()),
            function_name=func.getName(),
            chunk_count=len(chunks),
            chunks=chunks,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"functions"})
    @session.require_open
    def append_function_tail(
        function_address: Address,
        start: Address,
        end: Address,
    ) -> AppendFunctionTailResult:
        """Append a tail (non-contiguous range) to a function body.

        Args:
            function_address: Address or name of the owning function.
            start: Start address of the tail region.
            end: End address of the tail region (exclusive).
        """
        from ghidra.program.model.address import AddressSet  # noqa: PLC0415

        func = resolve_function(function_address)
        start_addr = resolve_address(start)
        end_addr = resolve_address(end)

        # end is exclusive, so the last included address is end - 1
        end_offset = end_addr.getOffset()
        if end_offset == 0:
            raise GhidraError("End address must be > start address", error_type="InvalidArgument")
        last_addr = start_addr.getNewAddress(end_offset - 1)

        program = session.program
        tx_id = program.startTransaction("Append function tail")
        try:
            # Build new body = existing body + new range
            current_body = func.getBody()
            new_body = AddressSet(current_body)
            new_body.addRange(start_addr, last_addr)
            func.setBody(new_body)
            program.endTransaction(tx_id, True)
        except GhidraError:
            program.endTransaction(tx_id, False)
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to append tail [{format_address(start_addr.getOffset())}, "
                f"{format_address(end_addr.getOffset())}) to function at "
                f"{format_address(func.getEntryPoint().getOffset())}: {e}",
                error_type="AppendFailed",
            ) from e

        return AppendFunctionTailResult(
            function=format_address(func.getEntryPoint().getOffset()),
            tail_start=format_address(start_addr.getOffset()),
            tail_end=format_address(end_addr.getOffset()),
        )

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"functions"})
    @session.require_open
    def remove_function_tail(
        function_address: Address,
        tail_address: Address,
    ) -> RemoveFunctionTailResult:
        """Remove a tail (non-contiguous range) from a function body.

        Removes the address range containing ``tail_address`` from the
        function body.  The entry-point range cannot be removed.

        Args:
            function_address: Address or name of the owning function.
            tail_address: Any address within the tail range to remove.
        """
        from ghidra.program.model.address import AddressSet  # noqa: PLC0415

        func = resolve_function(function_address)
        tail_addr = resolve_address(tail_address)
        entry = func.getEntryPoint()

        # Find the range containing tail_address
        body = func.getBody()
        target_range = None
        ranges = body.iterator()
        while ranges.hasNext():
            addr_range = ranges.next()
            if addr_range.contains(tail_addr):
                target_range = addr_range
                break

        if target_range is None:
            raise GhidraError(
                f"Address {format_address(tail_addr.getOffset())} is not in "
                f"function {func.getName()}",
                error_type="NotFound",
            )

        # Don't allow removing the range that contains the entry point
        if target_range.contains(entry):
            raise GhidraError(
                "Cannot remove the range containing the function entry point",
                error_type="InvalidArgument",
            )

        program = session.program
        range_start = target_range.getMinAddress()
        range_end_exclusive = target_range.getMaxAddress().getOffset() + 1

        tx_id = program.startTransaction("Remove function tail")
        try:
            new_body = AddressSet(body)
            new_body.deleteRange(target_range.getMinAddress(), target_range.getMaxAddress())
            func.setBody(new_body)
            program.endTransaction(tx_id, True)
        except GhidraError:
            program.endTransaction(tx_id, False)
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to remove tail at {format_address(tail_addr.getOffset())} "
                f"from function at {format_address(entry.getOffset())}: {e}",
                error_type="RemoveFailed",
            ) from e

        return RemoveFunctionTailResult(
            function=format_address(entry.getOffset()),
            removed_tail_start=format_address(range_start.getOffset()),
            removed_tail_end=format_address(range_end_exclusive),
        )
