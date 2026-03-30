# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Pydantic models for structured tool output schemas.

These models are used with ``@mcp.tool(output_schema=...)`` so that MCP
clients can discover the shape of tool responses ahead of time.  The tool
implementations continue to return plain dicts — FastMCP emits the schema
in the tool definition and passes the dict through as structured content.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Pagination envelope — shared by all paginated endpoints
# ---------------------------------------------------------------------------


class PaginatedResult(BaseModel):
    """Paginated result set."""

    items: list[dict] = Field(description="Page of result items.")
    total: int = Field(
        description="Total number of matching items (may be approximate for large sets)."
    )
    offset: int = Field(description="Starting offset of this page.")
    limit: int = Field(description="Maximum items per page.")
    has_more: bool = Field(description="Whether more items exist beyond this page.")


# ---------------------------------------------------------------------------
# Function-related schemas
# ---------------------------------------------------------------------------


class FunctionSummary(BaseModel):
    """Brief function info returned by list_functions."""

    name: str = Field(description="Function name.")
    start: str = Field(description="Start address (hex).")
    end: str = Field(description="End address (hex, exclusive).")
    size: int = Field(description="Function size in bytes.")


class FunctionListResult(PaginatedResult):
    """Paginated list of functions."""

    items: list[FunctionSummary] = Field(description="Page of function summaries.")  # type: ignore[assignment]


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


class RenameResult(BaseModel):
    """Result of a rename operation."""

    address: str = Field(description="Address of the renamed item (hex).")
    old_name: str = Field(description="Previous name.")
    new_name: str = Field(description="New name.")


# ---------------------------------------------------------------------------
# Cross-reference schemas
# ---------------------------------------------------------------------------


class XrefTo(BaseModel):
    """A cross-reference TO an address."""

    from_: str = Field(alias="from", description="Source address of the reference (hex).")
    from_name: str = Field(description="Function name containing the source address.")
    type: str = Field(description="Cross-reference type (e.g. 'Code_Near_Call', 'Data_Read').")
    is_code: bool = Field(description="Whether this is a code (vs data) reference.")


class XrefToResult(PaginatedResult):
    """Paginated cross-references TO an address."""

    address: str = Field(description="Target address queried (hex).")
    items: list[XrefTo] = Field(description="Page of cross-references.")  # type: ignore[assignment]


class XrefFrom(BaseModel):
    """A cross-reference FROM an address."""

    to: str = Field(description="Target address of the reference (hex).")
    to_name: str = Field(description="Function name containing the target address.")
    type: str = Field(description="Cross-reference type.")
    is_code: bool = Field(description="Whether this is a code (vs data) reference.")


class XrefFromResult(PaginatedResult):
    """Paginated cross-references FROM an address."""

    address: str = Field(description="Source address queried (hex).")
    items: list[XrefFrom] = Field(description="Page of cross-references.")  # type: ignore[assignment]


class CallGraphEntry(BaseModel):
    """A node in a call graph."""

    address: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")


class CallGraphResult(BaseModel):
    """Call graph showing callers and callees of a function."""

    function: CallGraphEntry = Field(description="The queried function.")
    callers: list[dict] = Field(
        description="Functions that call this function (recursive with depth)."
    )
    callees: list[dict] = Field(
        description="Functions called by this function (recursive with depth)."
    )
