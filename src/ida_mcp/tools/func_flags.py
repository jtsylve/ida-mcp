# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Function flag manipulation tools — library marking, hidden ranges, byte flags."""

from __future__ import annotations

import ida_bytes
import ida_funcs
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    META_BATCH,
    Address,
    IDAError,
    Limit,
    Offset,
    async_paginate_iter,
    format_address,
    get_func_name,
    resolve_address,
    resolve_function,
)
from ida_mcp.models import PaginatedResult
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class SetFunctionFlagsResult(BaseModel):
    """Result of setting function flags."""

    address: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    changed: dict[str, bool] = Field(description="Flags that were changed.")
    old_flags: int = Field(description="Previous flags bitmask.")
    flags: int = Field(description="New flags bitmask.")


class ByteFlagsResult(BaseModel):
    """Byte-level flags at an address."""

    address: str = Field(description="Address (hex).")
    raw_flags: str = Field(description="Raw flags value (hex).")
    is_code: bool = Field(description="Address contains code.")
    is_data: bool = Field(description="Address contains data.")
    is_tail: bool = Field(description="Address is a tail byte.")
    is_head: bool = Field(description="Address is a head byte.")
    is_loaded: bool = Field(description="Address is loaded.")
    has_value: bool = Field(description="Address has a value.")
    has_xref: bool = Field(description="Address has cross-references.")
    has_name: bool = Field(description="Address has a name.")
    has_dummy_name: bool = Field(description="Address has a dummy name.")
    has_auto_name: bool = Field(description="Address has an auto-generated name.")
    has_user_name: bool = Field(description="Address has a user-defined name.")
    has_comment: bool = Field(description="Address has a comment.")
    has_extra_comment: bool = Field(description="Address has extra comments.")
    item_size: int = Field(description="Size of the item at this address.")


class AddHiddenRangeResult(BaseModel):
    """Result of adding a hidden range."""

    start: str = Field(description="Range start address (hex).")
    end: str = Field(description="Range end address (hex).")
    description: str = Field(description="Range description.")


class DeleteHiddenRangeResult(BaseModel):
    """Result of deleting a hidden range."""

    address: str = Field(description="Address in the hidden range (hex).")
    old_start: str | None = Field(description="Previous start address (hex).")
    old_end: str | None = Field(description="Previous end address (hex).")
    old_description: str = Field(description="Previous description.")


class HiddenRangeItem(BaseModel):
    """A hidden range."""

    start: str = Field(description="Range start address (hex).")
    end: str = Field(description="Range end address (hex).")
    description: str = Field(description="Range description.")
    size: int = Field(description="Range size in bytes.")


class HiddenRangeListResult(PaginatedResult[HiddenRangeItem]):
    """Paginated list of hidden ranges."""

    items: list[HiddenRangeItem] = Field(description="Page of hidden ranges.")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"functions"},
    )
    @session.require_open
    def set_function_flags(
        address: Address,
        library: bool | None = None,
        thunk: bool | None = None,
        noreturn: bool | None = None,
        hidden: bool | None = None,
    ) -> SetFunctionFlagsResult:
        """Set or clear function flags (library, thunk, noreturn, hidden).

        Only provided flags are changed; others are left as-is.

        Args:
            address: Address or name of the function.
            library: Mark/unmark as library function.
            thunk: Mark/unmark as thunk (wrapper) function.
            noreturn: Mark/unmark as non-returning.
            hidden: Mark/unmark as hidden (collapsed in listing).
        """
        func = resolve_function(address)

        old_flags = func.flags
        flags = func.flags
        flag_map = {
            "library": (library, ida_funcs.FUNC_LIB),
            "thunk": (thunk, ida_funcs.FUNC_THUNK),
            "noreturn": (noreturn, ida_funcs.FUNC_NORET),
            "hidden": (hidden, ida_funcs.FUNC_HIDDEN),
        }

        changed = {}
        for name, (value, bit) in flag_map.items():
            if value is None:
                continue
            if value:
                flags |= bit
            else:
                flags &= ~bit
            changed[name] = value

        if not changed:
            return SetFunctionFlagsResult(
                address=format_address(func.start_ea),
                name=get_func_name(func.start_ea),
                changed=changed,
                old_flags=old_flags,
                flags=func.flags,
            )

        func.flags = flags
        if not ida_funcs.update_func(func):
            raise IDAError(
                f"Failed to update function flags at {format_address(func.start_ea)}",
                error_type="UpdateFailed",
            )

        return SetFunctionFlagsResult(
            address=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            changed=changed,
            old_flags=old_flags,
            flags=func.flags,
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"functions"},
    )
    @session.require_open
    def get_byte_flags(
        address: Address,
    ) -> ByteFlagsResult:
        """Get IDA internal flags for a byte (code/data/head/xref status).

        Args:
            address: Address to query.
        """
        ea = resolve_address(address)

        flags = ida_bytes.get_flags(ea)
        return ByteFlagsResult(
            address=format_address(ea),
            raw_flags=f"0x{flags:X}",
            is_code=ida_bytes.is_code(flags),
            is_data=ida_bytes.is_data(flags),
            is_tail=ida_bytes.is_tail(flags),
            is_head=ida_bytes.is_head(flags),
            is_loaded=ida_bytes.is_loaded(ea),
            has_value=ida_bytes.has_value(flags),
            has_xref=ida_bytes.has_xref(flags),
            has_name=ida_bytes.has_name(flags),
            has_dummy_name=ida_bytes.has_dummy_name(flags),
            has_auto_name=ida_bytes.has_auto_name(flags),
            has_user_name=ida_bytes.has_user_name(flags),
            has_comment=ida_bytes.has_cmt(flags),
            has_extra_comment=ida_bytes.has_extra_cmts(flags),
            item_size=ida_bytes.get_item_size(ea),
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"functions"},
    )
    @session.require_open
    def add_hidden_range(
        start_address: Address,
        end_address: Address,
        description: str = "",
    ) -> AddHiddenRangeResult:
        """Create a hidden (collapsed) range in the disassembly listing.

        Hidden ranges collapse a range of addresses into a single line in the
        listing, useful for hiding uninteresting code or data.

        Args:
            start_address: Start of the range.
            end_address: End of the range (exclusive).
            description: Optional description shown when collapsed.
        """
        start = resolve_address(start_address)
        end = resolve_address(end_address)

        if not ida_bytes.add_hidden_range(start, end, description, "", "", 0xFFFFFFFF):
            raise IDAError(
                f"Failed to add hidden range {format_address(start)}-{format_address(end)}",
                error_type="AddFailed",
            )
        return AddHiddenRangeResult(
            start=format_address(start),
            end=format_address(end),
            description=description,
        )

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"functions"},
    )
    @session.require_open
    def delete_hidden_range(
        address: Address,
    ) -> DeleteHiddenRangeResult:
        """Delete a hidden range that contains the given address.

        Args:
            address: Any address within the hidden range.
        """
        ea = resolve_address(address)

        hr = ida_bytes.get_hidden_range(ea)
        old_start = format_address(hr.start_ea) if hr else None
        old_end = format_address(hr.end_ea) if hr else None
        old_description = (hr.description or "") if hr else ""

        if not ida_bytes.del_hidden_range(ea):
            raise IDAError(
                f"Failed to delete hidden range at {format_address(ea)}", error_type="DeleteFailed"
            )
        return DeleteHiddenRangeResult(
            address=format_address(ea),
            old_start=old_start,
            old_end=old_end,
            old_description=old_description,
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"functions"},
        meta=META_BATCH,
    )
    @session.require_open
    async def get_hidden_ranges(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> HiddenRangeListResult:
        """List all hidden (collapsed) ranges in the database.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """

        def _iter():
            hr = ida_bytes.get_first_hidden_range()
            while hr is not None:
                yield HiddenRangeItem(
                    start=format_address(hr.start_ea),
                    end=format_address(hr.end_ea),
                    description=hr.description or "",
                    size=hr.end_ea - hr.start_ea,
                )
                hr = ida_bytes.get_next_hidden_range(hr.end_ea)

        return HiddenRangeListResult(**await async_paginate_iter(_iter(), offset, limit))
