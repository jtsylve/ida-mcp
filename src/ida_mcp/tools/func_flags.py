# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Function flag manipulation tools — library marking, hidden ranges, byte flags."""

from __future__ import annotations

import ida_bytes
import ida_funcs
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import (
    format_address,
    get_func_name,
    paginate_iter,
    resolve_address,
    resolve_function,
)
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def set_function_flags(
        address: str,
        library: bool | None = None,
        thunk: bool | None = None,
        noreturn: bool | None = None,
        hidden: bool | None = None,
    ) -> dict:
        """Set or clear function flags (library, thunk, noreturn, hidden).

        Only provided flags are changed; others are left as-is.

        Args:
            address: Address or name of the function.
            library: Mark/unmark as library function.
            thunk: Mark/unmark as thunk (wrapper) function.
            noreturn: Mark/unmark as non-returning.
            hidden: Mark/unmark as hidden (collapsed in listing).
        """
        func, err = resolve_function(address)
        if err:
            return err

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
            return {
                "address": format_address(func.start_ea),
                "name": get_func_name(func.start_ea),
                "changed": changed,
                "old_flags": old_flags,
                "flags": func.flags,
            }

        func.flags = flags
        if not ida_funcs.update_func(func):
            return {
                "error": f"Failed to update function flags at {format_address(func.start_ea)}",
                "error_type": "UpdateFailed",
            }

        return {
            "address": format_address(func.start_ea),
            "name": get_func_name(func.start_ea),
            "changed": changed,
            "old_flags": old_flags,
            "flags": func.flags,
        }

    @mcp.tool()
    @session.require_open
    def get_byte_flags(address: str) -> dict:
        """Get IDA internal flags for a byte address.

        Returns decoded flag information showing what IDA knows about this
        address: whether it's code, data, head of an item, has xrefs, etc.

        Args:
            address: Address to query.
        """
        ea, err = resolve_address(address)
        if err:
            return err

        flags = ida_bytes.get_flags(ea)
        return {
            "address": format_address(ea),
            "raw_flags": f"0x{flags:X}",
            "is_code": ida_bytes.is_code(flags),
            "is_data": ida_bytes.is_data(flags),
            "is_tail": ida_bytes.is_tail(flags),
            "is_head": ida_bytes.is_head(flags),
            "is_loaded": ida_bytes.is_loaded(ea),
            "has_value": ida_bytes.has_value(flags),
            "has_xref": ida_bytes.has_xref(flags),
            "has_name": ida_bytes.has_name(flags),
            "has_dummy_name": ida_bytes.has_dummy_name(flags),
            "has_auto_name": ida_bytes.has_auto_name(flags),
            "has_user_name": ida_bytes.has_user_name(flags),
            "has_comment": ida_bytes.has_cmt(flags),
            "has_extra_comment": ida_bytes.has_extra_cmts(flags),
            "item_size": ida_bytes.get_item_size(ea),
        }

    @mcp.tool()
    @session.require_open
    def add_hidden_range(start_address: str, end_address: str, description: str = "") -> dict:
        """Create a hidden (collapsed) range in the disassembly listing.

        Hidden ranges collapse a range of addresses into a single line in the
        listing, useful for hiding uninteresting code or data.

        Args:
            start_address: Start of the range.
            end_address: End of the range (exclusive).
            description: Optional description shown when collapsed.
        """
        start, err = resolve_address(start_address)
        if err:
            return err
        end, err = resolve_address(end_address)
        if err:
            return err

        if not ida_bytes.add_hidden_range(start, end, description, "", "", 0xFFFFFFFF):
            return {
                "error": f"Failed to add hidden range {format_address(start)}-{format_address(end)}",
                "error_type": "AddFailed",
            }
        return {
            "start": format_address(start),
            "end": format_address(end),
            "description": description,
        }

    @mcp.tool()
    @session.require_open
    def delete_hidden_range(address: str) -> dict:
        """Delete a hidden range that contains the given address.

        Args:
            address: Any address within the hidden range.
        """
        ea, err = resolve_address(address)
        if err:
            return err

        hr = ida_bytes.get_hidden_range(ea)
        old_start = format_address(hr.start_ea) if hr else None
        old_end = format_address(hr.end_ea) if hr else None
        old_description = (hr.description or "") if hr else ""

        if not ida_bytes.del_hidden_range(ea):
            return {
                "error": f"Failed to delete hidden range at {format_address(ea)}",
                "error_type": "DeleteFailed",
            }
        return {
            "address": format_address(ea),
            "old_start": old_start,
            "old_end": old_end,
            "old_description": old_description,
        }

    @mcp.tool()
    @session.require_open
    def get_hidden_ranges(offset: int = 0, limit: int = 100) -> dict:
        """List all hidden (collapsed) ranges in the database.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """

        def _iter():
            hr = ida_bytes.get_first_hidden_range()
            while hr is not None:
                yield {
                    "start": format_address(hr.start_ea),
                    "end": format_address(hr.end_ea),
                    "description": hr.description or "",
                    "size": hr.end_ea - hr.start_ea,
                }
                hr = ida_bytes.get_next_hidden_range(hr.end_ea)

        return paginate_iter(_iter(), offset, limit)
