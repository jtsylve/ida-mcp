# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Additional address metadata tools — source line numbers and analysis flags."""

from __future__ import annotations

import ida_nalt
from fastmcp import FastMCP

from ida_mcp.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    IDAError,
    format_address,
    is_bad_addr,
    resolve_address,
)
from ida_mcp.session import session


def _valid_linnum(linnum: int) -> int | None:
    """Return linnum if it's a real source line number, else None."""
    return linnum if not is_bad_addr(linnum) and linnum >= 0 else None


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"metadata"},
    )
    @session.require_open
    def get_source_line_number(
        address: Address,
    ) -> dict:
        """Get the source file line number associated with an address.

        Returns the DWARF/debug-info source line mapping stored in the
        database for the given address. Returns null if no mapping exists.

        Args:
            address: Address to query.
        """
        ea = resolve_address(address)

        linnum = ida_nalt.get_source_linnum(ea)
        return {"address": format_address(ea), "line_number": _valid_linnum(linnum)}

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"metadata"},
    )
    @session.require_open
    def set_source_line_number(
        address: Address,
        line_number: int,
    ) -> dict:
        """Set the source file line number for an address.

        Associates a source line number with an address in the database.
        Useful when adding debug information manually or correlating
        binary addresses with source positions.

        Args:
            address: Address to annotate.
            line_number: Source line number (1-based).
        """
        ea = resolve_address(address)

        if line_number < 0:
            raise IDAError("line_number must be non-negative", error_type="InvalidArgument")

        old_linnum = ida_nalt.get_source_linnum(ea)
        ida_nalt.set_source_linnum(ea, line_number)
        return {
            "address": format_address(ea),
            "old_line_number": _valid_linnum(old_linnum),
            "line_number": line_number,
        }

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"metadata"},
    )
    @session.require_open
    def get_address_info(
        address: Address,
    ) -> dict:
        """Get IDA's analysis flags and metadata for an address.

        Returns a decoded view of the additional flags IDA stores for an
        address, including analysis hints (no-return, library item, etc.)
        and type provenance information.

        Args:
            address: Address to query.
        """
        ea = resolve_address(address)

        flags = ida_nalt.get_aflags(ea)
        linnum = ida_nalt.get_source_linnum(ea)

        return {
            "address": format_address(ea),
            "no_return": bool(ida_nalt.is_noret(ea)),
            "is_library_item": bool(ida_nalt.is_libitem(ea)),
            "is_hidden": bool(ida_nalt.is_hidden_item(ea)),
            "type_guessed_by_ida": bool(ida_nalt.is_type_guessed_by_ida(ea)),
            "type_guessed_by_hexrays": bool(ida_nalt.is_type_guessed_by_hexrays(ea)),
            "type_determined_by_hexrays": bool(ida_nalt.is_type_determined_by_hexrays(ea)),
            "func_guessed_by_hexrays": bool(ida_nalt.is_func_guessed_by_hexrays(ea)),
            "fixed_sp_delta": bool(ida_nalt.is_fixed_spd(ea)),
            "source_line_number": _valid_linnum(linnum),
            "raw_aflags": flags,
        }

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"metadata"},
    )
    @session.require_open
    def set_library_item(
        address: Address,
        is_library: bool,
    ) -> dict:
        """Mark or unmark an address as a library item.

        Library items are shown differently in IDA and excluded from
        certain analysis outputs. Useful for marking known library code.

        Args:
            address: Address to mark.
            is_library: True to mark as library item, False to clear.
        """
        ea = resolve_address(address)

        old_value = bool(ida_nalt.is_libitem(ea))
        if is_library:
            ida_nalt.set_libitem(ea)
        else:
            ida_nalt.clr_libitem(ea)

        return {
            "address": format_address(ea),
            "old_is_library_item": old_value,
            "is_library_item": is_library,
        }
