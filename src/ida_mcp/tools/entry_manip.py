# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Entry point manipulation tools."""

from __future__ import annotations

import ida_entry
from fastmcp import FastMCP

from ida_mcp.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    IDAError,
    format_address,
    resolve_address,
)
from ida_mcp.session import session


def _resolve_entry(ordinal: int) -> int:
    """Resolve an entry point ordinal to its address.

    Raises :class:`IDAError` if the entry point is not found.
    """
    ea = ida_entry.get_entry(ordinal)
    if ea is None or ea == 0:
        raise IDAError(f"Entry point not found at ordinal {ordinal}", error_type="NotFound")
    return ea


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"metadata"},
    )
    @session.require_open
    def add_entry_point(
        address: Address,
        name: str,
        ordinal: int = 0,
        make_code: bool = True,
    ) -> dict:
        """Add an entry point to the database.

        Args:
            address: Address of the entry point.
            name: Name for the entry point.
            ordinal: Ordinal number (0 to auto-assign).
            make_code: Whether to mark the address as code.
        """
        ea = resolve_address(address)

        success = ida_entry.add_entry(ordinal, ea, name, make_code)
        if not success:
            raise IDAError(
                f"Failed to add entry point at {format_address(ea)}", error_type="AddFailed"
            )

        return {
            "address": format_address(ea),
            "name": name,
            "ordinal": ordinal,
        }

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"metadata"},
    )
    @session.require_open
    def rename_entry_point(ordinal: int, name: str) -> dict:
        """Rename an entry point by its ordinal number.

        Args:
            ordinal: Ordinal number of the entry point.
            name: New name for the entry point.
        """
        ea = _resolve_entry(ordinal)

        old_name = ida_entry.get_entry_name(ordinal) or ""
        success = ida_entry.rename_entry(ordinal, name)
        if not success:
            raise IDAError(
                f"Failed to rename entry point at ordinal {ordinal}", error_type="RenameFailed"
            )

        return {
            "ordinal": ordinal,
            "address": format_address(ea),
            "old_name": old_name,
            "new_name": name,
        }

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"metadata"},
    )
    @session.require_open
    def set_entry_forwarder(ordinal: int, name: str) -> dict:
        """Set a forwarder name for an entry point.

        Forwarders redirect an entry point to another module's export
        (e.g. "NTDLL.RtlAllocateHeap").

        Args:
            ordinal: Ordinal number of the entry point.
            name: Forwarder name string.
        """
        ea = _resolve_entry(ordinal)

        old_forwarder = ida_entry.get_entry_forwarder(ordinal) or ""
        success = ida_entry.set_entry_forwarder(ordinal, name)
        if not success:
            raise IDAError(
                f"Failed to set forwarder for entry point at ordinal {ordinal}",
                error_type="SetFailed",
            )

        return {
            "ordinal": ordinal,
            "address": format_address(ea),
            "old_forwarder": old_forwarder,
            "forwarder": name,
        }

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"metadata"},
    )
    @session.require_open
    def get_entry_forwarder(ordinal: int) -> dict:
        """Get the forwarder name for an entry point.

        Args:
            ordinal: Ordinal number of the entry point.
        """
        ea = _resolve_entry(ordinal)

        forwarder = ida_entry.get_entry_forwarder(ordinal) or ""
        return {
            "ordinal": ordinal,
            "address": format_address(ea),
            "name": ida_entry.get_entry_name(ordinal) or "",
            "forwarder": forwarder,
        }
