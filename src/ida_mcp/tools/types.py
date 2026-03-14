# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Type query and application tools."""

from __future__ import annotations

import idc
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import format_address, resolve_address
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def get_type_info(address: str) -> dict:
        """Get type information at an address.

        Args:
            address: Address or symbol name.
        """
        ea, err = resolve_address(address)
        if err:
            return err

        type_str = idc.get_type(ea) or ""
        name = idc.get_name(ea) or ""

        return {
            "address": format_address(ea),
            "name": name,
            "type": type_str,
        }

    @mcp.tool()
    @session.require_open
    def set_type(address: str, type_string: str) -> dict:
        """Apply a C type declaration at an address.

        Args:
            address: Address or symbol name.
            type_string: C type string (e.g. "int (*)(void *, int)").
        """
        ea, err = resolve_address(address)
        if err:
            return err

        success = idc.SetType(ea, type_string)
        if not success:
            return {
                "error": f"Failed to apply type {type_string!r} at {format_address(ea)}",
                "error_type": "SetTypeFailed",
            }
        return {
            "address": format_address(ea),
            "type": type_string,
        }
