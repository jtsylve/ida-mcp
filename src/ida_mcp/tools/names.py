# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Naming and labeling tools — rename addresses, list named items."""

from __future__ import annotations

import ida_name
import idautils
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import compile_filter, format_address, paginate_iter, resolve_address
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def rename_address(address: str, new_name: str) -> dict:
        """Rename any address (globals, data labels, variables, etc.).

        Unlike rename_function, this works on any address in the database.

        Args:
            address: Address or current name to rename.
            new_name: The new name to assign. Pass empty string to remove the name.
        """
        ea, err = resolve_address(address)
        if err:
            return err

        old_name = ida_name.get_name(ea) or ""
        success = ida_name.set_name(ea, new_name, ida_name.SN_CHECK)
        if not success:
            return {
                "error": f"Failed to rename {format_address(ea)} to {new_name!r}",
                "error_type": "RenameFailed",
            }

        return {
            "address": format_address(ea),
            "old_name": old_name,
            "new_name": new_name,
        }

    @mcp.tool()
    @session.require_open
    def list_names(offset: int = 0, limit: int = 100, filter_pattern: str = "") -> dict:
        """List all named locations in the database (functions, globals, data labels, etc.).

        Large binaries can have thousands of names. Use filter_pattern
        to narrow results with a regex. For function-specific name searches,
        list_functions or search_functions_by_pattern may be more targeted.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
            filter_pattern: Optional regex to filter names.
        """
        pattern, err = compile_filter(filter_pattern)
        if err:
            return err

        def _iter():
            for ea, name in idautils.Names():
                if pattern and not pattern.search(name):
                    continue
                yield {"address": format_address(ea), "name": name}

        return paginate_iter(_iter(), offset, limit)
