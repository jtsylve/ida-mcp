# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Import, export, and entry point enumeration tools."""

from __future__ import annotations

import ida_entry
import ida_loader
import ida_nalt
import idautils
from fastmcp import FastMCP

from ida_mcp.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    Limit,
    Offset,
    format_address,
    paginate,
    paginate_iter,
    resolve_address,
)
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"metadata"},
    )
    @session.require_open
    def get_imports(
        module_filter: str = "",
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List all imported functions grouped by module.

        Use module_filter to narrow results to a specific library (e.g.
        "kernel32", "libc"). After finding an import address, use
        get_xrefs_to to find all code that calls it.

        Args:
            module_filter: Optional substring to filter module names (case-insensitive).
            offset: Pagination offset (applied to the flat list of imports).
            limit: Maximum number of import entries.
        """
        all_imports = []

        def _import_cb(ea, name, ordinal):
            all_imports.append(
                {
                    "module": current_module,
                    "address": format_address(ea),
                    "name": name or "",
                    "ordinal": ordinal,
                }
            )
            return True  # continue enumeration

        filter_lower = module_filter.lower()
        for i in range(ida_nalt.get_import_module_qty()):
            current_module = ida_nalt.get_import_module_name(i) or ""
            if filter_lower and filter_lower not in current_module.lower():
                continue
            ida_nalt.enum_import_names(i, _import_cb)

        return paginate(all_imports, offset, limit)

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"metadata"},
    )
    @session.require_open
    def get_exports(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List all exported symbols.

        Good starting point for analyzing shared libraries or DLLs —
        exports are the public API. Use get_xrefs_to on an export address
        to find internal callers.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """

        def _iter():
            for index, ordinal, ea, name in idautils.Entries():
                yield {
                    "index": index,
                    "ordinal": ordinal,
                    "address": format_address(ea),
                    "name": name or "",
                }

        return paginate_iter(_iter(), offset, limit)

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"metadata"},
    )
    @session.require_open
    def get_entry_points(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List all entry points of the binary.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """

        def _iter():
            for i in range(ida_entry.get_entry_qty()):
                ordinal = ida_entry.get_entry_ordinal(i)
                ea = ida_entry.get_entry(ordinal)
                name = ida_entry.get_entry_name(ordinal) or ""
                yield {
                    "ordinal": ordinal,
                    "address": format_address(ea),
                    "name": name,
                }

        return paginate_iter(_iter(), offset, limit)

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"metadata"},
    )
    @session.require_open
    def set_import_name(
        modnode: int,
        address: Address,
        name: str,
    ) -> dict:
        """Set the name of an import entry.

        Associates a name with an import at the given address in the
        specified module node.

        Args:
            modnode: Module node identifier (from import enumeration).
            address: Linear address of the import entry.
            name: Name to set for the import.
        """
        ea = resolve_address(address)
        ida_loader.set_import_name(modnode, ea, name)
        return {"modnode": modnode, "address": format_address(ea), "name": name}

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"metadata"},
    )
    @session.require_open
    def set_import_ordinal(
        modnode: int,
        address: Address,
        ordinal: int,
    ) -> dict:
        """Set the ordinal of an import entry.

        Associates an ordinal number with an import at the given address
        in the specified module node.

        Args:
            modnode: Module node identifier (from import enumeration).
            address: Linear address of the import entry.
            ordinal: Ordinal number to set.
        """
        ea = resolve_address(address)
        ida_loader.set_import_ordinal(modnode, ea, ordinal)
        return {"modnode": modnode, "address": format_address(ea), "ordinal": ordinal}
