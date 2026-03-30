# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Name demangling tools for C++ symbol analysis."""

from __future__ import annotations

import ida_name
import idautils
from fastmcp import FastMCP

from ida_mcp.helpers import compile_filter, format_address, paginate_iter, resolve_address
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def demangle_name(name: str, disable_mask: int = 0) -> dict:
        """Demangle a C++ mangled symbol name.

        Converts mangled names like "_ZN3FooC1Ev" to readable forms
        like "Foo::Foo(void)".

        Args:
            name: The mangled symbol name.
            disable_mask: Bitmask of demangler features to disable (0 for default).
        """
        result = ida_name.demangle_name(name, disable_mask)
        if result is None or result == name:
            return {
                "name": name,
                "demangled": None,
                "is_mangled": False,
            }

        return {
            "name": name,
            "demangled": result,
            "is_mangled": True,
        }

    @mcp.tool()
    @session.require_open
    def demangle_at_address(address: str) -> dict:
        """Demangle the symbol name at a given address.

        Args:
            address: Address or symbol name to demangle.
        """
        ea = resolve_address(address)

        name = ida_name.get_name(ea)
        if not name:
            return {
                "address": format_address(ea),
                "name": None,
                "demangled": None,
                "is_mangled": False,
            }

        demangled = ida_name.demangle_name(name, 0)
        return {
            "address": format_address(ea),
            "name": name,
            "demangled": demangled if demangled and demangled != name else None,
            "is_mangled": demangled is not None and demangled != name,
        }

    @mcp.tool()
    @session.require_open
    def list_demangled_names(offset: int = 0, limit: int = 100, filter_pattern: str = "") -> dict:
        """List all named addresses with their demangled forms.

        Only includes names that have a demangled form (i.e. mangled C++ names).
        Useful for C++ binaries where mangled names are unreadable. Large C++
        binaries can have thousands of mangled names — use filter_pattern to
        narrow results (e.g. "vector|string"). For a quick check of a single
        symbol, use demangle_name or demangle_at_address instead.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
            filter_pattern: Optional regex to filter demangled names.
        """
        pattern = compile_filter(filter_pattern)

        def _iter():
            for ea, name in idautils.Names():
                demangled = ida_name.demangle_name(name, 0)
                if not demangled or demangled == name:
                    continue
                if pattern and not pattern.search(demangled):
                    continue
                yield {
                    "address": format_address(ea),
                    "name": name,
                    "demangled": demangled,
                }

        return paginate_iter(_iter(), offset, limit)
