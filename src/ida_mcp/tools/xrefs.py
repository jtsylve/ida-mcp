# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Cross-reference analysis tools."""

from __future__ import annotations

from typing import Annotated

import ida_funcs
import idautils
from fastmcp import FastMCP
from pydantic import Field

from ida_mcp.helpers import (
    ANNO_READ_ONLY,
    Address,
    Limit,
    Offset,
    format_address,
    get_func_name,
    paginate_iter,
    resolve_address,
    resolve_function,
    xref_type_name,
)
from ida_mcp.models import CallGraphResult, XrefFromResult, XrefToResult
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"xrefs"},
        output_schema=XrefToResult.model_json_schema(),
    )
    @session.require_open
    def get_xrefs_to(
        address: Address,
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """Get all cross-references TO an address.

        Shows what code or data references the given address. Returns both
        code xrefs (calls, jumps) and data xrefs (reads, writes) — check
        is_code to distinguish them.

        Commonly used after get_strings to find what code references a
        string, or after get_imports to find callers of an imported function.
        Popular addresses (malloc, printf, etc.) may have hundreds of xrefs;
        use pagination to manage large result sets.

        Args:
            address: Target address or symbol name.
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        ea = resolve_address(address)

        result = paginate_iter(
            (
                {
                    "from": format_address(xref.frm),
                    "from_name": get_func_name(xref.frm),
                    "type": xref_type_name(xref.type),
                    "is_code": xref.iscode,
                }
                for xref in idautils.XrefsTo(ea)
            ),
            offset,
            limit,
        )
        result["address"] = format_address(ea)
        return result

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"xrefs"},
        output_schema=XrefFromResult.model_json_schema(),
    )
    @session.require_open
    def get_xrefs_from(
        address: Address,
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """Get all cross-references FROM an address.

        Shows what the given address references. Useful after search_bytes
        or search_text to understand what a found instruction accesses.
        For function-level call analysis, get_call_graph is more convenient.

        Args:
            address: Source address or symbol name.
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        ea = resolve_address(address)

        result = paginate_iter(
            (
                {
                    "to": format_address(xref.to),
                    "to_name": get_func_name(xref.to),
                    "type": xref_type_name(xref.type),
                    "is_code": xref.iscode,
                }
                for xref in idautils.XrefsFrom(ea)
            ),
            offset,
            limit,
        )
        result["address"] = format_address(ea)
        return result

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"xrefs"},
        output_schema=CallGraphResult.model_json_schema(),
    )
    @session.require_open
    def get_call_graph(
        address: Address,
        depth: Annotated[
            int, Field(description="How many levels deep to traverse (1-3).", ge=1)
        ] = 1,
    ) -> dict:
        """Get the call graph for a function (callers and callees).

        Output grows exponentially with depth. depth=1 returns direct
        callers/callees and is always safe. depth=2 on hub functions
        (malloc, printf, etc.) can return thousands of entries and may
        timeout. depth=3 is not recommended for most use cases. For
        simpler queries, get_xrefs_to (callers) or get_xrefs_from
        (callees) may suffice.

        Args:
            address: Address or name of the function.
            depth: How many levels deep to traverse (1-3, default 1).
        """
        func = resolve_function(address)

        depth = max(1, min(depth, 3))

        def _get_callees(func_ea: int, current_depth: int, visited: set | None = None) -> list:
            if current_depth <= 0:
                return []
            if visited is None:
                visited = set()
            if func_ea in visited:
                return []
            visited.add(func_ea)
            callees = set()
            f = ida_funcs.get_func(func_ea)
            if f is None:
                return []
            for item_ea in idautils.FuncItems(f.start_ea):
                for ref in idautils.CodeRefsFrom(item_ea, False):
                    callee_func = ida_funcs.get_func(ref)
                    if callee_func and callee_func.start_ea != func_ea:
                        callees.add(callee_func.start_ea)

            result = []
            for callee_ea in sorted(callees):
                entry = {
                    "address": format_address(callee_ea),
                    "name": get_func_name(callee_ea),
                }
                if current_depth > 1:
                    entry["callees"] = _get_callees(callee_ea, current_depth - 1, visited)
                result.append(entry)
            return result

        def _get_callers(func_ea: int, current_depth: int, visited: set | None = None) -> list:
            if current_depth <= 0:
                return []
            if visited is None:
                visited = set()
            if func_ea in visited:
                return []
            visited.add(func_ea)
            callers = set()
            for ref in idautils.CodeRefsTo(func_ea, False):
                caller_func = ida_funcs.get_func(ref)
                if caller_func and caller_func.start_ea != func_ea:
                    callers.add(caller_func.start_ea)

            result = []
            for caller_ea in sorted(callers):
                entry = {
                    "address": format_address(caller_ea),
                    "name": get_func_name(caller_ea),
                }
                if current_depth > 1:
                    entry["callers"] = _get_callers(caller_ea, current_depth - 1, visited)
                result.append(entry)
            return result

        return {
            "function": {
                "address": format_address(func.start_ea),
                "name": get_func_name(func.start_ea),
            },
            "callers": _get_callers(func.start_ea, depth),
            "callees": _get_callees(func.start_ea, depth),
        }
