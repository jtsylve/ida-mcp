# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Cross-reference analysis tools."""

from __future__ import annotations

from typing import Annotated

import ida_funcs
import idautils
from fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

from re_mcp_ida.helpers import (
    ANNO_READ_ONLY,
    META_BATCH,
    Address,
    Limit,
    Offset,
    async_paginate_iter,
    call_ida,
    format_address,
    get_func_name,
    resolve_address,
    resolve_function,
    xref_type_name,
)
from re_mcp_ida.models import PaginatedResult
from re_mcp_ida.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class XrefTo(BaseModel):
    """A cross-reference TO an address."""

    model_config = ConfigDict(populate_by_name=True)

    from_: str = Field(alias="from", description="Source address of the reference (hex).")
    from_name: str = Field(description="Function name containing the source address.")
    type: str = Field(description="Cross-reference type (e.g. 'Code_Near_Call', 'Data_Read').")
    is_code: bool = Field(description="Whether this is a code (vs data) reference.")


class XrefToResult(PaginatedResult[XrefTo]):
    """Paginated cross-references TO an address."""

    address: str = Field(description="Target address queried (hex).")
    items: list[XrefTo] = Field(description="Page of cross-references.")


class XrefFrom(BaseModel):
    """A cross-reference FROM an address."""

    to: str = Field(description="Target address of the reference (hex).")
    to_name: str = Field(description="Function name containing the target address.")
    type: str = Field(description="Cross-reference type.")
    is_code: bool = Field(description="Whether this is a code (vs data) reference.")


class XrefFromResult(PaginatedResult[XrefFrom]):
    """Paginated cross-references FROM an address."""

    address: str = Field(description="Source address queried (hex).")
    items: list[XrefFrom] = Field(description="Page of cross-references.")


class CallGraphEntry(BaseModel):
    """A node in a call graph."""

    address: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")


class CallGraphResult(BaseModel):
    """Call graph showing callers and callees of a function.

    ``callers`` and ``callees`` are recursive trees: each entry contains
    ``address``, ``name``, and (when depth > 1) a nested ``callers`` or
    ``callees`` list.  Typed as ``list[dict]`` because Pydantic's JSON Schema
    output doesn't support recursive ``$ref`` cycles cleanly.
    """

    function: CallGraphEntry = Field(description="The queried function.")
    callers: list[dict] = Field(
        description="Functions that call this function (recursive with depth)."
    )
    callees: list[dict] = Field(
        description="Functions called by this function (recursive with depth)."
    )


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"xrefs"},
    )
    @session.require_open
    async def get_xrefs_to(
        address: Address,
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> XrefToResult:
        """List all cross-references pointing TO an address (callers, data readers, etc.).

        Returns both code xrefs (calls, jumps) and data xrefs (pointer references) —
        check is_code to distinguish them. For function-level caller/callee analysis,
        get_call_graph is more convenient. Use find_code_by_string to combine
        get_strings + get_xrefs_to in a single call.

        Args:
            address: Target address or symbol name.
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        ea = await call_ida(resolve_address, address)

        result = await async_paginate_iter(
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
        return XrefToResult(address=format_address(ea), **result)

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"xrefs"},
        meta=META_BATCH,
    )
    @session.require_open
    async def get_xrefs_from(
        address: Address,
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> XrefFromResult:
        """List all cross-references originating FROM an address (callees, data accesses).

        Shows what the given address references — useful after search_bytes or
        search_text to understand what a found instruction accesses. For
        function-level callee traversal, get_call_graph is more convenient.

        Args:
            address: Source address or symbol name.
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        ea = await call_ida(resolve_address, address)

        result = await async_paginate_iter(
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
        return XrefFromResult(address=format_address(ea), **result)

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"xrefs"},
    )
    @session.require_open
    def get_call_graph(
        address: Address,
        depth: Annotated[
            int, Field(description="How many levels deep to traverse (1-3).", ge=1, le=3)
        ] = 1,
    ) -> CallGraphResult:
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

        return CallGraphResult(
            function=CallGraphEntry(
                address=format_address(func.start_ea),
                name=get_func_name(func.start_ea),
            ),
            callers=_get_callers(func.start_ea, depth),
            callees=_get_callees(func.start_ea, depth),
        )
