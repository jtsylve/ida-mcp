# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Name demangling tools for C++ symbol analysis."""

from __future__ import annotations

import ida_name
import idautils
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_READ_ONLY,
    META_BATCH,
    Address,
    FilterPattern,
    Limit,
    Offset,
    async_paginate_iter,
    compile_filter,
    format_address,
    is_cancelled,
    resolve_address,
)
from ida_mcp.models import PaginatedResult
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class DemangleResult(BaseModel):
    """Result of demangling a name."""

    name: str = Field(description="Original mangled name.")
    demangled: str | None = Field(description="Demangled name, or null if not mangled.")
    is_mangled: bool = Field(description="Whether the name was mangled.")


class DemangleAtAddressResult(BaseModel):
    """Result of demangling the name at an address."""

    address: str = Field(description="Address (hex).")
    name: str | None = Field(description="Name at the address.")
    demangled: str | None = Field(description="Demangled name, or null if not mangled.")
    is_mangled: bool = Field(description="Whether the name was mangled.")


class DemangledNameItem(BaseModel):
    """A demangled name entry."""

    address: str = Field(description="Address (hex).")
    mangled: str = Field(description="Mangled name.")
    demangled: str = Field(description="Demangled name.")


class DemangledNameListResult(PaginatedResult[DemangledNameItem]):
    """Paginated list of demangled names."""

    items: list[DemangledNameItem] = Field(description="Page of demangled names.")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"utility"},
    )
    @session.require_open
    def demangle_name(name: str, disable_mask: int = 0) -> DemangleResult:
        """Demangle a C++ mangled symbol name.

        Converts mangled names like "_ZN3FooC1Ev" to readable forms
        like "Foo::Foo(void)".

        Args:
            name: The mangled symbol name.
            disable_mask: Bitmask of demangler features to disable (0 for default).
        """
        result = ida_name.demangle_name(name, disable_mask)
        if result is None or result == name:
            return DemangleResult(
                name=name,
                demangled=None,
                is_mangled=False,
            )

        return DemangleResult(
            name=name,
            demangled=result,
            is_mangled=True,
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"utility"},
    )
    @session.require_open
    def demangle_at_address(
        address: Address,
    ) -> DemangleAtAddressResult:
        """Demangle the symbol name at a given address.

        Args:
            address: Address or symbol name to demangle.
        """
        ea = resolve_address(address)

        name = ida_name.get_name(ea)
        if not name:
            return DemangleAtAddressResult(
                address=format_address(ea),
                name=None,
                demangled=None,
                is_mangled=False,
            )

        demangled = ida_name.demangle_name(name, 0)
        return DemangleAtAddressResult(
            address=format_address(ea),
            name=name,
            demangled=demangled if demangled and demangled != name else None,
            is_mangled=demangled is not None and demangled != name,
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"utility"},
        meta=META_BATCH,
    )
    @session.require_open
    async def list_demangled_names(
        offset: Offset = 0,
        limit: Limit = 100,
        filter_pattern: FilterPattern = "",
    ) -> DemangledNameListResult:
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
                if is_cancelled():
                    return
                demangled = ida_name.demangle_name(name, 0)
                if not demangled or demangled == name:
                    continue
                if pattern and not pattern.search(demangled):
                    continue
                yield {
                    "address": format_address(ea),
                    "mangled": name,
                    "demangled": demangled,
                }

        return DemangledNameListResult(
            **await async_paginate_iter(_iter(), offset, limit, progress_label="Demangling names")
        )
