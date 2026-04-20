# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Name demangling tools for C++ symbol analysis."""

from __future__ import annotations

from typing import Annotated

import ida_name
import idautils
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_READ_ONLY,
    META_BATCH,
    Address,
    FilterPattern,
    IDAError,
    Limit,
    Offset,
    async_paginate_iter,
    call_ida,
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


class DemangledNameFilter(BaseModel):
    """A filter for batch demangled name search."""

    pattern: str = Field(description="Regex pattern to match demangled names.")
    limit: int = Field(default=100, ge=1, description="Max matches for this filter.")


class DemangledNameGroup(BaseModel):
    """Matches for one filter in a batch demangled name search."""

    pattern: str = Field(description="The regex pattern used.")
    matches: list[DemangledNameItem] = Field(description="Matching demangled names.")
    total_scanned: int = Field(description="Total names scanned.")


class BatchDemangledNamesResult(BaseModel):
    """Result of batch demangled name search with multiple filters."""

    groups: list[DemangledNameGroup] = Field(description="Results grouped by filter.")
    cancelled: bool = Field(default=False, description="Whether search was cancelled early.")


def _batch_demangled_names(filters: list[DemangledNameFilter]) -> BatchDemangledNamesResult:
    """Run batch demangled name search — single pass over all names for all patterns."""
    compiled = [(compile_filter(f.pattern), f.limit, f.pattern) for f in filters]
    per_filter: list[list[dict]] = [[] for _ in compiled]
    cancelled = False
    remaining = len(compiled)
    total = 0
    for ea, name in idautils.Names():
        if is_cancelled():
            cancelled = True
            break
        demangled = ida_name.demangle_name(name, 0)
        if not demangled or demangled == name:
            continue
        total += 1
        for fi, (pat, lim, _) in enumerate(compiled):
            if len(per_filter[fi]) >= lim:
                continue
            if pat and not pat.search(demangled):
                continue
            per_filter[fi].append(
                {
                    "address": format_address(ea),
                    "mangled": name,
                    "demangled": demangled,
                }
            )
            if len(per_filter[fi]) >= lim:
                remaining -= 1
        if remaining <= 0:
            break

    groups = [
        DemangledNameGroup(pattern=raw_pattern, matches=per_filter[fi], total_scanned=total)
        for fi, (_, _, raw_pattern) in enumerate(compiled)
    ]
    return BatchDemangledNamesResult(groups=groups, cancelled=cancelled)


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"utility", "symbols"},
    )
    @session.require_open
    def demangle_name(name: str, disable_mask: int = 0) -> DemangleResult:
        """Demangle a C++ symbol name to readable form (e.g., _ZN3FooC1Ev -> Foo::Foo(void)).

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
        tags={"utility", "symbols"},
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
        tags={"utility", "symbols"},
        meta=META_BATCH,
    )
    @session.require_open
    async def list_demangled_names(
        offset: Offset = 0,
        limit: Limit = 100,
        filter_pattern: FilterPattern = "",
        filters: Annotated[
            list[DemangledNameFilter],
            Field(
                description=(
                    "Batch mode: list of filters to search for multiple "
                    "patterns in one pass (max 10). Mutually exclusive with "
                    "filter_pattern."
                ),
                max_length=10,
            ),
        ] = [],  # noqa: B006
    ) -> DemangledNameListResult | BatchDemangledNamesResult:
        """List named addresses with demangled forms (C++ only; paginated, regex-filterable).

        **Single mode** — use filter_pattern for paginated results.
        **Batch mode** — pass filters (list of {pattern, limit}) to search
        multiple patterns in one pass. For a single symbol, use demangle_name
        or demangle_at_address instead.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
            filter_pattern: Optional regex to filter demangled names.
            filters: Batch mode — list of filters for multi-pattern search.
        """
        # Batch mode — single pass over all names for all patterns
        if filters:
            if filter_pattern:
                raise IDAError(
                    "Provide either filters (batch) or filter_pattern (single), not both",
                    error_type="InvalidArgument",
                )
            return await call_ida(_batch_demangled_names, filters)

        # Single mode
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

        return DemangledNameListResult(**await async_paginate_iter(_iter(), offset, limit))
