# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Naming and labeling tools — rename addresses, list named items."""

from __future__ import annotations

from typing import Annotated

import ida_name
import idautils
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_MUTATE,
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
from ida_mcp.models import PaginatedResult, RenameResult
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class NameItem(BaseModel):
    """A named address."""

    address: str = Field(description="Address (hex).")
    name: str = Field(description="Name at address.")


class NameListResult(PaginatedResult[NameItem]):
    """Paginated list of names."""

    items: list[NameItem] = Field(description="Page of names.")


class NameFilter(BaseModel):
    """A filter for batch name search."""

    pattern: str = Field(description="Regex pattern to match names.")
    limit: int = Field(default=100, ge=1, description="Max matches for this filter.")


class NameGroup(BaseModel):
    """Matches for one filter in a batch name search."""

    pattern: str = Field(description="The regex pattern used.")
    matches: list[NameItem] = Field(description="Matching names.")
    total_scanned: int = Field(description="Total names scanned.")


class BatchNamesResult(BaseModel):
    """Result of batch name search with multiple filters."""

    groups: list[NameGroup] = Field(description="Results grouped by filter.")
    cancelled: bool = Field(default=False, description="Whether search was cancelled early.")


def _batch_names(filters: list[NameFilter]) -> BatchNamesResult:
    """Run batch name search — single pass over all names for all patterns."""
    compiled = [(compile_filter(f.pattern), f.limit, f.pattern) for f in filters]
    per_filter: list[list[dict]] = [[] for _ in compiled]
    cancelled = False
    remaining = len(compiled)
    total = 0
    for ea, name in idautils.Names():
        if is_cancelled():
            cancelled = True
            break
        total += 1
        for fi, (pat, lim, _) in enumerate(compiled):
            if len(per_filter[fi]) >= lim:
                continue
            if pat and not pat.search(name):
                continue
            per_filter[fi].append({"address": format_address(ea), "name": name})
            if len(per_filter[fi]) >= lim:
                remaining -= 1
        if remaining <= 0:
            break

    groups = [
        NameGroup(pattern=raw_pattern, matches=per_filter[fi], total_scanned=total)
        for fi, (_, _, raw_pattern) in enumerate(compiled)
    ]
    return BatchNamesResult(groups=groups, cancelled=cancelled)


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"navigation"},
    )
    @session.require_open
    def rename_address(
        address: Address,
        new_name: str,
    ) -> RenameResult:
        """Rename ONE label (data, jump target, any non-function address).

        Works on any address, unlike rename_function which requires a function start.
        Use rename_function when renaming a function — it validates the function exists.
        Pass empty string to remove an existing name.

        Args:
            address: Address or current name to rename.
            new_name: New name to assign. Pass empty string to remove the name.
        """
        ea = resolve_address(address)

        old_name = ida_name.get_name(ea) or ""
        success = ida_name.set_name(ea, new_name, ida_name.SN_CHECK)
        if not success:
            raise IDAError(
                f"Failed to rename {format_address(ea)} to {new_name!r}", error_type="RenameFailed"
            )

        return RenameResult(
            address=format_address(ea),
            old_name=old_name,
            new_name=new_name,
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"navigation"},
        meta=META_BATCH,
    )
    @session.require_open
    async def list_names(
        offset: Offset = 0,
        limit: Limit = 100,
        filter_pattern: FilterPattern = "",
        filters: Annotated[
            list[NameFilter] | None,
            Field(
                description=(
                    "Batch mode: list of filters to search for multiple "
                    "patterns in one pass (max 10). Mutually exclusive with "
                    "filter_pattern."
                ),
                max_length=10,
            ),
        ] = None,
    ) -> NameListResult | BatchNamesResult:
        """List every named location (functions + globals + data labels), regex-filterable.

        **Single mode** — use filter_pattern to get a paginated list of
        names.  **Batch mode** — pass filters (a list of ``{pattern,
        limit}``) to search for multiple patterns in a single pass.

        Large binaries can have thousands of names. Use filter_pattern
        to narrow results with a regex. For function-specific name searches,
        list_functions with filter_pattern may be more targeted.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
            filter_pattern: Optional regex to filter names.
            filters: Batch mode — list of filters for multi-pattern search.
        """
        # Batch mode — single pass over all names for all patterns
        if filters:
            if filter_pattern:
                raise IDAError(
                    "Provide either filters (batch) or filter_pattern (single), not both",
                    error_type="InvalidArgument",
                )
            return await call_ida(_batch_names, filters)

        # Single mode
        pattern = compile_filter(filter_pattern)

        def _iter():
            for ea, name in idautils.Names():
                if is_cancelled():
                    return
                if pattern and not pattern.search(name):
                    continue
                yield {"address": format_address(ea), "name": name}

        return NameListResult(**await async_paginate_iter(_iter(), offset, limit))
