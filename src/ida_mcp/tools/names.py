# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Naming and labeling tools — rename addresses, list named items."""

from __future__ import annotations

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
        """Rename any address (globals, data labels, variables, etc.).

        Unlike rename_function, this works on any address in the database.

        Args:
            address: Address or current name to rename.
            new_name: The new name to assign. Pass empty string to remove the name.
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
    ) -> NameListResult:
        """List all named locations in the database (functions, globals, data labels, etc.).

        Large binaries can have thousands of names. Use filter_pattern
        to narrow results with a regex. For function-specific name searches,
        list_functions with filter_pattern may be more targeted.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
            filter_pattern: Optional regex to filter names.
        """
        pattern = compile_filter(filter_pattern)

        def _iter():
            for ea, name in idautils.Names():
                if is_cancelled():
                    return
                if pattern and not pattern.search(name):
                    continue
                yield {"address": format_address(ea), "name": name}

        return NameListResult(
            **await async_paginate_iter(_iter(), offset, limit, progress_label="Listing names")
        )
