# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Bookmark (marked position) tools."""

from __future__ import annotations

import idc
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    META_BATCH,
    Address,
    IDAError,
    Limit,
    Offset,
    async_paginate_iter,
    format_address,
    is_bad_addr,
    resolve_address,
)
from ida_mcp.models import PaginatedResult
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class SetBookmarkResult(BaseModel):
    """Result of setting a bookmark."""

    address: str = Field(description="Bookmark address (hex).")
    slot: int = Field(description="Bookmark slot number.")
    old_description: str = Field(description="Previous description.")
    description: str = Field(description="New description.")


class BookmarkItem(BaseModel):
    """A bookmark entry."""

    address: str = Field(description="Bookmark address (hex).")
    slot: int = Field(description="Bookmark slot number.")
    description: str = Field(description="Bookmark description.")


class BookmarkListResult(PaginatedResult[BookmarkItem]):
    """Paginated list of bookmarks."""

    items: list[BookmarkItem] = Field(description="Page of bookmarks.")


class DeleteBookmarkResult(BaseModel):
    """Result of deleting a bookmark."""

    slot: int = Field(description="Bookmark slot number.")
    address: str = Field(description="Bookmark address (hex).")
    old_description: str = Field(description="Previous description.")


# IDA supports bookmark slots 1..1024.
_MAX_BOOKMARK_SLOT = 1024


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"navigation"},
    )
    @session.require_open
    def set_bookmark(
        address: Address,
        description: str = "",
        slot: int = -1,
    ) -> SetBookmarkResult:
        """Set a bookmark (marked position) at an address.

        Args:
            address: Address to bookmark.
            description: Description for the bookmark.
            slot: Bookmark slot (1-1024, or -1 to auto-assign the first free slot).
        """
        ea = resolve_address(address)

        if slot != -1 and (slot < 1 or slot > _MAX_BOOKMARK_SLOT):
            raise IDAError(
                f"Bookmark slot {slot} out of range (1..{_MAX_BOOKMARK_SLOT})",
                error_type="InvalidArgument",
            )

        if slot == -1:
            # Find first free slot
            for i in range(1, _MAX_BOOKMARK_SLOT + 1):
                bm = idc.get_bookmark(i)
                if bm is None or is_bad_addr(bm):
                    slot = i
                    break
            else:
                raise IDAError("No free bookmark slots", error_type="NoSlot")

        old_ea = idc.get_bookmark(slot)
        old_description = ""
        if old_ea is not None and not is_bad_addr(old_ea):
            old_description = idc.get_bookmark_desc(slot) or ""

        idc.put_bookmark(ea, 0, 0, 0, slot, description)
        return SetBookmarkResult(
            address=format_address(ea),
            slot=slot,
            old_description=old_description,
            description=description,
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"navigation"},
        meta=META_BATCH,
    )
    @session.require_open
    async def get_bookmarks(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> BookmarkListResult:
        """List all bookmarks (marked positions) in the database.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """

        def _iter():
            for i in range(1, _MAX_BOOKMARK_SLOT + 1):
                ea = idc.get_bookmark(i)
                if ea is not None and not is_bad_addr(ea):
                    desc = idc.get_bookmark_desc(i)
                    yield {
                        "slot": i,
                        "address": format_address(ea),
                        "description": desc or "",
                    }

        return BookmarkListResult(
            **await async_paginate_iter(_iter(), offset, limit, progress_label="Listing bookmarks")
        )

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"navigation"},
    )
    @session.require_open
    def delete_bookmark(slot: int) -> DeleteBookmarkResult:
        """Delete a bookmark by slot number.

        Args:
            slot: Bookmark slot number to delete.
        """
        if slot < 1 or slot > _MAX_BOOKMARK_SLOT:
            raise IDAError(
                f"Bookmark slot {slot} out of range (1..{_MAX_BOOKMARK_SLOT})",
                error_type="InvalidArgument",
            )

        ea = idc.get_bookmark(slot)
        if ea is None or is_bad_addr(ea):
            raise IDAError(f"No bookmark in slot {slot}", error_type="NotFound")

        old_description = idc.get_bookmark_desc(slot) or ""
        idc.put_bookmark(0, 0, 0, 0, slot, "")
        return DeleteBookmarkResult(
            slot=slot,
            address=format_address(ea),
            old_description=old_description,
        )
