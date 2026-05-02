# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Bookmark management tools."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ghidra_mcp.exceptions import GhidraError
from ghidra_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    Limit,
    Offset,
    format_address,
    paginate_iter,
    resolve_address,
)
from ghidra_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class SetBookmarkResult(BaseModel):
    """Result of setting a bookmark."""

    address: str = Field(description="Bookmark address (hex).")
    category: str = Field(description="Bookmark category.")
    description: str = Field(description="Bookmark description.")
    status: str = Field(description="Operation status.")


class BookmarkItem(BaseModel):
    """A bookmark entry."""

    address: str = Field(description="Bookmark address (hex).")
    category: str = Field(description="Bookmark category.")
    description: str = Field(description="Bookmark description.")
    type: str = Field(description="Bookmark type.")


class DeleteBookmarkResult(BaseModel):
    """Result of deleting a bookmark."""

    address: str = Field(description="Bookmark address (hex).")
    category: str = Field(description="Category filter used.")
    removed_count: int = Field(description="Number of bookmarks removed.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"navigation"})
    @session.require_open
    def set_bookmark(
        address: Address,
        description: str = "",
        category: str = "Analysis",
    ) -> SetBookmarkResult:
        """Set a bookmark at an address.

        Args:
            address: Address to bookmark.
            description: Description for the bookmark.
            category: Bookmark category (e.g. "Analysis", "Suspicious", "TODO").
        """
        program = session.program
        addr = resolve_address(address)
        bm_mgr = program.getBookmarkManager()

        tx_id = program.startTransaction("Set bookmark")
        try:
            bm_mgr.setBookmark(addr, "Note", category, description)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to set bookmark: {e}", error_type="BookmarkFailed") from e

        return SetBookmarkResult(
            address=format_address(addr.getOffset()),
            category=category,
            description=description,
            status="ok",
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"navigation"})
    @session.require_open
    def get_bookmarks(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List all bookmarks in the database, paginated.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        program = session.program
        bm_mgr = program.getBookmarkManager()

        def _gen():
            bm_iter = bm_mgr.getBookmarksIterator()
            while bm_iter.hasNext():
                bm = bm_iter.next()
                yield BookmarkItem(
                    address=format_address(bm.getAddress().getOffset()),
                    category=bm.getCategory() or "",
                    description=bm.getComment() or "",
                    type=bm.getTypeString() or "Note",
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"navigation"})
    @session.require_open
    def delete_bookmark(
        address: Address,
        category: str = "",
    ) -> DeleteBookmarkResult:
        """Delete bookmark(s) at an address.

        Args:
            address: Address of the bookmark(s) to delete.
            category: If provided, only delete bookmarks in this category.
                Empty string deletes all bookmarks at the address.
        """
        program = session.program
        addr = resolve_address(address)
        bm_mgr = program.getBookmarkManager()

        # Collect bookmarks to remove
        bookmarks = list(bm_mgr.getBookmarks(addr))
        if category:
            bookmarks = [bm for bm in bookmarks if bm.getCategory() == category]

        if not bookmarks:
            raise GhidraError(
                f"No bookmarks at {format_address(addr.getOffset())}"
                + (f" in category {category!r}" if category else ""),
                error_type="NotFound",
            )

        tx_id = program.startTransaction("Delete bookmark")
        try:
            for bm in bookmarks:
                bm_mgr.removeBookmark(bm)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to delete bookmark: {e}", error_type="BookmarkFailed") from e

        return DeleteBookmarkResult(
            address=format_address(addr.getOffset()),
            category=category,
            removed_count=len(bookmarks),
        )
