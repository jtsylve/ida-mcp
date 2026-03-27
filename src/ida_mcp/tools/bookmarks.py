# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Bookmark (marked position) tools."""

from __future__ import annotations

import idc
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import format_address, is_bad_addr, paginate_iter, resolve_address
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def set_bookmark(address: str, description: str = "", slot: int = -1) -> dict:
        """Set a bookmark (marked position) at an address.

        Args:
            address: Address to bookmark.
            description: Description for the bookmark.
            slot: Bookmark slot (1-1024, or -1 to auto-assign the first free slot).
        """
        ea, err = resolve_address(address)
        if err:
            return err

        if slot == -1:
            # Find first free slot
            for i in range(1, 1025):
                bm = idc.get_bookmark(i)
                if bm is None or is_bad_addr(bm):
                    slot = i
                    break
            else:
                return {"error": "No free bookmark slots", "error_type": "NoSlot"}

        old_ea = idc.get_bookmark(slot)
        old_description = ""
        if old_ea is not None and not is_bad_addr(old_ea):
            old_description = idc.get_bookmark_desc(slot) or ""

        idc.put_bookmark(ea, 0, 0, 0, slot, description)
        return {
            "address": format_address(ea),
            "slot": slot,
            "old_description": old_description,
            "description": description,
        }

    @mcp.tool()
    @session.require_open
    def get_bookmarks(offset: int = 0, limit: int = 100) -> dict:
        """List all bookmarks (marked positions) in the database.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """

        def _iter():
            for i in range(1, 1025):
                ea = idc.get_bookmark(i)
                if ea is not None and not is_bad_addr(ea):
                    desc = idc.get_bookmark_desc(i)
                    yield {
                        "slot": i,
                        "address": format_address(ea),
                        "description": desc or "",
                    }

        return paginate_iter(_iter(), offset, limit)

    @mcp.tool()
    @session.require_open
    def delete_bookmark(slot: int) -> dict:
        """Delete a bookmark by slot number.

        Args:
            slot: Bookmark slot number to delete.
        """
        ea = idc.get_bookmark(slot)
        if ea is None or is_bad_addr(ea):
            return {"error": f"No bookmark in slot {slot}", "error_type": "NotFound"}

        old_description = idc.get_bookmark_desc(slot) or ""
        idc.put_bookmark(0, 0, 0, 0, slot, "")
        return {
            "slot": slot,
            "address": format_address(ea),
            "old_description": old_description,
        }
