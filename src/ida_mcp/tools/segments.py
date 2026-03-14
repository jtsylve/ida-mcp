# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Segment creation and modification tools."""

from __future__ import annotations

import ida_segment
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import format_address, parse_permissions, resolve_address, resolve_segment
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def create_segment(
        name: str,
        start_address: str,
        end_address: str,
        segment_class: str = "DATA",
        bitness: int = 0,
        permissions: str = "RW-",
    ) -> dict:
        """Create a new segment in the database.

        Args:
            name: Name for the segment (e.g. ".mydata").
            start_address: Start address of the segment.
            end_address: End address of the segment (exclusive).
            segment_class: Segment class — "CODE", "DATA", "BSS", "STACK", etc.
            bitness: Address size — 0 for 16-bit, 1 for 32-bit, 2 for 64-bit.
            permissions: Permission string like "RWX", "R--", "RW-".
        """
        start, err = resolve_address(start_address)
        if err:
            return err
        end, err = resolve_address(end_address)
        if err:
            return err

        perm, err = parse_permissions(permissions)
        if err:
            return err

        seg = ida_segment.segment_t()
        seg.start_ea = start
        seg.end_ea = end
        seg.perm = perm
        seg.bitness = bitness

        if not ida_segment.add_segm_ex(seg, name, segment_class, 0):
            return {
                "error": f"Failed to create segment {name!r}",
                "error_type": "CreateFailed",
            }

        return {
            "name": name,
            "start": format_address(start),
            "end": format_address(end),
            "class": segment_class,
            "bitness": bitness,
            "permissions": permissions,
        }

    @mcp.tool()
    @session.require_open
    def delete_segment(address: str) -> dict:
        """Delete the segment containing the given address.

        Args:
            address: Any address within the segment to delete.
        """
        seg, err = resolve_segment(address)
        if err:
            return err

        name = ida_segment.get_segm_name(seg)
        start = seg.start_ea
        if not ida_segment.del_segm(start, ida_segment.SEGMOD_KILL):
            return {
                "error": f"Failed to delete segment {name!r}",
                "error_type": "DeleteFailed",
            }
        return {
            "name": name,
            "start": format_address(start),
        }

    @mcp.tool()
    @session.require_open
    def set_segment_name(address: str, new_name: str) -> dict:
        """Rename a segment.

        Args:
            address: Any address within the segment.
            new_name: New name for the segment.
        """
        seg, err = resolve_segment(address)
        if err:
            return err

        old_name = ida_segment.get_segm_name(seg)
        if not ida_segment.set_segm_name(seg, new_name):
            return {
                "error": f"Failed to rename segment {old_name!r} to {new_name!r}",
                "error_type": "RenameFailed",
            }
        return {
            "old_name": old_name,
            "new_name": new_name,
        }

    @mcp.tool()
    @session.require_open
    def set_segment_permissions(address: str, permissions: str) -> dict:
        """Change segment permissions.

        Args:
            address: Any address within the segment.
            permissions: Permission string like "RWX", "R-X", "RW-".
        """
        seg, err = resolve_segment(address)
        if err:
            return err

        perm, err = parse_permissions(permissions)
        if err:
            return err

        seg.perm = perm
        seg_name = ida_segment.get_segm_name(seg)
        if not seg.update():
            return {
                "error": f"Failed to set permissions on segment {seg_name!r}",
                "error_type": "UpdateFailed",
            }
        return {
            "segment": seg_name,
            "permissions": permissions,
        }

    @mcp.tool()
    @session.require_open
    def set_segment_bitness(address: str, bitness: int) -> dict:
        """Change the addressing mode (bitness) of a segment.

        Args:
            address: Any address within the segment.
            bitness: Address size — 0 for 16-bit, 1 for 32-bit, 2 for 64-bit.
        """
        seg, err = resolve_segment(address)
        if err:
            return err

        if bitness not in (0, 1, 2):
            return {
                "error": f"Invalid bitness: {bitness} (must be 0, 1, or 2)",
                "error_type": "InvalidArgument",
            }

        seg_name = ida_segment.get_segm_name(seg)
        if not ida_segment.set_segm_addressing(seg, bitness):
            return {
                "error": f"Failed to set bitness on segment {seg_name!r}",
                "error_type": "UpdateFailed",
            }
        return {
            "segment": seg_name,
            "bitness": bitness,
        }

    @mcp.tool()
    @session.require_open
    def set_segment_class(address: str, segment_class: str) -> dict:
        """Change the class of a segment.

        Args:
            address: Any address within the segment.
            segment_class: New class — "CODE", "DATA", "BSS", "STACK", etc.
        """
        seg, err = resolve_segment(address)
        if err:
            return err

        seg_name = ida_segment.get_segm_name(seg)
        if not ida_segment.set_segm_class(seg, segment_class):
            return {
                "error": f"Failed to set class on segment {seg_name!r}",
                "error_type": "UpdateFailed",
            }
        return {
            "segment": seg_name,
            "class": segment_class,
        }
