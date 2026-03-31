# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Data and memory operations — read bytes, list segments."""

from __future__ import annotations

import ida_bytes
import ida_segment
from fastmcp import FastMCP

from ida_mcp.helpers import (
    ANNO_READ_ONLY,
    Address,
    IDAError,
    Limit,
    Offset,
    format_address,
    format_permissions,
    paginate,
    resolve_address,
    segment_bitness,
)
from ida_mcp.models import ReadBytesResult, SegmentListResult
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"segments"},
    )
    @session.require_open
    def read_bytes(
        address: Address,
        size: int = 16,
    ) -> ReadBytesResult:
        """Read raw bytes from the database at a given address.

        Args:
            address: Address to read from (hex string or symbol name).
            size: Number of bytes to read (max 4096).
        """
        ea = resolve_address(address)

        size = max(1, min(size, 4096))
        data = ida_bytes.get_bytes(ea, size)
        if data is None:
            raise IDAError(
                f"Cannot read {size} bytes at {format_address(ea)}", error_type="ReadError"
            )

        # Format as hex dump with ASCII
        hex_lines = []
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            hex_lines.append(f"{format_address(ea + i)}  {hex_part:<48s}  {ascii_part}")

        return ReadBytesResult(
            address=format_address(ea),
            size=len(data),
            hex=data.hex(),
            dump="\n".join(hex_lines),
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"segments"},
    )
    @session.require_open
    def get_segments(
        offset: Offset = 0,
        limit: Limit = 50,
    ) -> SegmentListResult:
        """List all segments in the binary.

        Useful for understanding memory layout before targeted operations.
        Segment addresses can be used as start_address/end_address bounds
        for search_bytes, find_immediate, or get_fixups to avoid scanning
        the entire binary.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        segments = []
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            if seg is None:
                continue
            segments.append(
                {
                    "name": ida_segment.get_segm_name(seg),
                    "start": format_address(seg.start_ea),
                    "end": format_address(seg.end_ea),
                    "size": seg.end_ea - seg.start_ea,
                    "class": ida_segment.get_segm_class(seg),
                    "permissions": format_permissions(seg.perm),
                    "bitness": segment_bitness(seg.bitness),
                }
            )

        return SegmentListResult(**paginate(segments, offset, limit))
