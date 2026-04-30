# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Data and memory operations — read bytes, list segments, pointer tables."""

from __future__ import annotations

import struct
from typing import Annotated

import ida_bytes
import ida_ida
import ida_nalt
import ida_name
import ida_segment
from fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

from ida_mcp.helpers import (
    ANNO_READ_ONLY,
    Address,
    IDAError,
    Limit,
    Offset,
    check_cancelled,
    decode_string,
    format_address,
    format_permissions,
    is_bad_addr,
    paginate,
    resolve_address,
    segment_bitness,
)
from ida_mcp.models import PaginatedResult
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ReadBytesResult(BaseModel):
    """Raw bytes read from the database."""

    address: str = Field(description="Start address (hex).")
    size: int = Field(description="Number of bytes read.")
    hex: str = Field(description="Hex string of bytes.")
    dump: str = Field(description="Hex dump with ASCII.")


class SegmentSummary(BaseModel):
    """Brief segment information."""

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(description="Segment name.")
    start: str = Field(description="Start address (hex).")
    end: str = Field(description="End address (hex, exclusive).")
    size: int = Field(description="Segment size in bytes.")
    class_: str | None = Field(alias="class", description="Segment class.")
    permissions: str = Field(description="Permissions string (e.g. 'RWX').")
    bitness: int = Field(description="Segment bitness (16, 32, or 64).")


class SegmentListResult(PaginatedResult[SegmentSummary]):
    """Paginated list of segments."""

    items: list[SegmentSummary] = Field(description="Page of segments.")


class PointerEntry(BaseModel):
    """An entry in a pointer table."""

    index: int = Field(description="Index in the table.")
    address: str = Field(description="Address of the pointer slot (hex).")
    value: str = Field(description="Pointer value / target address (hex).")
    target_name: str = Field(default="", description="Name at the target, if any.")
    target_string: str = Field(default="", description="String at the target, if detected.")


class PointerTableResult(BaseModel):
    """Result of reading a pointer table."""

    entries: list[PointerEntry] = Field(description="Table entries.")
    pointer_size: int = Field(description="Size of each pointer in bytes.")
    base_address: str = Field(description="Base address of the table (hex).")


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
        """List all segments (memory layout, permissions, address ranges).

        Segment addresses can bound search_bytes, find_immediate, or
        get_fixups to avoid scanning the entire binary.

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

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"data"},
    )
    @session.require_open
    def read_pointer_table(
        address: Address,
        count: Annotated[
            int,
            Field(description="Number of pointers to read.", ge=1, le=4096),
        ],
        dereference: bool = True,
    ) -> PointerTableResult:
        """Read an array of pointers (vtable, dispatch table, etc.) with optional dereference.

        Uses database bitness for pointer size (4 or 8 bytes). When
        dereference is True, resolves names and auto-detects strings.

        Args:
            address: Start address of the pointer table.
            count: Number of pointers to read (max 4096).
            dereference: Resolve names and strings at target addresses.
        """
        ea = resolve_address(address)
        ptr_size = 8 if ida_ida.inf_is_64bit() else 4
        fmt = "<Q" if ptr_size == 8 else "<I"
        total_bytes = count * ptr_size

        data = ida_bytes.get_bytes(ea, total_bytes)
        if data is None or len(data) < total_bytes:
            raise IDAError(
                f"Cannot read {total_bytes} bytes at {format_address(ea)}",
                error_type="ReadError",
            )

        entries: list[PointerEntry] = []
        for i in range(count):
            check_cancelled()
            offset = i * ptr_size
            (ptr_val,) = struct.unpack_from(fmt, data, offset)
            entry = PointerEntry(
                index=i,
                address=format_address(ea + offset),
                value=format_address(ptr_val),
            )

            if dereference and not is_bad_addr(ptr_val):
                name = ida_name.get_name(ptr_val)
                if name:
                    entry.target_name = name
                # Try to read a string at the target
                flags = ida_bytes.get_flags(ptr_val)
                if ida_bytes.is_strlit(flags):
                    ti = ida_nalt.opinfo_t()
                    if ida_bytes.get_opinfo(ti, ptr_val, 0, flags):
                        str_type = ti.strtype
                    else:
                        str_type = ida_nalt.STRTYPE_C
                    length = ida_bytes.get_max_strlit_length(
                        ptr_val, str_type, ida_bytes.ALOPT_IGNCLT
                    )
                    if length > 0:
                        s = decode_string(ptr_val, length, str_type)
                        if s:
                            entry.target_string = s

            entries.append(entry)

        return PointerTableResult(
            entries=entries,
            pointer_size=ptr_size,
            base_address=format_address(ea),
        )
