# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Segment creation and modification tools."""

from __future__ import annotations

import ida_segment
from fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

from re_mcp_ida.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    Address,
    IDAError,
    format_address,
    format_permissions,
    parse_permissions,
    resolve_address,
    resolve_segment,
)
from re_mcp_ida.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class CreateSegmentResult(BaseModel):
    """Result of creating a segment."""

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(description="Segment name.")
    start: str = Field(description="Start address (hex).")
    end: str = Field(description="End address (hex, exclusive).")
    class_: str = Field(alias="class", description="Segment class.")
    bitness: int = Field(description="Segment bitness (0=16, 1=32, 2=64).")
    permissions: str = Field(description="Permission string.")


class DeleteSegmentResult(BaseModel):
    """Result of deleting a segment."""

    name: str = Field(description="Segment name.")
    start: str = Field(description="Start address (hex).")
    old_end: str = Field(description="Previous end address (hex).")
    old_permissions: str = Field(description="Previous permissions.")
    old_class: str = Field(description="Previous segment class.")


class SetSegmentNameResult(BaseModel):
    """Result of renaming a segment."""

    old_name: str = Field(description="Previous segment name.")
    new_name: str = Field(description="New segment name.")


class SetSegmentPermissionsResult(BaseModel):
    """Result of changing segment permissions."""

    segment: str = Field(description="Segment name.")
    old_permissions: str = Field(description="Previous permissions.")
    permissions: str = Field(description="New permissions.")


class SetSegmentBitnessResult(BaseModel):
    """Result of changing segment bitness."""

    segment: str = Field(description="Segment name.")
    old_bitness: int = Field(description="Previous bitness value.")
    bitness: int = Field(description="New bitness value.")


class SetSegmentClassResult(BaseModel):
    """Result of changing segment class."""

    model_config = ConfigDict(populate_by_name=True)

    segment: str = Field(description="Segment name.")
    old_class: str = Field(description="Previous segment class.")
    class_: str = Field(alias="class", description="New segment class.")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"segments"},
    )
    @session.require_open
    def create_segment(
        name: str,
        start_address: Address,
        end_address: Address,
        segment_class: str = "DATA",
        bitness: int = 0,
        permissions: str = "RW-",
    ) -> CreateSegmentResult:
        """Create a new segment in the database.

        Args:
            name: Name for the segment (e.g. ".mydata").
            start_address: Start address of the segment.
            end_address: End address of the segment (exclusive).
            segment_class: Segment class — "CODE", "DATA", "BSS", "STACK", etc.
            bitness: Address size — 0 for 16-bit, 1 for 32-bit, 2 for 64-bit.
            permissions: Permission string like "RWX", "R--", "RW-".
        """
        start = resolve_address(start_address)
        end = resolve_address(end_address)

        perm = parse_permissions(permissions)

        seg = ida_segment.segment_t()
        seg.start_ea = start
        seg.end_ea = end
        seg.perm = perm
        seg.bitness = bitness

        if not ida_segment.add_segm_ex(seg, name, segment_class, 0):
            raise IDAError(f"Failed to create segment {name!r}", error_type="CreateFailed")

        return CreateSegmentResult(
            name=name,
            start=format_address(start),
            end=format_address(end),
            class_=segment_class,
            bitness=bitness,
            permissions=permissions,
        )

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"segments"},
    )
    @session.require_open
    def delete_segment(
        address: Address,
    ) -> DeleteSegmentResult:
        """Delete the segment containing the given address.

        Args:
            address: Any address within the segment to delete.
        """
        seg = resolve_segment(address)

        name = ida_segment.get_segm_name(seg)
        start = seg.start_ea
        old_end = format_address(seg.end_ea)
        old_permissions = format_permissions(seg.perm)
        old_class = ida_segment.get_segm_class(seg) or ""
        if not ida_segment.del_segm(start, ida_segment.SEGMOD_KILL):
            raise IDAError(f"Failed to delete segment {name!r}", error_type="DeleteFailed")
        return DeleteSegmentResult(
            name=name,
            start=format_address(start),
            old_end=old_end,
            old_permissions=old_permissions,
            old_class=old_class,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"segments"},
    )
    @session.require_open
    def set_segment_name(
        address: Address,
        new_name: str,
    ) -> SetSegmentNameResult:
        """Rename a segment.

        Args:
            address: Any address within the segment.
            new_name: New name for the segment.
        """
        seg = resolve_segment(address)

        old_name = ida_segment.get_segm_name(seg)
        if not ida_segment.set_segm_name(seg, new_name):
            raise IDAError(
                f"Failed to rename segment {old_name!r} to {new_name!r}", error_type="RenameFailed"
            )
        return SetSegmentNameResult(old_name=old_name, new_name=new_name)

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"segments"},
    )
    @session.require_open
    def set_segment_permissions(
        address: Address,
        permissions: str,
    ) -> SetSegmentPermissionsResult:
        """Change segment permissions (e.g., RWX, R-X, RW-).

        Args:
            address: Any address within the segment.
            permissions: Permission string like "RWX", "R-X", "RW-".
        """
        seg = resolve_segment(address)

        perm = parse_permissions(permissions)

        old_perm = seg.perm
        seg.perm = perm
        seg_name = ida_segment.get_segm_name(seg)
        if not seg.update():
            raise IDAError(
                f"Failed to set permissions on segment {seg_name!r}", error_type="UpdateFailed"
            )
        return SetSegmentPermissionsResult(
            segment=seg_name,
            old_permissions=format_permissions(old_perm),
            permissions=permissions,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"segments"},
    )
    @session.require_open
    def set_segment_bitness(
        address: Address,
        bitness: int,
    ) -> SetSegmentBitnessResult:
        """Change the addressing mode of a segment (16/32/64-bit).

        Args:
            address: Any address within the segment.
            bitness: Address size — 0 for 16-bit, 1 for 32-bit, 2 for 64-bit.
        """
        seg = resolve_segment(address)

        if bitness not in (0, 1, 2):
            raise IDAError(
                f"Invalid bitness: {bitness} (must be 0, 1, or 2)", error_type="InvalidArgument"
            )

        old_bitness = seg.bitness
        seg_name = ida_segment.get_segm_name(seg)
        if not ida_segment.set_segm_addressing(seg, bitness):
            raise IDAError(
                f"Failed to set bitness on segment {seg_name!r}", error_type="UpdateFailed"
            )
        return SetSegmentBitnessResult(segment=seg_name, old_bitness=old_bitness, bitness=bitness)

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"segments"},
    )
    @session.require_open
    def set_segment_class(
        address: Address,
        segment_class: str,
    ) -> SetSegmentClassResult:
        """Change the class of a segment (CODE/DATA/BSS/STACK/etc.).

        Args:
            address: Any address within the segment.
            segment_class: New class — "CODE", "DATA", "BSS", "STACK", etc.
        """
        seg = resolve_segment(address)

        seg_name = ida_segment.get_segm_name(seg)
        old_class = ida_segment.get_segm_class(seg) or ""
        if not ida_segment.set_segm_class(seg, segment_class):
            raise IDAError(
                f"Failed to set class on segment {seg_name!r}", error_type="UpdateFailed"
            )
        return SetSegmentClassResult(segment=seg_name, old_class=old_class, class_=segment_class)
