# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Address and function coloring tools."""

from __future__ import annotations

import idc
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ida.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    IDAError,
    format_address,
    resolve_address,
)
from re_mcp_ida.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class SetColorResult(BaseModel):
    """Result of setting a color."""

    address: str = Field(description="Address (hex).")
    old_color: str | None = Field(description="Previous color.")
    color: str = Field(description="New color.")
    what: str = Field(description="Color target type.")


class GetColorResult(BaseModel):
    """Color at an address."""

    address: str = Field(description="Address (hex).")
    what: str = Field(description="Color target type.")
    color: str | None = Field(description="Color value, or null if unset.")
    has_color: bool = Field(description="Whether a color is set.")


def _swap_rb(color: int) -> int:
    """Swap red and blue channels (RGB <-> BGR)."""
    return ((color & 0xFF) << 16) | (color & 0xFF00) | ((color >> 16) & 0xFF)


def register(mcp: FastMCP):
    _WHAT_MAP = {
        "item": idc.CIC_ITEM,
        "func": idc.CIC_FUNC,
        "segm": idc.CIC_SEGM,
    }

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification", "colors"},
    )
    @session.require_open
    def set_color(
        address: Address,
        color: str,
        what: str = "item",
    ) -> SetColorResult:
        """Set the background color of an address, function, or segment.

        Args:
            address: The address to colorize.
            color: Color as hex RGB string (e.g. "FF0000" for red, "00FF00" for green).
                Use empty string "" to remove color.
            what: What to color — "item" (single address), "func" (entire function),
                or "segm" (entire segment).
        """
        ea = resolve_address(address)

        what_val = _WHAT_MAP.get(what)
        if what_val is None:
            raise IDAError(
                f"Invalid 'what' value: {what!r}",
                error_type="InvalidArgument",
                valid_values=list(_WHAT_MAP),
            )

        if color == "":
            color_val = 0xFFFFFFFF  # DEFCOLOR — removes color
        else:
            color = color.removeprefix("#")
            if len(color) != 6:
                raise IDAError(
                    f"Color must be 6 hex digits (RRGGBB), got {color!r}",
                    error_type="InvalidArgument",
                )
            try:
                rgb = int(color, 16)
            except ValueError:
                raise IDAError(f"Invalid color: {color!r}", error_type="InvalidArgument") from None
            # IDA uses BGR format internally
            color_val = _swap_rb(rgb)

        old_color_val = idc.get_color(ea, what_val)
        old_color = None if old_color_val == 0xFFFFFFFF else f"{_swap_rb(old_color_val):06X}"

        result = idc.set_color(ea, what_val, color_val)
        # CIC_ITEM always succeeds (void C function, returns None).
        # CIC_FUNC/CIC_SEGM return False when the address has no function/segment.
        if result is False:
            raise IDAError(
                f"Failed to set color at {format_address(ea)}", error_type="SetColorFailed"
            )
        return SetColorResult(
            address=format_address(ea),
            old_color=old_color,
            color=color or "default",
            what=what,
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"colors"},
    )
    @session.require_open
    def get_color(
        address: Address,
        what: str = "item",
    ) -> GetColorResult:
        """Get the background color of an address, function, or segment.

        Args:
            address: The address to query.
            what: What to query — "item", "func", or "segm".
        """
        ea = resolve_address(address)

        what_val = _WHAT_MAP.get(what)
        if what_val is None:
            raise IDAError(
                f"Invalid 'what' value: {what!r}",
                error_type="InvalidArgument",
                valid_values=list(_WHAT_MAP),
            )

        color_val = idc.get_color(ea, what_val)
        if color_val == 0xFFFFFFFF:
            return GetColorResult(
                address=format_address(ea),
                what=what,
                color=None,
                has_color=False,
            )

        # Convert from IDA BGR to RGB
        rgb = f"{_swap_rb(color_val):06X}"

        return GetColorResult(
            address=format_address(ea),
            what=what,
            color=rgb,
            has_color=True,
        )
