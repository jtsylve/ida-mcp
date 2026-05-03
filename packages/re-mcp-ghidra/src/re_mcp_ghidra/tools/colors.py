# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Address and function coloring tools.

Ghidra stores per-address colors via integer property maps on code units.
In headless mode the ``ColorizingService`` plugin is not available, so
colors are read/written through the program's property-map API directly.
The property ``"Color"`` stores an RGB integer on each code unit.
"""

from __future__ import annotations

import contextlib

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    format_address,
    resolve_address,
)
from re_mcp_ghidra.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

_COLOR_PROPERTY = "Color"


class SetColorResult(BaseModel):
    """Result of setting a color."""

    address: str = Field(description="Address (hex).")
    old_color: str | None = Field(description="Previous color (#RRGGBB), or null if unset.")
    color: str = Field(description="New color (#RRGGBB), or 'default' if cleared.")
    what: str = Field(description="Color target type.")


class GetColorResult(BaseModel):
    """Color at an address."""

    address: str = Field(description="Address (hex).")
    what: str = Field(description="Color target type.")
    color: str | None = Field(description="Color value (#RRGGBB), or null if unset.")
    has_color: bool = Field(description="Whether a color is set.")


def _parse_color(color_str: str) -> int | None:
    """Parse a ``#RRGGBB`` or ``RRGGBB`` string to an RGB int, or None to clear."""
    if not color_str:
        return None
    color_str = color_str.removeprefix("#")
    if len(color_str) != 6:
        raise GhidraError(
            f"Color must be 6 hex digits (RRGGBB), got {color_str!r}",
            error_type="InvalidArgument",
        )
    try:
        return int(color_str, 16)
    except ValueError:
        raise GhidraError(f"Invalid color: {color_str!r}", error_type="InvalidArgument") from None


def _format_rgb(value: int) -> str:
    """Format an RGB integer as ``#RRGGBB``."""
    return f"#{value & 0xFFFFFF:06X}"


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"modification", "colors"})
    @session.require_open
    def set_color(
        address: Address,
        color: str,
        what: str = "item",
    ) -> SetColorResult:
        """Set the background color of an address or function.

        Ghidra stores per-address colors as an integer property on code
        units.  In headless mode some rendering-level coloring is
        unavailable; this sets the ``Color`` property that the Ghidra UI
        reads when available.

        Args:
            address: The address to colorize.
            color: Color as hex RGB string (e.g. "#FF0000" for red).
                Use empty string "" to remove color.
            what: What to color -- "item" (single address) or "func"
                (all addresses in the containing function).
        """
        if what not in ("item", "func"):
            raise GhidraError(
                f"Invalid 'what' value: {what!r}. Must be 'item' or 'func'.",
                error_type="InvalidArgument",
            )

        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)
        new_color = _parse_color(color)

        # Determine the set of addresses to apply the color to
        if what == "func":
            func_mgr = program.getFunctionManager()
            func = func_mgr.getFunctionContaining(addr)
            if func is None:
                raise GhidraError(
                    f"No function at {format_address(addr.getOffset())}",
                    error_type="NotFound",
                )
            addresses = func.getBody()
        else:
            addresses = None  # single address

        # Read old color from the primary address
        cu = listing.getCodeUnitAt(addr)
        old_color = None
        if cu is not None:
            try:
                old_val = cu.getIntProperty(_COLOR_PROPERTY)
                old_color = _format_rgb(old_val)
            except Exception:
                pass  # Property not set

        tx_id = program.startTransaction("Set color")
        try:
            if addresses is not None:
                # Apply to all code units in the function body
                cu_iter = listing.getCodeUnits(addresses, True)
                while cu_iter.hasNext():
                    unit = cu_iter.next()
                    if new_color is not None:
                        unit.setProperty(_COLOR_PROPERTY, new_color)
                    else:
                        with contextlib.suppress(Exception):
                            unit.removeProperty(_COLOR_PROPERTY)
            else:
                if cu is None:
                    raise GhidraError(
                        f"No code unit at {format_address(addr.getOffset())}",
                        error_type="NotFound",
                    )
                if new_color is not None:
                    cu.setProperty(_COLOR_PROPERTY, new_color)
                else:
                    with contextlib.suppress(Exception):
                        cu.removeProperty(_COLOR_PROPERTY)

            program.endTransaction(tx_id, True)
        except GhidraError:
            program.endTransaction(tx_id, False)
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to set color: {e}", error_type="SetColorFailed") from e

        return SetColorResult(
            address=format_address(addr.getOffset()),
            old_color=old_color,
            color=_format_rgb(new_color) if new_color is not None else "default",
            what=what,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"colors"})
    @session.require_open
    def get_color(
        address: Address,
        what: str = "item",
    ) -> GetColorResult:
        """Get the background color of an address.

        Args:
            address: The address to query.
            what: What to query -- "item" or "func" (reads color at
                function entry point).
        """
        if what not in ("item", "func"):
            raise GhidraError(
                f"Invalid 'what' value: {what!r}. Must be 'item' or 'func'.",
                error_type="InvalidArgument",
            )

        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)

        if what == "func":
            func_mgr = program.getFunctionManager()
            func = func_mgr.getFunctionContaining(addr)
            if func is None:
                raise GhidraError(
                    f"No function at {format_address(addr.getOffset())}",
                    error_type="NotFound",
                )
            addr = func.getEntryPoint()

        cu = listing.getCodeUnitAt(addr)
        if cu is None:
            return GetColorResult(
                address=format_address(addr.getOffset()),
                what=what,
                color=None,
                has_color=False,
            )

        try:
            val = cu.getIntProperty(_COLOR_PROPERTY)
            return GetColorResult(
                address=format_address(addr.getOffset()),
                what=what,
                color=_format_rgb(val),
                has_color=True,
            )
        except Exception:
            return GetColorResult(
                address=format_address(addr.getOffset()),
                what=what,
                color=None,
                has_color=False,
            )
