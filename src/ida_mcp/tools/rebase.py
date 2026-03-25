# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Segment moving and program rebasing tools."""

from __future__ import annotations

import ida_ida
import ida_segment
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import format_address, parse_address, resolve_address, resolve_segment
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def move_segment(address: str, new_start: str) -> dict:
        """Move a segment to a new starting address.

        Relocates the entire segment and updates all references.

        Args:
            address: Any address within the segment to move.
            new_start: New starting address for the segment.
        """
        seg, err = resolve_segment(address)
        if err:
            return err
        to, err = resolve_address(new_start)
        if err:
            return err

        old_start = seg.start_ea
        name = ida_segment.get_segm_name(seg)
        code = ida_segment.move_segm(seg, to)

        if code != 0:
            error_msg = ida_segment.move_segm_strerror(code)
            return {
                "error": f"Failed to move segment: {error_msg}",
                "error_type": "MoveFailed",
                "error_code": int(code),
            }

        return {
            "segment": name,
            "old_start": format_address(old_start),
            "new_start": format_address(to),
        }

    @mcp.tool()
    @session.require_open
    def rebase_program(delta: str) -> dict:
        """Rebase the entire program by a given delta.

        Shifts all addresses in the database by the specified amount.

        Args:
            delta: Address delta to shift by (can be negative with "0x" prefix,
                e.g. "0x1000" to shift forward, "-0x1000" to shift back).
        """
        try:
            delta_val = -parse_address(delta[1:]) if delta.startswith("-") else parse_address(delta)
        except ValueError as e:
            return {"error": str(e), "error_type": "InvalidAddress"}

        old_base = ida_ida.inf_get_min_ea()
        code = ida_segment.rebase_program(delta_val, ida_segment.MSF_FIXONCE)
        if code != 0:
            return {
                "error": f"Rebase failed with code {code}",
                "error_type": "RebaseFailed",
                "error_code": code,
            }

        return {
            "old_base": format_address(old_base),
            "delta": format_address(delta_val)
            if delta_val >= 0
            else f"-{format_address(-delta_val)}",
        }
