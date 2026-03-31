# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Type query and application tools."""

from __future__ import annotations

import idc
from fastmcp import FastMCP

from ida_mcp.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    IDAError,
    format_address,
    resolve_address,
)
from ida_mcp.models import GetTypeInfoResult, SetTypeResult
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"types"},
    )
    @session.require_open
    def get_type_info(
        address: Address,
    ) -> GetTypeInfoResult:
        """Get type information at an address.

        Args:
            address: Address or symbol name.
        """
        ea = resolve_address(address)

        type_str = idc.get_type(ea) or ""
        name = idc.get_name(ea) or ""

        return GetTypeInfoResult(
            address=format_address(ea),
            name=name,
            type=type_str,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"types"},
    )
    @session.require_open
    def set_type(
        address: Address,
        type_string: str,
    ) -> SetTypeResult:
        """Apply a C type declaration at an address.

        Args:
            address: Address or symbol name.
            type_string: C type string (e.g. "int (*)(void *, int)").
        """
        ea = resolve_address(address)

        old_type = idc.get_type(ea) or ""
        success = idc.SetType(ea, type_string)
        if not success:
            raise IDAError(
                f"Failed to apply type {type_string!r} at {format_address(ea)}",
                error_type="SetTypeFailed",
            )
        return SetTypeResult(
            address=format_address(ea),
            old_type=old_type,
            type=type_string,
        )
