# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Type query and application tools."""

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


class GetTypeInfoResult(BaseModel):
    """Type information at an address."""

    address: str = Field(description="Address (hex).")
    name: str = Field(description="Name at address.")
    type: str = Field(description="Type string.")


class SetTypeResult(BaseModel):
    """Result of setting a type at an address."""

    address: str = Field(description="Address (hex).")
    old_type: str = Field(description="Previous type.")
    type: str = Field(description="New type.")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"types"},
    )
    @session.require_open
    def get_type_info(
        address: Address,
    ) -> GetTypeInfoResult:
        """Read the name and current IDA type string at an address.

        Returns empty strings if no type has been applied. Use set_type or
        apply_type_at_address to assign a type, and get_local_type to look
        up the full declaration for a named type.

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
        """Apply an inline C type string at a data address.

        Use this for inline types and function pointer declarations. For types
        already defined in the local type library (structs, enums, typedefs),
        use apply_type_at_address instead — it resolves by name and is safer
        for complex types. For function prototypes, prefer set_function_type.

        Args:
            address: Address or symbol name.
            type_string: C type declaration (e.g. "int (*)(void *, int)", "unsigned int").
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
