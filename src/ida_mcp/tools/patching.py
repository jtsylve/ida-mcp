# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Binary modification tools — patching, code/function creation, undefine."""

from __future__ import annotations

import ida_bytes
import ida_funcs
import ida_ua
import ida_undo
import idc
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    Address,
    HexBytes,
    IDAError,
    format_address,
    get_func_name,
    get_old_item_info,
    resolve_address,
)
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class PatchBytesResult(BaseModel):
    """Result of patching bytes."""

    address: str = Field(description="Patch address (hex).")
    size: int = Field(description="Number of bytes patched.")
    old_bytes: str = Field(description="Previous bytes (hex).")
    new_bytes: str = Field(description="New bytes (hex).")


class CreateFunctionResult(BaseModel):
    """Result of creating a function."""

    address: str = Field(description="Function start address (hex).")
    name: str = Field(description="Function name.")
    end: str = Field(description="Function end address (hex, exclusive).")
    size: int = Field(description="Function size in bytes.")


class MakeCodeResult(BaseModel):
    """Result of converting to code."""

    address: str = Field(description="Target address (hex).")
    old_item_type: str = Field(description="Previous item type at address.")
    old_item_size: int = Field(description="Previous item size in bytes.")
    size: int = Field(description="Instruction size in bytes.")


class UndefineResult(BaseModel):
    """Result of undefining an item."""

    address: str = Field(description="Target address (hex).")
    old_item_type: str = Field(description="Previous item type at address.")
    old_item_size: int = Field(description="Previous item size in bytes.")
    size: int = Field(description="Number of bytes undefined.")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"modification", "patching"},
    )
    @session.require_open
    def patch_bytes(
        address: Address,
        hex_bytes: HexBytes,
    ) -> PatchBytesResult:
        """Patch bytes at an address in the database.

        Args:
            address: Address to patch.
            hex_bytes: Hex string of bytes to write (e.g. "90 90 90" or "909090").
        """
        ea = resolve_address(address)

        # Parse hex bytes
        _MAX_PATCH_HEX_LEN = 2 * 1024 * 1024  # 1 MB of data = 2M hex chars
        cleaned = hex_bytes.replace(" ", "")
        if not cleaned:
            raise IDAError("Empty hex string", error_type="InvalidArgument")
        if len(cleaned) > _MAX_PATCH_HEX_LEN:
            raise IDAError(
                f"Patch data too large ({len(cleaned)} hex chars, max {_MAX_PATCH_HEX_LEN})",
                error_type="InvalidArgument",
            )
        try:
            new_bytes = bytes.fromhex(cleaned)
        except ValueError:
            raise IDAError(
                f"Invalid hex string: {hex_bytes!r}", error_type="InvalidArgument"
            ) from None

        # Read old bytes for the response
        old_bytes = ida_bytes.get_bytes(ea, len(new_bytes))

        # Create an undo point so the patch can be reverted
        ida_undo.create_undo_point("patch_bytes", "patch_bytes")

        # Patch atomically
        ida_bytes.patch_bytes(ea, new_bytes)

        return PatchBytesResult(
            address=format_address(ea),
            size=len(new_bytes),
            old_bytes=old_bytes.hex() if old_bytes else "",
            new_bytes=new_bytes.hex(),
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def create_function(
        address: Address,
    ) -> CreateFunctionResult:
        """Create a function at the given address.

        IDA will auto-detect function boundaries.

        Args:
            address: Start address for the new function.
        """
        ea = resolve_address(address)

        success = ida_funcs.add_func(ea)
        if not success:
            raise IDAError(
                f"Failed to create function at {format_address(ea)}", error_type="CreateFailed"
            )

        func = ida_funcs.get_func(ea)
        name = get_func_name(ea)
        return CreateFunctionResult(
            address=format_address(ea),
            name=name,
            end=format_address(func.end_ea) if func else "",
            size=func.size() if func else 0,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def make_code(
        address: Address,
    ) -> MakeCodeResult:
        """Convert bytes at an address into a code instruction.

        Unlike create_function, this just marks the bytes as code without
        creating a function boundary. Useful for fixing misidentified data
        or extending analysis into unreached code.

        Args:
            address: Address to convert to code.
        """
        ea = resolve_address(address)

        old_item_type, old_item_size = get_old_item_info(ea)

        length = ida_ua.create_insn(ea)
        if length == 0:
            raise IDAError(
                f"Failed to create instruction at {format_address(ea)}", error_type="CreateFailed"
            )

        return MakeCodeResult(
            address=format_address(ea),
            old_item_type=old_item_type,
            old_item_size=old_item_size,
            size=length,
        )

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"modification"},
    )
    @session.require_open
    def undefine(
        address: Address,
        size: int = 1,
    ) -> UndefineResult:
        """Undefine (delete) items at an address, converting them back to raw bytes.

        Args:
            address: Address to undefine.
            size: Number of bytes to undefine.
        """
        ea = resolve_address(address)

        old_item_type, old_item_size = get_old_item_info(ea)

        success = idc.del_items(ea, 0, size)
        if not success:
            raise IDAError(
                f"Failed to undefine {size} bytes at {format_address(ea)}",
                error_type="UndefineFailed",
            )
        return UndefineResult(
            address=format_address(ea),
            old_item_type=old_item_type,
            old_item_size=old_item_size,
            size=size,
        )
