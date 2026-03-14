# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Binary modification tools -- patching, code/function creation, undefine."""

from __future__ import annotations

import ida_bytes
import ida_funcs
import ida_ua
import ida_undo
import idc
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import format_address, get_func_name, resolve_address
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def patch_bytes(address: str, hex_bytes: str) -> dict:
        """Patch bytes at an address in the database.

        Args:
            address: Address to patch.
            hex_bytes: Hex string of bytes to write (e.g. "90 90 90" or "909090").
        """
        ea, err = resolve_address(address)
        if err:
            return err

        # Parse hex bytes
        _MAX_PATCH_HEX_LEN = 2 * 1024 * 1024  # 1 MB of data = 2M hex chars
        cleaned = hex_bytes.replace(" ", "")
        if not cleaned:
            return {"error": "Empty hex string", "error_type": "InvalidArgument"}
        if len(cleaned) > _MAX_PATCH_HEX_LEN:
            return {
                "error": f"Patch data too large ({len(cleaned)} hex chars, max {_MAX_PATCH_HEX_LEN})",
                "error_type": "InvalidArgument",
            }
        try:
            new_bytes = bytes.fromhex(cleaned)
        except ValueError:
            return {
                "error": f"Invalid hex string: {hex_bytes!r}",
                "error_type": "InvalidArgument",
            }

        # Read old bytes for the response
        old_bytes = ida_bytes.get_bytes(ea, len(new_bytes))

        # Create an undo point so the patch can be reverted
        ida_undo.create_undo_point("patch_bytes", "patch_bytes")

        # Patch atomically
        ida_bytes.patch_bytes(ea, new_bytes)

        return {
            "address": format_address(ea),
            "size": len(new_bytes),
            "old_bytes": old_bytes.hex() if old_bytes else "",
            "new_bytes": new_bytes.hex(),
        }

    @mcp.tool()
    @session.require_open
    def create_function(address: str) -> dict:
        """Create a function at the given address.

        IDA will auto-detect function boundaries.

        Args:
            address: Start address for the new function.
        """
        ea, err = resolve_address(address)
        if err:
            return err

        success = ida_funcs.add_func(ea)
        if not success:
            return {
                "error": f"Failed to create function at {format_address(ea)}",
                "error_type": "CreateFailed",
            }

        func = ida_funcs.get_func(ea)
        name = get_func_name(ea)
        return {
            "address": format_address(ea),
            "name": name,
            "end": format_address(func.end_ea) if func else "",
            "size": func.size() if func else 0,
        }

    @mcp.tool()
    @session.require_open
    def make_code(address: str) -> dict:
        """Convert bytes at an address into a code instruction.

        Unlike create_function, this just marks the bytes as code without
        creating a function boundary. Useful for fixing misidentified data
        or extending analysis into unreached code.

        Args:
            address: Address to convert to code.
        """
        ea, err = resolve_address(address)
        if err:
            return err

        length = ida_ua.create_insn(ea)
        if length == 0:
            return {
                "error": f"Failed to create instruction at {format_address(ea)}",
                "error_type": "CreateFailed",
            }

        return {
            "address": format_address(ea),
            "size": length,
        }

    @mcp.tool()
    @session.require_open
    def undefine(address: str, size: int = 1) -> dict:
        """Undefine (delete) items at an address, converting them back to raw bytes.

        Args:
            address: Address to undefine.
            size: Number of bytes to undefine.
        """
        ea, err = resolve_address(address)
        if err:
            return err

        success = idc.del_items(ea, 0, size)
        if not success:
            return {
                "error": f"Failed to undefine {size} bytes at {format_address(ea)}",
                "error_type": "UndefineFailed",
            }
        return {
            "address": format_address(ea),
            "size": size,
        }
