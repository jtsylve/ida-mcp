# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Instruction assembly tools."""

from __future__ import annotations

import ida_bytes
import ida_undo
import idautils
from fastmcp import FastMCP

from ida_mcp.helpers import format_address, resolve_address
from ida_mcp.session import session


def _assemble_at(ea: int, instruction: str) -> tuple[bytes, dict | None]:
    """Assemble *instruction* at *ea*.

    Returns ``(assembled_bytes, error_dict)``.  On error *assembled_bytes*
    is empty and *error_dict* contains the failure reason.
    """
    result = idautils.Assemble(ea, instruction)
    if isinstance(result, str):
        return b"", {"error": result, "error_type": "AssemblyFailed"}

    success, assembled_bytes = result
    if not success:
        return b"", {
            "error": f"Failed to assemble: {instruction!r}",
            "error_type": "AssemblyFailed",
        }
    return assembled_bytes, None


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def assemble_instruction(address: str, instruction: str) -> dict:
        """Assemble an instruction at the given address without modifying the database.

        Converts an assembly mnemonic into machine code bytes. The instruction is
        assembled in the context of the current processor and segment settings at
        that address. Use patch_asm to assemble and write in one step.

        Args:
            address: Address where the instruction should be assembled.
            instruction: Assembly instruction text (e.g. "nop", "mov eax, 1").
        """
        ea, err = resolve_address(address)
        if err:
            return err

        assembled_bytes, err = _assemble_at(ea, instruction)
        if err:
            return err

        old_bytes_data = ida_bytes.get_bytes(ea, len(assembled_bytes))
        return {
            "address": format_address(ea),
            "instruction": instruction,
            "old_bytes": old_bytes_data.hex() if old_bytes_data else "",
            "bytes": assembled_bytes.hex(),
            "length": len(assembled_bytes),
        }

    @mcp.tool()
    @session.require_open
    def patch_asm(address: str, instruction: str) -> dict:
        """Assemble an instruction and patch it into the database in one step.

        Combines assemble_instruction and patch_bytes: assembles the given
        instruction at the address, then patches the resulting bytes into the
        database. Creates an undo point so the change can be reverted.

        Args:
            address: Address where the instruction should be assembled and patched.
            instruction: Assembly instruction text (e.g. "nop", "mov eax, 1").
        """
        ea, err = resolve_address(address)
        if err:
            return err

        assembled_bytes, err = _assemble_at(ea, instruction)
        if err:
            return err

        old_bytes_data = ida_bytes.get_bytes(ea, len(assembled_bytes))

        ida_undo.create_undo_point("patch_asm", "patch_asm")
        ida_bytes.patch_bytes(ea, assembled_bytes)

        return {
            "address": format_address(ea),
            "instruction": instruction,
            "old_bytes": old_bytes_data.hex() if old_bytes_data else "",
            "new_bytes": assembled_bytes.hex(),
            "length": len(assembled_bytes),
            "patched": True,
        }
