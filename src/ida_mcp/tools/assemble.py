# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Instruction assembly tools."""

from __future__ import annotations

import ida_bytes
import idautils
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import format_address, resolve_address
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def assemble_instruction(address: str, instruction: str) -> dict:
        """Assemble an instruction at the given address.

        Converts an assembly mnemonic into bytes and patches them at the address.
        The instruction is assembled in the context of the current processor and
        segment settings at that address.

        Args:
            address: Address where the instruction should be assembled.
            instruction: Assembly instruction text (e.g. "nop", "mov eax, 1").
        """
        ea, err = resolve_address(address)
        if err:
            return err

        result = idautils.Assemble(ea, instruction)
        if isinstance(result, str):
            return {"error": result, "error_type": "AssemblyFailed"}

        success, assembled_bytes = result
        if not success:
            return {
                "error": f"Failed to assemble: {instruction!r}",
                "error_type": "AssemblyFailed",
            }

        old_bytes_data = ida_bytes.get_bytes(ea, len(assembled_bytes))
        return {
            "address": format_address(ea),
            "instruction": instruction,
            "old_bytes": old_bytes_data.hex() if old_bytes_data else "",
            "bytes": assembled_bytes.hex(),
            "length": len(assembled_bytes),
        }
