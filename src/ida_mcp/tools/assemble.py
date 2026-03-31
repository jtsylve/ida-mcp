# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Instruction assembly tools."""

from __future__ import annotations

import ida_bytes
import ida_undo
import idautils
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_READ_ONLY,
    Address,
    IDAError,
    format_address,
    resolve_address,
)
from ida_mcp.session import session


class AssembleResult(BaseModel):
    """Result of assembling an instruction."""

    address: str = Field(description="Target address (hex).")
    instruction: str = Field(description="Assembly instruction.")
    old_bytes: str = Field(description="Previous bytes (hex).")
    bytes: str = Field(description="Assembled bytes (hex).")
    length: int = Field(description="Instruction length in bytes.")


class PatchAsmResult(BaseModel):
    """Result of patching with assembly."""

    address: str = Field(description="Target address (hex).")
    instruction: str = Field(description="Assembly instruction.")
    old_bytes: str = Field(description="Previous bytes (hex).")
    new_bytes: str = Field(description="New bytes (hex).")
    length: int = Field(description="Instruction length in bytes.")
    patched: bool = Field(description="Whether bytes were patched.")


def _assemble_at(ea: int, instruction: str) -> bytes:
    """Assemble *instruction* at *ea*.  Raises :class:`IDAError` on failure."""
    result = idautils.Assemble(ea, instruction)
    if isinstance(result, str):
        raise IDAError(result, error_type="AssemblyFailed")

    success, assembled_bytes = result
    if not success:
        raise IDAError(f"Failed to assemble: {instruction!r}", error_type="AssemblyFailed")
    return assembled_bytes


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"disassembly", "assembler"},
    )
    @session.require_open
    def assemble_instruction(
        address: Address,
        instruction: str,
    ) -> AssembleResult:
        """Assemble an instruction at the given address without modifying the database.

        Converts an assembly mnemonic into machine code bytes. The instruction is
        assembled in the context of the current processor and segment settings at
        that address. Use patch_asm to assemble and write in one step.

        Args:
            address: Address where the instruction should be assembled.
            instruction: Assembly instruction text (e.g. "nop", "mov eax, 1").
        """
        ea = resolve_address(address)
        assembled_bytes = _assemble_at(ea, instruction)

        old_bytes_data = ida_bytes.get_bytes(ea, len(assembled_bytes))
        return AssembleResult(
            address=format_address(ea),
            instruction=instruction,
            old_bytes=old_bytes_data.hex() if old_bytes_data else "",
            bytes=assembled_bytes.hex(),
            length=len(assembled_bytes),
        )

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"disassembly", "assembler"},
    )
    @session.require_open
    def patch_asm(
        address: Address,
        instruction: str,
    ) -> PatchAsmResult:
        """Assemble an instruction and patch it into the database in one step.

        Combines assemble_instruction and patch_bytes: assembles the given
        instruction at the address, then patches the resulting bytes into the
        database. Creates an undo point so the change can be reverted.

        Args:
            address: Address where the instruction should be assembled and patched.
            instruction: Assembly instruction text (e.g. "nop", "mov eax, 1").
        """
        ea = resolve_address(address)
        assembled_bytes = _assemble_at(ea, instruction)

        old_bytes_data = ida_bytes.get_bytes(ea, len(assembled_bytes))

        ida_undo.create_undo_point("patch_asm", "patch_asm")
        ida_bytes.patch_bytes(ea, assembled_bytes)

        return PatchAsmResult(
            address=format_address(ea),
            instruction=instruction,
            old_bytes=old_bytes_data.hex() if old_bytes_data else "",
            new_bytes=assembled_bytes.hex(),
            length=len(assembled_bytes),
            patched=True,
        )
