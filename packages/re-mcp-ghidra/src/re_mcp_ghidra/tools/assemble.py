# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Instruction assembly tools."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_READ_ONLY,
    Address,
    format_address,
    resolve_address,
)
from re_mcp_ghidra.session import session


class AssembleResult(BaseModel):
    """Result of assembling an instruction."""

    address: str = Field(description="Target address (hex).")
    instruction: str = Field(description="Assembly instruction.")
    old_bytes: str = Field(description="Previous bytes (hex).")
    assembled_bytes: str = Field(description="Assembled bytes (hex).")
    length: int = Field(description="Instruction length in bytes.")


class PatchAsmResult(BaseModel):
    """Result of patching with assembly."""

    address: str = Field(description="Target address (hex).")
    instruction: str = Field(description="Assembly instruction.")
    old_bytes: str = Field(description="Previous bytes (hex).")
    new_bytes: str = Field(description="New bytes (hex).")
    length: int = Field(description="Instruction length in bytes.")
    patched: bool = Field(description="Whether bytes were patched.")


def _read_bytes_hex(program, addr, length: int) -> str:
    """Read bytes from the program memory and return as hex string."""
    mem = program.getMemory()
    buf = bytearray(length)
    try:
        mem.getBytes(addr, buf)
        return buf.hex()
    except Exception:
        return ""


def _assemble_at(program, addr, instruction: str) -> bytes:
    """Assemble an instruction at the given address.

    Returns the assembled bytes. Raises :class:`GhidraError` on failure.
    """
    from ghidra.app.plugin.assembler import Assemblers  # noqa: PLC0415

    try:
        assembler = Assemblers.getAssembler(program)
        result = assembler.assembleLine(addr, instruction)
        if result is None:
            raise GhidraError(
                f"Assembly produced no result: {instruction!r}",
                error_type="AssemblyFailed",
            )

        # Check for assembly conflicts before reading bytes
        conflict = result.getConflict()
        if conflict is not None:
            raise GhidraError(
                f"Assembly conflict at {instruction!r}: {conflict}",
                error_type="AssemblyFailed",
            )

        # Get bytes from the InstructionBlock's data
        insn = result.getInstructionAt(addr)
        if insn is None:
            raise GhidraError(
                f"Assembly produced no instructions: {instruction!r}",
                error_type="AssemblyFailed",
            )

        length = insn.getLength()
        return bytes(insn.getByte(i) & 0xFF for i in range(length))
    except GhidraError:
        raise
    except Exception as e:
        raise GhidraError(
            f"Failed to assemble: {instruction!r}: {e}", error_type="AssemblyFailed"
        ) from e


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"disassembly", "assembler"})
    @session.require_open
    def assemble_instruction(
        address: Address,
        instruction: str,
    ) -> AssembleResult:
        """Assemble an instruction at an address without patching (dry-run).

        Use patch_asm to assemble and write in one step.

        Args:
            address: Address where the instruction should be assembled.
            instruction: Assembly instruction text (e.g. "NOP", "MOV EAX,1").
        """
        program = session.program
        addr = resolve_address(address)
        assembled = _assemble_at(program, addr, instruction)
        old_bytes = _read_bytes_hex(program, addr, len(assembled))

        return AssembleResult(
            address=format_address(addr.getOffset()),
            instruction=instruction,
            old_bytes=old_bytes,
            assembled_bytes=assembled.hex(),
            length=len(assembled),
        )

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"disassembly", "assembler"})
    @session.require_open
    def patch_asm(
        address: Address,
        instruction: str,
    ) -> PatchAsmResult:
        """Assemble and patch an instruction into the database in one step.

        Combines assemble_instruction + byte patching within a transaction.

        Args:
            address: Address where the instruction should be assembled and patched.
            instruction: Assembly instruction text (e.g. "NOP", "MOV EAX,1").
        """
        program = session.program
        addr = resolve_address(address)
        assembled = _assemble_at(program, addr, instruction)
        old_bytes = _read_bytes_hex(program, addr, len(assembled))

        mem = program.getMemory()
        tx_id = program.startTransaction("Patch assembly")
        try:
            mem.setBytes(addr, assembled)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to patch bytes: {e}", error_type="PatchFailed") from e

        return PatchAsmResult(
            address=format_address(addr.getOffset()),
            instruction=instruction,
            old_bytes=old_bytes,
            new_bytes=assembled.hex(),
            length=len(assembled),
            patched=True,
        )
