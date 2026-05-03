# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Instruction and operand analysis tools — decode instructions and their operands."""

from __future__ import annotations

from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_READ_ONLY,
    Address,
    format_address,
    resolve_address,
)
from re_mcp_ghidra.session import session


class OperandDetail(BaseModel):
    """Decoded operand information."""

    index: int = Field(description="Operand index.")
    representation: str = Field(description="Operand text representation.")
    type: str = Field(description="Operand type description.")
    value: str | None = Field(default=None, description="Scalar/address value (hex), if any.")


class DecodeInstructionResult(BaseModel):
    """Decoded instruction with operand details."""

    address: str = Field(description="Instruction address (hex).")
    mnemonic: str = Field(description="Instruction mnemonic.")
    disasm: str = Field(description="Full disassembly text.")
    size: int = Field(description="Instruction size in bytes.")
    operand_count: int = Field(description="Number of operands.")
    operands: list[OperandDetail] = Field(description="Operand details.")


class DecodedInstructionBrief(BaseModel):
    """Brief decoded instruction info."""

    address: str = Field(description="Instruction address (hex).")
    mnemonic: str = Field(description="Instruction mnemonic.")
    disasm: str = Field(description="Full disassembly text.")
    size: int = Field(description="Instruction size in bytes.")


class DecodeInstructionsResult(BaseModel):
    """Multiple decoded instructions."""

    start: str = Field(description="Start address (hex).")
    instruction_count: int = Field(description="Number of instructions decoded.")
    instructions: list[DecodedInstructionBrief] = Field(description="Decoded instructions.")


class GetOperandValueResult(BaseModel):
    """Operand value at an address."""

    address: str = Field(description="Instruction address (hex).")
    operand_index: int = Field(description="Operand index.")
    representation: str = Field(description="Operand text representation.")
    value: str | None = Field(description="Resolved operand value (hex) or null.")


def _get_instruction_at(program, addr):
    """Get the instruction at an address, raising GhidraError if none."""
    listing = program.getListing()
    insn = listing.getInstructionAt(addr)
    if insn is None:
        raise GhidraError(
            f"No instruction at {format_address(addr.getOffset())}",
            error_type="NotFound",
        )
    return insn


def _format_disasm(insn) -> str:
    """Format a full disassembly line from an instruction."""
    mnemonic = insn.getMnemonicString()
    operands = []
    for i in range(insn.getNumOperands()):
        op_str = insn.getDefaultOperandRepresentation(i)
        if op_str:
            operands.append(op_str)
    if operands:
        return f"{mnemonic} {', '.join(operands)}"
    return mnemonic


def _build_operand_detail(insn, index: int) -> OperandDetail:
    """Build an OperandDetail for a single operand."""
    representation = insn.getDefaultOperandRepresentation(index) or ""
    op_objects = insn.getOpObjects(index)

    op_type = "unknown"
    value = None

    if op_objects:
        obj = op_objects[0]
        obj_class = type(obj).__name__

        if "Register" in obj_class:
            op_type = "register"
        elif "Scalar" in obj_class:
            op_type = "scalar"
            value = format_address(obj.getUnsignedValue())
        elif "Address" in obj_class:
            op_type = "address"
            value = format_address(obj.getOffset())
        else:
            op_type = obj_class.lower()
    else:
        # Try to get scalar value directly
        scalar = insn.getScalar(index)
        if scalar is not None:
            op_type = "scalar"
            value = format_address(scalar.getUnsignedValue())

    return OperandDetail(
        index=index,
        representation=representation,
        type=op_type,
        value=value,
    )


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"disassembly"})
    @session.require_open
    def decode_instruction(
        address: Address,
    ) -> DecodeInstructionResult:
        """Decode ONE instruction at an address (mnemonic, operands, size).

        Operand indices from the result can be used with get_operand_value.

        Args:
            address: Address of the instruction.
        """
        program = session.program
        addr = resolve_address(address)
        insn = _get_instruction_at(program, addr)

        num_ops = insn.getNumOperands()
        operands = [_build_operand_detail(insn, i) for i in range(num_ops)]

        return DecodeInstructionResult(
            address=format_address(addr.getOffset()),
            mnemonic=insn.getMnemonicString(),
            disasm=_format_disasm(insn),
            size=insn.getLength(),
            operand_count=num_ops,
            operands=operands,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"disassembly"})
    @session.require_open
    def decode_instructions(
        address: Address,
        count: Annotated[
            int, Field(description="Number of instructions to decode.", ge=1, le=200)
        ] = 20,
    ) -> DecodeInstructionsResult:
        """Decode N sequential instructions from any address (not bounded by function limits).

        Use for shellcode, inline data, or ranges across function boundaries.
        For a complete function listing, prefer disassemble_function.

        Args:
            address: Starting address.
            count: Number of instructions to decode (max 200).
        """
        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)

        instructions = []
        current = addr
        for _ in range(count):
            insn = listing.getInstructionAt(current)
            if insn is None:
                break
            instructions.append(
                DecodedInstructionBrief(
                    address=format_address(current.getOffset()),
                    mnemonic=insn.getMnemonicString(),
                    disasm=_format_disasm(insn),
                    size=insn.getLength(),
                )
            )
            current = current.add(insn.getLength())

        return DecodeInstructionsResult(
            start=format_address(addr.getOffset()),
            instruction_count=len(instructions),
            instructions=instructions,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"disassembly"})
    @session.require_open
    def get_operand_value(
        address: Address,
        operand_index: int = 0,
    ) -> GetOperandValueResult:
        """Get the resolved value of an instruction operand.

        Uses Ghidra's analysis to resolve operand values including
        computed addresses, register-relative offsets, etc.

        Args:
            address: Address of the instruction.
            operand_index: Which operand (0-based).
        """
        program = session.program
        addr = resolve_address(address)
        insn = _get_instruction_at(program, addr)

        num_ops = insn.getNumOperands()
        if operand_index < 0 or operand_index >= num_ops:
            raise GhidraError(
                f"Operand index {operand_index} out of range (instruction has {num_ops} operands)",
                error_type="InvalidArgument",
            )

        representation = insn.getDefaultOperandRepresentation(operand_index) or ""

        # Try to resolve a scalar or address value
        value = None
        scalar = insn.getScalar(operand_index)
        if scalar is not None:
            value = format_address(scalar.getUnsignedValue())
        else:
            # Try opObjects for address references
            op_objects = insn.getOpObjects(operand_index)
            if op_objects:
                obj = op_objects[0]
                obj_class = type(obj).__name__
                if "Scalar" in obj_class:
                    value = format_address(obj.getUnsignedValue())
                elif "Address" in obj_class:
                    value = format_address(obj.getOffset())

        return GetOperandValueResult(
            address=format_address(addr.getOffset()),
            operand_index=operand_index,
            representation=representation,
            value=value,
        )
