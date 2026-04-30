# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Processor and architecture information tools."""

from __future__ import annotations

import ida_ida
import ida_idp
import idautils
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_READ_ONLY,
    Address,
    decode_insn_at,
    format_address,
    resolve_address,
)
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ProcessorInfoResult(BaseModel):
    """Processor information."""

    processor: str = Field(description="Processor name.")
    bitness: int = Field(description="Default address size in bits.")
    is_64bit: bool = Field(description="Whether the processor is 64-bit.")
    register_names: list[str] = Field(description="Available register names.")


class GetRegisterNameResult(BaseModel):
    """Register name lookup result."""

    register_number: int = Field(description="Register number.")
    width: int = Field(description="Register width.")
    name: str = Field(description="Register name.")


class InstructionCheckResult(BaseModel):
    """Result of checking instruction type."""

    address: str = Field(description="Instruction address (hex).")
    is_call: bool | None = Field(default=None, description="Whether this is a call instruction.")
    is_return: bool | None = Field(
        default=None, description="Whether this is a return instruction."
    )
    is_alignment: bool | None = Field(
        default=None, description="Whether this is an alignment instruction."
    )
    alignment_size: int | None = Field(
        default=None, description="Alignment size (if alignment instruction)."
    )


class InstructionListResult(BaseModel):
    """List of processor instructions."""

    processor: str = Field(description="Processor name.")
    count: int = Field(description="Number of instructions.")
    instructions: list[str] = Field(description="Instruction mnemonics.")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"analysis"},
    )
    @session.require_open
    def get_processor_info() -> ProcessorInfoResult:
        """Get processor/architecture info (name, registers, bitness)."""
        reg_names = ida_idp.ph_get_regnames()

        return ProcessorInfoResult(
            processor=ida_idp.get_idp_name(),
            bitness=ida_ida.inf_get_app_bitness(),
            is_64bit=ida_ida.inf_is_64bit(),
            register_names=list(reg_names) if reg_names else [],
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"analysis"},
    )
    @session.require_open
    def get_register_name(register_number: int, width: int = 0) -> GetRegisterNameResult:
        """Get the name of a register by its number and width.

        Args:
            register_number: The register number (processor-specific).
            width: Register width in bytes (0 for default width).
        """
        if width == 0:
            width = 8 if ida_ida.inf_is_64bit() else 4

        name = ida_idp.get_reg_name(register_number, width)
        return GetRegisterNameResult(
            register_number=register_number,
            width=width,
            name=name or "",
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"analysis"},
    )
    @session.require_open
    def is_call_instruction(
        address: Address,
    ) -> InstructionCheckResult:
        """Check whether the instruction at an address is a call.

        Args:
            address: Address of the instruction.
        """
        ea = resolve_address(address)

        insn = decode_insn_at(ea)

        return InstructionCheckResult(
            address=format_address(ea),
            is_call=bool(ida_idp.is_call_insn(insn)),
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"analysis"},
    )
    @session.require_open
    def is_return_instruction(
        address: Address,
    ) -> InstructionCheckResult:
        """Check whether the instruction at an address is a return.

        Args:
            address: Address of the instruction.
        """
        ea = resolve_address(address)

        insn = decode_insn_at(ea)

        return InstructionCheckResult(
            address=format_address(ea),
            is_return=bool(ida_idp.is_ret_insn(insn)),
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"analysis"},
    )
    @session.require_open
    def is_alignment_instruction(
        address: Address,
    ) -> InstructionCheckResult:
        """Check whether an instruction is alignment padding (NOP sled, etc.).

        Args:
            address: Address of the instruction.
        """
        ea = resolve_address(address)

        align_size = ida_idp.is_align_insn(ea)
        return InstructionCheckResult(
            address=format_address(ea),
            is_alignment=align_size > 0,
            alignment_size=max(0, align_size),
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"analysis"},
    )
    @session.require_open
    def get_instruction_list() -> InstructionListResult:
        """Get all instruction mnemonics recognized by the current processor."""
        mnemonics = list(idautils.GetInstructionList())
        return InstructionListResult(
            processor=ida_idp.get_idp_name(),
            count=len(mnemonics),
            instructions=mnemonics,
        )
