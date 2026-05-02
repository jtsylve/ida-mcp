# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Processor and architecture information tools."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ghidra_mcp.exceptions import GhidraError
from ghidra_mcp.helpers import (
    ANNO_READ_ONLY,
    Address,
    format_address,
    resolve_address,
)
from ghidra_mcp.session import session


class ProcessorInfoResult(BaseModel):
    """Processor information."""

    processor: str = Field(description="Processor/language name.")
    bitness: int = Field(description="Default address size in bits.")
    is_64bit: bool = Field(description="Whether the processor is 64-bit.")
    endian: str = Field(description="Endianness ('big' or 'little').")
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


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def get_processor_info() -> ProcessorInfoResult:
        """Get processor/architecture info (language, bitness, endianness, registers)."""
        program = session.program
        language = program.getLanguage()
        addr_size = program.getDefaultPointerSize() * 8

        # Collect register names
        reg_names = [reg.getName() for reg in language.getRegisters()]

        return ProcessorInfoResult(
            processor=str(language.getLanguageID()),
            bitness=addr_size,
            is_64bit=addr_size == 64,
            endian="big" if language.isBigEndian() else "little",
            register_names=reg_names,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def get_register_name(register_number: int, width: int = 0) -> GetRegisterNameResult:
        """Get the name of a register by its number and width.

        Args:
            register_number: The register number (processor-specific).
            width: Register width in bytes (0 for default pointer size).
        """
        program = session.program
        language = program.getLanguage()

        if width == 0:
            width = program.getDefaultPointerSize()

        # Search through registers for a matching number
        name = ""
        for reg in language.getRegisters():
            if reg.getOffset() == register_number and reg.getMinimumByteSize() == width:
                name = reg.getName()
                break

        # Fallback: just match by offset
        if not name:
            for reg in language.getRegisters():
                if reg.getOffset() == register_number:
                    name = reg.getName()
                    break

        return GetRegisterNameResult(
            register_number=register_number,
            width=width,
            name=name,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def is_call_instruction(
        address: Address,
    ) -> InstructionCheckResult:
        """Check whether the instruction at an address is a call.

        Args:
            address: Address of the instruction.
        """
        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)

        insn = listing.getInstructionAt(addr)
        if insn is None:
            raise GhidraError(
                f"No instruction at {format_address(addr.getOffset())}",
                error_type="NotFound",
            )

        flow_type = insn.getFlowType()
        return InstructionCheckResult(
            address=format_address(addr.getOffset()),
            is_call=flow_type.isCall(),
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def is_return_instruction(
        address: Address,
    ) -> InstructionCheckResult:
        """Check whether the instruction at an address is a return.

        Args:
            address: Address of the instruction.
        """
        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)

        insn = listing.getInstructionAt(addr)
        if insn is None:
            raise GhidraError(
                f"No instruction at {format_address(addr.getOffset())}",
                error_type="NotFound",
            )

        flow_type = insn.getFlowType()
        return InstructionCheckResult(
            address=format_address(addr.getOffset()),
            is_return=flow_type.isTerminal(),
        )
