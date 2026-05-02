# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Operand representation tools -- change how operands display in disassembly."""

from __future__ import annotations

from typing import Literal

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ghidra_mcp.exceptions import GhidraError
from ghidra_mcp.helpers import (
    ANNO_MUTATE,
    Address,
    format_address,
    resolve_address,
)
from ghidra_mcp.session import session


class SetOperandFormatResult(BaseModel):
    """Result of changing operand representation."""

    address: str = Field(description="Instruction address (hex).")
    operand: int = Field(description="Operand index.")
    format: str = Field(description="New display format.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"modification", "operands"})
    @session.require_open
    def set_operand_format(
        address: Address,
        operand_num: int,
        display_format: Literal["hex", "decimal", "binary", "octal", "char"],
    ) -> SetOperandFormatResult:
        """Change an operand's numeric display format (hex/dec/bin/oct/char).

        Uses Ghidra's FormatSettingsDefinition to change how a scalar
        operand value is displayed in the listing.

        Args:
            address: Instruction address.
            operand_num: Operand index (0-based).
            display_format: Display format -- "hex", "decimal", "binary", "octal",
                or "char".
        """
        from ghidra.program.model.data import FormatSettingsDefinition  # noqa: PLC0415

        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)

        cu = listing.getCodeUnitAt(addr)
        if cu is None:
            raise GhidraError(
                f"No code unit at {format_address(addr.getOffset())}",
                error_type="NotFound",
            )

        format_map = {
            "hex": FormatSettingsDefinition.HEX,
            "decimal": FormatSettingsDefinition.DECIMAL,
            "binary": FormatSettingsDefinition.BINARY,
            "octal": FormatSettingsDefinition.OCTAL,
            "char": FormatSettingsDefinition.CHAR,
        }

        fmt_value = format_map[display_format]
        fmt_def = FormatSettingsDefinition.DEF

        tx_id = program.startTransaction("Set operand format")
        try:
            fmt_def.setChoice(cu, operand_num, fmt_value)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to set operand format: {e}", error_type="SetOperandFailed"
            ) from e

        return SetOperandFormatResult(
            address=format_address(addr.getOffset()),
            operand=operand_num,
            format=display_format,
        )
