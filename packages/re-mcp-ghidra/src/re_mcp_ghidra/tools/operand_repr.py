# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Operand representation tools -- change how operands display in disassembly."""

from __future__ import annotations

from typing import Literal

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_MUTATE,
    Address,
    format_address,
    resolve_address,
)
from re_mcp_ghidra.session import session


class SetOperandFormatResult(BaseModel):
    """Result of changing operand representation."""

    address: str = Field(description="Instruction address (hex).")
    operand: int = Field(description="Operand index.")
    format: str = Field(description="New display format.")


_DATA_FORMAT_VALUES = {"hex": 0, "decimal": 1, "binary": 2, "octal": 3, "char": 4}


def _format_scalar(value: int, display_format: str) -> str:
    """Build the equate name Ghidra expects for a given display format."""
    uval = value & 0xFFFFFFFFFFFFFFFF
    if display_format == "hex":
        return f"0x{uval:X}"
    if display_format == "decimal":
        return str(uval)
    if display_format == "binary":
        return f"{uval:b}b"
    if display_format == "octal":
        return f"{uval:o}o"
    if display_format == "char":
        return repr(chr(value & 0xFF))
    raise GhidraError(f"Unknown format: {display_format}", error_type="InvalidArgument")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"modification", "operands"})
    @session.require_open
    def set_operand_format(
        address: Address,
        operand_num: int,
        display_format: Literal["hex", "decimal", "binary", "octal", "char"],
    ) -> SetOperandFormatResult:
        """Change an operand's numeric display format (hex/dec/bin/oct/char).

        For instructions, applies a display equate (Ghidra's equivalent of
        IDA's operand format change).  For data, sets the format setting
        directly on the code unit.

        Args:
            address: Instruction address.
            operand_num: Operand index (0-based).
            display_format: Display format -- "hex", "decimal", "binary", "octal",
                or "char".
        """
        from ghidra.program.model.listing import Data, Instruction  # noqa: PLC0415

        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)

        cu = listing.getCodeUnitAt(addr)
        if cu is None:
            raise GhidraError(
                f"No code unit at {format_address(addr.getOffset())}",
                error_type="NotFound",
            )

        tx_id = program.startTransaction("Set operand format")
        try:
            if isinstance(cu, Data):
                cu.setLong("format", _DATA_FORMAT_VALUES[display_format])
            elif isinstance(cu, Instruction):
                # Instructions use equates to change operand display format
                from ghidra.app.cmd.equate import SetEquateCmd  # noqa: PLC0415

                scalar = cu.getScalar(operand_num)
                if scalar is None:
                    program.endTransaction(tx_id, False)
                    raise GhidraError(
                        f"Operand {operand_num} at {format_address(addr.getOffset())} "
                        "has no scalar value",
                        error_type="InvalidArgument",
                    )

                equate_name = _format_scalar(scalar.getUnsignedValue(), display_format)
                cmd = SetEquateCmd(equate_name, addr, operand_num, scalar.getValue())
                if not cmd.applyTo(program):
                    program.endTransaction(tx_id, False)
                    raise GhidraError(
                        f"Failed to set equate: {cmd.getStatusMsg()}",
                        error_type="SetOperandFailed",
                    )
            else:
                program.endTransaction(tx_id, False)
                raise GhidraError(
                    f"Unsupported code unit type at {format_address(addr.getOffset())}",
                    error_type="InvalidArgument",
                )
            program.endTransaction(tx_id, True)
        except GhidraError:
            raise
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
