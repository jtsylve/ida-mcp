# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Operand representation tools — change how operands display in disassembly."""

from __future__ import annotations

import ida_bytes
import idc
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_MUTATE,
    Address,
    IDAError,
    OperandIndex,
    decode_insn_at,
    format_address,
    resolve_address,
    resolve_enum,
    resolve_struct,
    validate_operand_num,
)
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class SetOperandReprResult(BaseModel):
    """Result of changing operand representation."""

    address: str = Field(description="Instruction address (hex).")
    operand: int = Field(description="Operand index.")
    old_format: str = Field(description="Previous format.")
    format: str = Field(description="New format.")


class SetOperandOffsetResult(BaseModel):
    """Result of setting operand as offset."""

    address: str = Field(description="Instruction address (hex).")
    operand: int = Field(description="Operand index.")
    old_format: str = Field(description="Previous format.")
    format: str = Field(description="New format.")
    base: str = Field(description="Offset base address (hex).")


class SetOperandEnumResult(BaseModel):
    """Result of setting operand as enum."""

    address: str = Field(description="Instruction address (hex).")
    operand: int = Field(description="Operand index.")
    old_format: str = Field(description="Previous format.")
    enum: str = Field(description="Enum name.")


class SetOperandStructOffsetResult(BaseModel):
    """Result of setting operand as struct offset."""

    address: str = Field(description="Instruction address (hex).")
    operand: int = Field(description="Operand index.")
    old_format: str = Field(description="Previous format.")
    struct: str = Field(description="Struct name.")


def _get_operand_format(ea: int, n: int) -> str:
    """Read the current display format of an operand."""
    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_numop(flags, n):
        return "numeric"
    return "default"


def _set_operand_repr(ea: int, operand_num: int, fmt_name: str, idc_func) -> SetOperandReprResult:
    """Shared implementation for set_operand_<format> tools."""
    validate_operand_num(operand_num)
    old_format = _get_operand_format(ea, operand_num)
    if not idc_func(ea, operand_num):
        raise IDAError(
            f"Failed to set operand {operand_num} to {fmt_name} at {format_address(ea)}",
            error_type="SetOperandFailed",
        )
    return SetOperandReprResult(
        address=format_address(ea),
        operand=operand_num,
        old_format=old_format,
        format=fmt_name,
    )


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def set_operand_hex(
        address: Address,
        operand_num: OperandIndex,
    ) -> SetOperandReprResult:
        """Display an operand as hexadecimal.

        Args:
            address: Instruction address.
            operand_num: Operand index (0-based).
        """
        return _set_operand_repr(resolve_address(address), operand_num, "hex", idc.op_hex)

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def set_operand_decimal(
        address: Address,
        operand_num: OperandIndex,
    ) -> SetOperandReprResult:
        """Display an operand as decimal.

        Args:
            address: Instruction address.
            operand_num: Operand index (0-based).
        """
        return _set_operand_repr(resolve_address(address), operand_num, "decimal", idc.op_dec)

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def set_operand_binary(
        address: Address,
        operand_num: OperandIndex,
    ) -> SetOperandReprResult:
        """Display an operand as binary.

        Args:
            address: Instruction address.
            operand_num: Operand index (0-based).
        """
        return _set_operand_repr(resolve_address(address), operand_num, "binary", idc.op_bin)

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def set_operand_octal(
        address: Address,
        operand_num: OperandIndex,
    ) -> SetOperandReprResult:
        """Display an operand as octal.

        Args:
            address: Instruction address.
            operand_num: Operand index (0-based).
        """
        return _set_operand_repr(resolve_address(address), operand_num, "octal", idc.op_oct)

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def set_operand_char(
        address: Address,
        operand_num: OperandIndex,
    ) -> SetOperandReprResult:
        """Display an operand as a character constant.

        Args:
            address: Instruction address.
            operand_num: Operand index (0-based).
        """
        return _set_operand_repr(resolve_address(address), operand_num, "char", idc.op_chr)

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def set_operand_offset(
        address: Address,
        operand_num: OperandIndex,
        base: int = 0,
    ) -> SetOperandOffsetResult:
        """Convert an operand to an offset reference.

        Makes IDA treat the operand value as a pointer/offset, creating a
        cross-reference to the target address.

        Args:
            address: Instruction address.
            operand_num: Operand index (0-based).
            base: Base address for the offset calculation (0 for flat).
        """
        validate_operand_num(operand_num)
        ea = resolve_address(address)

        old_format = _get_operand_format(ea, operand_num)
        if not idc.op_plain_offset(ea, operand_num, base):
            raise IDAError(
                f"Failed to set operand {operand_num} to offset at {format_address(ea)}",
                error_type="SetOperandFailed",
            )
        return SetOperandOffsetResult(
            address=format_address(ea),
            operand=operand_num,
            old_format=old_format,
            format="offset",
            base=format_address(base),
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def set_operand_enum(
        address: Address,
        operand_num: OperandIndex,
        enum_name: str,
    ) -> SetOperandEnumResult:
        """Apply an enum type to an operand, displaying it as an enum member name.

        Args:
            address: Instruction address.
            operand_num: Operand index (0-based).
            enum_name: Name of the enum to apply.
        """
        validate_operand_num(operand_num)
        ea = resolve_address(address)

        eid = resolve_enum(enum_name)

        old_format = _get_operand_format(ea, operand_num)
        if not idc.op_enum(ea, operand_num, eid, 0):
            raise IDAError(
                f"Failed to apply enum {enum_name!r} to operand {operand_num} at {format_address(ea)}",
                error_type="SetOperandFailed",
            )
        return SetOperandEnumResult(
            address=format_address(ea),
            operand=operand_num,
            old_format=old_format,
            enum=enum_name,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def set_operand_struct_offset(
        address: Address,
        operand_num: OperandIndex,
        struct_name: str,
    ) -> SetOperandStructOffsetResult:
        """Apply a structure offset to an operand.

        Makes IDA display the operand as a struct member access (e.g. struc.field).

        Args:
            address: Instruction address.
            operand_num: Operand index (0-based).
            struct_name: Name of the structure.
        """
        validate_operand_num(operand_num)
        ea = resolve_address(address)

        sid = resolve_struct(struct_name)

        insn = decode_insn_at(ea)
        old_format = _get_operand_format(ea, operand_num)
        if not ida_bytes.op_stroff(insn, operand_num, [sid], 0):
            raise IDAError(
                f"Failed to apply struct {struct_name!r} to operand {operand_num} at {format_address(ea)}",
                error_type="SetOperandFailed",
            )
        return SetOperandStructOffsetResult(
            address=format_address(ea),
            operand=operand_num,
            old_format=old_format,
            struct=struct_name,
        )
