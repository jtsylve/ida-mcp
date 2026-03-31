# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Operand representation tools — change how operands display in disassembly."""

from __future__ import annotations

import ida_bytes
import idc
from fastmcp import FastMCP

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
from ida_mcp.models import (
    SetOperandEnumResult,
    SetOperandOffsetResult,
    SetOperandReprResult,
    SetOperandStructOffsetResult,
)
from ida_mcp.session import session


def _get_operand_format(ea: int, n: int) -> str:
    """Read the current display format of an operand."""
    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_numop(flags, n):
        return "numeric"
    return "default"


def _make_set_operand_tool(mcp: FastMCP, fmt_name: str, idc_func, doc: str):
    """Register a set_operand_<format> tool using the common pattern."""

    @mcp.tool(
        name=f"set_operand_{fmt_name}",
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def _tool(
        address: Address,
        operand_num: OperandIndex,
    ) -> SetOperandReprResult:
        validate_operand_num(operand_num)
        ea = resolve_address(address)

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

    _tool.__doc__ = doc
    return _tool


_OPERAND_FORMATS = [
    (
        "hex",
        idc.op_hex,
        "Display an operand as hexadecimal.\n\nArgs:\n    address: Instruction address.\n    operand_num: Operand index (0-based).",
    ),
    (
        "decimal",
        idc.op_dec,
        "Display an operand as decimal.\n\nArgs:\n    address: Instruction address.\n    operand_num: Operand index (0-based).",
    ),
    (
        "binary",
        idc.op_bin,
        "Display an operand as binary.\n\nArgs:\n    address: Instruction address.\n    operand_num: Operand index (0-based).",
    ),
    (
        "octal",
        idc.op_oct,
        "Display an operand as octal.\n\nArgs:\n    address: Instruction address.\n    operand_num: Operand index (0-based).",
    ),
    (
        "char",
        idc.op_chr,
        "Display an operand as a character constant.\n\nArgs:\n    address: Instruction address.\n    operand_num: Operand index (0-based).",
    ),
]


def register(mcp: FastMCP):
    for fmt_name, idc_func, doc in _OPERAND_FORMATS:
        _make_set_operand_tool(mcp, fmt_name, idc_func, doc)

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
