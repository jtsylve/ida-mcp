# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Operand representation tools -- change how operands display in disassembly."""

from __future__ import annotations

import ida_bytes
import idc
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import (
    decode_insn_at,
    format_address,
    resolve_address,
    resolve_enum,
    resolve_struct,
    validate_operand_num,
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

    @mcp.tool(name=f"set_operand_{fmt_name}")
    @session.require_open
    def _tool(address: str, operand_num: int) -> dict:
        if err := validate_operand_num(operand_num):
            return err
        ea, err = resolve_address(address)
        if err:
            return err

        old_format = _get_operand_format(ea, operand_num)
        if not idc_func(ea, operand_num):
            return {
                "error": f"Failed to set operand {operand_num} to {fmt_name} at {format_address(ea)}",
                "error_type": "SetOperandFailed",
            }
        return {
            "address": format_address(ea),
            "operand": operand_num,
            "old_format": old_format,
            "format": fmt_name,
        }

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

    @mcp.tool()
    @session.require_open
    def set_operand_offset(address: str, operand_num: int, base: int = 0) -> dict:
        """Convert an operand to an offset reference.

        Makes IDA treat the operand value as a pointer/offset, creating a
        cross-reference to the target address.

        Args:
            address: Instruction address.
            operand_num: Operand index (0-based).
            base: Base address for the offset calculation (0 for flat).
        """
        if err := validate_operand_num(operand_num):
            return err
        ea, err = resolve_address(address)
        if err:
            return err

        old_format = _get_operand_format(ea, operand_num)
        if not idc.op_plain_offset(ea, operand_num, base):
            return {
                "error": f"Failed to set operand {operand_num} to offset at {format_address(ea)}",
                "error_type": "SetOperandFailed",
            }
        return {
            "address": format_address(ea),
            "operand": operand_num,
            "old_format": old_format,
            "format": "offset",
            "base": format_address(base),
        }

    @mcp.tool()
    @session.require_open
    def set_operand_enum(address: str, operand_num: int, enum_name: str) -> dict:
        """Apply an enum type to an operand, displaying it as an enum member name.

        Args:
            address: Instruction address.
            operand_num: Operand index (0-based).
            enum_name: Name of the enum to apply.
        """
        if err := validate_operand_num(operand_num):
            return err
        ea, err = resolve_address(address)
        if err:
            return err

        eid, err = resolve_enum(enum_name)
        if err:
            return err

        old_format = _get_operand_format(ea, operand_num)
        if not idc.op_enum(ea, operand_num, eid, 0):
            return {
                "error": f"Failed to apply enum {enum_name!r} to operand {operand_num} at {format_address(ea)}",
                "error_type": "SetOperandFailed",
            }
        return {
            "address": format_address(ea),
            "operand": operand_num,
            "old_format": old_format,
            "enum": enum_name,
        }

    @mcp.tool()
    @session.require_open
    def set_operand_struct_offset(address: str, operand_num: int, struct_name: str) -> dict:
        """Apply a structure offset to an operand.

        Makes IDA display the operand as a struct member access (e.g., struc.field).

        Args:
            address: Instruction address.
            operand_num: Operand index (0-based).
            struct_name: Name of the structure.
        """
        if err := validate_operand_num(operand_num):
            return err
        ea, err = resolve_address(address)
        if err:
            return err

        sid, err = resolve_struct(struct_name)
        if err:
            return err

        insn, err = decode_insn_at(ea)
        if err:
            return err
        old_format = _get_operand_format(ea, operand_num)
        if not ida_bytes.op_stroff(insn, operand_num, [sid], 0):
            return {
                "error": f"Failed to apply struct {struct_name!r} to operand {operand_num} at {format_address(ea)}",
                "error_type": "SetOperandFailed",
            }
        return {
            "address": format_address(ea),
            "operand": operand_num,
            "old_format": old_format,
            "struct": struct_name,
        }
