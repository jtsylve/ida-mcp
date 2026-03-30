# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Instruction and operand analysis tools — decode instructions and their operands."""

from __future__ import annotations

import logging

import ida_ida
import ida_idp
import ida_ua
import idc
from fastmcp import FastMCP

from ida_mcp.helpers import (
    IDAError,
    clean_disasm_line,
    decode_insn_at,
    format_address,
    resolve_address,
    validate_operand_num,
)
from ida_mcp.session import session

_OPERAND_TYPE_NAMES = {
    0: "void",  # o_void
    1: "reg",  # o_reg
    2: "mem",  # o_mem
    3: "phrase",  # o_phrase (base+index)
    4: "displ",  # o_displ (base+index+displacement)
    5: "imm",  # o_imm
    6: "far",  # o_far
    7: "near",  # o_near
}


def _get_max_operands():
    """Return the max number of operands IDA supports per instruction."""
    try:
        return ida_ida.UA_MAXOP
    except AttributeError:
        return 8


log = logging.getLogger(__name__)


def _reg_name(reg, dtype):
    """Get register name, with fallback."""
    try:
        name = ida_idp.get_reg_name(reg, dtype)
        if name:
            return name
    except Exception:
        log.warning("Failed to get register name for reg=%s dtype=%s", reg, dtype)
    return f"reg{reg}"


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def decode_instruction(address: str) -> dict:
        """Decode a single instruction at an address, including all operands.

        Returns mnemonic, operand details (type, value, register), and size.
        Operand indices from the result can be used with set_operand_*
        and get_operand_value tools.

        Args:
            address: Address of the instruction.
        """
        ea = resolve_address(address)

        insn = decode_insn_at(ea)

        operands = []
        for i in range(_get_max_operands()):
            op = insn.ops[i]
            if op.type == ida_ua.o_void:
                break
            op_info = {
                "index": i,
                "type": _OPERAND_TYPE_NAMES.get(op.type, f"unknown({op.type})"),
                "type_id": op.type,
            }
            if op.type == ida_ua.o_reg:
                op_info["register"] = _reg_name(op.reg, op.dtype)
            elif op.type == ida_ua.o_imm:
                op_info["value"] = format_address(op.value)
            elif op.type in (ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near):
                op_info["address"] = format_address(op.addr)
            elif op.type == ida_ua.o_displ:
                op_info["displacement"] = op.addr
                op_info["register"] = _reg_name(op.reg, op.dtype)
            elif op.type == ida_ua.o_phrase:
                op_info["register"] = _reg_name(op.reg, op.dtype)

            operands.append(op_info)

        return {
            "address": format_address(ea),
            "disasm": clean_disasm_line(ea),
            "mnemonic": insn.get_canon_mnem(),
            "size": insn.size,
            "operand_count": len(operands),
            "operands": operands,
        }

    @mcp.tool()
    @session.require_open
    def decode_instructions(address: str, count: int = 20) -> dict:
        """Decode multiple sequential instructions starting at an address.

        Args:
            address: Starting address.
            count: Number of instructions to decode (max 200).
        """
        ea = resolve_address(address)

        count = min(count, 200)
        instructions = []
        current = ea

        for _ in range(count):
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, current)
            if length == 0:
                break
            instructions.append(
                {
                    "address": format_address(current),
                    "disasm": clean_disasm_line(current),
                    "mnemonic": insn.get_canon_mnem(),
                    "size": insn.size,
                }
            )
            current += insn.size

        return {
            "start": format_address(ea),
            "instruction_count": len(instructions),
            "instructions": instructions,
        }

    @mcp.tool()
    @session.require_open
    def get_operand_value(address: str, operand_index: int = 0) -> dict:
        """Get the resolved value of an instruction operand.

        Uses IDA's analysis to resolve operand values including
        computed addresses, register-relative offsets, etc.

        Args:
            address: Address of the instruction.
            operand_index: Which operand (0-based).
        """
        ea = resolve_address(address)

        validate_operand_num(operand_index)

        op_type = idc.get_operand_type(ea, operand_index)
        if op_type == 0:  # o_void
            raise IDAError(
                f"No operand {operand_index} at {format_address(ea)}", error_type="InvalidArgument"
            )

        value = idc.get_operand_value(ea, operand_index)

        return {
            "address": format_address(ea),
            "operand_index": operand_index,
            "type": _OPERAND_TYPE_NAMES.get(op_type, f"unknown({op_type})"),
            "value": format_address(value) if value is not None else None,
        }
