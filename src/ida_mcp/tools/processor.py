# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Processor and architecture information tools."""

from __future__ import annotations

import ida_ida
import ida_idp
import idautils
from fastmcp import FastMCP

from ida_mcp.helpers import decode_insn_at, format_address, resolve_address
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def get_processor_info() -> dict:
        """Get information about the processor/architecture of the loaded binary.

        Returns processor name, register names, bitness, and other architecture details.
        """
        reg_names = ida_idp.ph_get_regnames()

        return {
            "processor": ida_idp.get_idp_name(),
            "bitness": ida_ida.inf_get_app_bitness(),
            "is_64bit": ida_ida.inf_is_64bit(),
            "register_names": list(reg_names) if reg_names else [],
        }

    @mcp.tool()
    @session.require_open
    def get_register_name(register_number: int, width: int = 0) -> dict:
        """Get the name of a register by its number and width.

        Args:
            register_number: The register number (processor-specific).
            width: Register width in bytes (0 for default width).
        """
        if width == 0:
            width = 8 if ida_ida.inf_is_64bit() else 4

        name = ida_idp.get_reg_name(register_number, width)
        return {
            "register_number": register_number,
            "width": width,
            "name": name or "",
        }

    @mcp.tool()
    @session.require_open
    def is_call_instruction(address: str) -> dict:
        """Check if the instruction at the given address is a call instruction.

        Args:
            address: Address of the instruction.
        """
        ea, err = resolve_address(address)
        if err:
            return err

        insn, err = decode_insn_at(ea)
        if err:
            return err

        return {
            "address": format_address(ea),
            "is_call": bool(ida_idp.is_call_insn(insn)),
        }

    @mcp.tool()
    @session.require_open
    def is_return_instruction(address: str) -> dict:
        """Check if the instruction at the given address is a return instruction.

        Args:
            address: Address of the instruction.
        """
        ea, err = resolve_address(address)
        if err:
            return err

        insn, err = decode_insn_at(ea)
        if err:
            return err

        return {
            "address": format_address(ea),
            "is_return": bool(ida_idp.is_ret_insn(insn)),
        }

    @mcp.tool()
    @session.require_open
    def is_alignment_instruction(address: str) -> dict:
        """Check if the instruction at the given address is an alignment instruction (NOP/padding).

        Args:
            address: Address of the instruction.
        """
        ea, err = resolve_address(address)
        if err:
            return err

        align_size = ida_idp.is_align_insn(ea)
        return {
            "address": format_address(ea),
            "is_alignment": align_size > 0,
            "alignment_size": max(0, align_size),
        }

    @mcp.tool()
    @session.require_open
    def get_instruction_list() -> dict:
        """Get the list of all instruction mnemonics for the current processor.

        Returns all recognized instruction names for the loaded binary's
        architecture (e.g. x86: mov, push, call, ...).
        """
        mnemonics = list(idautils.GetInstructionList())
        return {
            "processor": ida_idp.get_idp_name(),
            "count": len(mnemonics),
            "instructions": mnemonics,
        }
