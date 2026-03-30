# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Register value tracking tools."""

from __future__ import annotations

import ida_idp
import ida_regfinder
from fastmcp import FastMCP

from ida_mcp.helpers import (
    ANNO_READ_ONLY,
    Address,
    IDAError,
    format_address,
    resolve_address,
)
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"analysis"},
    )
    @session.require_open
    def find_register_value(
        address: Address,
        register: str,
    ) -> dict:
        """Find the value of a register at a specific address using IDA's register tracker.

        The register tracker traces backwards from the address to determine
        what value a register holds. Useful for resolving indirect calls,
        computed addresses, etc.

        Args:
            address: Address at which to find the register value.
            register: Register name (e.g. "rax", "eax", "r8", "ecx").
        """
        ea = resolve_address(address)

        # Resolve register name to number.
        # IDA's register list uses short base names (e.g. "ax", "di") but
        # users will often use the full x86-64 names ("rax", "rdi", "edi").
        # Strip common prefixes to match the base name.
        reg_names = ida_idp.ph_get_regnames()
        reg_num = None
        reg_lower = register.lower()
        # Also try stripping e/r prefix for x86 (e.g. rax->ax, edi->di)
        stripped = reg_lower[1:] if len(reg_lower) > 2 and reg_lower[0] in ("e", "r") else None
        if reg_names:
            fallback = None
            for i, name in enumerate(reg_names):
                name_lower = name.lower()
                if name_lower == reg_lower:
                    reg_num = i
                    break
                if stripped and fallback is None and name_lower == stripped:
                    fallback = i
            if reg_num is None:
                reg_num = fallback

        if reg_num is None:
            raise IDAError(
                f"Unknown register: {register!r}",
                error_type="InvalidArgument",
                available_registers=list(reg_names) if reg_names else [],
            )

        rvi = ida_regfinder.reg_value_info_t()
        found = ida_regfinder.find_reg_value_info(rvi, ea, reg_num)
        if not found:
            return {
                "address": format_address(ea),
                "register": register,
                "found": False,
                "reason": "Register tracker not supported or value unknown",
            }

        result = {
            "address": format_address(ea),
            "register": register,
            "found": True,
            "value": format_address(rvi.value),
        }

        return result

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"analysis"},
    )
    @session.require_open
    def find_stack_pointer_value(
        address: Address,
    ) -> dict:
        """Find the stack pointer value at a specific address.

        Uses IDA's register tracker to determine the stack pointer offset
        relative to the function entry.

        Args:
            address: Address at which to find the SP value.
        """
        ea = resolve_address(address)

        try:
            sp_val = ida_regfinder.find_sp_value(ea)
        except Exception as e:
            raise IDAError(f"Stack pointer tracking failed: {e}", error_type="NotSupported") from e
        return {
            "address": format_address(ea),
            "sp_value": sp_val,
        }
