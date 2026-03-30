# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Stack frame and local variable analysis tools."""

from __future__ import annotations

import ida_typeinf
import idc
from fastmcp import FastMCP

from ida_mcp.helpers import (
    ANNO_READ_ONLY,
    Address,
    decompile_at,
    format_address,
    get_func_name,
    resolve_function,
)
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"functions"},
    )
    @session.require_open
    def get_stack_frame(
        address: Address,
    ) -> dict:
        """Get the stack frame layout of a function.

        Shows local variables, saved registers, and arguments with their
        offsets, sizes, and names. Does not require Hex-Rays. For typed
        variable info from decompilation, use get_function_vars instead.

        Args:
            address: Address or name of the function.
        """
        func = resolve_function(address)

        frame_tif = ida_typeinf.tinfo_t()
        if not frame_tif.get_func_frame(func):
            return {
                "function": format_address(func.start_ea),
                "name": get_func_name(func.start_ea),
                "frame": None,
                "message": "No stack frame defined for this function",
            }

        udt = ida_typeinf.udt_type_data_t()
        frame_tif.get_udt_details(udt)

        members = []
        for udm in udt:
            if udm.is_gap():
                continue
            byte_offset = udm.offset // 8
            members.append(
                {
                    "offset": byte_offset,
                    "name": udm.name or f"var_{byte_offset:X}",
                    "size": udm.size // 8,
                }
            )

        return {
            "function": format_address(func.start_ea),
            "name": get_func_name(func.start_ea),
            "frame_size": idc.get_func_attr(func.start_ea, idc.FUNCATTR_FRSIZE),
            "local_size": func.frsize,
            "saved_regs_size": func.frregs,
            "args_size": func.argsize,
            "member_count": len(members),
            "members": members,
        }

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"functions"},
    )
    @session.require_open
    def get_function_vars(
        address: Address,
    ) -> dict:
        """Get local variables and parameters of a function via decompilation.

        Uses Hex-Rays to extract typed local variable and parameter info.
        For stack frame layout analysis without decompilation, use
        get_stack_frame instead.

        Args:
            address: Address or name of the function.
        """
        cfunc, func = decompile_at(address)

        variables = [
            {
                "name": lvar.name,
                "type": str(lvar.type()),
                "is_arg": lvar.is_arg_var,
                "is_result": lvar.is_result_var,
                "width": lvar.width,
            }
            for lvar in cfunc.lvars
        ]

        return {
            "function": format_address(func.start_ea),
            "name": get_func_name(func.start_ea),
            "variable_count": len(variables),
            "variables": variables,
        }
