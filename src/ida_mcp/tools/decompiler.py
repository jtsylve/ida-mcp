# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Hex-Rays decompiler interaction tools — rename/retype variables, microcode, comments."""

from __future__ import annotations

import ida_hexrays
from fastmcp import FastMCP

from ida_mcp.helpers import (
    IDAError,
    decompile_at,
    format_address,
    get_func_name,
    parse_type,
    resolve_address,
    resolve_function,
)
from ida_mcp.session import session

_MATURITY_MAP = {
    "MMAT_GENERATED": ida_hexrays.MMAT_GENERATED,
    "MMAT_PREOPTIMIZED": ida_hexrays.MMAT_PREOPTIMIZED,
    "MMAT_LOCOPT": ida_hexrays.MMAT_LOCOPT,
    "MMAT_CALLS": ida_hexrays.MMAT_CALLS,
    "MMAT_GLBOPT1": ida_hexrays.MMAT_GLBOPT1,
    "MMAT_GLBOPT2": ida_hexrays.MMAT_GLBOPT2,
    "MMAT_GLBOPT3": ida_hexrays.MMAT_GLBOPT3,
    "MMAT_LVARS": ida_hexrays.MMAT_LVARS,
}


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def rename_decompiler_variable(function_address: str, old_name: str, new_name: str) -> dict:
        """Rename a local variable or parameter in Hex-Rays decompilation output.

        Args:
            function_address: Address or name of the function.
            old_name: Current variable name in the pseudocode.
            new_name: New name to assign to the variable.
        """
        cfunc, func = decompile_at(function_address)

        # Verify the variable exists
        available = [lvar.name for lvar in cfunc.lvars]
        if old_name not in available:
            raise IDAError(f"Variable not found: {old_name!r}", error_type="NotFound")

        # IDA 9.x: rename_lvar(func_ea, old_name, new_name) — all strings
        success = ida_hexrays.rename_lvar(cfunc.entry_ea, old_name, new_name)
        if not success:
            raise IDAError(
                f"Failed to rename variable {old_name!r} to {new_name!r}", error_type="RenameFailed"
            )
        return {
            "function": format_address(func.start_ea),
            "old_name": old_name,
            "new_name": new_name,
        }

    @mcp.tool()
    @session.require_open
    def retype_decompiler_variable(
        function_address: str, variable_name: str, new_type: str
    ) -> dict:
        """Change the type of a local variable or parameter in Hex-Rays decompilation.

        Args:
            function_address: Address or name of the function.
            variable_name: Name of the variable to retype.
            new_type: C type string to apply (e.g. "int *", "struct foo *").
        """
        cfunc, func = decompile_at(function_address)

        # Parse the new type
        tinfo = parse_type(new_type)

        # Find and retype the variable.
        # IDA 9.x: use modify_user_lvar_info() — cfuncptr_t has no set_lvar_type().
        for lvar in cfunc.lvars:
            if lvar.name == variable_name:
                old_type = str(lvar.type())
                info = ida_hexrays.lvar_saved_info_t()
                info.ll = lvar
                info.type = tinfo
                success = ida_hexrays.modify_user_lvar_info(
                    cfunc.entry_ea, ida_hexrays.MLI_TYPE, info
                )
                if not success:
                    raise IDAError(
                        f"Failed to set type on {variable_name!r}", error_type="RetypeFailed"
                    )
                return {
                    "function": format_address(func.start_ea),
                    "variable": variable_name,
                    "old_type": old_type,
                    "new_type": str(tinfo),
                }

        raise IDAError(f"Variable not found: {variable_name!r}", error_type="NotFound")

    @mcp.tool()
    @session.require_open
    def get_microcode(function_address: str, maturity: str = "MMAT_LVARS") -> dict:
        """Get Hex-Rays microcode for a function at a specified maturity level.

        Microcode is the intermediate representation used by the decompiler.
        Lower levels are closer to assembly, higher levels closer to C.
        Use MMAT_GENERATED for speed (closest to assembly), MMAT_LVARS for
        closest-to-C analysis. Complex functions may hit internal limits
        (50,000 insns/block) — try a lower maturity level if that happens.

        Args:
            function_address: Address or name of the function.
            maturity: Maturity level — one of MMAT_GENERATED, MMAT_PREOPTIMIZED,
                MMAT_LOCOPT, MMAT_CALLS, MMAT_GLBOPT1, MMAT_GLBOPT2,
                MMAT_GLBOPT3, MMAT_LVARS.
        """
        func = resolve_function(function_address)

        mat_val = _MATURITY_MAP.get(maturity)
        if mat_val is None:
            raise IDAError(f"Invalid maturity level: {maturity!r}", error_type="InvalidArgument")

        try:
            mbr = ida_hexrays.mba_ranges_t(func)
            mba = ida_hexrays.gen_microcode(
                mbr,
                None,  # hf
                None,  # retlist
                0,  # decomp_flags
                mat_val,
            )
        except Exception as e:
            raise IDAError(f"Microcode generation failed: {e}", error_type="MicrocodeFailed") from e

        if mba is None:
            raise IDAError("Microcode generation returned no result", error_type="MicrocodeFailed")

        _MAX_INSNS_PER_BLOCK = 50_000
        blocks = []
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            lines = []
            insn = blk.head
            safety = 0
            while insn is not None and safety < _MAX_INSNS_PER_BLOCK:
                lines.append(insn.dstr())
                insn = insn.next if insn.next != insn else None
                safety += 1
            blocks.append(
                {
                    "block_index": i,
                    "start": format_address(blk.start),
                    "end": format_address(blk.end),
                    "instruction_count": len(lines),
                    "instructions": lines,
                }
            )

        return {
            "function": format_address(func.start_ea),
            "name": get_func_name(func.start_ea),
            "maturity": maturity,
            "block_count": len(blocks),
            "blocks": blocks,
        }

    @mcp.tool()
    @session.require_open
    def set_decompiler_comment(address: str, comment: str, function_address: str = "") -> dict:
        """Set a comment in the Hex-Rays decompiler pseudocode at a specific address.

        This sets a comment that appears in the decompiled output, not in the
        disassembly view. The address should point to an instruction within the
        function.

        Args:
            address: Address where the comment should appear.
            function_address: Address or name of the containing function (auto-detected if empty).
            comment: Comment text to set (empty string to delete).
        """
        ea = resolve_address(address)

        cfunc, func = decompile_at(function_address or address)
        func_ea = func.start_ea

        # Find the treeloc for the address
        tl = ida_hexrays.treeloc_t()
        tl.ea = ea
        tl.itp = ida_hexrays.ITP_SEMI

        old_comment = cfunc.get_user_cmt(tl, ida_hexrays.RETRIEVE_ALWAYS) or ""

        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()

        return {
            "address": format_address(ea),
            "function": format_address(func_ea),
            "old_comment": old_comment,
            "comment": comment,
        }

    @mcp.tool()
    @session.require_open
    def get_decompiler_comments(function_address: str) -> dict:
        """Get all user-defined comments in the decompiled pseudocode of a function.

        Args:
            function_address: Address or name of the function.
        """
        cfunc, func = decompile_at(function_address)

        comments = []
        cmts = cfunc.user_cmts
        if cmts is not None:
            it = ida_hexrays.user_cmts_begin(cmts)
            while it != ida_hexrays.user_cmts_end(cmts):
                tl = ida_hexrays.user_cmts_first(it)
                cmt = ida_hexrays.user_cmts_second(it)
                comments.append(
                    {
                        "address": format_address(tl.ea),
                        "comment": str(cmt),
                    }
                )
                it = ida_hexrays.user_cmts_next(it)

        return {
            "function": format_address(func.start_ea),
            "name": get_func_name(func.start_ea),
            "comments": comments,
        }

    @mcp.tool()
    @session.require_open
    def list_decompiler_variables(function_address: str) -> dict:
        """List all local variables and parameters in the decompiled pseudocode.

        Shows name, type, storage location, and whether it's a parameter for
        each variable in the decompilation output.

        Args:
            function_address: Address or name of the function.
        """
        cfunc, func = decompile_at(function_address)

        variables = []
        for lvar in cfunc.lvars:
            var_info = {
                "name": lvar.name,
                "type": str(lvar.type()),
                "is_arg": lvar.is_arg_var,
                "is_stk_var": lvar.is_stk_var(),
                "is_reg_var": lvar.is_reg_var(),
            }
            if lvar.is_reg_var():
                var_info["register"] = lvar.get_reg1()
            if lvar.is_stk_var():
                var_info["stack_offset"] = lvar.get_stkoff()
            variables.append(var_info)

        return {
            "function": format_address(func.start_ea),
            "name": get_func_name(func.start_ea),
            "variable_count": len(variables),
            "variables": variables,
        }
