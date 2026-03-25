# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Register variable tools — map physical registers to names within address ranges."""

from __future__ import annotations

import ida_frame
import idautils
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import format_address, get_func_name, resolve_address, resolve_function
from ida_mcp.session import session

_REGVAR_ERRORS = {
    ida_frame.REGVAR_ERROR_OK: "ok",
    ida_frame.REGVAR_ERROR_ARG: "invalid_argument",
    ida_frame.REGVAR_ERROR_RANGE: "invalid_range",
    ida_frame.REGVAR_ERROR_NAME: "invalid_name",
}


def _resolve_regvar(function_address: str, address: str, register_name: str) -> tuple:
    """Resolve a register variable by function, address, and register name.

    Returns (func, rv, error_dict).  *error_dict* is ``None`` on success.
    """
    func, err = resolve_function(function_address)
    if err:
        return None, None, err
    ea, err = resolve_address(address)
    if err:
        return None, None, err
    rv = ida_frame.find_regvar(func, ea, register_name)
    if rv is None:
        return (
            None,
            None,
            {
                "error": f"No register variable for {register_name!r} at {format_address(ea)}",
                "error_type": "NotFound",
            },
        )
    return func, rv, None


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def add_regvar(
        function_address: str,
        start_address: str,
        end_address: str,
        register_name: str,
        user_name: str,
        comment: str = "",
    ) -> dict:
        """Define a register variable within a function.

        Maps a physical register to a user-defined name for the range
        [start_address, end_address). This affects disassembly display for
        that address range — register references will show the user name.

        Args:
            function_address: Address or name of the containing function.
            start_address: Start of the range where this mapping applies.
            end_address: End of the range (exclusive).
            register_name: Canonical register name (e.g. "eax", "rbx").
            user_name: Name to display instead of the register.
            comment: Optional comment for this definition.
        """
        func, err = resolve_function(function_address)
        if err:
            return err
        start, err = resolve_address(start_address)
        if err:
            return err
        end, err = resolve_address(end_address)
        if err:
            return err

        rc = ida_frame.add_regvar(func, start, end, register_name, user_name, comment)
        if rc != ida_frame.REGVAR_ERROR_OK:
            return {
                "error": f"add_regvar failed: {_REGVAR_ERRORS.get(rc, f'code {rc}')}",
                "error_type": "OperationFailed",
            }
        return {
            "function": format_address(func.start_ea),
            "start": format_address(start),
            "end": format_address(end),
            "register": register_name,
            "name": user_name,
        }

    @mcp.tool()
    @session.require_open
    def delete_regvar(
        function_address: str,
        start_address: str,
        end_address: str,
        register_name: str,
    ) -> dict:
        """Delete a register variable definition.

        Removes the mapping of a register to a user name within the given
        address range. After deletion the register returns to its canonical
        name in disassembly.

        Args:
            function_address: Address or name of the containing function.
            start_address: Start of the range.
            end_address: End of the range (exclusive).
            register_name: Canonical register name (e.g. "eax", "rbx").
        """
        func, err = resolve_function(function_address)
        if err:
            return err
        start, err = resolve_address(start_address)
        if err:
            return err
        end, err = resolve_address(end_address)
        if err:
            return err

        # Read old values before deletion
        rv = ida_frame.find_regvar(func, start, register_name)
        old_name = (rv.user or "") if rv else ""
        old_comment = (rv.cmt or "") if rv else ""

        rc = ida_frame.del_regvar(func, start, end, register_name)
        if rc != ida_frame.REGVAR_ERROR_OK:
            return {
                "error": f"del_regvar failed: {_REGVAR_ERRORS.get(rc, f'code {rc}')}",
                "error_type": "OperationFailed",
            }
        return {
            "function": format_address(func.start_ea),
            "start": format_address(start),
            "end": format_address(end),
            "register": register_name,
            "old_name": old_name,
            "old_comment": old_comment,
        }

    @mcp.tool()
    @session.require_open
    def get_regvar(function_address: str, address: str, register_name: str) -> dict:
        """Get the register variable definition at an address for a specific register.

        Args:
            function_address: Address or name of the containing function.
            address: Address to query.
            register_name: Canonical register name (e.g. "eax", "rbx").
        """
        func, rv, err = _resolve_regvar(function_address, address, register_name)
        if err:
            return err
        return {
            "function": format_address(func.start_ea),
            "start": format_address(rv.start_ea),
            "end": format_address(rv.end_ea),
            "register": rv.canon,
            "name": rv.user,
            "comment": rv.cmt or "",
        }

    @mcp.tool()
    @session.require_open
    def list_regvars(function_address: str) -> dict:
        """List all register variable definitions in a function.

        Iterates function instructions and collects all register-to-name
        mappings defined within the function.

        Args:
            function_address: Address or name of the function.
        """
        func, err = resolve_function(function_address)
        if err:
            return err

        seen: set[tuple] = set()
        regvars = []
        for ea in idautils.FuncItems(func.start_ea):
            if not ida_frame.has_regvar(func, ea):
                continue
            rv = ida_frame.find_regvar(func, ea, None)
            if rv is None:
                continue
            key = (rv.start_ea, rv.end_ea, rv.canon)
            if key in seen:
                continue
            seen.add(key)
            regvars.append(
                {
                    "start": format_address(rv.start_ea),
                    "end": format_address(rv.end_ea),
                    "register": rv.canon,
                    "name": rv.user,
                    "comment": rv.cmt or "",
                }
            )

        return {
            "function": format_address(func.start_ea),
            "name": get_func_name(func.start_ea),
            "count": len(regvars),
            "regvars": regvars,
        }

    @mcp.tool()
    @session.require_open
    def rename_regvar(
        function_address: str, address: str, register_name: str, new_name: str
    ) -> dict:
        """Rename a register variable's user-defined name.

        Args:
            function_address: Address or name of the containing function.
            address: Any address within the regvar's range.
            register_name: Canonical register name (e.g. "eax", "rbx").
            new_name: New user-defined name.
        """
        func, rv, err = _resolve_regvar(function_address, address, register_name)
        if err:
            return err

        old_name = rv.user or ""
        rc = ida_frame.rename_regvar(func, rv, new_name)
        if rc != ida_frame.REGVAR_ERROR_OK:
            return {
                "error": f"rename_regvar failed: {_REGVAR_ERRORS.get(rc, f'code {rc}')}",
                "error_type": "OperationFailed",
            }
        return {
            "function": format_address(func.start_ea),
            "register": register_name,
            "old_name": old_name,
            "name": new_name,
        }

    @mcp.tool()
    @session.require_open
    def set_regvar_comment(
        function_address: str, address: str, register_name: str, comment: str
    ) -> dict:
        """Set the comment on a register variable definition.

        Args:
            function_address: Address or name of the containing function.
            address: Any address within the regvar's range.
            register_name: Canonical register name (e.g. "eax", "rbx").
            comment: New comment text.
        """
        func, rv, err = _resolve_regvar(function_address, address, register_name)
        if err:
            return err

        old_comment = rv.cmt or ""
        rc = ida_frame.set_regvar_cmt(func, rv, comment)
        if rc != ida_frame.REGVAR_ERROR_OK:
            return {
                "error": f"set_regvar_cmt failed: {_REGVAR_ERRORS.get(rc, f'code {rc}')}",
                "error_type": "OperationFailed",
            }
        return {
            "function": format_address(func.start_ea),
            "register": register_name,
            "old_comment": old_comment,
            "comment": comment,
        }
