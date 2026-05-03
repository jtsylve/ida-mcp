# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Register variable tools — map physical registers to names within address ranges."""

from __future__ import annotations

import ida_frame
import ida_funcs
import idautils
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ida.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    IDAError,
    format_address,
    get_func_name,
    resolve_address,
    resolve_function,
)
from re_mcp_ida.session import session


class RegvarResult(BaseModel):
    """Result of a regvar operation."""

    function: str = Field(description="Function address (hex).")
    start: str | None = Field(default=None, description="Range start address (hex).")
    end: str | None = Field(default=None, description="Range end address (hex).")
    register_name: str = Field(description="Register name.")
    name: str | None = Field(default=None, description="Regvar name.")
    comment: str | None = Field(default=None, description="Regvar comment.")
    old_name: str | None = Field(default=None, description="Previous name (for rename).")
    old_comment: str | None = Field(default=None, description="Previous comment (for set_comment).")


class RegvarInfo(BaseModel):
    """Register variable details."""

    start: str = Field(description="Range start address (hex).")
    end: str = Field(description="Range end address (hex).")
    register_name: str = Field(description="Register name.")
    name: str = Field(description="Regvar name.")
    comment: str = Field(description="Regvar comment.")


class ListRegvarsResult(BaseModel):
    """Register variables for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    count: int = Field(description="Number of regvars.")
    regvars: list[RegvarInfo] = Field(description="Register variables.")


_REGVAR_ERRORS = {
    ida_frame.REGVAR_ERROR_OK: "ok",
    ida_frame.REGVAR_ERROR_ARG: "invalid_argument",
    ida_frame.REGVAR_ERROR_RANGE: "invalid_range",
    ida_frame.REGVAR_ERROR_NAME: "invalid_name",
}


def _resolve_regvar(
    function_address: str, address: str, register_name: str
) -> tuple[ida_funcs.func_t, ida_frame.regvar_t]:
    """Resolve a register variable by function, address, and register name.

    Returns ``(func, rv)``.  Raises :class:`IDAError` on failure.
    """
    func = resolve_function(function_address)
    ea = resolve_address(address)
    rv = ida_frame.find_regvar(func, ea, register_name)
    if rv is None:
        raise IDAError(
            f"No register variable for {register_name!r} at {format_address(ea)}",
            error_type="NotFound",
        )
    return func, rv


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"metadata", "registers"},
    )
    @session.require_open
    def add_regvar(
        function_address: Address,
        start_address: Address,
        end_address: Address,
        register_name: str,
        user_name: str,
        comment: str = "",
    ) -> RegvarResult:
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
        func = resolve_function(function_address)
        start = resolve_address(start_address)
        end = resolve_address(end_address)

        rc = ida_frame.add_regvar(func, start, end, register_name, user_name, comment)
        if rc != ida_frame.REGVAR_ERROR_OK:
            raise IDAError(
                f"add_regvar failed: {_REGVAR_ERRORS.get(rc, f'code {rc}')}",
                error_type="OperationFailed",
            )
        return RegvarResult(
            function=format_address(func.start_ea),
            start=format_address(start),
            end=format_address(end),
            register_name=register_name,
            name=user_name,
        )

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"metadata", "registers"},
    )
    @session.require_open
    def delete_regvar(
        function_address: Address,
        start_address: Address,
        end_address: Address,
        register_name: str,
    ) -> RegvarResult:
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
        func = resolve_function(function_address)
        start = resolve_address(start_address)
        end = resolve_address(end_address)

        # Read old values before deletion
        rv = ida_frame.find_regvar(func, start, register_name)
        old_name = (rv.user or "") if rv else ""
        old_comment = (rv.cmt or "") if rv else ""

        rc = ida_frame.del_regvar(func, start, end, register_name)
        if rc != ida_frame.REGVAR_ERROR_OK:
            raise IDAError(
                f"del_regvar failed: {_REGVAR_ERRORS.get(rc, f'code {rc}')}",
                error_type="OperationFailed",
            )
        return RegvarResult(
            function=format_address(func.start_ea),
            start=format_address(start),
            end=format_address(end),
            register_name=register_name,
            old_name=old_name,
            old_comment=old_comment,
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"metadata", "registers"},
    )
    @session.require_open
    def get_regvar(
        function_address: Address,
        address: Address,
        register_name: str,
    ) -> RegvarResult:
        """Get the register variable definition at an address for a specific register.

        Args:
            function_address: Address or name of the containing function.
            address: Address to query.
            register_name: Canonical register name (e.g. "eax", "rbx").
        """
        func, rv = _resolve_regvar(function_address, address, register_name)
        return RegvarResult(
            function=format_address(func.start_ea),
            start=format_address(rv.start_ea),
            end=format_address(rv.end_ea),
            register_name=rv.canon,
            name=rv.user,
            comment=rv.cmt or "",
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"metadata", "registers"},
    )
    @session.require_open
    def list_regvars(
        function_address: Address,
    ) -> ListRegvarsResult:
        """List all register variable definitions in a function.

        Iterates function instructions and collects all register-to-name
        mappings defined within the function.

        Args:
            function_address: Address or name of the function.
        """
        func = resolve_function(function_address)

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
                RegvarInfo(
                    start=format_address(rv.start_ea),
                    end=format_address(rv.end_ea),
                    register_name=rv.canon,
                    name=rv.user,
                    comment=rv.cmt or "",
                )
            )

        return ListRegvarsResult(
            function=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            count=len(regvars),
            regvars=regvars,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"metadata", "registers"},
    )
    @session.require_open
    def rename_regvar(
        function_address: Address,
        address: Address,
        register_name: str,
        new_name: str,
    ) -> RegvarResult:
        """Rename a regvar alias in the disassembly view (register-scoped, per-range).

        Args:
            function_address: Address or name of the containing function.
            address: Any address within the regvar's range.
            register_name: Canonical register name (e.g. "eax", "rbx").
            new_name: New user-defined name.
        """
        func, rv = _resolve_regvar(function_address, address, register_name)

        old_name = rv.user or ""
        rc = ida_frame.rename_regvar(func, rv, new_name)
        if rc != ida_frame.REGVAR_ERROR_OK:
            raise IDAError(
                f"rename_regvar failed: {_REGVAR_ERRORS.get(rc, f'code {rc}')}",
                error_type="OperationFailed",
            )
        return RegvarResult(
            function=format_address(func.start_ea),
            register_name=register_name,
            old_name=old_name,
            name=new_name,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"metadata", "registers"},
    )
    @session.require_open
    def set_regvar_comment(
        function_address: Address,
        address: Address,
        register_name: str,
        comment: str,
    ) -> RegvarResult:
        """Set the comment on a register variable definition.

        Args:
            function_address: Address or name of the containing function.
            address: Any address within the regvar's range.
            register_name: Canonical register name (e.g. "eax", "rbx").
            comment: New comment text.
        """
        func, rv = _resolve_regvar(function_address, address, register_name)

        old_comment = rv.cmt or ""
        rc = ida_frame.set_regvar_cmt(func, rv, comment)
        if rc != ida_frame.REGVAR_ERROR_OK:
            raise IDAError(
                f"set_regvar_cmt failed: {_REGVAR_ERRORS.get(rc, f'code {rc}')}",
                error_type="OperationFailed",
            )
        return RegvarResult(
            function=format_address(func.start_ea),
            register_name=register_name,
            old_comment=old_comment,
            comment=comment,
        )
