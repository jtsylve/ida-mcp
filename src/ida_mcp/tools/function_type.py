# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Function prototype and calling convention tools."""

from __future__ import annotations

import ida_nalt
import ida_typeinf
import idc
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    IDAError,
    format_address,
    get_func_name,
    resolve_function,
)
from ida_mcp.session import session


class FunctionTypeParameter(BaseModel):
    """A function type parameter."""

    name: str = Field(description="Parameter name.")
    type: str = Field(description="Parameter type.")


class FunctionTypeDetail(BaseModel):
    """Detailed function type information."""

    return_type: str = Field(description="Return type.")
    calling_convention: str = Field(description="Calling convention.")
    parameters: list[FunctionTypeParameter] = Field(description="Function parameters.")


class GetFunctionTypeResult(BaseModel):
    """Function type information."""

    address: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    type: str = Field(description="Function type string.")
    details: FunctionTypeDetail | None = Field(
        description="Parsed type details, or null if parsing failed."
    )


class SetFunctionTypeResult(BaseModel):
    """Result of setting a function type."""

    address: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    old_type: str = Field(description="Previous type.")
    type: str = Field(description="New type.")


class SetCallingConventionResult(BaseModel):
    """Result of setting a function's calling convention."""

    address: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    old_convention: str = Field(description="Previous calling convention.")
    convention: str = Field(description="New calling convention.")


_CC_NAMES = {
    ida_typeinf.CM_CC_CDECL: "cdecl",
    ida_typeinf.CM_CC_STDCALL: "stdcall",
    ida_typeinf.CM_CC_PASCAL: "pascal",
    ida_typeinf.CM_CC_FASTCALL: "fastcall",
    ida_typeinf.CM_CC_THISCALL: "thiscall",
}

_CC_MAP = {v: k for k, v in _CC_NAMES.items()}


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"functions", "types"},
    )
    @session.require_open
    def get_function_type(
        address: Address,
    ) -> GetFunctionTypeResult:
        """Get the full type signature (prototype) of a function.

        Returns the return type, parameters, and calling convention.

        Args:
            address: Address or name of the function.
        """
        func = resolve_function(address)

        tinfo = ida_typeinf.tinfo_t()
        if not ida_nalt.get_tinfo(tinfo, func.start_ea) and not ida_typeinf.guess_tinfo(
            tinfo, func.start_ea
        ):
            type_str = idc.get_type(func.start_ea) or ""
            return GetFunctionTypeResult(
                address=format_address(func.start_ea),
                name=get_func_name(func.start_ea),
                type=type_str,
                details=None,
            )

        # Extract function details
        fi = ida_typeinf.func_type_data_t()
        if tinfo.get_func_details(fi):
            params = []
            for i in range(fi.size()):
                param = fi[i]
                params.append(
                    {
                        "name": param.name or f"arg{i}",
                        "type": str(param.type),
                    }
                )

            return GetFunctionTypeResult(
                address=format_address(func.start_ea),
                name=get_func_name(func.start_ea),
                type=str(tinfo),
                details=FunctionTypeDetail(
                    return_type=str(fi.rettype),
                    calling_convention=_CC_NAMES.get(fi.get_cc() & 0xF0, f"cc_{fi.get_cc():#x}"),
                    parameters=params,
                ),
            )

        return GetFunctionTypeResult(
            address=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            type=str(tinfo),
            details=None,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"functions", "types"},
    )
    @session.require_open
    def set_function_type(
        address: Address,
        type_string: str,
    ) -> SetFunctionTypeResult:
        """Set the full type signature (prototype) of a function.

        Args:
            address: Address or name of the function.
            type_string: C function declaration, e.g. "int __cdecl foo(int a, char *b)".
        """
        func = resolve_function(address)

        old_type = idc.get_type(func.start_ea) or ""
        success = idc.SetType(func.start_ea, type_string)
        if not success:
            raise IDAError("Failed to set function type", error_type="SetTypeFailed")

        return SetFunctionTypeResult(
            address=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            old_type=old_type,
            type=type_string,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"functions", "types"},
    )
    @session.require_open
    def set_function_calling_convention(
        address: Address,
        convention: str,
    ) -> SetCallingConventionResult:
        """Change the calling convention of a function.

        Args:
            address: Address or name of the function.
            convention: Calling convention — "cdecl", "stdcall", "fastcall", "thiscall", "pascal".
        """
        func = resolve_function(address)

        cc_val = _CC_MAP.get(convention.lower())
        if cc_val is None:
            raise IDAError(
                f"Unknown calling convention: {convention!r}",
                error_type="InvalidArgument",
                valid_conventions=list(_CC_MAP),
            )

        tinfo = ida_typeinf.tinfo_t()
        if not ida_nalt.get_tinfo(tinfo, func.start_ea) and not ida_typeinf.guess_tinfo(
            tinfo, func.start_ea
        ):
            raise IDAError(
                "Cannot determine function type to change convention", error_type="NoType"
            )

        fi = ida_typeinf.func_type_data_t()
        if not tinfo.get_func_details(fi):
            raise IDAError("Cannot get function details", error_type="NoType")

        old_convention = _CC_NAMES.get(fi.get_cc() & 0xF0, f"cc_{fi.get_cc():#x}")
        fi.set_cc((fi.get_cc() & 0x0F) | cc_val)
        new_tinfo = ida_typeinf.tinfo_t()
        if not new_tinfo.create_func(fi):
            raise IDAError("Failed to create new function type", error_type="CreateFailed")

        success = ida_typeinf.apply_tinfo(func.start_ea, new_tinfo, ida_typeinf.TINFO_DEFINITE)
        if not success:
            raise IDAError(
                f"Failed to apply calling convention {convention!r}", error_type="ApplyFailed"
            )
        return SetCallingConventionResult(
            address=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            old_convention=old_convention,
            convention=convention,
        )
