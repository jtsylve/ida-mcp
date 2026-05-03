# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Stack frame and local variable analysis tools."""

from __future__ import annotations

import ida_typeinf
import idc
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ida.helpers import (
    ANNO_READ_ONLY,
    META_DECOMPILER,
    Address,
    decompile_at,
    format_address,
    get_func_name,
    resolve_function,
)
from re_mcp_ida.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class FrameMember(BaseModel):
    """Stack frame member."""

    offset: int = Field(description="Frame offset.")
    name: str = Field(description="Member name.")
    size: int = Field(description="Member size in bytes.")


class FrameDetail(BaseModel):
    """Stack frame details."""

    frame_size: int = Field(description="Total frame size.")
    local_size: int = Field(description="Local variable area size.")
    saved_regs_size: int = Field(description="Saved registers area size.")
    args_size: int = Field(description="Arguments area size.")
    member_count: int = Field(description="Number of frame members.")
    members: list[FrameMember] = Field(description="Frame members.")


class GetStackFrameResult(BaseModel):
    """Stack frame for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    frame: FrameDetail | None = Field(description="Frame details, or null if no frame.")


class FunctionVariable(BaseModel):
    """A decompiler variable."""

    name: str = Field(description="Variable name.")
    type: str = Field(description="Variable type.")
    is_arg: bool = Field(description="Whether this is a function argument.")
    is_result: bool = Field(description="Whether this is the return value.")
    width: int = Field(description="Variable width in bytes.")


class GetFunctionVarsResult(BaseModel):
    """Function variables from the decompiler."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    variable_count: int = Field(description="Number of variables.")
    variables: list[FunctionVariable] = Field(description="Variable list.")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"functions"},
    )
    @session.require_open
    def get_stack_frame(
        address: Address,
    ) -> GetStackFrameResult:
        """Get the stack frame layout of a function (offsets, sizes, no Hex-Rays needed).

        For typed variable info from decompilation, use get_function_vars.

        Args:
            address: Address or name of the function.
        """
        func = resolve_function(address)

        frame_tif = ida_typeinf.tinfo_t()
        if not frame_tif.get_func_frame(func):
            return GetStackFrameResult(
                function=format_address(func.start_ea),
                name=get_func_name(func.start_ea),
                frame=None,
            )

        udt = ida_typeinf.udt_type_data_t()
        frame_tif.get_udt_details(udt)

        members = []
        for udm in udt:
            if udm.is_gap():
                continue
            byte_offset = udm.offset // 8
            members.append(
                FrameMember(
                    offset=byte_offset,
                    name=udm.name or f"var_{byte_offset:X}",
                    size=udm.size // 8,
                )
            )

        return GetStackFrameResult(
            function=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            frame=FrameDetail(
                frame_size=idc.get_func_attr(func.start_ea, idc.FUNCATTR_FRSIZE),
                local_size=func.frsize,
                saved_regs_size=func.frregs,
                args_size=func.argsize,
                member_count=len(members),
                members=members,
            ),
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"functions", "decompiler"},
        meta=META_DECOMPILER,
    )
    @session.require_open
    def get_function_vars(
        address: Address,
    ) -> GetFunctionVarsResult:
        """Get typed locals/params via Hex-Rays decompilation (for raw frame use get_stack_frame).

        Args:
            address: Address or name of the function.
        """
        cfunc, func = decompile_at(address)

        variables = [
            FunctionVariable(
                name=lvar.name,
                type=str(lvar.type()),
                is_arg=lvar.is_arg_var,
                is_result=lvar.is_result_var,
                width=lvar.width,
            )
            for lvar in cfunc.lvars
        ]

        return GetFunctionVarsResult(
            function=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            variable_count=len(variables),
            variables=variables,
        )
