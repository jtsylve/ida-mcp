# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Stack frame and function variable analysis tools."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ghidra_mcp.exceptions import GhidraError
from ghidra_mcp.helpers import (
    ANNO_READ_ONLY,
    Address,
    format_address,
    resolve_function,
)
from ghidra_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class FrameMember(BaseModel):
    """Stack frame member."""

    offset: int = Field(description="Frame offset.")
    name: str = Field(description="Member name.")
    size: int = Field(description="Member size in bytes.")
    type: str = Field(default="", description="Data type.")
    comment: str = Field(default="", description="Member comment.")


class FrameDetail(BaseModel):
    """Stack frame details."""

    frame_size: int = Field(description="Total frame size.")
    parameter_offset: int = Field(description="Parameter area offset.")
    local_size: int = Field(description="Local variable area size.")
    parameter_size: int = Field(description="Parameter area size.")
    return_address_offset: int = Field(description="Return address offset.")
    member_count: int = Field(description="Number of frame members.")
    members: list[FrameMember] = Field(description="Frame members.")


class GetStackFrameResult(BaseModel):
    """Stack frame for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    frame: FrameDetail | None = Field(description="Frame details, or null if no frame.")


class FunctionVariable(BaseModel):
    """A decompiler variable from HighFunction."""

    name: str = Field(description="Variable name.")
    type: str = Field(description="Variable type.")
    is_param: bool = Field(description="Whether this is a function parameter.")
    size: int = Field(description="Variable size in bytes.")
    storage: str = Field(default="", description="Storage location description.")


class GetFunctionVarsResult(BaseModel):
    """Function variables from the decompiler."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    variable_count: int = Field(description="Number of variables.")
    variables: list[FunctionVariable] = Field(description="Variable list.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions"})
    @session.require_open
    def get_stack_frame(
        address: Address,
    ) -> GetStackFrameResult:
        """Get the stack frame layout of a function (offsets, sizes, types).

        For typed variable info from decompilation, use get_function_vars.

        Args:
            address: Address or name of the function.
        """
        func = resolve_function(address)
        stack_frame = func.getStackFrame()
        entry = func.getEntryPoint().getOffset()

        if stack_frame is None:
            return GetStackFrameResult(
                function=format_address(entry),
                name=func.getName(),
                frame=None,
            )

        variables = stack_frame.getStackVariables()
        members = []
        for var in variables:
            dt = var.getDataType()
            members.append(
                FrameMember(
                    offset=var.getStackOffset(),
                    name=var.getName() or f"var_{abs(var.getStackOffset()):X}",
                    size=var.getLength(),
                    type=dt.getName() if dt else "",
                    comment=var.getComment() or "",
                )
            )

        # Sort by offset
        members.sort(key=lambda m: m.offset)

        return GetStackFrameResult(
            function=format_address(entry),
            name=func.getName(),
            frame=FrameDetail(
                frame_size=stack_frame.getFrameSize(),
                parameter_offset=stack_frame.getParameterOffset(),
                local_size=stack_frame.getLocalSize(),
                parameter_size=stack_frame.getParameterSize(),
                return_address_offset=stack_frame.getReturnAddressOffset(),
                member_count=len(members),
                members=members,
            ),
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions", "decompiler"})
    @session.require_open
    def get_function_vars(
        address: Address,
    ) -> GetFunctionVarsResult:
        """Get typed locals and parameters via decompilation.

        For the raw stack frame layout, use get_stack_frame.

        Args:
            address: Address or name of the function.
        """
        from ghidra.app.decompiler import DecompInterface  # noqa: PLC0415
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        func = resolve_function(address)
        program = session.program

        decomp = DecompInterface()
        decomp.openProgram(program)
        try:
            results = decomp.decompileFunction(func, 60, TaskMonitor.DUMMY)
            if not results.decompileCompleted():
                error_msg = results.getErrorMessage() or "Decompilation failed"
                raise GhidraError(error_msg, error_type="DecompilationFailed")

            high_func = results.getHighFunction()
            if high_func is None:
                raise GhidraError(
                    "Decompilation returned no HighFunction",
                    error_type="DecompilationFailed",
                )

            variables = []
            local_sym_map = high_func.getLocalSymbolMap()
            sym_iter = local_sym_map.getSymbols()
            while sym_iter.hasNext():
                sym = sym_iter.next()
                high_var = sym.getHighVariable()
                var_type = str(high_var.getDataType()) if high_var else "undefined"
                var_size = high_var.getSize() if high_var else 0
                storage_desc = str(sym.getStorage()) if sym.getStorage() else ""

                variables.append(
                    FunctionVariable(
                        name=sym.getName(),
                        type=var_type,
                        is_param=sym.isParameter(),
                        size=var_size,
                        storage=storage_desc,
                    )
                )
        finally:
            decomp.dispose()

        entry = func.getEntryPoint().getOffset()
        return GetFunctionVarsResult(
            function=format_address(entry),
            name=func.getName(),
            variable_count=len(variables),
            variables=variables,
        )
