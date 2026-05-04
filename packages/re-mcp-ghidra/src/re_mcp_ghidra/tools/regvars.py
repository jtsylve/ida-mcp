# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Register variable tools -- list and rename local variables via the decompiler.

In IDA, register variables (regvars) map physical registers to names
within address ranges. Ghidra's equivalent operates through the
decompiler's HighFunction / HighVariable / HighSymbol abstractions.
"""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    format_address,
    resolve_function,
)
from re_mcp_ghidra.session import session


class RegvarInfo(BaseModel):
    """Local variable information from the decompiler."""

    name: str = Field(description="Variable name.")
    data_type: str = Field(description="Variable data type.")
    storage: str = Field(description="Storage location (register, stack, etc.).")
    is_parameter: bool = Field(description="Whether this is a function parameter.")


class ListRegvarsResult(BaseModel):
    """Local variables for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    count: int = Field(description="Number of variables.")
    variables: list[RegvarInfo] = Field(description="Local variables.")


class RenameRegvarResult(BaseModel):
    """Result of renaming a local variable."""

    function: str = Field(description="Function address (hex).")
    old_name: str = Field(description="Previous variable name.")
    new_name: str = Field(description="New variable name.")
    status: str = Field(description="Status message.")


def _decompile_function(func):
    """Decompile a function and return the DecompileResults."""
    from ghidra.app.decompiler import DecompInterface  # noqa: PLC0415
    from ghidra.util.task import TaskMonitor  # noqa: PLC0415

    program = session.program
    decomp = DecompInterface()
    decomp.openProgram(program)

    try:
        results = decomp.decompileFunction(func, 60, TaskMonitor.DUMMY)
        if not results.decompileCompleted():
            error_msg = results.getErrorMessage() or "Decompilation failed"
            raise GhidraError(error_msg, error_type="DecompilationFailed")
        return results
    except GhidraError:
        raise
    finally:
        decomp.dispose()


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"metadata", "registers"})
    @session.require_open
    def list_regvars(function_address: Address) -> ListRegvarsResult:
        """List all local variables in a function via the decompiler.

        Returns variables from the decompiler's HighFunction, including
        registers, stack variables, and parameters.

        Args:
            function_address: Address or name of the function.
        """
        func = resolve_function(function_address)
        results = _decompile_function(func)
        high_func = results.getHighFunction()
        if high_func is None:
            raise GhidraError("Failed to get high function", error_type="DecompilationFailed")

        variables = []
        local_sym_map = high_func.getLocalSymbolMap()
        for sym in local_sym_map.getSymbols():
            hv = sym.getHighVariable()
            storage = ""
            if hv is not None:
                rep = hv.getRepresentative()
                if rep is not None:
                    storage = str(rep)

            variables.append(
                RegvarInfo(
                    name=sym.getName(),
                    data_type=str(sym.getDataType()),
                    storage=storage,
                    is_parameter=sym.isParameter(),
                )
            )

        entry = func.getEntryPoint()
        return ListRegvarsResult(
            function=format_address(entry.getOffset()),
            name=func.getName(),
            count=len(variables),
            variables=variables,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"metadata", "registers"})
    @session.require_open
    def rename_regvar(
        function_address: Address,
        old_name: str,
        new_name: str,
    ) -> RenameRegvarResult:
        """Rename a local variable in the decompiler view.

        Finds the variable by its current name in the decompiled function
        and renames it via HighFunctionDBUtil.

        Args:
            function_address: Address or name of the function.
            old_name: Current variable name.
            new_name: New variable name.
        """
        from ghidra.program.model.pcode import HighFunctionDBUtil  # noqa: PLC0415
        from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

        func = resolve_function(function_address)
        results = _decompile_function(func)
        high_func = results.getHighFunction()
        if high_func is None:
            raise GhidraError("Failed to get high function", error_type="DecompilationFailed")

        local_sym_map = high_func.getLocalSymbolMap()
        target_sym = None
        for sym in local_sym_map.getSymbols():
            if sym.getName() == old_name:
                target_sym = sym
                break

        if target_sym is None:
            raise GhidraError(
                f"Variable {old_name!r} not found in function",
                error_type="NotFound",
            )

        high_var = target_sym.getHighVariable()
        if high_var is None:
            raise GhidraError(
                f"No high variable for {old_name!r}",
                error_type="NotFound",
            )

        program = session.program
        tx_id = program.startTransaction("Rename variable")
        try:
            HighFunctionDBUtil.updateDBVariable(
                target_sym,
                new_name,
                None,
                SourceType.USER_DEFINED,
            )
            program.endTransaction(tx_id, True)
        except GhidraError:
            program.endTransaction(tx_id, False)
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to rename variable: {e}", error_type="RenameFailed") from e

        return RenameRegvarResult(
            function=format_address(func.getEntryPoint().getOffset()),
            old_name=old_name,
            new_name=new_name,
            status="renamed",
        )
