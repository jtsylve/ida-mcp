# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Decompiler variable tools — list, rename, retype variables and get comments."""

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

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class DecompilerVariable(BaseModel):
    """A decompiler local variable or parameter."""

    name: str = Field(description="Variable name.")
    type: str = Field(description="Variable type.")
    is_param: bool = Field(description="Whether this is a function parameter.")
    size: int = Field(description="Variable size in bytes.")
    storage: str = Field(default="", description="Storage location description.")


class ListDecompilerVarsResult(BaseModel):
    """Decompiler variables for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    variable_count: int = Field(description="Number of variables.")
    variables: list[DecompilerVariable] = Field(description="Variable list.")


class RenameDecompilerVarResult(BaseModel):
    """Result of renaming a decompiler variable."""

    function: str = Field(description="Function address (hex).")
    old_name: str = Field(description="Previous variable name.")
    new_name: str = Field(description="New variable name.")


class RetypeDecompilerVarResult(BaseModel):
    """Result of retyping a decompiler variable."""

    function: str = Field(description="Function address (hex).")
    variable: str = Field(description="Variable name.")
    old_type: str = Field(description="Previous variable type.")
    new_type: str = Field(description="New variable type.")


class DecompilerCommentItem(BaseModel):
    """A decompiler comment at an address."""

    address: str = Field(description="Comment address (hex).")
    comment: str = Field(description="Comment text.")


class GetDecompilerCommentsResult(BaseModel):
    """Decompiler comments for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    comments: list[DecompilerCommentItem] = Field(description="Comments.")


def _decompile(func):
    """Decompile a function, returning (DecompileResults, HighFunction).

    Raises :class:`GhidraError` on failure.
    """
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

        high_func = results.getHighFunction()
        if high_func is None:
            raise GhidraError(
                "Decompilation returned no HighFunction", error_type="DecompilationFailed"
            )
        return results, high_func
    except GhidraError:
        raise
    except Exception as e:
        raise GhidraError(f"Decompilation failed: {e}", error_type="DecompilationFailed") from e
    finally:
        decomp.dispose()


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"decompiler"})
    @session.require_open
    def list_decompiler_variables(
        function_address: Address,
    ) -> ListDecompilerVarsResult:
        """List decompiler locals and parameters for a function.

        Returns each variable's name, type, storage, and whether it is a
        parameter.  Use this before rename_decompiler_variable or
        retype_decompiler_variable to get the exact current names.

        Args:
            function_address: Address or name of the function.
        """
        func = resolve_function(function_address)
        _results, high_func = _decompile(func)

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
                DecompilerVariable(
                    name=sym.getName(),
                    type=var_type,
                    is_param=sym.isParameter(),
                    size=var_size,
                    storage=storage_desc,
                )
            )

        entry = func.getEntryPoint().getOffset()
        return ListDecompilerVarsResult(
            function=format_address(entry),
            name=func.getName(),
            variable_count=len(variables),
            variables=variables,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"decompiler", "modification"})
    @session.require_open
    def rename_decompiler_variable(
        function_address: Address,
        old_name: str,
        new_name: str,
    ) -> RenameDecompilerVarResult:
        """Rename a decompiler local variable or parameter.

        Args:
            function_address: Address or name of the function.
            old_name: Current variable name in the decompiler output.
            new_name: New name to assign to the variable.
        """
        from ghidra.app.decompiler import DecompInterface  # noqa: PLC0415
        from ghidra.program.model.pcode import HighFunctionDBUtil  # noqa: PLC0415
        from ghidra.program.model.symbol import SourceType  # noqa: PLC0415
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        func = resolve_function(function_address)
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

            # Find the symbol by name
            local_sym_map = high_func.getLocalSymbolMap()
            available = []
            target_sym = None
            sym_iter = local_sym_map.getSymbols()
            while sym_iter.hasNext():
                sym = sym_iter.next()
                available.append(sym.getName())
                if sym.getName() == old_name:
                    target_sym = sym

            if target_sym is None:
                raise GhidraError(
                    f"Variable not found: {old_name!r}",
                    error_type="NotFound",
                )

            high_var = target_sym.getHighVariable()
            if high_var is None:
                raise GhidraError(
                    f"No high variable for {old_name!r}",
                    error_type="NotFound",
                )

            tx_id = program.startTransaction("Rename decompiler variable")
            try:
                HighFunctionDBUtil.updateDBVariable(
                    target_sym,
                    new_name,
                    None,  # keep existing type
                    SourceType.USER_DEFINED,
                )
                program.endTransaction(tx_id, True)
            except Exception as e:
                program.endTransaction(tx_id, False)
                raise GhidraError(
                    f"Failed to rename variable: {e}", error_type="RenameFailed"
                ) from e
        finally:
            decomp.dispose()

        entry = func.getEntryPoint().getOffset()
        return RenameDecompilerVarResult(
            function=format_address(entry),
            old_name=old_name,
            new_name=new_name,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"decompiler", "modification"})
    @session.require_open
    def retype_decompiler_variable(
        function_address: Address,
        variable_name: str,
        new_type: str,
    ) -> RetypeDecompilerVarResult:
        """Retype a decompiler local variable or parameter.

        Args:
            function_address: Address or name of the function.
            variable_name: Name of the variable to retype.
            new_type: C type string to apply (e.g. "int *", "struct foo *").
        """
        from ghidra.app.decompiler import DecompInterface  # noqa: PLC0415
        from ghidra.program.model.pcode import HighFunctionDBUtil  # noqa: PLC0415
        from ghidra.program.model.symbol import SourceType  # noqa: PLC0415
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        func = resolve_function(function_address)
        program = session.program

        # Parse the new type using the program's data type manager
        from re_mcp_ghidra.tools.structs import _parse_data_type  # noqa: PLC0415

        new_dt = _parse_data_type(new_type)

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

            # Find the symbol by name
            local_sym_map = high_func.getLocalSymbolMap()
            target_sym = None
            sym_iter = local_sym_map.getSymbols()
            while sym_iter.hasNext():
                sym = sym_iter.next()
                if sym.getName() == variable_name:
                    target_sym = sym
                    break

            if target_sym is None:
                raise GhidraError(
                    f"Variable not found: {variable_name!r}",
                    error_type="NotFound",
                )

            high_var = target_sym.getHighVariable()
            old_type = str(high_var.getDataType()) if high_var else "undefined"

            tx_id = program.startTransaction("Retype decompiler variable")
            try:
                HighFunctionDBUtil.updateDBVariable(
                    target_sym,
                    None,  # keep existing name
                    new_dt,
                    SourceType.USER_DEFINED,
                )
                program.endTransaction(tx_id, True)
            except Exception as e:
                program.endTransaction(tx_id, False)
                raise GhidraError(
                    f"Failed to retype variable: {e}", error_type="RetypeFailed"
                ) from e
        finally:
            decomp.dispose()

        entry = func.getEntryPoint().getOffset()
        return RetypeDecompilerVarResult(
            function=format_address(entry),
            variable=variable_name,
            old_type=old_type,
            new_type=new_type,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"decompiler", "comments"})
    @session.require_open
    def get_decompiler_comments(
        function_address: Address,
    ) -> GetDecompilerCommentsResult:
        """List pre-comments (visible in decompiler) for a function.

        Returns PRE comments on code units within the function body,
        which Ghidra's decompiler renders above the corresponding
        pseudocode line.

        Args:
            function_address: Address or name of the function.
        """
        from ghidra.program.model.listing import CodeUnit  # noqa: PLC0415

        func = resolve_function(function_address)
        program = session.program
        listing = program.getListing()
        body = func.getBody()

        comments = []
        cu_iter = listing.getCodeUnits(body, True)
        while cu_iter.hasNext():
            cu = cu_iter.next()
            pre_cmt = cu.getComment(CodeUnit.PRE_COMMENT)
            if pre_cmt:
                comments.append(
                    DecompilerCommentItem(
                        address=format_address(cu.getAddress().getOffset()),
                        comment=pre_cmt,
                    )
                )

        entry = func.getEntryPoint().getOffset()
        return GetDecompilerCommentsResult(
            function=format_address(entry),
            name=func.getName(),
            comments=comments,
        )
