# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Function prototype and calling convention tools."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ghidra_mcp.exceptions import GhidraError
from ghidra_mcp.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    format_address,
    resolve_function,
)
from ghidra_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class FunctionTypeParameter(BaseModel):
    """A function type parameter."""

    name: str = Field(description="Parameter name.")
    type: str = Field(description="Parameter type.")
    ordinal: int = Field(description="Parameter ordinal index.")


class FunctionTypeDetail(BaseModel):
    """Detailed function type information."""

    return_type: str = Field(description="Return type.")
    calling_convention: str = Field(description="Calling convention.")
    parameters: list[FunctionTypeParameter] = Field(description="Function parameters.")


class GetFunctionTypeResult(BaseModel):
    """Function type information."""

    address: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    signature: str = Field(description="Full function signature string.")
    details: FunctionTypeDetail = Field(description="Parsed type details.")


class SetFunctionTypeResult(BaseModel):
    """Result of setting a function type."""

    address: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    old_signature: str = Field(description="Previous signature.")
    new_signature: str = Field(description="New signature.")
    status: str = Field(description="Status.")


class SetCallingConventionResult(BaseModel):
    """Result of setting a function's calling convention."""

    address: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    old_convention: str = Field(description="Previous calling convention.")
    convention: str = Field(description="New calling convention.")
    status: str = Field(description="Status.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions", "types"})
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
        entry = func.getEntryPoint().getOffset()

        signature = func.getPrototypeString(False, False) or ""
        return_type = func.getReturnType()
        calling_convention = func.getCallingConventionName() or ""

        params = [
            FunctionTypeParameter(
                name=param.getName() or f"param_{param.getOrdinal()}",
                type=str(param.getDataType()),
                ordinal=param.getOrdinal(),
            )
            for param in func.getParameters()
        ]

        return GetFunctionTypeResult(
            address=format_address(entry),
            name=func.getName(),
            signature=signature,
            details=FunctionTypeDetail(
                return_type=str(return_type),
                calling_convention=calling_convention,
                parameters=params,
            ),
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"functions", "types"})
    @session.require_open
    def set_function_type(
        address: Address,
        type_string: str,
    ) -> SetFunctionTypeResult:
        """Set a function's full C prototype (return + args + calling convention).

        Parses a C function declaration and applies it to the function.

        Args:
            address: Address or name of the function.
            type_string: C function declaration, e.g. "int foo(int a, char *b)".
        """
        from ghidra.app.util.cparser import CParser  # noqa: PLC0415
        from ghidra.program.model.data import FunctionDefinitionDataType  # noqa: PLC0415

        func = resolve_function(address)
        program = session.program
        entry = func.getEntryPoint().getOffset()

        old_signature = func.getPrototypeString(False, False) or ""

        # Parse the type string using CParser
        dtm = program.getDataTypeManager()
        parser = CParser(dtm)

        tx_id = program.startTransaction("Set function type")
        try:
            parsed_dt = parser.parse(type_string)

            if not isinstance(parsed_dt, FunctionDefinitionDataType):
                raise GhidraError(
                    f"Parsed type is not a function definition: {type_string!r}",
                    error_type="InvalidArgument",
                )

            # Apply the parsed function definition to the function
            from ghidra.program.model.listing.Function import FunctionUpdateType  # noqa: PLC0415
            from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

            ret_type = parsed_dt.getReturnType()
            func.setReturnType(ret_type, SourceType.USER_DEFINED)

            # Apply parameters
            params = []
            from ghidra.program.model.listing import ParameterImpl  # noqa: PLC0415

            for arg in parsed_dt.getArguments():
                param = ParameterImpl(
                    arg.getName() or "",
                    arg.getDataType(),
                    program,
                )
                params.append(param)

            func.replaceParameters(
                params,
                FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                True,
                SourceType.USER_DEFINED,
            )

            program.endTransaction(tx_id, True)
        except GhidraError:
            program.endTransaction(tx_id, False)
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to set function type: {e}", error_type="SetTypeFailed"
            ) from e

        new_signature = func.getPrototypeString(False, False) or ""
        return SetFunctionTypeResult(
            address=format_address(entry),
            name=func.getName(),
            old_signature=old_signature,
            new_signature=new_signature,
            status="updated",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"functions", "types"})
    @session.require_open
    def set_function_calling_convention(
        address: Address,
        convention: str,
    ) -> SetCallingConventionResult:
        """Change the calling convention of a function.

        Args:
            address: Address or name of the function.
            convention: Calling convention name (e.g. "__cdecl", "__stdcall",
                "__fastcall", "__thiscall"). Use get_function_type to see
                the current convention.
        """
        func = resolve_function(address)
        program = session.program
        entry = func.getEntryPoint().getOffset()

        old_convention = func.getCallingConventionName() or ""

        tx_id = program.startTransaction("Set calling convention")
        try:
            func.setCallingConvention(convention)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to set calling convention {convention!r}: {e}",
                error_type="SetConventionFailed",
            ) from e

        return SetCallingConventionResult(
            address=format_address(entry),
            name=func.getName(),
            old_convention=old_convention,
            convention=convention,
            status="updated",
        )
