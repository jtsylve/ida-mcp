# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Type information tools — query and apply types."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    FilterPattern,
    Limit,
    Offset,
    compile_filter,
    format_address,
    paginate_iter,
    resolve_address,
)
from re_mcp_ghidra.session import session


class TypeInfoResult(BaseModel):
    address: str
    type_name: str = ""
    type_size: int | None = None
    function_signature: str = ""


class SetTypeResult(BaseModel):
    address: str
    type_name: str
    status: str


class LocalTypeItem(BaseModel):
    name: str
    category: str = ""
    size: int
    kind: str = Field(description="Type kind: struct, union, enum, typedef, etc.")


class ParseTypeResult(BaseModel):
    type_name: str
    size: int
    kind: str
    status: str


class ApplyTypeResult(BaseModel):
    address: str
    type_name: str
    status: str


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"types"})
    @session.require_open
    def get_type_info(address: Address) -> TypeInfoResult:
        """Get type information at an address."""
        program = session.program
        listing = program.getListing()
        func_mgr = program.getFunctionManager()
        addr = resolve_address(address)

        # Check if there's a function at this address
        func = func_mgr.getFunctionAt(addr)
        if func:
            return TypeInfoResult(
                address=format_address(addr.getOffset()),
                type_name=str(func.getReturnType()),
                function_signature=func.getPrototypeString(False, False),
            )

        # Check for data type
        data = listing.getDataAt(addr)
        if data is not None:
            dt = data.getDataType()
            return TypeInfoResult(
                address=format_address(addr.getOffset()),
                type_name=dt.getName(),
                type_size=dt.getLength(),
            )

        return TypeInfoResult(
            address=format_address(addr.getOffset()),
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"types"})
    @session.require_open
    def set_type(address: Address, type_string: str) -> SetTypeResult:
        """Apply a data type at an address.

        Args:
            address: Target address.
            type_string: C type string (e.g. "int", "char *", "struct foo").
        """
        from re_mcp_ghidra.tools.structs import _parse_data_type  # noqa: PLC0415

        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)

        dt = _parse_data_type(type_string)

        tx_id = program.startTransaction("Set type")
        try:
            listing.clearCodeUnits(addr, addr.add(dt.getLength() - 1), False)
            listing.createData(addr, dt)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to set type: {e}", error_type="SetTypeFailed") from e

        return SetTypeResult(
            address=format_address(addr.getOffset()),
            type_name=type_string,
            status="ok",
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"types"})
    @session.require_open
    def list_local_types(
        offset: Offset = 0,
        limit: Limit = 100,
        filter_pattern: FilterPattern = "",
    ) -> dict:
        """List locally defined data types."""
        from ghidra.program.model.data import (  # noqa: PLC0415
            Enum,
            FunctionDefinition,
            Structure,
            TypeDef,
            Union,
        )

        program = session.program
        dtm = program.getDataTypeManager()
        filt = compile_filter(filter_pattern)

        def _gen():
            for dt in dtm.getAllDataTypes():
                name = dt.getName()
                if filt and not filt.search(name):
                    continue

                kind = "other"
                if isinstance(dt, Structure):
                    kind = "struct"
                elif isinstance(dt, Union):
                    kind = "union"
                elif isinstance(dt, Enum):
                    kind = "enum"
                elif isinstance(dt, TypeDef):
                    kind = "typedef"
                elif isinstance(dt, FunctionDefinition):
                    kind = "function"

                cat = dt.getCategoryPath()
                yield LocalTypeItem(
                    name=name,
                    category=str(cat) if cat else "",
                    size=dt.getLength(),
                    kind=kind,
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"types"})
    @session.require_open
    def parse_type_declaration(declaration: str) -> ParseTypeResult:
        """Parse a C type declaration and add it to the program's type library.

        Args:
            declaration: C declaration (e.g. "typedef int DWORD;" or
                         "struct point { int x; int y; };").
        """
        from ghidra.app.util.cparser.C import CParser  # noqa: PLC0415

        program = session.program
        dtm = program.getDataTypeManager()

        tx_id = program.startTransaction("Parse type declaration")
        try:
            parser = CParser(dtm)
            dt = parser.parse(declaration)
            if dt is None:
                program.endTransaction(tx_id, False)
                raise GhidraError(
                    f"Failed to parse declaration: {declaration!r}",
                    error_type="ParseError",
                )
            dtm.addDataType(dt, None)
            program.endTransaction(tx_id, True)

            kind = "other"
            from ghidra.program.model.data import Enum, Structure, Union  # noqa: PLC0415

            if isinstance(dt, Structure):
                kind = "struct"
            elif isinstance(dt, Union):
                kind = "union"
            elif isinstance(dt, Enum):
                kind = "enum"

            return ParseTypeResult(
                type_name=dt.getName(),
                size=dt.getLength(),
                kind=kind,
                status="parsed",
            )
        except GhidraError:
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to parse declaration: {e}", error_type="ParseError") from e

    @mcp.tool(annotations=ANNO_MUTATE, tags={"types"})
    @session.require_open
    def apply_type_at_address(
        address: Address,
        type_name: str,
    ) -> ApplyTypeResult:
        """Apply a named type from the type library at an address.

        The type must already exist (defined via parse_type_declaration
        or present in the program's built-in types).
        """
        program = session.program
        listing = program.getListing()
        dtm = program.getDataTypeManager()
        addr = resolve_address(address)

        # Find the named type
        dt = None
        for existing in dtm.getAllDataTypes():
            if existing.getName() == type_name:
                dt = existing
                break

        if dt is None:
            raise GhidraError(
                f"Type {type_name!r} not found. Use parse_type_declaration first.",
                error_type="NotFound",
            )

        tx_id = program.startTransaction("Apply type at address")
        try:
            listing.clearCodeUnits(addr, addr.add(dt.getLength() - 1), False)
            listing.createData(addr, dt)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to apply type: {e}", error_type="ApplyTypeFailed") from e

        return ApplyTypeResult(
            address=format_address(addr.getOffset()),
            type_name=type_name,
            status="applied",
        )
