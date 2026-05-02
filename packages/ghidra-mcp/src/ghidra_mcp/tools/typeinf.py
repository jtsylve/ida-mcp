# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Extended type library management tools -- detailed type info and deletion."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ghidra_mcp.exceptions import GhidraError
from ghidra_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_READ_ONLY,
)
from ghidra_mcp.session import session


class TypeMember(BaseModel):
    """A member of a struct/union type."""

    name: str = Field(description="Member name.")
    type: str = Field(description="Member type.")
    offset: int = Field(description="Member offset in bytes.")
    size: int = Field(description="Member size in bytes.")
    comment: str = Field(default="", description="Member comment.")


class GetLocalTypeResult(BaseModel):
    """Detailed local type information."""

    name: str = Field(description="Type name.")
    category: str = Field(description="Category path.")
    size: int = Field(description="Type size in bytes.")
    kind: str = Field(description="Type kind (struct, union, enum, typedef, other).")
    declaration: str = Field(description="Type declaration string.")
    members: list[TypeMember] | None = Field(
        default=None, description="Members for struct/union types."
    )
    enum_values: dict[str, int] | None = Field(
        default=None, description="Enum name-value pairs for enum types."
    )


class DeleteLocalTypeResult(BaseModel):
    """Result of deleting a local type."""

    name: str = Field(description="Deleted type name.")
    category: str = Field(description="Category path.")
    status: str = Field(description="Status message.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"types"})
    @session.require_open
    def get_local_type(name: str) -> GetLocalTypeResult:
        """Get detailed type information including members by name.

        For structs/unions, returns all member details (name, type, offset,
        size). For enums, returns name-value pairs. Use list_local_types
        to browse available types.

        Args:
            name: Name of the data type.
        """
        from ghidra.program.model.data import (  # noqa: PLC0415
            Enum,
            Structure,
            TypeDef,
            Union,
        )

        program = session.program
        dtm = program.getDataTypeManager()

        # Find the type by name
        dt = None
        for existing in dtm.getAllDataTypes():
            if existing.getName() == name:
                dt = existing
                break

        if dt is None:
            raise GhidraError(f"Type not found: {name!r}", error_type="NotFound")

        kind = "other"
        members = None
        enum_values = None

        if isinstance(dt, Structure):
            kind = "struct"
            members = []
            for i in range(dt.getNumComponents()):
                comp = dt.getComponent(i)
                members.append(
                    TypeMember(
                        name=comp.getFieldName() or f"field_{i}",
                        type=comp.getDataType().getName(),
                        offset=comp.getOffset(),
                        size=comp.getLength(),
                        comment=comp.getComment() or "",
                    )
                )
        elif isinstance(dt, Union):
            kind = "union"
            members = []
            for i in range(dt.getNumComponents()):
                comp = dt.getComponent(i)
                members.append(
                    TypeMember(
                        name=comp.getFieldName() or f"field_{i}",
                        type=comp.getDataType().getName(),
                        offset=0,
                        size=comp.getLength(),
                        comment=comp.getComment() or "",
                    )
                )
        elif isinstance(dt, Enum):
            kind = "enum"
            enum_values = {}
            for en_name in dt.getNames():
                enum_values[en_name] = dt.getValue(en_name)
        elif isinstance(dt, TypeDef):
            kind = "typedef"

        cat = dt.getCategoryPath()
        return GetLocalTypeResult(
            name=dt.getName(),
            category=str(cat) if cat else "",
            size=dt.getLength(),
            kind=kind,
            declaration=str(dt),
            members=members,
            enum_values=enum_values,
        )

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"types"})
    @session.require_open
    def delete_local_type(name: str) -> DeleteLocalTypeResult:
        """Remove a data type from the program's data type manager.

        Irreversible -- the type declaration is removed. Use undo to
        revert if needed.

        Args:
            name: Name of the data type to delete.
        """
        program = session.program
        dtm = program.getDataTypeManager()

        # Find the type by name
        dt = None
        for existing in dtm.getAllDataTypes():
            if existing.getName() == name:
                dt = existing
                break

        if dt is None:
            raise GhidraError(f"Type not found: {name!r}", error_type="NotFound")

        cat = dt.getCategoryPath()

        tx_id = program.startTransaction("Delete local type")
        try:
            dtm.remove(dt, None)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to delete type: {e}", error_type="DeleteFailed") from e

        return DeleteLocalTypeResult(
            name=name,
            category=str(cat) if cat else "",
            status="deleted",
        )
