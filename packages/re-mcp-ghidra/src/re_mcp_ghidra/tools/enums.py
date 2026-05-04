# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Enum creation and management tools."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_MUTATE_NON_IDEMPOTENT,
    ANNO_READ_ONLY,
    Limit,
    Offset,
    paginate,
    paginate_iter,
)
from re_mcp_ghidra.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class EnumSummary(BaseModel):
    """Brief enum info."""

    name: str = Field(description="Enum name.")
    member_count: int = Field(description="Number of members.")
    category: str = Field(default="", description="Category path.")


class EnumMemberItem(BaseModel):
    """Enum member info."""

    name: str = Field(description="Member name.")
    value: int = Field(description="Member value.")


class CreateEnumResult(BaseModel):
    """Result of creating an enum."""

    name: str = Field(description="Enum name.")
    bitfield: bool = Field(description="Whether this is a bitfield.")
    status: str = Field(description="Status.")


class DeleteEnumResult(BaseModel):
    """Result of deleting an enum."""

    name: str = Field(description="Enum name.")
    old_member_count: int = Field(description="Previous member count.")
    status: str = Field(description="Status.")


class AddEnumMemberResult(BaseModel):
    """Result of adding an enum member."""

    enum: str = Field(description="Enum name.")
    member: str = Field(description="Member name.")
    value: int = Field(description="Member value.")
    status: str = Field(description="Status.")


class RenameEnumResult(BaseModel):
    """Result of renaming an enum."""

    old_name: str = Field(description="Previous enum name.")
    new_name: str = Field(description="New enum name.")
    status: str = Field(description="Status.")


class DeleteEnumMemberResult(BaseModel):
    """Result of deleting an enum member."""

    enum: str = Field(description="Enum name.")
    member: str = Field(description="Deleted member name.")
    value: int = Field(description="Member value.")
    status: str = Field(description="Status.")


class RenameEnumMemberResult(BaseModel):
    """Result of renaming an enum member."""

    enum: str = Field(description="Enum name.")
    old_name: str = Field(description="Previous member name.")
    new_name: str = Field(description="New member name.")
    value: int = Field(description="Member value.")
    status: str = Field(description="Status.")


def _resolve_enum(name: str):
    """Resolve an enum by name from the data type manager.

    Returns an ``EnumDataType`` instance. Raises :class:`GhidraError` if not found.
    """
    from ghidra.program.model.data import Enum  # noqa: PLC0415

    program = session.program
    dtm = program.getDataTypeManager()
    for dt in dtm.getAllDataTypes():
        if dt.getName() == name and isinstance(dt, Enum):
            return dt

    raise GhidraError(f"Enum not found: {name}", error_type="NotFound")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"types", "enums"})
    @session.require_open
    def list_enums(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List all enums in the database, paginated.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        from ghidra.program.model.data import Enum  # noqa: PLC0415

        program = session.program
        dtm = program.getDataTypeManager()

        def _gen():
            for dt in dtm.getAllDataTypes():
                if not isinstance(dt, Enum):
                    continue
                cat = dt.getCategoryPath()
                yield EnumSummary(
                    name=dt.getName(),
                    member_count=dt.getCount(),
                    category=str(cat) if cat else "",
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_MUTATE_NON_IDEMPOTENT, tags={"types", "enums"})
    @session.require_open
    def create_enum(name: str, bitfield: bool = False) -> CreateEnumResult:
        """Create a new enum type.

        Args:
            name: Name for the enum.
            bitfield: If True, create as a bitfield enum (unused in Ghidra but
                reserved for future use).
        """
        from ghidra.program.model.data import CategoryPath, EnumDataType  # noqa: PLC0415

        program = session.program
        dtm = program.getDataTypeManager()

        tx_id = program.startTransaction("Create enum")
        try:
            enum_dt = EnumDataType(CategoryPath.ROOT, name, 4)
            dtm.addDataType(enum_dt, None)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to create enum: {e}", error_type="CreateFailed") from e

        return CreateEnumResult(name=name, bitfield=bitfield, status="created")

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"types", "enums"})
    @session.require_open
    def delete_enum(name: str) -> DeleteEnumResult:
        """Delete an enum by name.

        Args:
            name: Name of the enum to delete.
        """
        enum_dt = _resolve_enum(name)
        old_member_count = enum_dt.getCount()

        program = session.program
        dtm = program.getDataTypeManager()

        tx_id = program.startTransaction("Delete enum")
        try:
            dtm.remove(enum_dt, None)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to delete enum: {e}", error_type="DeleteFailed") from e

        return DeleteEnumResult(name=name, old_member_count=old_member_count, status="deleted")

    @mcp.tool(annotations=ANNO_MUTATE, tags={"types", "enums"})
    @session.require_open
    def add_enum_member(enum_name: str, member_name: str, value: int) -> AddEnumMemberResult:
        """Add a member to an enum.

        Args:
            enum_name: Name of the enum.
            member_name: Name for the new member.
            value: Integer value for the member.
        """
        enum_dt = _resolve_enum(enum_name)

        program = session.program
        tx_id = program.startTransaction("Add enum member")
        try:
            enum_dt.add(member_name, value)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to add enum member: {e}", error_type="AddMemberFailed"
            ) from e

        return AddEnumMemberResult(enum=enum_name, member=member_name, value=value, status="added")

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"types", "enums"})
    @session.require_open
    def get_enum_members(
        enum_name: str,
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List all members of an enum, paginated.

        Args:
            enum_name: Name of the enum.
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        enum_dt = _resolve_enum(enum_name)

        members = []
        for value in enum_dt.getValues():
            name = enum_dt.getName(value)
            members.append(EnumMemberItem(name=name or "", value=int(value)).model_dump())

        return paginate(members, offset, limit)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"types", "enums"})
    @session.require_open
    def rename_enum(old_name: str, new_name: str) -> RenameEnumResult:
        """Rename an enum.

        Args:
            old_name: Current name of the enum.
            new_name: New name for the enum.
        """
        enum_dt = _resolve_enum(old_name)

        program = session.program
        tx_id = program.startTransaction("Rename enum")
        try:
            enum_dt.setName(new_name)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to rename enum {old_name!r} to {new_name!r}",
                error_type="RenameFailed",
            ) from e

        return RenameEnumResult(old_name=old_name, new_name=new_name, status="renamed")

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"types", "enums"})
    @session.require_open
    def delete_enum_member(enum_name: str, value: int) -> DeleteEnumMemberResult:
        """Delete a member from an enum by its value.

        Args:
            enum_name: Name of the enum.
            value: Integer value of the member to delete.
        """
        enum_dt = _resolve_enum(enum_name)

        member_name = enum_dt.getName(value)
        if member_name is None:
            raise GhidraError(f"No member with value {value} in {enum_name}", error_type="NotFound")

        program = session.program
        tx_id = program.startTransaction("Delete enum member")
        try:
            enum_dt.remove(member_name)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to delete enum member: {e}", error_type="DeleteFailed"
            ) from e

        return DeleteEnumMemberResult(
            enum=enum_name, member=member_name, value=value, status="deleted"
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"types", "enums"})
    @session.require_open
    def rename_enum_member(enum_name: str, value: int, new_name: str) -> RenameEnumMemberResult:
        """Rename an enum member by its value.

        Args:
            enum_name: Name of the enum.
            value: Integer value of the member to rename.
            new_name: New name for the member.
        """
        enum_dt = _resolve_enum(enum_name)

        old_name = enum_dt.getName(value)
        if old_name is None:
            raise GhidraError(f"No member with value {value} in {enum_name}", error_type="NotFound")

        program = session.program
        tx_id = program.startTransaction("Rename enum member")
        try:
            # Ghidra EnumDataType: remove old by name, add with new name
            enum_dt.remove(old_name)
            enum_dt.add(new_name, value)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to rename enum member: {e}", error_type="RenameFailed"
            ) from e

        return RenameEnumMemberResult(
            enum=enum_name, old_name=old_name, new_name=new_name, value=value, status="renamed"
        )
