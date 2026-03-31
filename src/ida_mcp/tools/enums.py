# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Enum creation and management tools."""

from __future__ import annotations

import ida_typeinf
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    IDAError,
    Limit,
    Offset,
    is_bad_addr,
    is_cancelled,
    paginate,
    paginate_iter,
)
from ida_mcp.models import PaginatedResult
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class EnumSummary(BaseModel):
    """Brief enum info."""

    name: str = Field(description="Enum name.")
    member_count: int = Field(description="Number of members.")
    bitfield: bool = Field(description="Whether this is a bitfield.")


class EnumListResult(PaginatedResult[EnumSummary]):
    """Paginated list of enums."""

    items: list[EnumSummary] = Field(description="Page of enums.")


class CreateEnumResult(BaseModel):
    """Result of creating an enum."""

    name: str = Field(description="Enum name.")
    bitfield: bool = Field(description="Whether this is a bitfield.")


class DeleteEnumResult(BaseModel):
    """Result of deleting an enum."""

    name: str = Field(description="Enum name.")
    old_member_count: int = Field(description="Previous member count.")


class AddEnumMemberResult(BaseModel):
    """Result of adding an enum member."""

    enum: str = Field(description="Enum name.")
    member: str = Field(description="Member name.")
    value: int = Field(description="Member value.")


class EnumMemberItem(BaseModel):
    """Enum member info."""

    name: str = Field(description="Member name.")
    value: int = Field(description="Member value.")


class EnumMemberListResult(PaginatedResult[EnumMemberItem]):
    """Paginated list of enum members."""

    items: list[EnumMemberItem] = Field(description="Page of enum members.")


class RenameEnumResult(BaseModel):
    """Result of renaming an enum."""

    old_name: str = Field(description="Previous enum name.")
    new_name: str = Field(description="New enum name.")


class DeleteEnumMemberResult(BaseModel):
    """Result of deleting an enum member."""

    enum: str = Field(description="Enum name.")
    member: str = Field(description="Deleted member name.")
    value: int = Field(description="Member value.")


class RenameEnumMemberResult(BaseModel):
    """Result of renaming an enum member."""

    enum: str = Field(description="Enum name.")
    old_name: str = Field(description="Previous member name.")
    new_name: str = Field(description="New member name.")
    value: int = Field(description="Member value.")


class SetEnumMemberCommentResult(BaseModel):
    """Result of setting an enum member comment."""

    enum: str = Field(description="Enum name.")
    value: int = Field(description="Member value.")
    old_comment: str = Field(description="Previous comment.")
    comment: str = Field(description="New comment.")


def _get_enum_tif(
    name: str,
) -> tuple[ida_typeinf.tinfo_t, ida_typeinf.enum_type_data_t]:
    """Load enum tinfo_t and enum_type_data_t by name.

    Raises :class:`IDAError` if the enum is not found or cannot be loaded.
    """
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, name):
        raise IDAError(f"Enum not found: {name}", error_type="NotFound")
    if not tif.is_enum():
        raise IDAError(f"Not an enum: {name}", error_type="NotFound")
    edt = ida_typeinf.enum_type_data_t()
    if not tif.get_enum_details(edt):
        raise IDAError(f"Cannot get enum details: {name}", error_type="InternalError")
    return tif, edt


def _find_member_by_value(edt: ida_typeinf.enum_type_data_t, value: int, enum_name: str) -> int:
    """Find an enum member index by value.  Raises :class:`IDAError` if not found."""
    idx = next((i for i in range(len(edt)) if edt[i].value == value), -1)
    if idx == -1:
        raise IDAError(f"No member with value {value} in {enum_name}", error_type="NotFound")
    return idx


def _save_enum(tif: ida_typeinf.tinfo_t, edt: ida_typeinf.enum_type_data_t, name: str) -> None:
    """Rebuild tif from modified edt and save.  Raises :class:`IDAError` on failure."""
    is_bf = edt.is_bf()
    if not tif.create_enum(edt):
        raise IDAError("Failed to rebuild enum type", error_type="InternalError")
    if is_bf:
        tif.set_enum_is_bitmask(ida_typeinf.tinfo_t.ENUMBM_ON)
    result = tif.set_named_type(None, name, ida_typeinf.NTF_REPLACE)
    if result != ida_typeinf.TERR_OK:
        raise IDAError(f"Failed to save enum (error {result})", error_type="SaveFailed")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"types"},
    )
    @session.require_open
    def list_enums(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> EnumListResult:
        """List all defined enums in the database.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """

        def _iter():
            limit_ord = ida_typeinf.get_ordinal_limit()
            for ordinal in range(1, limit_ord):
                if is_cancelled():
                    return
                tif = ida_typeinf.tinfo_t()
                if tif.get_numbered_type(None, ordinal) and tif.is_enum():
                    name = tif.get_type_name() or ""
                    edt = ida_typeinf.enum_type_data_t()
                    bitfield = tif.get_enum_details(edt) and edt.is_bf()
                    yield {
                        "name": name,
                        "member_count": tif.get_enum_nmembers(),
                        "bitfield": bool(bitfield),
                    }

        return EnumListResult(**paginate_iter(_iter(), offset, limit))

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"types"},
    )
    @session.require_open
    def create_enum(name: str, bitfield: bool = False) -> CreateEnumResult:
        """Create a new enum type.

        Args:
            name: Name for the enum.
            bitfield: If True, create as a bitfield enum (members are bitmasks).
        """
        existing = ida_typeinf.get_named_type_tid(name)
        if not is_bad_addr(existing):
            raise IDAError(f"Type already exists: {name}", error_type="AlreadyExists")

        edt = ida_typeinf.enum_type_data_t()
        tid = ida_typeinf.create_enum_type(name, edt, 0, ida_typeinf.no_sign, bitfield)
        if is_bad_addr(tid):
            raise IDAError(f"Failed to create enum: {name}", error_type="CreateFailed")

        return CreateEnumResult(name=name, bitfield=bitfield)

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"types"},
    )
    @session.require_open
    def delete_enum(name: str) -> DeleteEnumResult:
        """Delete an enum by name.

        Args:
            name: Name of the enum to delete.
        """
        tif, edt = _get_enum_tif(name)

        old_member_count = len(edt)
        ordinal = tif.get_ordinal()
        if not ida_typeinf.del_numbered_type(None, ordinal):
            raise IDAError(f"Failed to delete enum: {name}", error_type="DeleteFailed")
        return DeleteEnumResult(name=name, old_member_count=old_member_count)

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"types"},
    )
    @session.require_open
    def add_enum_member(enum_name: str, member_name: str, value: int) -> AddEnumMemberResult:
        """Add a member to an enum.

        Args:
            enum_name: Name of the enum.
            member_name: Name for the new member.
            value: Integer value for the member.
        """
        tif, edt = _get_enum_tif(enum_name)

        for i in range(len(edt)):
            if edt[i].name == member_name:
                raise IDAError(f"Member already exists: {member_name}", error_type="AlreadyExists")

        edt.push_back(ida_typeinf.edm_t(member_name, value))

        _save_enum(tif, edt, enum_name)
        return AddEnumMemberResult(enum=enum_name, member=member_name, value=value)

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"types"},
    )
    @session.require_open
    def get_enum_members(
        enum_name: str,
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> EnumMemberListResult:
        """List all members of an enum.

        Args:
            enum_name: Name of the enum.
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        _tif, edt = _get_enum_tif(enum_name)

        members = [{"name": edt[i].name or "", "value": edt[i].value} for i in range(len(edt))]
        return EnumMemberListResult(**paginate(members, offset, limit))

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"types"},
    )
    @session.require_open
    def rename_enum(old_name: str, new_name: str) -> RenameEnumResult:
        """Rename an enum.

        Args:
            old_name: Current name of the enum.
            new_name: New name for the enum.
        """
        tif, _edt = _get_enum_tif(old_name)

        result = tif.rename_type(new_name)
        if result != ida_typeinf.TERR_OK:
            raise IDAError(
                f"Failed to rename enum {old_name!r} to {new_name!r}", error_type="RenameFailed"
            )
        return RenameEnumResult(old_name=old_name, new_name=new_name)

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"types"},
    )
    @session.require_open
    def delete_enum_member(enum_name: str, value: int) -> DeleteEnumMemberResult:
        """Delete a member from an enum by its value.

        Args:
            enum_name: Name of the enum.
            value: Integer value of the member to delete.
        """
        tif, edt = _get_enum_tif(enum_name)

        idx = _find_member_by_value(edt, value, enum_name)

        member_name = edt[idx].name or ""
        # Python SWIG doesn't support C++ iterator arithmetic; rebuild without the member.
        new_edt = ida_typeinf.enum_type_data_t()
        for i in range(len(edt)):
            if i != idx:
                new_edt.push_back(edt[i])
        edt = new_edt

        _save_enum(tif, edt, enum_name)
        return DeleteEnumMemberResult(enum=enum_name, member=member_name, value=value)

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"types"},
    )
    @session.require_open
    def rename_enum_member(enum_name: str, value: int, new_name: str) -> RenameEnumMemberResult:
        """Rename an enum member.

        Args:
            enum_name: Name of the enum.
            value: Integer value of the member to rename.
            new_name: New name for the member.
        """
        tif, edt = _get_enum_tif(enum_name)

        idx = _find_member_by_value(edt, value, enum_name)

        old_name = edt[idx].name or ""
        edt[idx].name = new_name

        _save_enum(tif, edt, enum_name)
        return RenameEnumMemberResult(
            enum=enum_name, old_name=old_name, new_name=new_name, value=value
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"types"},
    )
    @session.require_open
    def set_enum_member_comment(
        enum_name: str, value: int, comment: str
    ) -> SetEnumMemberCommentResult:
        """Set a comment on an enum member.

        Args:
            enum_name: Name of the enum.
            value: Integer value of the member.
            comment: Comment text.
        """
        tif, edt = _get_enum_tif(enum_name)

        idx = _find_member_by_value(edt, value, enum_name)

        old_comment = edt[idx].cmt or ""
        edt[idx].cmt = comment

        _save_enum(tif, edt, enum_name)
        return SetEnumMemberCommentResult(
            enum=enum_name, value=value, old_comment=old_comment, comment=comment
        )
