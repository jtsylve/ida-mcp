# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Structure creation and modification tools."""

from __future__ import annotations

import idautils
import idc
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
    paginate_iter,
    parse_type,
    resolve_struct,
)
from ida_mcp.models import PaginatedResult
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class StructSummary(BaseModel):
    """Brief structure info."""

    name: str = Field(description="Structure name.")
    id: int = Field(description="Structure ID.")
    size: int = Field(description="Structure size in bytes.")
    member_count: int = Field(description="Number of members.")
    is_union: bool = Field(description="Whether this is a union.")


class StructListResult(PaginatedResult[StructSummary]):
    """Paginated list of structures."""

    items: list[StructSummary] = Field(description="Page of structures.")


class StructMember(BaseModel):
    """Structure member details."""

    offset: int = Field(description="Member offset in bytes.")
    name: str = Field(description="Member name.")
    size: int = Field(description="Member size in bytes.")


class StructDetailResult(BaseModel):
    """Detailed structure information."""

    name: str = Field(description="Structure name.")
    id: int = Field(description="Structure ID.")
    size: int = Field(description="Structure size in bytes.")
    member_count: int = Field(description="Number of members.")
    members: list[StructMember] = Field(description="Structure members.")


class CreateStructResult(BaseModel):
    """Result of creating a structure."""

    name: str = Field(description="Structure name.")
    id: int = Field(description="Structure ID.")
    is_union: bool = Field(description="Whether this is a union.")


class DeleteStructResult(BaseModel):
    """Result of deleting a structure."""

    name: str = Field(description="Structure name.")
    old_size: int = Field(description="Previous structure size.")
    old_member_count: int = Field(description="Previous member count.")


class AddStructMemberResult(BaseModel):
    """Result of adding a structure member."""

    struct: str = Field(description="Structure name.")
    member: str = Field(description="Member name.")
    offset: int = Field(description="Member offset.")
    size: int = Field(description="Member size.")


class RenameStructMemberResult(BaseModel):
    """Result of renaming a structure member."""

    struct: str = Field(description="Structure name.")
    old_name: str = Field(description="Previous member name.")
    new_name: str = Field(description="New member name.")


class DeleteStructMemberResult(BaseModel):
    """Result of deleting a structure member."""

    struct: str = Field(description="Structure name.")
    member: str = Field(description="Deleted member name.")
    old_size: int = Field(description="Previous member size.")


class RetypeStructMemberResult(BaseModel):
    """Result of retyping a structure member."""

    struct: str = Field(description="Structure name.")
    member: str = Field(description="Member name.")
    old_type: str = Field(description="Previous type.")
    type: str = Field(description="New type.")


class SetStructMemberCommentResult(BaseModel):
    """Result of setting a structure member comment."""

    struct: str = Field(description="Structure name.")
    member: str = Field(description="Member name.")
    old_comment: str = Field(description="Previous comment.")
    comment: str = Field(description="New comment.")
    repeatable: bool = Field(description="Whether the comment is repeatable.")


def _resolve_member_offset(sid: int, member_name: str) -> int:
    """Find a struct member by name.  Raises :class:`IDAError` if not found."""
    offset = idc.get_member_offset(sid, member_name)
    if offset == -1:
        raise IDAError(f"Member not found: {member_name}", error_type="NotFound")
    return offset


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"types"},
    )
    @session.require_open
    def list_structures(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> StructListResult:
        """List all defined structures/structs in the database.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """

        def _iter():
            for _idx, sid, name in idautils.Structs():
                yield {
                    "name": name,
                    "id": sid,
                    "size": idc.get_struc_size(sid),
                    "member_count": idc.get_member_qty(sid),
                    "is_union": idc.is_union(sid),
                }

        return StructListResult(**paginate_iter(_iter(), offset, limit))

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"types"},
    )
    @session.require_open
    def get_structure(name: str) -> StructDetailResult:
        """Get detailed information about a structure including all members.

        Args:
            name: Name of the structure.
        """
        sid = resolve_struct(name)

        members = []
        for member_offset, member_name, member_size in idautils.StructMembers(sid):
            members.append(
                {
                    "offset": member_offset,
                    "name": member_name,
                    "size": member_size,
                }
            )

        return StructDetailResult(
            name=name,
            id=sid,
            size=idc.get_struc_size(sid),
            member_count=len(members),
            members=members,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"types"},
    )
    @session.require_open
    def create_structure(name: str, is_union: bool = False) -> CreateStructResult:
        """Create a new structure or union.

        Args:
            name: Name for the new structure.
            is_union: If True, create a union instead of a struct.
        """
        sid = idc.get_struc_id(name)
        if not is_bad_addr(sid):
            raise IDAError(f"Structure already exists: {name}", error_type="AlreadyExists")

        sid = idc.add_struc(idc.BADADDR, name, is_union)
        if is_bad_addr(sid):
            raise IDAError(f"Failed to create structure: {name}", error_type="CreateFailed")

        return CreateStructResult(name=name, id=sid, is_union=is_union)

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"types"},
    )
    @session.require_open
    def delete_structure(name: str) -> DeleteStructResult:
        """Delete a structure by name.

        Args:
            name: Name of the structure to delete.
        """
        sid = resolve_struct(name)

        old_size = idc.get_struc_size(sid)
        old_member_count = idc.get_member_qty(sid)
        if not idc.del_struc(sid):
            raise IDAError(f"Failed to delete structure: {name}", error_type="DeleteFailed")
        return DeleteStructResult(name=name, old_size=old_size, old_member_count=old_member_count)

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"types"},
    )
    @session.require_open
    def add_struct_member(
        struct_name: str,
        member_name: str,
        offset: int = -1,
        size: int = 1,
        type_str: str = "",
    ) -> AddStructMemberResult:
        """Add a member to an existing structure.

        Args:
            struct_name: Name of the structure.
            member_name: Name for the new member.
            offset: Byte offset (-1 to append at end).
            size: Size in bytes (1, 2, 4, or 8).
            type_str: Optional C type string for the member.
        """
        sid = resolve_struct(struct_name)

        flag_map = {1: idc.FF_BYTE, 2: idc.FF_WORD, 4: idc.FF_DWORD, 8: idc.FF_QWORD}
        flag = flag_map.get(size)
        if flag is None:
            raise IDAError(
                f"Invalid member size: {size}. Must be 1, 2, 4, or 8.", error_type="InvalidArgument"
            )
        flags = flag | idc.FF_DATA

        if offset == -1:
            offset = idc.get_struc_size(sid) or 0

        err_code = idc.add_struc_member(sid, member_name, offset, flags, -1, size)
        if err_code != 0:
            raise IDAError(f"Failed to add member (error {err_code})", error_type="AddMemberFailed")

        if type_str:
            mid = idc.get_member_id(sid, offset)
            if mid != -1 and not idc.SetType(mid, type_str):
                raise IDAError(
                    f"Member added but failed to set type {type_str!r}", error_type="SetTypeFailed"
                )

        return AddStructMemberResult(
            struct=struct_name, member=member_name, offset=offset, size=size
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"types"},
    )
    @session.require_open
    def rename_struct_member(
        struct_name: str, old_name: str, new_name: str
    ) -> RenameStructMemberResult:
        """Rename a member of a structure.

        Args:
            struct_name: Name of the structure.
            old_name: Current name of the member.
            new_name: New name for the member.
        """
        sid = resolve_struct(struct_name)

        member_offset = _resolve_member_offset(sid, old_name)

        if not idc.set_member_name(sid, member_offset, new_name):
            raise IDAError(
                f"Failed to rename member {old_name!r} to {new_name!r}", error_type="RenameFailed"
            )
        return RenameStructMemberResult(struct=struct_name, old_name=old_name, new_name=new_name)

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"types"},
    )
    @session.require_open
    def delete_struct_member(struct_name: str, member_name: str) -> DeleteStructMemberResult:
        """Delete a member from a structure.

        Args:
            struct_name: Name of the structure.
            member_name: Name of the member to delete.
        """
        sid = resolve_struct(struct_name)

        member_offset = _resolve_member_offset(sid, member_name)

        old_size = idc.get_member_size(sid, member_offset) or 0
        if not idc.del_struc_member(sid, member_offset):
            raise IDAError(f"Failed to delete member {member_name!r}", error_type="DeleteFailed")
        return DeleteStructMemberResult(struct=struct_name, member=member_name, old_size=old_size)

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"types"},
    )
    @session.require_open
    def retype_struct_member(
        struct_name: str, member_name: str, type_str: str
    ) -> RetypeStructMemberResult:
        """Change the type of a structure member.

        Args:
            struct_name: Name of the structure.
            member_name: Name of the member to retype.
            type_str: C type string (e.g. "int", "char *", "struct foo").
        """
        sid = resolve_struct(struct_name)

        member_offset = _resolve_member_offset(sid, member_name)

        mid = idc.get_member_id(sid, member_offset)
        if mid == -1:
            raise IDAError(f"Cannot resolve member ID for {member_name!r}", error_type="NotFound")

        old_type = idc.get_type(mid) or ""

        tinfo = parse_type(type_str)

        if not idc.SetType(mid, type_str):
            raise IDAError(f"Failed to set type on {member_name!r}", error_type="RetypeFailed")

        return RetypeStructMemberResult(
            struct=struct_name, member=member_name, old_type=old_type, type=str(tinfo)
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"types"},
    )
    @session.require_open
    def set_struct_member_comment(
        struct_name: str, member_name: str, comment: str, repeatable: bool = False
    ) -> SetStructMemberCommentResult:
        """Set a comment on a structure member.

        Args:
            struct_name: Name of the structure.
            member_name: Name of the member.
            comment: Comment text.
            repeatable: If True, set as repeatable comment.
        """
        sid = resolve_struct(struct_name)

        member_offset = _resolve_member_offset(sid, member_name)

        old_comment = idc.get_member_cmt(sid, member_offset, repeatable) or ""
        if not idc.set_member_cmt(sid, member_offset, comment, repeatable):
            raise IDAError(
                f"Failed to set comment on member {member_name!r}", error_type="SetCommentFailed"
            )
        return SetStructMemberCommentResult(
            struct=struct_name,
            member=member_name,
            old_comment=old_comment,
            comment=comment,
            repeatable=repeatable,
        )
