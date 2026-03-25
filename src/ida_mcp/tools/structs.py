# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Structure creation and modification tools."""

from __future__ import annotations

import idautils
import idc
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import is_bad_addr, paginate_iter, parse_type, resolve_struct
from ida_mcp.session import session


def _resolve_member_offset(sid: int, member_name: str) -> tuple[int, dict | None]:
    """Find a struct member by name, returning (byte_offset, error_dict)."""
    offset = idc.get_member_offset(sid, member_name)
    if offset == -1:
        return -1, {"error": f"Member not found: {member_name}", "error_type": "NotFound"}
    return offset, None


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def list_structures(offset: int = 0, limit: int = 100) -> dict:
        """List all defined structures/structs in the database.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results (max 500).
        """

        def _iter():
            for idx, sid, name in idautils.Structs():
                yield {
                    "index": idx,
                    "id": sid,
                    "name": name,
                    "size": idc.get_struc_size(sid),
                }

        return paginate_iter(_iter(), offset, limit)

    @mcp.tool()
    @session.require_open
    def get_structure(name: str) -> dict:
        """Get detailed information about a structure including all members.

        Args:
            name: Name of the structure.
        """
        sid, err = resolve_struct(name)
        if err:
            return err

        members = []
        for member_offset, member_name, member_size in idautils.StructMembers(sid):
            members.append(
                {
                    "offset": member_offset,
                    "name": member_name,
                    "size": member_size,
                }
            )

        return {
            "name": name,
            "id": sid,
            "size": idc.get_struc_size(sid),
            "member_count": len(members),
            "members": members,
        }

    @mcp.tool()
    @session.require_open
    def create_structure(name: str, is_union: bool = False) -> dict:
        """Create a new structure or union.

        Args:
            name: Name for the new structure.
            is_union: If True, create a union instead of a struct.
        """
        sid = idc.get_struc_id(name)
        if not is_bad_addr(sid):
            return {
                "error": f"Structure already exists: {name}",
                "error_type": "AlreadyExists",
            }

        sid = idc.add_struc(idc.BADADDR, name, is_union)
        if is_bad_addr(sid):
            return {
                "error": f"Failed to create structure: {name}",
                "error_type": "CreateFailed",
            }

        return {
            "name": name,
            "id": sid,
            "is_union": is_union,
        }

    @mcp.tool()
    @session.require_open
    def delete_structure(name: str) -> dict:
        """Delete a structure by name.

        Args:
            name: Name of the structure to delete.
        """
        sid, err = resolve_struct(name)
        if err:
            return err

        old_size = idc.get_struc_size(sid)
        old_member_count = idc.get_member_qty(sid)
        if not idc.del_struc(sid):
            return {
                "error": f"Failed to delete structure: {name}",
                "error_type": "DeleteFailed",
            }
        return {"name": name, "old_size": old_size, "old_member_count": old_member_count}

    @mcp.tool()
    @session.require_open
    def add_struct_member(
        struct_name: str,
        member_name: str,
        offset: int = -1,
        size: int = 1,
        type_str: str = "",
    ) -> dict:
        """Add a member to an existing structure.

        Args:
            struct_name: Name of the structure.
            member_name: Name for the new member.
            offset: Byte offset (-1 to append at end).
            size: Size in bytes (1, 2, 4, or 8).
            type_str: Optional C type string for the member.
        """
        sid, err = resolve_struct(struct_name)
        if err:
            return err

        # Map size to IDA data flags
        flag_map = {1: idc.FF_BYTE, 2: idc.FF_WORD, 4: idc.FF_DWORD, 8: idc.FF_QWORD}
        flag = flag_map.get(size)
        if flag is None:
            return {
                "error": f"Invalid member size: {size}. Must be 1, 2, 4, or 8.",
                "error_type": "InvalidArgument",
            }
        flags = flag | idc.FF_DATA

        if offset == -1:
            offset = idc.get_struc_size(sid) or 0

        err_code = idc.add_struc_member(sid, member_name, offset, flags, -1, size)
        if err_code != 0:
            return {
                "error": f"Failed to add member (error {err_code})",
                "error_type": "AddMemberFailed",
            }

        # Optionally set the type
        if type_str:
            mid = idc.get_member_id(sid, offset)
            if mid != -1 and not idc.SetType(mid, type_str):
                return {
                    "error": f"Member added but failed to set type {type_str!r}",
                    "error_type": "SetTypeFailed",
                }

        return {
            "struct": struct_name,
            "member": member_name,
            "offset": offset,
            "size": size,
        }

    @mcp.tool()
    @session.require_open
    def rename_struct_member(struct_name: str, old_name: str, new_name: str) -> dict:
        """Rename a member of a structure.

        Args:
            struct_name: Name of the structure.
            old_name: Current name of the member.
            new_name: New name for the member.
        """
        sid, err = resolve_struct(struct_name)
        if err:
            return err

        member_offset, err = _resolve_member_offset(sid, old_name)
        if err:
            return err

        if not idc.set_member_name(sid, member_offset, new_name):
            return {
                "error": f"Failed to rename member {old_name!r} to {new_name!r}",
                "error_type": "RenameFailed",
            }
        return {
            "struct": struct_name,
            "old_name": old_name,
            "new_name": new_name,
        }

    @mcp.tool()
    @session.require_open
    def delete_struct_member(struct_name: str, member_name: str) -> dict:
        """Delete a member from a structure.

        Args:
            struct_name: Name of the structure.
            member_name: Name of the member to delete.
        """
        sid, err = resolve_struct(struct_name)
        if err:
            return err

        member_offset, err = _resolve_member_offset(sid, member_name)
        if err:
            return err

        old_size = idc.get_member_size(sid, member_offset) or 0
        if not idc.del_struc_member(sid, member_offset):
            return {
                "error": f"Failed to delete member {member_name!r}",
                "error_type": "DeleteFailed",
            }
        return {
            "struct": struct_name,
            "member": member_name,
            "old_size": old_size,
        }

    @mcp.tool()
    @session.require_open
    def retype_struct_member(struct_name: str, member_name: str, type_str: str) -> dict:
        """Change the type of a structure member.

        Args:
            struct_name: Name of the structure.
            member_name: Name of the member to retype.
            type_str: C type string (e.g. "int", "char *", "struct foo").
        """
        sid, err = resolve_struct(struct_name)
        if err:
            return err

        member_offset, err = _resolve_member_offset(sid, member_name)
        if err:
            return err

        mid = idc.get_member_id(sid, member_offset)
        if mid == -1:
            return {
                "error": f"Cannot resolve member ID for {member_name!r}",
                "error_type": "NotFound",
            }

        old_type = idc.get_type(mid) or ""

        # Validate the type string first
        tinfo, err = parse_type(type_str)
        if err:
            return err

        if not idc.SetType(mid, type_str):
            return {
                "error": f"Failed to set type on {member_name!r}",
                "error_type": "RetypeFailed",
            }

        return {
            "struct": struct_name,
            "member": member_name,
            "old_type": old_type,
            "type": str(tinfo),
        }

    @mcp.tool()
    @session.require_open
    def set_struct_member_comment(
        struct_name: str, member_name: str, comment: str, repeatable: bool = False
    ) -> dict:
        """Set a comment on a structure member.

        Args:
            struct_name: Name of the structure.
            member_name: Name of the member.
            comment: Comment text.
            repeatable: If True, set as repeatable comment.
        """
        sid, err = resolve_struct(struct_name)
        if err:
            return err

        member_offset, err = _resolve_member_offset(sid, member_name)
        if err:
            return err

        old_comment = idc.get_member_cmt(sid, member_offset, repeatable) or ""
        if not idc.set_member_cmt(sid, member_offset, comment, repeatable):
            return {
                "error": f"Failed to set comment on member {member_name!r}",
                "error_type": "SetCommentFailed",
            }
        return {
            "struct": struct_name,
            "member": member_name,
            "old_comment": old_comment,
            "comment": comment,
            "repeatable": repeatable,
        }
