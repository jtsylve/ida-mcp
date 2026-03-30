# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Enum creation and management tools."""

from __future__ import annotations

import ida_typeinf
from fastmcp import FastMCP

from ida_mcp.helpers import IDAError, is_bad_addr, paginate, paginate_iter
from ida_mcp.session import session


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
    @mcp.tool()
    @session.require_open
    def list_enums(offset: int = 0, limit: int = 100) -> dict:
        """List all defined enums in the database.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """

        def _iter():
            limit_ord = ida_typeinf.get_ordinal_limit()
            for ordinal in range(1, limit_ord):
                tif = ida_typeinf.tinfo_t()
                if tif.get_numbered_type(None, ordinal) and tif.is_enum():
                    name = tif.get_type_name() or ""
                    yield {
                        "ordinal": ordinal,
                        "name": name,
                        "member_count": tif.get_enum_nmembers(),
                    }

        return paginate_iter(_iter(), offset, limit)

    @mcp.tool()
    @session.require_open
    def create_enum(name: str, bitfield: bool = False) -> dict:
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

        return {"name": name, "bitfield": bitfield}

    @mcp.tool()
    @session.require_open
    def delete_enum(name: str) -> dict:
        """Delete an enum by name.

        Args:
            name: Name of the enum to delete.
        """
        tif, edt = _get_enum_tif(name)

        old_member_count = len(edt)
        ordinal = tif.get_ordinal()
        if not ida_typeinf.del_numbered_type(None, ordinal):
            raise IDAError(f"Failed to delete enum: {name}", error_type="DeleteFailed")
        return {"name": name, "old_member_count": old_member_count}

    @mcp.tool()
    @session.require_open
    def add_enum_member(enum_name: str, member_name: str, value: int) -> dict:
        """Add a member to an enum.

        Args:
            enum_name: Name of the enum.
            member_name: Name for the new member.
            value: Integer value for the member.
        """
        tif, edt = _get_enum_tif(enum_name)

        # Check for duplicate name
        for i in range(len(edt)):
            if edt[i].name == member_name:
                raise IDAError(f"Member already exists: {member_name}", error_type="AlreadyExists")

        edt.push_back(ida_typeinf.edm_t(member_name, value))

        _save_enum(tif, edt, enum_name)
        return {"enum": enum_name, "member": member_name, "value": value}

    @mcp.tool()
    @session.require_open
    def get_enum_members(enum_name: str, offset: int = 0, limit: int = 100) -> dict:
        """List all members of an enum.

        Args:
            enum_name: Name of the enum.
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        _tif, edt = _get_enum_tif(enum_name)

        members = [{"name": edt[i].name or "", "value": edt[i].value} for i in range(len(edt))]
        return paginate(members, offset, limit)

    @mcp.tool()
    @session.require_open
    def rename_enum(old_name: str, new_name: str) -> dict:
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
        return {"old_name": old_name, "new_name": new_name}

    @mcp.tool()
    @session.require_open
    def delete_enum_member(enum_name: str, value: int) -> dict:
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
        return {"enum": enum_name, "member": member_name, "value": value}

    @mcp.tool()
    @session.require_open
    def rename_enum_member(enum_name: str, value: int, new_name: str) -> dict:
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
        return {
            "enum": enum_name,
            "old_name": old_name,
            "new_name": new_name,
            "value": value,
        }

    @mcp.tool()
    @session.require_open
    def set_enum_member_comment(enum_name: str, value: int, comment: str) -> dict:
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
        return {
            "enum": enum_name,
            "value": value,
            "old_comment": old_comment,
            "comment": comment,
        }
