# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Cross-reference manipulation tools — add and delete xrefs."""

from __future__ import annotations

import ida_xref
from fastmcp import FastMCP

from ida_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    Address,
    IDAError,
    format_address,
    resolve_address,
)
from ida_mcp.models import DeleteXrefResult, XrefManipResult
from ida_mcp.session import session

_CODE_XREF_TYPES = {
    "fl_CF": ida_xref.fl_CF,
    "fl_CN": ida_xref.fl_CN,
    "fl_JF": ida_xref.fl_JF,
    "fl_JN": ida_xref.fl_JN,
    "fl_F": ida_xref.fl_F,
}

_DATA_XREF_TYPES = {
    "dr_R": ida_xref.dr_R,
    "dr_W": ida_xref.dr_W,
    "dr_O": ida_xref.dr_O,
    "dr_I": ida_xref.dr_I,
    "dr_T": ida_xref.dr_T,
    "dr_S": ida_xref.dr_S,
}


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"xrefs"},
    )
    @session.require_open
    def add_code_xref(
        from_address: Address,
        to_address: Address,
        xref_type: str = "fl_CF",
    ) -> XrefManipResult:
        """Add a code cross-reference between two addresses.

        Args:
            from_address: Source address of the reference.
            to_address: Target address of the reference.
            xref_type: Reference type — "fl_CF" (call far), "fl_CN" (call near),
                "fl_JF" (jump far), "fl_JN" (jump near), "fl_F" (ordinary flow).
        """
        frm = resolve_address(from_address)
        to = resolve_address(to_address)

        cref = _CODE_XREF_TYPES.get(xref_type)
        if cref is None:
            raise IDAError(
                f"Invalid xref type: {xref_type!r}",
                error_type="InvalidArgument",
                valid_types=list(_CODE_XREF_TYPES),
            )

        if not ida_xref.add_cref(frm, to, cref):
            raise IDAError(
                f"Failed to add code xref from {format_address(frm)} to {format_address(to)}",
                error_type="AddXrefFailed",
            )
        return XrefManipResult(
            **{"from": format_address(frm), "to": format_address(to), "type": xref_type}
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"xrefs"},
    )
    @session.require_open
    def add_data_xref(
        from_address: Address,
        to_address: Address,
        xref_type: str = "dr_R",
    ) -> XrefManipResult:
        """Add a data cross-reference between two addresses.

        Args:
            from_address: Source address of the reference.
            to_address: Target address of the reference.
            xref_type: Reference type — "dr_R" (read), "dr_W" (write),
                "dr_O" (offset), "dr_I" (informational), "dr_T" (text),
                "dr_S" (stack).
        """
        frm = resolve_address(from_address)
        to = resolve_address(to_address)

        dref = _DATA_XREF_TYPES.get(xref_type)
        if dref is None:
            raise IDAError(
                f"Invalid xref type: {xref_type!r}",
                error_type="InvalidArgument",
                valid_types=list(_DATA_XREF_TYPES),
            )

        if not ida_xref.add_dref(frm, to, dref):
            raise IDAError(
                f"Failed to add data xref from {format_address(frm)} to {format_address(to)}",
                error_type="AddXrefFailed",
            )
        return XrefManipResult(
            **{"from": format_address(frm), "to": format_address(to), "type": xref_type}
        )

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"xrefs"},
    )
    @session.require_open
    def delete_code_xref(
        from_address: Address,
        to_address: Address,
        expand: bool = False,
    ) -> DeleteXrefResult:
        """Delete a code cross-reference.

        Args:
            from_address: Source address of the reference to remove.
            to_address: Target address of the reference to remove.
            expand: If True, the function at the target may be truncated.
        """
        frm = resolve_address(from_address)
        to = resolve_address(to_address)

        ida_xref.del_cref(frm, to, expand)
        return DeleteXrefResult(**{"from": format_address(frm), "to": format_address(to)})

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"xrefs"},
    )
    @session.require_open
    def delete_data_xref(
        from_address: Address,
        to_address: Address,
    ) -> DeleteXrefResult:
        """Delete a data cross-reference.

        Args:
            from_address: Source address of the reference to remove.
            to_address: Target address of the reference to remove.
        """
        frm = resolve_address(from_address)
        to = resolve_address(to_address)

        ida_xref.del_dref(frm, to)
        return DeleteXrefResult(**{"from": format_address(frm), "to": format_address(to)})
