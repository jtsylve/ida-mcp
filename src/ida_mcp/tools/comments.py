# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Comment and annotation tools."""

from __future__ import annotations

import ida_funcs
import idc
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_MUTATE,
    ANNO_MUTATE_NON_IDEMPOTENT,
    ANNO_READ_ONLY,
    Address,
    IDAError,
    format_address,
    resolve_address,
    resolve_function,
)
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class GetCommentResult(BaseModel):
    """Comments at an address."""

    address: str = Field(description="Address (hex).")
    comment: str = Field(description="Regular comment.")
    repeatable_comment: str = Field(description="Repeatable comment.")


class SetCommentResult(BaseModel):
    """Result of setting a comment."""

    address: str = Field(description="Address (hex).")
    old_comment: str = Field(description="Previous comment.")
    comment: str = Field(description="New comment.")
    repeatable: bool = Field(description="Whether the comment is repeatable.")


class AppendCommentResult(BaseModel):
    """Result of appending to a comment."""

    address: str = Field(description="Address (hex).")
    old_comment: str = Field(description="Previous comment.")
    comment: str = Field(description="New combined comment.")
    repeatable: bool = Field(description="Whether the comment is repeatable.")
    appended: bool = Field(description="Whether text was appended (vs set fresh).")


class GetFunctionCommentResult(BaseModel):
    """Function comments."""

    address: str = Field(description="Function address (hex).")
    comment: str = Field(description="Regular function comment.")
    repeatable_comment: str = Field(description="Repeatable function comment.")


class SetFunctionCommentResult(BaseModel):
    """Result of setting a function comment."""

    address: str = Field(description="Function address (hex).")
    old_comment: str = Field(description="Previous comment.")
    comment: str = Field(description="New comment.")
    repeatable: bool = Field(description="Whether the comment is repeatable.")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"comments"},
    )
    @session.require_open
    def get_comment(
        address: Address,
    ) -> GetCommentResult:
        """Return the regular and repeatable disassembly comments at an address.

        For pseudocode comments (Hex-Rays), use get_decompiler_comments instead.
        For function-level comments, use get_function_comment.

        Args:
            address: Address or symbol name.
        """
        ea = resolve_address(address)

        return GetCommentResult(
            address=format_address(ea),
            comment=idc.get_cmt(ea, False) or "",
            repeatable_comment=idc.get_cmt(ea, True) or "",
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def set_comment(
        address: Address,
        comment: str,
        repeatable: bool = False,
    ) -> SetCommentResult:
        """Set a disassembly comment at an address.

        Repeatable comments propagate to all xref sites. To annotate a pseudocode
        line instead, use set_decompiler_comment. To annotate an entire function,
        use set_function_comment. To append without overwriting, use append_comment.

        Args:
            address: Address or symbol name.
            comment: Comment text to set. Pass empty string to delete.
            repeatable: If True, set as a repeatable comment (propagates to xref sites).
        """
        ea = resolve_address(address)

        old_comment = idc.get_cmt(ea, repeatable) or ""
        if not idc.set_cmt(ea, comment, repeatable):
            raise IDAError(
                f"Failed to set comment at {format_address(ea)}", error_type="SetCommentFailed"
            )
        return SetCommentResult(
            address=format_address(ea),
            old_comment=old_comment,
            comment=comment,
            repeatable=repeatable,
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"comments"},
    )
    @session.require_open
    def get_function_comment(
        address: Address,
    ) -> GetFunctionCommentResult:
        """Return the regular and repeatable comments attached to a function definition.

        These are function-level comments (shown at the function header), distinct from
        per-instruction comments returned by get_comment.

        Args:
            address: Address or name of the function.
        """
        func = resolve_function(address)

        return GetFunctionCommentResult(
            address=format_address(func.start_ea),
            comment=ida_funcs.get_func_cmt(func, False) or "",
            repeatable_comment=ida_funcs.get_func_cmt(func, True) or "",
        )

    @mcp.tool(
        annotations=ANNO_MUTATE_NON_IDEMPOTENT,
        tags={"modification"},
    )
    @session.require_open
    def append_comment(
        address: Address,
        comment: str,
        repeatable: bool = False,
        separator: str = "\n",
    ) -> AppendCommentResult:
        """Append text to an existing comment without overwriting it.

        If the comment already contains the exact text, it is not duplicated.
        If no existing comment is present, this behaves like set_comment.

        Args:
            address: Address or symbol name.
            comment: Comment text to append.
            repeatable: If True, append to the repeatable comment.
            separator: Separator between existing and new text (default newline).
        """
        ea = resolve_address(address)

        existing = idc.get_cmt(ea, repeatable) or ""

        if comment in existing:
            return AppendCommentResult(
                address=format_address(ea),
                old_comment=existing,
                comment=existing,
                repeatable=repeatable,
                appended=False,
            )

        new_comment = f"{existing}{separator}{comment}" if existing else comment
        if not idc.set_cmt(ea, new_comment, repeatable):
            raise IDAError(
                f"Failed to set comment at {format_address(ea)}", error_type="SetCommentFailed"
            )
        return AppendCommentResult(
            address=format_address(ea),
            old_comment=existing,
            comment=new_comment,
            repeatable=repeatable,
            appended=True,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def set_function_comment(
        address: Address,
        comment: str,
        repeatable: bool = True,
    ) -> SetFunctionCommentResult:
        """Set a comment on a function definition (shown at the function header).

        Defaults to repeatable=True so the comment appears at every call site.
        Use set_comment for per-instruction annotations.

        Args:
            address: Address or name of the function.
            comment: Comment text to set. Pass empty string to delete.
            repeatable: If True, the comment appears at call sites too (default True).
        """
        func = resolve_function(address)

        old_comment = ida_funcs.get_func_cmt(func, repeatable) or ""
        if not ida_funcs.set_func_cmt(func, comment, repeatable):
            raise IDAError(
                f"Failed to set function comment at {format_address(func.start_ea)}",
                error_type="SetCommentFailed",
            )
        return SetFunctionCommentResult(
            address=format_address(func.start_ea),
            old_comment=old_comment,
            comment=comment,
            repeatable=repeatable,
        )
