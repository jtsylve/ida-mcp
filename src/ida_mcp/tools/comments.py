# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Comment and annotation tools."""

from __future__ import annotations

import ida_funcs
import idc
from fastmcp import FastMCP

from ida_mcp.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    IDAError,
    format_address,
    resolve_address,
    resolve_function,
)
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"modification"},
    )
    @session.require_open
    def get_comment(
        address: Address,
    ) -> dict:
        """Get comments at an address (both regular and repeatable).

        Args:
            address: Address or symbol name.
        """
        ea = resolve_address(address)

        return {
            "address": format_address(ea),
            "comment": idc.get_cmt(ea, False) or "",
            "repeatable_comment": idc.get_cmt(ea, True) or "",
        }

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def set_comment(
        address: Address,
        comment: str,
        repeatable: bool = False,
    ) -> dict:
        """Set a comment at an address.

        Args:
            address: Address or symbol name.
            comment: Comment text to set.
            repeatable: If True, set as a repeatable comment.
        """
        ea = resolve_address(address)

        old_comment = idc.get_cmt(ea, repeatable) or ""
        if not idc.set_cmt(ea, comment, repeatable):
            raise IDAError(
                f"Failed to set comment at {format_address(ea)}", error_type="SetCommentFailed"
            )
        return {
            "address": format_address(ea),
            "old_comment": old_comment,
            "comment": comment,
            "repeatable": repeatable,
        }

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"modification"},
    )
    @session.require_open
    def get_function_comment(
        address: Address,
    ) -> dict:
        """Get comments on a function (both regular and repeatable).

        Args:
            address: Address or name of the function.
        """
        func = resolve_function(address)

        return {
            "address": format_address(func.start_ea),
            "comment": ida_funcs.get_func_cmt(func, False) or "",
            "repeatable_comment": ida_funcs.get_func_cmt(func, True) or "",
        }

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def append_comment(
        address: Address,
        comment: str,
        repeatable: bool = False,
        separator: str = "\n",
    ) -> dict:
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
            return {
                "address": format_address(ea),
                "old_comment": existing,
                "comment": existing,
                "repeatable": repeatable,
                "appended": False,
            }

        new_comment = f"{existing}{separator}{comment}" if existing else comment
        if not idc.set_cmt(ea, new_comment, repeatable):
            raise IDAError(
                f"Failed to set comment at {format_address(ea)}", error_type="SetCommentFailed"
            )
        return {
            "address": format_address(ea),
            "old_comment": existing,
            "comment": new_comment,
            "repeatable": repeatable,
            "appended": True,
        }

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def set_function_comment(
        address: Address,
        comment: str,
        repeatable: bool = True,
    ) -> dict:
        """Set a comment on a function.

        Args:
            address: Address or name of the function.
            comment: Comment text to set.
            repeatable: If True, set as a repeatable comment (default True).
        """
        func = resolve_function(address)

        old_comment = ida_funcs.get_func_cmt(func, repeatable) or ""
        if not ida_funcs.set_func_cmt(func, comment, repeatable):
            raise IDAError(
                f"Failed to set function comment at {format_address(func.start_ea)}",
                error_type="SetCommentFailed",
            )
        return {
            "address": format_address(func.start_ea),
            "old_comment": old_comment,
            "comment": comment,
            "repeatable": repeatable,
        }
