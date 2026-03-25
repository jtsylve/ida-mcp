# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Comment and annotation tools."""

from __future__ import annotations

import ida_funcs
import idc
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import format_address, resolve_address, resolve_function
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def get_comment(address: str) -> dict:
        """Get comments at an address (both regular and repeatable).

        Args:
            address: Address or symbol name.
        """
        ea, err = resolve_address(address)
        if err:
            return err

        return {
            "address": format_address(ea),
            "comment": idc.get_cmt(ea, False) or "",
            "repeatable_comment": idc.get_cmt(ea, True) or "",
        }

    @mcp.tool()
    @session.require_open
    def set_comment(address: str, comment: str, repeatable: bool = False) -> dict:
        """Set a comment at an address.

        Args:
            address: Address or symbol name.
            comment: Comment text to set.
            repeatable: If True, set as a repeatable comment.
        """
        ea, err = resolve_address(address)
        if err:
            return err

        old_comment = idc.get_cmt(ea, repeatable) or ""
        if not idc.set_cmt(ea, comment, repeatable):
            return {
                "error": f"Failed to set comment at {format_address(ea)}",
                "error_type": "SetCommentFailed",
            }
        return {
            "address": format_address(ea),
            "old_comment": old_comment,
            "comment": comment,
            "repeatable": repeatable,
        }

    @mcp.tool()
    @session.require_open
    def get_function_comment(address: str) -> dict:
        """Get comments on a function (both regular and repeatable).

        Args:
            address: Address or name of the function.
        """
        func, err = resolve_function(address)
        if err:
            return err

        return {
            "address": format_address(func.start_ea),
            "comment": ida_funcs.get_func_cmt(func, False) or "",
            "repeatable_comment": ida_funcs.get_func_cmt(func, True) or "",
        }

    @mcp.tool()
    @session.require_open
    def set_function_comment(address: str, comment: str, repeatable: bool = True) -> dict:
        """Set a comment on a function.

        Args:
            address: Address or name of the function.
            comment: Comment text to set.
            repeatable: If True, set as a repeatable comment (default True).
        """
        func, err = resolve_function(address)
        if err:
            return err

        old_comment = ida_funcs.get_func_cmt(func, repeatable) or ""
        if not ida_funcs.set_func_cmt(func, comment, repeatable):
            return {
                "error": f"Failed to set function comment at {format_address(func.start_ea)}",
                "error_type": "SetCommentFailed",
            }
        return {
            "address": format_address(func.start_ea),
            "old_comment": old_comment,
            "comment": comment,
            "repeatable": repeatable,
        }
