# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Undo and redo operations."""

from __future__ import annotations

import ida_undo
from fastmcp import FastMCP

from ida_mcp.helpers import IDAError
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def undo() -> dict:
        """Undo the last database modification.

        Reverts the most recent change to the IDA database.
        """
        if not ida_undo.perform_undo():
            raise IDAError("Nothing to undo", error_type="UndoFailed")
        return {"action": "undo"}

    @mcp.tool()
    @session.require_open
    def redo() -> dict:
        """Redo the last undone database modification.

        Re-applies the most recently undone change.
        """
        if not ida_undo.perform_redo():
            raise IDAError("Nothing to redo", error_type="RedoFailed")
        return {"action": "redo"}
