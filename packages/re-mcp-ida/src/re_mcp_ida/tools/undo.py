# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Undo and redo operations."""

from __future__ import annotations

import ida_undo
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ida.helpers import ANNO_DESTRUCTIVE, IDAError
from re_mcp_ida.session import session


class UndoRedoResult(BaseModel):
    """Result of an undo/redo operation."""

    action: str = Field(description="Action performed.")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"utility"},
    )
    @session.require_open
    def undo() -> UndoRedoResult:
        """Undo the last database modification."""
        if not ida_undo.perform_undo():
            raise IDAError("Nothing to undo", error_type="UndoFailed")
        return UndoRedoResult(action="undo")

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"utility"},
    )
    @session.require_open
    def redo() -> UndoRedoResult:
        """Redo the last undone database modification."""
        if not ida_undo.perform_redo():
            raise IDAError("Nothing to redo", error_type="RedoFailed")
        return UndoRedoResult(action="redo")
