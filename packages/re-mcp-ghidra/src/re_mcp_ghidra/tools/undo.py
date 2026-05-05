# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Undo and redo operations."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import ANNO_DESTRUCTIVE
from re_mcp_ghidra.session import session


class UndoRedoResult(BaseModel):
    """Result of an undo/redo operation."""

    action: str = Field(description="Action performed.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"utility"})
    @session.require_open
    def undo() -> UndoRedoResult:
        """Undo the last database modification."""
        session._end_open_transactions()
        program = session.program
        if not program.canUndo():
            raise GhidraError("Nothing to undo", error_type="UndoFailed")
        try:
            program.undo()
        except Exception as e:
            raise GhidraError(f"Undo failed: {e}", error_type="UndoFailed") from e
        return UndoRedoResult(action="undo")

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"utility"})
    @session.require_open
    def redo() -> UndoRedoResult:
        """Redo the last undone database modification."""
        session._end_open_transactions()
        program = session.program
        if not program.canRedo():
            raise GhidraError("Nothing to redo", error_type="RedoFailed")
        try:
            program.redo()
        except Exception as e:
            raise GhidraError(f"Redo failed: {e}", error_type="RedoFailed") from e
        return UndoRedoResult(action="redo")
