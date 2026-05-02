# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Undo and redo operations."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ghidra_mcp.exceptions import GhidraError
from ghidra_mcp.helpers import ANNO_DESTRUCTIVE
from ghidra_mcp.session import session


class UndoRedoResult(BaseModel):
    """Result of an undo/redo operation."""

    action: str = Field(description="Action performed.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"utility"})
    @session.require_open
    def undo() -> UndoRedoResult:
        """Undo the last database modification."""
        program = session.program
        try:
            program.undo()
        except Exception as e:
            raise GhidraError(f"Undo failed: {e}", error_type="UndoFailed") from e
        return UndoRedoResult(action="undo")

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"utility"})
    @session.require_open
    def redo() -> UndoRedoResult:
        """Redo the last undone database modification."""
        program = session.program
        try:
            program.redo()
        except Exception as e:
            raise GhidraError(f"Redo failed: {e}", error_type="RedoFailed") from e
        return UndoRedoResult(action="redo")
