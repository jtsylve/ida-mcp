# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Undo and redo operations."""

from __future__ import annotations

import contextlib

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import ANNO_DESTRUCTIVE
from re_mcp_ghidra.session import session


class UndoRedoResult(BaseModel):
    """Result of an undo/redo operation."""

    action: str = Field(description="Action performed.")


def _end_open_transactions(program) -> None:
    """End any open transactions so undo/redo can proceed.

    Ghidra cannot undo/redo while a transaction is active.  The pyhidra
    environment (or prior tool calls whose endTransaction was swallowed
    by the JVM) may leave a transaction open.  We commit it here so the
    undo/redo history becomes accessible.
    """
    tx_info = program.getCurrentTransactionInfo()
    if tx_info is not None:
        with contextlib.suppress(Exception):
            program.endTransaction(int(tx_info.getID()), True)


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"utility"})
    @session.require_open
    def undo() -> UndoRedoResult:
        """Undo the last database modification."""
        program = session.program
        _end_open_transactions(program)
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
        program = session.program
        _end_open_transactions(program)
        if not program.canRedo():
            raise GhidraError("Nothing to redo", error_type="RedoFailed")
        try:
            program.redo()
        except Exception as e:
            raise GhidraError(f"Redo failed: {e}", error_type="RedoFailed") from e
        return UndoRedoResult(action="redo")
