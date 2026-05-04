# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Database snapshot management tools.

Ghidra uses project-level versioning rather than IDA-style in-database
snapshots. ``take_snapshot`` saves the program to the project, and
``list_snapshots`` returns an empty list (Ghidra does not expose an
in-memory snapshot tree like IDA's ``snapshot_t``).
"""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import ANNO_MUTATE, ANNO_READ_ONLY
from re_mcp_ghidra.session import session


class TakeSnapshotResult(BaseModel):
    """Result of taking a snapshot (saving the program)."""

    description: str = Field(description="Snapshot description.")
    status: str = Field(description="Status message.")


class SnapshotInfo(BaseModel):
    """Snapshot information (stub)."""

    id: str = Field(description="Snapshot ID.")
    description: str = Field(description="Snapshot description.")


class ListSnapshotsResult(BaseModel):
    """List of database snapshots."""

    snapshots: list[SnapshotInfo] = Field(description="Available snapshots.")
    count: int = Field(description="Number of snapshots.")
    note: str = Field(
        default="Ghidra uses project-level versioning. Use the Ghidra project manager for full version history.",
        description="Implementation note.",
    )


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"metadata", "snapshots"})
    @session.require_open
    def take_snapshot(description: str = "") -> TakeSnapshotResult:
        """Save the current program state to the Ghidra project.

        Ghidra does not have IDA-style in-database snapshots. This tool
        saves the program to the project file, which acts as a checkpoint.

        Args:
            description: Optional description (informational only).
        """
        try:
            session.save()
        except GhidraError:
            raise
        except Exception as e:
            raise GhidraError(f"Failed to save: {e}", error_type="SaveFailed") from e

        return TakeSnapshotResult(
            description=description or "Program saved",
            status="saved",
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"metadata", "snapshots"})
    @session.require_open
    def list_snapshots() -> ListSnapshotsResult:
        """List database snapshots.

        Ghidra uses project-level file versioning rather than in-database
        snapshots. This tool returns an empty list. Use the Ghidra project
        manager for version history.
        """
        return ListSnapshotsResult(snapshots=[], count=0)
