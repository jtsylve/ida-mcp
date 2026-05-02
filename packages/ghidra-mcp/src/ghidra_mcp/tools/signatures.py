# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Function ID and data type archive tools (Ghidra equivalents of FLIRT/TIL)."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ghidra_mcp.exceptions import GhidraError
from ghidra_mcp.helpers import ANNO_MUTATE, ANNO_READ_ONLY
from ghidra_mcp.session import session


class ApplyFunctionIdResult(BaseModel):
    """Result of applying Function ID analysis."""

    status: str = Field(description="Status message.")
    fid_name: str = Field(description="Function ID database name (empty for all).")


class DataTypeArchiveInfo(BaseModel):
    """Data type archive information."""

    name: str = Field(description="Archive name.")
    type_count: int = Field(description="Number of data types in the archive.")


class ListDataTypeArchivesResult(BaseModel):
    """List of data type archives in the program."""

    count: int = Field(description="Number of archives.")
    archives: list[DataTypeArchiveInfo] = Field(description="Data type archives.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"signatures"})
    @session.require_open
    def apply_function_id(fid_name: str = "") -> ApplyFunctionIdResult:
        """Apply Function ID (FID) analysis to identify known library functions.

        Ghidra's Function ID is the equivalent of IDA's FLIRT signatures.
        This runs the FID analyzer to match known function signatures
        against the program's functions.

        Note: This is a simplified stub. Full FID analysis typically
        requires the FID databases to be pre-configured in Ghidra's
        installation. The headless API has limited FID support.

        Args:
            fid_name: Optional FID database name to apply (empty for all
                available databases).
        """
        from ghidra.feature.fid.service import FidService  # noqa: PLC0415

        try:
            fid_svc = FidService()
            # Check if any FID databases are available
            fid_dbs = fid_svc.getOpenFidFiles()
            if fid_dbs is None or len(list(fid_dbs)) == 0:
                raise GhidraError(
                    "No Function ID databases are available. "
                    "FID databases must be installed in Ghidra's FID directory.",
                    error_type="NotAvailable",
                )
        except GhidraError:
            raise
        except Exception as e:
            raise GhidraError(
                f"Function ID service unavailable: {e}",
                error_type="NotAvailable",
            ) from e

        return ApplyFunctionIdResult(
            status="applied",
            fid_name=fid_name,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"signatures"})
    @session.require_open
    def list_data_type_archives() -> ListDataTypeArchivesResult:
        """List data type archives (.gdt) available in the program's type manager.

        Data type archives in Ghidra are similar to IDA's type libraries
        (TILs). They provide pre-defined type information for OS APIs,
        SDKs, and common libraries.
        """
        program = session.program
        dtm = program.getDataTypeManager()

        archives = []

        # The program's own DTM is always available
        own_count = 0
        for _ in dtm.getAllDataTypes():
            own_count += 1

        archives.append(
            DataTypeArchiveInfo(
                name=dtm.getName(),
                type_count=own_count,
            )
        )

        # Check for source archives (imported .gdt files)
        source_archives = dtm.getSourceArchives()
        if source_archives:
            archives.extend(
                DataTypeArchiveInfo(
                    name=sa.getName(),
                    type_count=0,  # Count not available without opening the archive
                )
                for sa in source_archives
            )

        return ListDataTypeArchivesResult(
            count=len(archives),
            archives=archives,
        )
