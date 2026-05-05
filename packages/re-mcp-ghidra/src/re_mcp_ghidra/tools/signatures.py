# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Function ID and data type archive tools (Ghidra equivalents of FLIRT/TIL)."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import ANNO_MUTATE, ANNO_READ_ONLY
from re_mcp_ghidra.session import session


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

        Note: Full FID analysis requires the FID databases to be
        pre-configured in Ghidra's installation. The headless/pyghidra
        API has limited FID support.

        Args:
            fid_name: Optional FID database name to apply (empty for all
                available databases).
        """
        try:
            from ghidra.feature.fid.service import FidService  # noqa: PLC0415
        except ImportError:
            raise GhidraError(
                "Function ID plugin is not available in this Ghidra installation.",
                error_type="NotAvailable",
            ) from None

        try:
            from ghidra.util.task import TaskMonitor  # noqa: PLC0415

            program = session.program
            fid_svc = FidService()
            language = program.getLanguage()

            query_svc = fid_svc.openFidQueryService(language, False)
            if query_svc is None:
                raise GhidraError(
                    "No Function ID databases are available for this architecture. "
                    "FID databases must be installed in Ghidra's FID directory.",
                    error_type="NotAvailable",
                )

            tx_id = program.startTransaction("Apply Function ID")
            try:
                fid_svc.processProgram(program, query_svc, 10.0, TaskMonitor.DUMMY)
                program.endTransaction(tx_id, True)
            except Exception as e:
                program.endTransaction(tx_id, False)
                raise GhidraError(
                    f"Function ID analysis failed: {e}",
                    error_type="AnalysisFailed",
                ) from e
            finally:
                query_svc.close()
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
        own_count = dtm.getDataTypeCount(True)

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
