# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Analysis control tools — reanalyze, wait for analysis, problem listing."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    Limit,
    Offset,
    format_address,
    paginate_iter,
    resolve_address,
)
from re_mcp_ghidra.session import session


class ReanalyzeRangeResult(BaseModel):
    """Result of reanalyzing a range."""

    start: str = Field(description="Range start address (hex).")
    end: str = Field(description="Range end address (hex).")
    status: str = Field(description="Status message.")


class AnalysisCompleteResult(BaseModel):
    """Result of waiting for analysis to complete, with a database summary."""

    status: str = Field(description="Status: 'analysis_complete'.")
    function_count: int = Field(description="Number of functions after analysis.")
    segment_count: int = Field(description="Number of memory blocks.")
    entry_point_count: int = Field(description="Number of entry points.")
    min_address: str = Field(description="Minimum address (hex).")
    max_address: str = Field(description="Maximum address (hex).")


class AnalysisProblem(BaseModel):
    """An analysis problem (bookmark of type ERROR or WARNING)."""

    address: str = Field(description="Problem address (hex).")
    type: str = Field(description="Bookmark type (ERROR or WARNING).")
    category: str = Field(description="Bookmark category.")
    comment: str = Field(description="Bookmark comment.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"analysis"})
    @session.require_open
    def reanalyze_range(
        start_address: Address,
        end_address: Address,
    ) -> ReanalyzeRangeResult:
        """Reanalyze an address range by running Ghidra auto-analysis on it.

        Call after patching bytes, changing types, or creating new code
        to force Ghidra to re-analyze the affected range.

        Args:
            start_address: Start of the range.
            end_address: End of the range (exclusive).
        """
        from ghidra.app.cmd.disassemble import DisassembleCommand  # noqa: PLC0415
        from ghidra.base.project import GhidraProject  # noqa: PLC0415
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        program = session.program
        start = resolve_address(start_address)
        end = resolve_address(end_address)

        # Clear and re-disassemble the range, then run full analysis
        from ghidra.program.model.address import AddressSet  # noqa: PLC0415

        addr_set = AddressSet(start, end)

        tx_id = program.startTransaction("Reanalyze range")
        try:
            cmd = DisassembleCommand(addr_set, addr_set)
            cmd.applyTo(program, TaskMonitor.DUMMY)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to reanalyze range: {e}", error_type="AnalysisFailed") from e

        GhidraProject.analyze(program)

        return ReanalyzeRangeResult(
            start=format_address(start.getOffset()),
            end=format_address(end.getOffset()),
            status="analysis_complete",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"analysis"})
    @session.require_open
    def wait_for_analysis() -> AnalysisCompleteResult:
        """Run Ghidra's auto-analysis and wait for it to complete.

        Call this after opening a database or making changes (patches, type
        applications) to ensure the program is fully analyzed before querying.
        Returns a summary of database statistics after analysis finishes.
        """
        from ghidra.base.project import GhidraProject  # noqa: PLC0415

        program = session.program

        GhidraProject.analyze(program)

        func_mgr = program.getFunctionManager()
        memory = program.getMemory()
        sym_table = program.getSymbolTable()

        func_count = func_mgr.getFunctionCount()
        block_count = memory.getBlocks().__len__()

        # Count entry points via the symbol table
        from ghidra.program.model.symbol import SymbolType  # noqa: PLC0415

        entry_count = 0
        sym_iter = sym_table.getAllSymbols(True)
        for sym in sym_iter:
            if sym.getSymbolType() == SymbolType.FUNCTION and sym.isExternalEntryPoint():
                entry_count += 1

        min_addr = program.getMinAddress()
        max_addr = program.getMaxAddress()

        return AnalysisCompleteResult(
            status="analysis_complete",
            function_count=func_count,
            segment_count=block_count,
            entry_point_count=entry_count,
            min_address=format_address(min_addr.getOffset()) if min_addr else "0x0",
            max_address=format_address(max_addr.getOffset()) if max_addr else "0x0",
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def get_analysis_problems(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List analysis problems found by Ghidra (ERROR and WARNING bookmarks).

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        program = session.program
        bookmark_mgr = program.getBookmarkManager()

        def _gen():
            for bm_type in ("Error", "Warning"):
                bm_iter = bookmark_mgr.getBookmarksIterator(bm_type)
                while bm_iter.hasNext():
                    bm = bm_iter.next()
                    yield AnalysisProblem(
                        address=format_address(bm.getAddress().getOffset()),
                        type=bm.getTypeString(),
                        category=bm.getCategory() or "",
                        comment=bm.getComment() or "",
                    ).model_dump()

        return paginate_iter(_gen(), offset, limit)
