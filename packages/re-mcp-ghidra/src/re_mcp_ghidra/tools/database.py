# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Database information and lifecycle tools."""

from __future__ import annotations

import os

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import ANNO_MUTATE, ANNO_READ_ONLY, format_address
from re_mcp_ghidra.session import session


class OpenDatabaseResult(BaseModel):
    status: str = Field(description="Operation status.")
    path: str = Field(description="Path to the opened file.")
    pid: int = Field(description="Worker process ID.")
    processor: str = Field(description="Processor/language ID.")
    bitness: int = Field(description="Address size in bits.")
    file_type: str = Field(description="File format.")
    function_count: int = Field(description="Number of functions.")
    segment_count: int = Field(description="Number of memory segments.")
    capabilities: dict[str, bool] = Field(description="Available capabilities.")
    warnings: list[str] = Field(default_factory=list, description="Any warnings.")


class DatabaseInfoResult(BaseModel):
    file_path: str = Field(description="Path to the binary.")
    file_type: str = Field(description="File format.")
    processor: str = Field(description="Processor/language.")
    compiler_spec: str = Field(description="Compiler specification.")
    bitness: int = Field(description="Address size in bits.")
    endian: str = Field(description="Byte order (big/little).")
    min_address: str = Field(description="Minimum address (hex).")
    max_address: str = Field(description="Maximum address (hex).")
    image_base: str = Field(description="Image base address (hex).")
    function_count: int = Field(description="Number of functions.")
    segment_count: int = Field(description="Number of memory blocks.")
    entry_point_count: int = Field(description="Number of entry points.")
    capabilities: dict[str, bool] = Field(description="Available capabilities.")


class SaveDatabaseResult(BaseModel):
    """Result of saving a database."""

    status: str = Field(description="Status message.")
    path: str = Field(description="Path to the saved database file.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"database"})
    def open_database(
        file_path: str,
        run_auto_analysis: bool = False,
        force_new: bool = False,
        language: str = "",
        compiler_spec: str = "",
    ) -> OpenDatabaseResult:
        """Open a binary for analysis. Called by the worker on supervisor's behalf."""
        result = session.open(
            file_path,
            run_auto_analysis=run_auto_analysis,
            force_new=force_new,
            language=language,
            compiler_spec=compiler_spec,
        )

        program = session.program
        lang = program.getLanguage()
        mem = program.getMemory()

        return OpenDatabaseResult(
            status="ok",
            path=result["path"],
            pid=os.getpid(),
            processor=str(lang.getLanguageID()),
            bitness=lang.getLanguageDescription().getSize(),
            file_type=program.getExecutableFormat() or "unknown",
            function_count=program.getFunctionManager().getFunctionCount(),
            segment_count=len(list(mem.getBlocks())),
            capabilities=session.capabilities,
            warnings=result.get("warnings", []),
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"database"})
    @session.require_open
    def close_database(save: bool = True) -> dict:
        """Close the current database."""
        return session.close(save=save)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"database"})
    @session.require_open
    def get_database_info() -> DatabaseInfoResult:
        """Get metadata about the currently open database."""
        program = session.program
        lang = program.getLanguage()
        mem = program.getMemory()
        func_mgr = program.getFunctionManager()
        sym_table = program.getSymbolTable()

        blocks = list(mem.getBlocks())
        min_addr = mem.getMinAddress()
        max_addr = mem.getMaxAddress()

        entry_count = sum(1 for s in sym_table.getAllSymbols(True) if s.isExternalEntryPoint())

        return DatabaseInfoResult(
            file_path=program.getExecutablePath() or session.current_path or "",
            file_type=program.getExecutableFormat() or "unknown",
            processor=str(lang.getLanguageID()),
            compiler_spec=str(program.getCompilerSpec().getCompilerSpecID()),
            bitness=lang.getLanguageDescription().getSize(),
            endian="big" if lang.isBigEndian() else "little",
            min_address=format_address(min_addr.getOffset()) if min_addr else "0x0",
            max_address=format_address(max_addr.getOffset()) if max_addr else "0x0",
            image_base=format_address(program.getImageBase().getOffset()),
            function_count=func_mgr.getFunctionCount(),
            segment_count=len(blocks),
            entry_point_count=entry_count,
            capabilities=session.capabilities,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"database"})
    @session.require_open
    def save_database(outfile: str = "", flags: int = -1) -> SaveDatabaseResult:
        """Save the current database to disk.

        Args:
            outfile: Not supported for Ghidra (raises an error if provided).
            flags: Ignored (IDA-specific).
        """
        if outfile:
            raise GhidraError(
                "Ghidra does not support saving to an alternate path.",
                error_type="UnsupportedOperation",
            )
        session.save()
        return SaveDatabaseResult(status="saved", path=session.current_path)
