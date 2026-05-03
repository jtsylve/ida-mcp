# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Import, export, and entry point enumeration tools."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.helpers import (
    ANNO_READ_ONLY,
    Limit,
    Offset,
    format_address,
    paginate_iter,
)
from re_mcp_ghidra.session import session


class ImportItem(BaseModel):
    """An imported symbol."""

    module: str = Field(description="External library/module name.")
    address: str = Field(description="Import thunk address (hex).")
    name: str = Field(description="Import name.")


class ExportItem(BaseModel):
    """An exported symbol."""

    address: str = Field(description="Export address (hex).")
    name: str = Field(description="Export name.")


class EntryPointItem(BaseModel):
    """An entry point."""

    address: str = Field(description="Entry point address (hex).")
    name: str = Field(description="Entry point name.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"metadata"})
    @session.require_open
    def get_imports(
        module_filter: str = "",
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List all imported functions/symbols.

        Use module_filter to narrow results to a specific library (e.g.
        "kernel32", "libc"). After finding an import address, use
        get_xrefs_to to find all code that calls it.

        Args:
            module_filter: Optional substring to filter module/library names (case-insensitive).
            offset: Pagination offset.
            limit: Maximum number of import entries.
        """
        program = session.program
        sym_table = program.getSymbolTable()
        filter_lower = module_filter.lower()

        def _gen():
            ext_mgr = program.getExternalManager()
            for lib_name in ext_mgr.getExternalLibraryNames():
                if filter_lower and filter_lower not in lib_name.lower():
                    continue
                sym_iter = sym_table.getExternalSymbols()
                while sym_iter.hasNext():
                    sym = sym_iter.next()
                    ext_loc = sym.getExternalLocation()
                    if ext_loc is None:
                        continue
                    parent_lib = ext_loc.getLibraryName()
                    if parent_lib != lib_name:
                        continue
                    addr = sym.getAddress()
                    yield ImportItem(
                        module=lib_name,
                        address=format_address(addr.getOffset()),
                        name=sym.getName(),
                    ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"metadata"})
    @session.require_open
    def get_exports(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List all exported symbols.

        Good starting point for analyzing shared libraries or DLLs --
        exports are the public API. Use get_xrefs_to on an export address
        to find internal callers.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        program = session.program
        sym_table = program.getSymbolTable()

        def _gen():
            sym_iter = sym_table.getAllSymbols(True)
            for sym in sym_iter:
                if sym.isExternalEntryPoint():
                    addr = sym.getAddress()
                    if addr.isExternalAddress():
                        continue
                    yield ExportItem(
                        address=format_address(addr.getOffset()),
                        name=sym.getName(),
                    ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"metadata"})
    @session.require_open
    def get_entry_points(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List binary entry points (main/start/exports).

        Entry points are addresses where execution may begin. For shared
        libraries, get_exports is more complete (includes all exported symbols).

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        program = session.program
        sym_table = program.getSymbolTable()

        def _gen():
            sym_iter = sym_table.getAllSymbols(True)
            for sym in sym_iter:
                if sym.isExternalEntryPoint():
                    addr = sym.getAddress()
                    if addr.isExternalAddress():
                        continue
                    yield EntryPointItem(
                        address=format_address(addr.getOffset()),
                        name=sym.getName(),
                    ).model_dump()

        return paginate_iter(_gen(), offset, limit)
