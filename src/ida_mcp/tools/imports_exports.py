# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Import, export, and entry point enumeration tools."""

from __future__ import annotations

import ida_entry
import ida_loader
import ida_nalt
import idautils
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    META_BATCH,
    Address,
    Limit,
    Offset,
    async_paginate_iter,
    format_address,
    paginate,
    resolve_address,
)
from ida_mcp.models import PaginatedResult
from ida_mcp.session import session


class ImportItem(BaseModel):
    """An imported symbol."""

    module: str = Field(description="Module name.")
    address: str = Field(description="Import address (hex).")
    name: str = Field(description="Import name.")
    ordinal: int = Field(description="Import ordinal.")


class ImportListResult(PaginatedResult[ImportItem]):
    """Paginated list of imports."""

    items: list[ImportItem] = Field(description="Page of imports.")


class ExportItem(BaseModel):
    """An exported symbol."""

    index: int = Field(description="Export index.")
    ordinal: int = Field(description="Export ordinal.")
    address: str = Field(description="Export address (hex).")
    name: str = Field(description="Export name.")


class ExportListResult(PaginatedResult[ExportItem]):
    """Paginated list of exports."""

    items: list[ExportItem] = Field(description="Page of exports.")


class EntryPointItem(BaseModel):
    """An entry point."""

    ordinal: int = Field(description="Entry point ordinal.")
    address: str = Field(description="Entry point address (hex).")
    name: str = Field(description="Entry point name.")


class EntryPointListResult(PaginatedResult[EntryPointItem]):
    """Paginated list of entry points."""

    items: list[EntryPointItem] = Field(description="Page of entry points.")


class SetImportNameResult(BaseModel):
    """Result of setting an import name."""

    modnode: int = Field(description="Module node index.")
    address: str = Field(description="Import address (hex).")
    name: str = Field(description="New import name.")


class SetImportOrdinalResult(BaseModel):
    """Result of setting an import ordinal."""

    modnode: int = Field(description="Module node index.")
    address: str = Field(description="Import address (hex).")
    ordinal: int = Field(description="New import ordinal.")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"metadata"},
        meta=META_BATCH,
    )
    @session.require_open
    def get_imports(
        module_filter: str = "",
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> ImportListResult:
        """List all imported functions grouped by module.

        Use module_filter to narrow results to a specific library (e.g.
        "kernel32", "libc"). After finding an import address, use
        get_xrefs_to to find all code that calls it.

        Args:
            module_filter: Optional substring to filter module names (case-insensitive).
            offset: Pagination offset (applied to the flat list of imports).
            limit: Maximum number of import entries.
        """
        all_imports = []

        def _import_cb(ea, name, ordinal):
            all_imports.append(
                {
                    "module": current_module,
                    "address": format_address(ea),
                    "name": name or "",
                    "ordinal": ordinal,
                }
            )
            return True  # continue enumeration

        filter_lower = module_filter.lower()
        for i in range(ida_nalt.get_import_module_qty()):
            current_module = ida_nalt.get_import_module_name(i) or ""
            if filter_lower and filter_lower not in current_module.lower():
                continue
            ida_nalt.enum_import_names(i, _import_cb)

        return ImportListResult(**paginate(all_imports, offset, limit))

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"metadata"},
        meta=META_BATCH,
    )
    @session.require_open
    async def get_exports(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> ExportListResult:
        """List all exported symbols.

        Good starting point for analyzing shared libraries or DLLs —
        exports are the public API. Use get_xrefs_to on an export address
        to find internal callers.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """

        def _iter():
            for index, ordinal, ea, name in idautils.Entries():
                yield {
                    "index": index,
                    "ordinal": ordinal,
                    "address": format_address(ea),
                    "name": name or "",
                }

        return ExportListResult(
            **await async_paginate_iter(_iter(), offset, limit, progress_label="Listing exports")
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"metadata"},
        meta=META_BATCH,
    )
    @session.require_open
    async def get_entry_points(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> EntryPointListResult:
        """List all entry points of the binary.

        Entry points are addresses where execution may begin — main, DllMain,
        WinMain, export stubs, etc. For shared libraries, get_exports is more
        complete (includes all exported symbols, not just entry points).

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """

        def _iter():
            for i in range(ida_entry.get_entry_qty()):
                ordinal = ida_entry.get_entry_ordinal(i)
                ea = ida_entry.get_entry(ordinal)
                name = ida_entry.get_entry_name(ordinal) or ""
                yield {
                    "ordinal": ordinal,
                    "address": format_address(ea),
                    "name": name,
                }

        return EntryPointListResult(
            **await async_paginate_iter(
                _iter(), offset, limit, progress_label="Listing entry points"
            )
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"metadata"},
    )
    @session.require_open
    def set_import_name(
        modnode: int,
        address: Address,
        name: str,
    ) -> SetImportNameResult:
        """Set the name of an import entry in IDA's import module table.

        Low-level IDA API for annotating import stubs. The modnode is an
        internal IDA module node index (0-based, from
        ida_nalt.get_import_module_qty()), not obtainable from get_imports.
        In most cases, rename_address or rename_function is sufficient to
        rename an import stub without needing the module node.

        Args:
            modnode: Module node index (0-based internal IDA identifier).
            address: Linear address of the import entry.
            name: Name to set for the import.
        """
        ea = resolve_address(address)
        ida_loader.set_import_name(modnode, ea, name)
        return SetImportNameResult(modnode=modnode, address=format_address(ea), name=name)

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"metadata"},
    )
    @session.require_open
    def set_import_ordinal(
        modnode: int,
        address: Address,
        ordinal: int,
    ) -> SetImportOrdinalResult:
        """Set the ordinal of an import entry in IDA's import module table.

        Low-level IDA API. The modnode is an internal IDA module node index
        (0-based), not directly obtainable from get_imports output. See
        set_import_name for details.

        Args:
            modnode: Module node index (0-based internal IDA identifier).
            address: Linear address of the import entry.
            ordinal: Ordinal number to set.
        """
        ea = resolve_address(address)
        ida_loader.set_import_ordinal(modnode, ea, ordinal)
        return SetImportOrdinalResult(modnode=modnode, address=format_address(ea), ordinal=ordinal)
