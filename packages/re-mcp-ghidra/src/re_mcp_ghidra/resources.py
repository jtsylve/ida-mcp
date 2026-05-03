# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""MCP resources — read-only context endpoints for Ghidra."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator

from fastmcp import FastMCP
from fastmcp.exceptions import ResourceError
from re_mcp.exceptions import BackendError

from re_mcp_ghidra.helpers import (
    compile_filter,
    format_address,
    paginate_iter,
)
from re_mcp_ghidra.session import session

ANNO_RESOURCE: dict[str, bool] = {
    "readOnlyHint": True,
    "idempotentHint": True,
}


def _json(obj: object) -> str:
    return json.dumps(obj, separators=(",", ":"))


def _check_db() -> None:
    if not session.is_open():
        raise ResourceError("No database is open")


def _iter_entrypoints(filt: re.Pattern | None = None) -> Iterator[dict]:
    program = session.program
    symbol_table = program.getSymbolTable()
    for sym in symbol_table.getAllSymbols(True):
        if sym.isExternalEntryPoint():
            name = sym.getName()
            if filt and not filt.search(name):
                continue
            yield {
                "address": format_address(sym.getAddress().getOffset()),
                "name": name,
            }


def _iter_imports(filt: re.Pattern | None = None) -> Iterator[dict]:
    program = session.program
    ext_mgr = program.getExternalManager()
    for lib_name in ext_mgr.getExternalLibraryNames():
        for ext_loc in ext_mgr.getExternalLocations(lib_name):
            name = ext_loc.getLabel()
            if filt and not filt.search(name) and not filt.search(lib_name):
                continue
            addr = ext_loc.getAddress()
            yield {
                "module": lib_name,
                "address": format_address(addr.getOffset()) if addr else "EXTERNAL",
                "name": name,
            }


def _iter_exports(filt: re.Pattern | None = None) -> Iterator[dict]:
    program = session.program
    symbol_table = program.getSymbolTable()
    for sym in symbol_table.getAllSymbols(True):
        if sym.isExternalEntryPoint() or sym.isGlobal():
            from ghidra.program.model.symbol import SymbolType  # noqa: PLC0415

            if sym.getSymbolType() == SymbolType.FUNCTION or sym.isExternalEntryPoint():
                name = sym.getName()
                if filt and not filt.search(name):
                    continue
                yield {
                    "address": format_address(sym.getAddress().getOffset()),
                    "name": name,
                }


def register(mcp: FastMCP):
    def _paginate_and_json(items: Iterable[dict], result_key: str, offset: int, limit: int) -> str:
        if offset < 0 or limit < 0:
            raise ResourceError(f"offset and limit must be non-negative (got {offset=}, {limit=})")
        if limit:
            page = paginate_iter(items, offset, limit)
            return _json(
                {
                    "total": page["total"],
                    "count": len(page["items"]),
                    "has_more": page["has_more"],
                    result_key: page["items"],
                }
            )
        all_items = list(items)
        total = len(all_items)
        if offset:
            all_items = all_items[offset:]
        return _json({"total": total, "count": len(all_items), result_key: all_items})

    def _base_resource(collector, result_key: str, offset: int = 0, limit: int = 0) -> str:
        _check_db()
        return _paginate_and_json(collector(), result_key, offset, limit)

    def _search_resource(
        pattern: str, collector, result_key: str, offset: int = 0, limit: int = 0
    ) -> str:
        _check_db()
        try:
            filt = compile_filter(pattern)
        except BackendError as exc:
            raise ResourceError(str(exc)) from exc
        return _paginate_and_json(collector(filt), result_key, offset, limit)

    @mcp.resource(
        "ghidra://db/entrypoints{?offset,limit}",
        description="All entry points with address and name",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"core"},
        version=1,
    )
    def db_entrypoints(offset: int = 0, limit: int = 0) -> str:
        return _base_resource(_iter_entrypoints, "entries", offset, limit)

    @mcp.resource(
        "ghidra://db/entrypoints/search/{pattern}{?offset,limit}",
        description="Search entry points by name regex pattern",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"core", "search"},
        version=1,
    )
    def db_entrypoints_search(pattern: str, offset: int = 0, limit: int = 0) -> str:
        return _search_resource(pattern, _iter_entrypoints, "entries", offset, limit)

    @mcp.resource(
        "ghidra://db/imports{?offset,limit}",
        description="All imports grouped by module",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"core"},
        version=1,
    )
    def db_imports(offset: int = 0, limit: int = 0) -> str:
        return _base_resource(_iter_imports, "imports", offset, limit)

    @mcp.resource(
        "ghidra://db/imports/search/{pattern}{?offset,limit}",
        description="Search imports by module or symbol name regex",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"core", "search"},
        version=1,
    )
    def db_imports_search(pattern: str, offset: int = 0, limit: int = 0) -> str:
        return _search_resource(pattern, _iter_imports, "imports", offset, limit)

    @mcp.resource(
        "ghidra://db/exports{?offset,limit}",
        description="All exported symbols",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"core"},
        version=1,
    )
    def db_exports(offset: int = 0, limit: int = 0) -> str:
        return _base_resource(_iter_exports, "exports", offset, limit)

    @mcp.resource(
        "ghidra://db/exports/search/{pattern}{?offset,limit}",
        description="Search exports by name regex",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"core", "search"},
        version=1,
    )
    def db_exports_search(pattern: str, offset: int = 0, limit: int = 0) -> str:
        return _search_resource(pattern, _iter_exports, "exports", offset, limit)

    @mcp.resource(
        "ghidra://db/statistics",
        description="Summary counts: functions, strings, segments, names, coverage",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"browsable"},
        version=1,
    )
    def db_statistics() -> str:
        _check_db()
        program = session.program
        func_mgr = program.getFunctionManager()
        mem = program.getMemory()
        sym_table = program.getSymbolTable()

        func_count = func_mgr.getFunctionCount()

        blocks = list(mem.getBlocks())
        seg_count = len(blocks)

        name_count = sym_table.getNumSymbols()

        # Entry points
        entry_count = sum(1 for s in sym_table.getAllSymbols(True) if s.isExternalEntryPoint())

        # Code coverage
        total_range = 0
        for block in blocks:
            total_range += block.getSize()
        code_bytes = 0
        func_iter = func_mgr.getFunctions(True)
        while func_iter.hasNext():
            func = func_iter.next()
            body = func.getBody()
            code_bytes += body.getNumAddresses()

        coverage_pct = round(100.0 * code_bytes / total_range, 2) if total_range > 0 else 0.0

        return _json(
            {
                "function_count": func_count,
                "segment_count": seg_count,
                "entry_point_count": entry_count,
                "name_count": name_count,
                "code_coverage_percent": coverage_pct,
                "code_bytes": code_bytes,
                "total_address_range": total_range,
            }
        )
