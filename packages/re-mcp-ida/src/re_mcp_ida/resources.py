# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""MCP resources — read-only context endpoints.

Most database state is mutable (functions get renamed, structs get new
members, xrefs change after reanalysis) so tools are the primary
interface for querying live data.  Resources are reserved for
genuinely static or aggregate data that benefits from caching:

- **Imports / Exports / Entry points** — baked into the binary, stable.
- **Statistics** — aggregate snapshot, no tool equivalent.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator

import ida_entry
import ida_funcs
import ida_ida
import ida_nalt
import ida_segment
import idautils
from fastmcp import FastMCP
from fastmcp.exceptions import ResourceError
from re_mcp.exceptions import BackendError

from re_mcp_ida.helpers import (
    build_strlist,
    compile_filter,
    format_address,
    is_cancelled,
    paginate_iter,
)
from re_mcp_ida.session import session

# Resource-specific annotation preset (not used by tools).
ANNO_RESOURCE: dict[str, bool] = {
    "readOnlyHint": True,
    "idempotentHint": True,
}


def _json(obj: object) -> str:
    """Serialize to compact JSON."""
    return json.dumps(obj, separators=(",", ":"))


def _check_db() -> None:
    """Raise ResourceError if no database is open."""
    if not session.is_open():
        raise ResourceError("No database is open")


# ---------------------------------------------------------------------------
# Collection iterators
# ---------------------------------------------------------------------------


def _iter_entrypoints(filt: re.Pattern | None = None) -> Iterator[dict]:
    for i in range(ida_entry.get_entry_qty()):
        if is_cancelled():
            return
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal) or ""
        if filt and not filt.search(name):
            continue
        yield {
            "ordinal": ordinal,
            "address": format_address(ea),
            "name": name,
        }


def _iter_imports(filt: re.Pattern | None = None) -> Iterable[dict]:
    # Returns a list, not a generator — IDA's enum_import_names uses a
    # callback API that cannot yield lazily.
    all_imports: list[dict] = []
    current_module = ""

    def _import_cb(ea, name, ordinal):
        sym = name or ""
        if filt and not filt.search(sym) and not filt.search(current_module):
            return True
        all_imports.append(
            {
                "module": current_module,
                "address": format_address(ea),
                "name": sym,
                "ordinal": ordinal,
            }
        )
        return True

    for i in range(ida_nalt.get_import_module_qty()):
        if is_cancelled():
            break
        current_module = ida_nalt.get_import_module_name(i) or ""
        ida_nalt.enum_import_names(i, _import_cb)

    return all_imports


def _iter_exports(filt: re.Pattern | None = None) -> Iterator[dict]:
    for index, ordinal, ea, name in idautils.Entries():
        if is_cancelled():
            return
        sym = name or ""
        if filt and not filt.search(sym):
            continue
        yield {
            "index": index,
            "ordinal": ordinal,
            "address": format_address(ea),
            "name": sym,
        }


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register(mcp: FastMCP):
    # ------------------------------------------------------------------
    # Shared resource factories
    # ------------------------------------------------------------------
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

    # ==================================================================
    # Static binary data — imports, exports, entry points
    # ==================================================================

    @mcp.resource(
        "ida://idb/entrypoints{?offset,limit}",
        description="All entry points with ordinal, address, name",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"core"},
        version=1,
    )
    def idb_entrypoints(offset: int = 0, limit: int = 0) -> str:
        return _base_resource(_iter_entrypoints, "entries", offset, limit)

    @mcp.resource(
        "ida://idb/entrypoints/search/{pattern}{?offset,limit}",
        description="Search entry points by name regex pattern",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"core", "search"},
        version=1,
    )
    def idb_entrypoints_search(pattern: str, offset: int = 0, limit: int = 0) -> str:
        return _search_resource(pattern, _iter_entrypoints, "entries", offset, limit)

    @mcp.resource(
        "ida://idb/imports{?offset,limit}",
        description="All imports grouped by module",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"core"},
        version=1,
    )
    def idb_imports(offset: int = 0, limit: int = 0) -> str:
        return _base_resource(_iter_imports, "imports", offset, limit)

    @mcp.resource(
        "ida://idb/imports/search/{pattern}{?offset,limit}",
        description="Search imports by module or symbol name regex pattern",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"core", "search"},
        version=1,
    )
    def idb_imports_search(pattern: str, offset: int = 0, limit: int = 0) -> str:
        return _search_resource(pattern, _iter_imports, "imports", offset, limit)

    @mcp.resource(
        "ida://idb/exports{?offset,limit}",
        description="All exported symbols with ordinals",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"core"},
        version=1,
    )
    def idb_exports(offset: int = 0, limit: int = 0) -> str:
        return _base_resource(_iter_exports, "exports", offset, limit)

    @mcp.resource(
        "ida://idb/exports/search/{pattern}{?offset,limit}",
        description="Search exports by name regex pattern",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"core", "search"},
        version=1,
    )
    def idb_exports_search(pattern: str, offset: int = 0, limit: int = 0) -> str:
        return _search_resource(pattern, _iter_exports, "exports", offset, limit)

    # ==================================================================
    # Aggregate snapshot
    # ==================================================================

    @mcp.resource(
        "ida://idb/statistics",
        description="Summary counts: functions, strings, segments, names, coverage",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"browsable"},
        version=1,
    )
    def idb_statistics() -> str:
        _check_db()
        func_count = ida_funcs.get_func_qty()
        seg_count = ida_segment.get_segm_qty()
        entry_count = ida_entry.get_entry_qty()

        string_count = build_strlist()

        name_count = sum(1 for _ in idautils.Names())

        # Code coverage: sum of function sizes vs total address space
        min_ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()
        total_range = max_ea - min_ea if max_ea > min_ea else 1
        code_bytes = 0
        for i in range(func_count):
            func = ida_funcs.getn_func(i)
            if func:
                code_bytes += func.size()
        coverage_pct = round(100.0 * code_bytes / total_range, 2) if total_range > 0 else 0.0

        return _json(
            {
                "function_count": func_count,
                "segment_count": seg_count,
                "entry_point_count": entry_count,
                "string_count": string_count,
                "name_count": name_count,
                "code_coverage_percent": coverage_pct,
                "code_bytes": code_bytes,
                "total_address_range": total_range,
            }
        )
