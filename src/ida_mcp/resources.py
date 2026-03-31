# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""MCP resources — read-only, cacheable context endpoints.

Resources provide structured data about the open database without
consuming tool calls.  They are organized in four tiers:

- **Tier 1 — Core Context:** database metadata, paths, processor,
  segments, entry points, imports, exports.
- **Tier 2 — Structural Reference:** types, structs, enums,
  FLIRT signatures, type libraries.
- **Tier 3 — Browsable Collections:** strings, functions, names,
  bookmarks, statistics.
- **Tier 4 — Per-Entity:** parameterized resources for individual
  functions, stack frames, exceptions, variables, and cross-references.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator

import ida_entry
import ida_funcs
import ida_ida
import ida_idp
import ida_loader
import ida_nalt
import ida_segment
import ida_strlist
import ida_tryblks
import ida_typeinf
import idautils
import idc
from fastmcp import FastMCP
from fastmcp.exceptions import ResourceError

from ida_mcp.helpers import (
    META_DECOMPILER,
    IDAError,
    compile_filter,
    decode_string,
    decompile_at,
    format_address,
    format_permissions,
    get_func_name,
    is_bad_addr,
    is_cancelled,
    paginate_iter,
    resolve_address,
    resolve_function,
    safe_type_size,
    segment_bitness,
    xref_type_name,
)
from ida_mcp.session import session

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
# Collection helpers — shared by base resources and their search variants.
# Each accepts an optional compiled regex filter; None means match-all.
# ---------------------------------------------------------------------------


def _iter_segments(filt: re.Pattern | None = None) -> Iterator[dict]:
    for i in range(ida_segment.get_segm_qty()):
        if is_cancelled():
            return
        seg = ida_segment.getnseg(i)
        if seg is None:
            continue
        name = ida_segment.get_segm_name(seg)
        if filt and not filt.search(name):
            continue
        yield {
            "name": name,
            "start": format_address(seg.start_ea),
            "end": format_address(seg.end_ea),
            "size": seg.end_ea - seg.start_ea,
            "class": ida_segment.get_segm_class(seg),
            "permissions": format_permissions(seg.perm),
            "bitness": segment_bitness(seg.bitness),
        }


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


def _iter_imports(filt: re.Pattern | None = None) -> list[dict]:
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


def _iter_types(filt: re.Pattern | None = None) -> Iterator[dict]:
    til = ida_typeinf.get_idati()
    count = ida_typeinf.get_ordinal_count(til)
    for ordinal in range(1, count + 1):
        if is_cancelled():
            return
        name = ida_typeinf.get_numbered_type_name(til, ordinal)
        if not name:
            continue
        if filt and not filt.search(name):
            continue
        tinfo = ida_typeinf.tinfo_t()
        if tinfo.get_numbered_type(til, ordinal):
            yield {
                "ordinal": ordinal,
                "name": name,
                "type": str(tinfo),
                "is_struct": tinfo.is_struct(),
                "is_union": tinfo.is_union(),
                "is_enum": tinfo.is_enum(),
                "is_typedef": tinfo.is_typedef(),
            }


def _iter_structs(filt: re.Pattern | None = None) -> Iterator[dict]:
    for idx, sid, name in idautils.Structs():
        if is_cancelled():
            return
        if filt and not filt.search(name):
            continue
        yield {
            "index": idx,
            "id": sid,
            "name": name,
            "size": idc.get_struc_size(sid),
        }


def _iter_enums(filt: re.Pattern | None = None) -> Iterator[dict]:
    limit_ord = ida_typeinf.get_ordinal_limit()
    for ordinal in range(1, limit_ord):
        if is_cancelled():
            return
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal) and tif.is_enum():
            name = tif.get_type_name() or ""
            if filt and not filt.search(name):
                continue
            yield {
                "ordinal": ordinal,
                "name": name,
                "member_count": tif.get_enum_nmembers(),
            }


def _iter_strings(filt: re.Pattern | None = None) -> Iterator[dict]:
    ida_strlist.build_strlist()
    total = ida_strlist.get_strlist_qty()
    si = ida_strlist.string_info_t()
    for i in range(total):
        if is_cancelled():
            return
        if not ida_strlist.get_strlist_item(si, i):
            continue
        value = decode_string(si.ea, si.length, si.type)
        if value is None:
            continue
        if filt and not filt.search(value):
            continue
        yield {
            "address": format_address(si.ea),
            "value": value,
            "length": si.length,
        }


def _iter_functions(filt: re.Pattern | None = None) -> Iterator[dict]:
    total = ida_funcs.get_func_qty()
    for i in range(total):
        if is_cancelled():
            return
        func = ida_funcs.getn_func(i)
        if func is None:
            continue
        name = get_func_name(func.start_ea)
        if filt and not filt.search(name):
            continue
        yield {
            "address": format_address(func.start_ea),
            "name": name,
            "size": func.size(),
        }


def _iter_names(filt: re.Pattern | None = None) -> Iterator[dict]:
    for ea, name in idautils.Names():
        if is_cancelled():
            return
        if not filt or filt.search(name):
            yield {"address": format_address(ea), "name": name}


def _iter_bookmarks(filt: re.Pattern | None = None) -> Iterator[dict]:
    for i in range(1, 1025):
        if is_cancelled():
            return
        ea = idc.get_bookmark(i)
        if ea is not None and not is_bad_addr(ea):
            desc = idc.get_bookmark_desc(i)
            name = desc or ""
            if filt and not filt.search(name):
                continue
            yield {
                "slot": i,
                "address": format_address(ea),
                "description": name,
            }


def register(mcp: FastMCP):
    # ------------------------------------------------------------------
    # Shared resource factories: eliminate boilerplate across the
    # collector-backed base and ``/search/{pattern}`` resources.
    # ------------------------------------------------------------------
    def _paginate_and_json(items: Iterable[dict], result_key: str, offset: int, limit: int) -> str:
        """Paginate an iterable lazily and return a JSON response string.

        When *offset* or *limit* are set, uses ``paginate_iter`` so that
        generators are consumed lazily — only the requested page (plus a
        bounded lookahead) is materialised.  A *limit* of 0 (the default)
        means no limit: the iterable is fully consumed.
        """
        if offset < 0 or limit < 0:
            raise ResourceError(f"offset and limit must be non-negative (got {offset=}, {limit=})")
        if offset or limit:
            page = paginate_iter(items, offset, max(1, limit))
            return _json(
                {
                    "total": page["total"],
                    "count": len(page["items"]),
                    "has_more": page["has_more"],
                    result_key: page["items"],
                }
            )
        all_items = list(items)
        return _json({"total": len(all_items), "count": len(all_items), result_key: all_items})

    def _base_resource(collector, result_key: str, offset: int = 0, limit: int = 0) -> str:
        """Require an open DB, run *collector*, paginate, return JSON."""
        _check_db()
        return _paginate_and_json(collector(), result_key, offset, limit)

    def _search_resource(
        pattern: str, collector, result_key: str, offset: int = 0, limit: int = 0
    ) -> str:
        """Require an open DB, compile *pattern*, run *collector*, paginate, return JSON."""
        _check_db()
        try:
            filt = compile_filter(pattern)
        except IDAError as exc:
            raise ResourceError(str(exc)) from exc
        return _paginate_and_json(collector(filt), result_key, offset, limit)

    # ==================================================================
    # Tier 1 — Core Context
    # ==================================================================

    @mcp.resource(
        "ida://idb/metadata",
        description="Database metadata: file type, architecture, address ranges, counts",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"core"},
        version=1,
    )
    def idb_metadata() -> str:
        _check_db()
        return _json(
            {
                "file_path": session.current_path,
                "processor": ida_idp.get_idp_name(),
                "bitness": ida_ida.inf_get_app_bitness(),
                "file_type": ida_loader.get_file_type_name(),
                "min_address": format_address(ida_ida.inf_get_min_ea()),
                "max_address": format_address(ida_ida.inf_get_max_ea()),
                "entry_point": format_address(ida_ida.inf_get_start_ea()),
                "function_count": ida_funcs.get_func_qty(),
                "segment_count": ida_segment.get_segm_qty(),
                "entry_point_count": ida_entry.get_entry_qty(),
            }
        )

    @mcp.resource(
        "ida://idb/paths",
        description="File paths: input file, IDB database, ID0 component",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"core"},
        version=1,
    )
    def idb_paths() -> str:
        _check_db()
        return _json(
            {
                "input_file": ida_loader.get_path(ida_loader.PATH_TYPE_CMD),
                "idb_path": ida_loader.get_path(ida_loader.PATH_TYPE_IDB),
                "id0_path": ida_loader.get_path(ida_loader.PATH_TYPE_ID0),
            }
        )

    @mcp.resource(
        "ida://idb/processor",
        description="Processor info: name, registers, bitness, 64-bit flag",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"core"},
        version=1,
    )
    def idb_processor() -> str:
        _check_db()
        reg_names = ida_idp.ph_get_regnames()
        return _json(
            {
                "processor": ida_idp.get_idp_name(),
                "bitness": ida_ida.inf_get_app_bitness(),
                "is_64bit": ida_ida.inf_is_64bit(),
                "register_names": list(reg_names) if reg_names else [],
            }
        )

    @mcp.resource(
        "ida://idb/segments{?offset,limit}",
        description="All segments with name, address range, size, permissions, class",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"core"},
        version=1,
    )
    def idb_segments(offset: int = 0, limit: int = 0) -> str:
        return _base_resource(_iter_segments, "segments", offset, limit)

    @mcp.resource(
        "ida://idb/segments/search/{pattern}{?offset,limit}",
        description="Search segments by name regex pattern",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"core", "search"},
        version=1,
    )
    def idb_segments_search(pattern: str, offset: int = 0, limit: int = 0) -> str:
        return _search_resource(pattern, _iter_segments, "segments", offset, limit)

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
    # Tier 2 — Structural Reference
    # ==================================================================

    @mcp.resource(
        "ida://types{?offset,limit}",
        description="Local type catalog: ordinal, name, declaration, kind",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"structural"},
        version=1,
    )
    def res_types(offset: int = 0, limit: int = 0) -> str:
        return _base_resource(_iter_types, "types", offset, limit)

    @mcp.resource(
        "ida://types/search/{pattern}{?offset,limit}",
        description="Search local types by name regex pattern",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"structural", "search"},
        version=1,
    )
    def res_types_search(pattern: str, offset: int = 0, limit: int = 0) -> str:
        return _search_resource(pattern, _iter_types, "types", offset, limit)

    @mcp.resource(
        "ida://types/{name}",
        description="Individual type definition by name",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"structural"},
        version=1,
    )
    def res_type_by_name(name: str) -> str:
        _check_db()
        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.get_named_type(None, name):
            raise ResourceError(f"Type not found: {name}")
        return _json(
            {
                "name": name,
                "declaration": str(tinfo),
                "size": safe_type_size(tinfo.get_size()),
                "is_struct": tinfo.is_struct(),
                "is_union": tinfo.is_union(),
                "is_enum": tinfo.is_enum(),
                "is_typedef": tinfo.is_typedef(),
            }
        )

    @mcp.resource(
        "ida://structs{?offset,limit}",
        description="Structure/union catalog: name, size, member count",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"structural"},
        version=1,
    )
    def res_structs(offset: int = 0, limit: int = 0) -> str:
        return _base_resource(_iter_structs, "structs", offset, limit)

    @mcp.resource(
        "ida://structs/search/{pattern}{?offset,limit}",
        description="Search structures by name regex pattern",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"structural", "search"},
        version=1,
    )
    def res_structs_search(pattern: str, offset: int = 0, limit: int = 0) -> str:
        return _search_resource(pattern, _iter_structs, "structs", offset, limit)

    @mcp.resource(
        "ida://structs/{name}",
        description="Structure member layout: offset, size, type, name",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"structural"},
        version=1,
    )
    def res_struct_by_name(name: str) -> str:
        _check_db()
        sid = idc.get_struc_id(name)
        if is_bad_addr(sid):
            raise ResourceError(f"Structure not found: {name}")
        members = []
        for member_offset, member_name, member_size in idautils.StructMembers(sid):
            members.append(
                {
                    "offset": member_offset,
                    "name": member_name,
                    "size": member_size,
                }
            )
        return _json(
            {
                "name": name,
                "size": idc.get_struc_size(sid),
                "member_count": len(members),
                "members": members,
            }
        )

    @mcp.resource(
        "ida://enums{?offset,limit}",
        description="Enum catalog: name, member count",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"structural"},
        version=1,
    )
    def res_enums(offset: int = 0, limit: int = 0) -> str:
        return _base_resource(_iter_enums, "enums", offset, limit)

    @mcp.resource(
        "ida://enums/search/{pattern}{?offset,limit}",
        description="Search enums by name regex pattern",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"structural", "search"},
        version=1,
    )
    def res_enums_search(pattern: str, offset: int = 0, limit: int = 0) -> str:
        return _search_resource(pattern, _iter_enums, "enums", offset, limit)

    @mcp.resource(
        "ida://enums/{name}",
        description="Enum members: name, value",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"structural"},
        version=1,
    )
    def res_enum_by_name(name: str) -> str:
        _check_db()
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(None, name):
            raise ResourceError(f"Enum not found: {name}")
        if not tif.is_enum():
            raise ResourceError(f"Not an enum: {name}")
        edt = ida_typeinf.enum_type_data_t()
        if not tif.get_enum_details(edt):
            raise ResourceError(f"Cannot get enum details: {name}")
        members = [{"name": edt[i].name or "", "value": edt[i].value} for i in range(len(edt))]
        return _json({"name": name, "member_count": len(members), "members": members})

    @mcp.resource(
        "ida://signatures/flirt",
        description="Applied FLIRT signature files",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"structural"},
        version=1,
    )
    def res_flirt_sigs() -> str:
        _check_db()
        sigs = []
        n = ida_funcs.get_idasgn_qty()
        for i in range(n):
            desc = ida_funcs.get_idasgn_desc(i)
            if desc:
                name, optlibs = desc
                sigs.append({"index": i, "name": name, "optional_libs": optlibs})
        return _json({"count": len(sigs), "signatures": sigs})

    @mcp.resource(
        "ida://signatures/til",
        description="Loaded type information libraries",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"structural"},
        version=1,
    )
    def res_type_libs() -> str:
        _check_db()
        til = ida_typeinf.get_idati()
        libs = []
        for i in range(til.nbases):
            base = til.base(i)
            if base:
                libs.append(
                    {
                        "index": i,
                        "name": base.name,
                        "description": base.desc or "",
                    }
                )
        return _json({"count": len(libs), "libraries": libs})

    # ==================================================================
    # Tier 3 — Browsable Collections
    # ==================================================================

    @mcp.resource(
        "ida://strings{?offset,limit}",
        description="String table with address, value, length, encoding",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"browsable"},
        version=1,
    )
    def res_strings(offset: int = 0, limit: int = 0) -> str:
        return _base_resource(_iter_strings, "strings", offset, limit)

    @mcp.resource(
        "ida://strings/search/{pattern}{?offset,limit}",
        description="Search strings by regex pattern, with address, value, length",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"browsable", "search"},
        version=1,
    )
    def res_strings_search(pattern: str, offset: int = 0, limit: int = 0) -> str:
        return _search_resource(pattern, _iter_strings, "strings", offset, limit)

    @mcp.resource(
        "ida://functions{?offset,limit}",
        description="Function catalog with address, name, size",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"browsable"},
        version=1,
    )
    def res_functions(offset: int = 0, limit: int = 0) -> str:
        return _base_resource(_iter_functions, "functions", offset, limit)

    @mcp.resource(
        "ida://functions/search/{pattern}{?offset,limit}",
        description="Search functions by name regex pattern, with address, name, size",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"browsable", "search"},
        version=1,
    )
    def res_functions_search(pattern: str, offset: int = 0, limit: int = 0) -> str:
        return _search_resource(pattern, _iter_functions, "functions", offset, limit)

    @mcp.resource(
        "ida://names{?offset,limit}",
        description="Named locations with address and name",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"browsable"},
        version=1,
    )
    def res_names(offset: int = 0, limit: int = 0) -> str:
        return _base_resource(_iter_names, "names", offset, limit)

    @mcp.resource(
        "ida://names/search/{pattern}{?offset,limit}",
        description="Search named locations by name regex pattern, with address and name",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"browsable", "search"},
        version=1,
    )
    def res_names_search(pattern: str, offset: int = 0, limit: int = 0) -> str:
        return _search_resource(pattern, _iter_names, "names", offset, limit)

    @mcp.resource(
        "ida://bookmarks{?offset,limit}",
        description="User-set bookmarked positions",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"browsable"},
        version=1,
    )
    def res_bookmarks(offset: int = 0, limit: int = 0) -> str:
        return _base_resource(_iter_bookmarks, "bookmarks", offset, limit)

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

        ida_strlist.build_strlist()
        string_count = ida_strlist.get_strlist_qty()

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

    # ==================================================================
    # Tier 4 — Per-Entity Resources (parameterized)
    # ==================================================================

    @mcp.resource(
        "ida://functions/{addr}",
        description="Function metadata by address or name",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"per-entity"},
        version=1,
    )
    def res_function(addr: str) -> str:
        _check_db()
        try:
            func = resolve_function(addr)
        except IDAError as exc:
            raise ResourceError(str(exc)) from exc
        return _json(
            {
                "address": format_address(func.start_ea),
                "end": format_address(func.end_ea),
                "name": get_func_name(func.start_ea),
                "size": func.size(),
                "flags": func.flags,
                "is_thunk": bool(func.flags & ida_funcs.FUNC_THUNK),
                "is_library": bool(func.flags & ida_funcs.FUNC_LIB),
                "is_noreturn": bool(func.flags & ida_funcs.FUNC_NORET),
            }
        )

    @mcp.resource(
        "ida://functions/{addr}/stackframe",
        description="Stack frame layout for a function",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"per-entity"},
        version=1,
    )
    def res_function_stackframe(addr: str) -> str:
        _check_db()
        try:
            func = resolve_function(addr)
        except IDAError as exc:
            raise ResourceError(str(exc)) from exc

        frame_tif = ida_typeinf.tinfo_t()
        if not frame_tif.get_func_frame(func):
            return _json(
                {
                    "function": format_address(func.start_ea),
                    "name": get_func_name(func.start_ea),
                    "frame": None,
                    "message": "No stack frame defined for this function",
                }
            )

        udt = ida_typeinf.udt_type_data_t()
        frame_tif.get_udt_details(udt)

        members = []
        for udm in udt:
            if udm.is_gap():
                continue
            byte_offset = udm.offset // 8
            members.append(
                {
                    "offset": byte_offset,
                    "name": udm.name or f"var_{byte_offset:X}",
                    "size": udm.size // 8,
                }
            )

        return _json(
            {
                "function": format_address(func.start_ea),
                "name": get_func_name(func.start_ea),
                "frame_size": frame_tif.get_size(),
                "member_count": len(members),
                "members": members,
            }
        )

    @mcp.resource(
        "ida://functions/{addr}/exceptions",
        description="Try/catch exception handlers for a function",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"per-entity"},
        version=1,
    )
    def res_function_exceptions(addr: str) -> str:
        _check_db()
        try:
            func = resolve_function(addr)
        except IDAError as exc:
            raise ResourceError(str(exc)) from exc

        ranges = ida_tryblks.tryblks_t()
        n = ida_tryblks.get_tryblks(ranges, func.start_ea)

        handlers = []
        for i in range(n):
            tb = ranges.get(i)
            handler = {
                "try_start": format_address(tb.start_ea),
                "try_end": format_address(tb.end_ea),
                "catch_count": tb.size(),
            }
            catches = []
            for j in range(tb.size()):
                cb = tb.at(j)
                catches.append(
                    {
                        "start": format_address(cb.start_ea),
                        "end": format_address(cb.end_ea),
                    }
                )
            handler["catches"] = catches
            handlers.append(handler)

        return _json(
            {
                "function": format_address(func.start_ea),
                "name": get_func_name(func.start_ea),
                "handler_count": len(handlers),
                "handlers": handlers,
            }
        )

    @mcp.resource(
        "ida://functions/{addr}/vars",
        description="Decompiled local variables and parameters",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"per-entity"},
        meta=META_DECOMPILER,
        version=1,
    )
    def res_function_vars(addr: str) -> str:
        _check_db()
        try:
            cfunc, func = decompile_at(addr)
        except IDAError as exc:
            raise ResourceError(str(exc)) from exc

        variables = [
            {
                "name": lvar.name or "",
                "type": str(lvar.tif) if lvar.tif else "",
                "is_arg": lvar.is_arg_var,
                "is_result": lvar.is_result_var,
            }
            for lvar in cfunc.lvars
        ]

        return _json(
            {
                "function": format_address(func.start_ea),
                "name": get_func_name(func.start_ea),
                "variable_count": len(variables),
                "variables": variables,
            }
        )

    @mcp.resource(
        "ida://xrefs/from/{addr}",
        description="Cross-references from an address",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"per-entity"},
        version=1,
    )
    def res_xrefs_from(addr: str) -> str:
        _check_db()
        try:
            ea = resolve_address(addr)
        except IDAError as exc:
            raise ResourceError(str(exc)) from exc

        xrefs = [
            {
                "to": format_address(xref.to),
                "to_name": get_func_name(xref.to),
                "type": xref_type_name(xref.type),
                "is_code": xref.iscode,
            }
            for xref in idautils.XrefsFrom(ea)
        ]

        return _json(
            {
                "address": format_address(ea),
                "count": len(xrefs),
                "xrefs": xrefs,
            }
        )

    @mcp.resource(
        "ida://xrefs/to/{addr}",
        description="Cross-references to an address",
        mime_type="application/json",
        annotations=ANNO_RESOURCE,
        tags={"per-entity"},
        version=1,
    )
    def res_xrefs_to(addr: str) -> str:
        _check_db()
        try:
            ea = resolve_address(addr)
        except IDAError as exc:
            raise ResourceError(str(exc)) from exc

        xrefs = [
            {
                "from": format_address(xref.frm),
                "from_name": get_func_name(xref.frm),
                "type": xref_type_name(xref.type),
                "is_code": xref.iscode,
            }
            for xref in idautils.XrefsTo(ea)
        ]

        return _json(
            {
                "address": format_address(ea),
                "count": len(xrefs),
                "xrefs": xrefs,
            }
        )
