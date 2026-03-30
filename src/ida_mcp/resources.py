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

from ida_mcp.helpers import (
    IDAError,
    compile_filter,
    decode_string,
    decompile_at,
    format_address,
    format_permissions,
    get_func_name,
    is_bad_addr,
    is_cancelled,
    resolve_address,
    resolve_function,
    safe_type_size,
    segment_bitness,
    xref_type_name,
)
from ida_mcp.session import session


def _json(obj: object) -> str:
    """Serialize to compact JSON."""
    return json.dumps(obj, separators=(",", ":"))


def _require_db() -> str | None:
    """Return an error JSON string if no database is open, else None."""
    if not session.is_open():
        return _json({"error": "No database is open", "error_type": "NoDatabase"})
    return None


def _ida_error_json(exc: IDAError) -> str:
    """Convert an IDAError to a JSON error string for resources."""
    return str(exc)


# ---------------------------------------------------------------------------
# Collection helpers — shared by base resources and their search variants.
# Each accepts an optional compiled regex filter; None means match-all.
# ---------------------------------------------------------------------------


def _collect_segments(filt: re.Pattern | None = None) -> list[dict]:
    items = []
    for i in range(ida_segment.get_segm_qty()):
        if is_cancelled():
            break
        seg = ida_segment.getnseg(i)
        if seg is None:
            continue
        name = ida_segment.get_segm_name(seg)
        if filt and not filt.search(name):
            continue
        items.append(
            {
                "name": name,
                "start": format_address(seg.start_ea),
                "end": format_address(seg.end_ea),
                "size": seg.end_ea - seg.start_ea,
                "class": ida_segment.get_segm_class(seg),
                "permissions": format_permissions(seg.perm),
                "bitness": segment_bitness(seg.bitness),
            }
        )
    return items


def _collect_entrypoints(filt: re.Pattern | None = None) -> list[dict]:
    items = []
    for i in range(ida_entry.get_entry_qty()):
        if is_cancelled():
            break
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal) or ""
        if filt and not filt.search(name):
            continue
        items.append(
            {
                "ordinal": ordinal,
                "address": format_address(ea),
                "name": name,
            }
        )
    return items


def _collect_imports(filt: re.Pattern | None = None) -> list[dict]:
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


def _collect_exports(filt: re.Pattern | None = None) -> list[dict]:
    items = []
    for index, ordinal, ea, name in idautils.Entries():
        if is_cancelled():
            break
        sym = name or ""
        if filt and not filt.search(sym):
            continue
        items.append(
            {
                "index": index,
                "ordinal": ordinal,
                "address": format_address(ea),
                "name": sym,
            }
        )
    return items


def _collect_types(filt: re.Pattern | None = None) -> list[dict]:
    til = ida_typeinf.get_idati()
    count = ida_typeinf.get_ordinal_count(til)
    items = []
    for ordinal in range(1, count + 1):
        if is_cancelled():
            break
        name = ida_typeinf.get_numbered_type_name(til, ordinal)
        if not name:
            continue
        if filt and not filt.search(name):
            continue
        tinfo = ida_typeinf.tinfo_t()
        if tinfo.get_numbered_type(til, ordinal):
            items.append(
                {
                    "ordinal": ordinal,
                    "name": name,
                    "type": str(tinfo),
                    "is_struct": tinfo.is_struct(),
                    "is_union": tinfo.is_union(),
                    "is_enum": tinfo.is_enum(),
                    "is_typedef": tinfo.is_typedef(),
                }
            )
    return items


def _collect_structs(filt: re.Pattern | None = None) -> list[dict]:
    items = []
    for idx, sid, name in idautils.Structs():
        if is_cancelled():
            break
        if filt and not filt.search(name):
            continue
        items.append(
            {
                "index": idx,
                "id": sid,
                "name": name,
                "size": idc.get_struc_size(sid),
            }
        )
    return items


def _collect_enums(filt: re.Pattern | None = None) -> list[dict]:
    items = []
    limit_ord = ida_typeinf.get_ordinal_limit()
    for ordinal in range(1, limit_ord):
        if is_cancelled():
            break
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal) and tif.is_enum():
            name = tif.get_type_name() or ""
            if filt and not filt.search(name):
                continue
            items.append(
                {
                    "ordinal": ordinal,
                    "name": name,
                    "member_count": tif.get_enum_nmembers(),
                }
            )
    return items


def _collect_strings(filt: re.Pattern | None = None) -> list[dict]:
    ida_strlist.build_strlist()
    total = ida_strlist.get_strlist_qty()
    si = ida_strlist.string_info_t()
    items = []
    for i in range(total):
        if is_cancelled():
            break
        if not ida_strlist.get_strlist_item(si, i):
            continue
        value = decode_string(si.ea, si.length, si.type)
        if value is None:
            continue
        if filt and not filt.search(value):
            continue
        items.append(
            {
                "address": format_address(si.ea),
                "value": value,
                "length": si.length,
            }
        )
    return items


def _collect_functions(filt: re.Pattern | None = None) -> list[dict]:
    total = ida_funcs.get_func_qty()
    items = []
    for i in range(total):
        if is_cancelled():
            break
        func = ida_funcs.getn_func(i)
        if func is None:
            continue
        name = get_func_name(func.start_ea)
        if filt and not filt.search(name):
            continue
        items.append(
            {
                "address": format_address(func.start_ea),
                "name": name,
                "size": func.size(),
            }
        )
    return items


def _collect_names(filt: re.Pattern | None = None) -> list[dict]:
    items = []
    for ea, name in idautils.Names():
        if is_cancelled():
            break
        if not filt or filt.search(name):
            items.append({"address": format_address(ea), "name": name})
    return items


def register(mcp: FastMCP):
    # ------------------------------------------------------------------
    # Shared resource factories: eliminate boilerplate across the
    # collector-backed base and ``/search/{pattern}`` resources.
    # ------------------------------------------------------------------
    def _base_resource(collector, result_key: str) -> str:
        """Require an open DB, run *collector*, and return JSON."""
        if err := _require_db():
            return err
        items = collector()
        return _json({"count": len(items), result_key: items})

    def _search_resource(pattern: str, collector, result_key: str) -> str:
        """Require an open DB, compile *pattern*, run *collector*, return JSON."""
        if err := _require_db():
            return err
        try:
            filt = compile_filter(pattern)
        except IDAError as exc:
            return _ida_error_json(exc)
        items = collector(filt)
        return _json({"count": len(items), result_key: items})

    # ==================================================================
    # Tier 1 — Core Context
    # ==================================================================

    @mcp.resource(
        "ida://idb/metadata",
        description="Database metadata: file type, architecture, address ranges, counts",
    )
    def idb_metadata() -> str:
        if err := _require_db():
            return err
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
        "ida://idb/paths", description="File paths: input file, IDB database, ID0 component"
    )
    def idb_paths() -> str:
        if err := _require_db():
            return err
        return _json(
            {
                "input_file": ida_loader.get_path(ida_loader.PATH_TYPE_CMD),
                "idb_path": ida_loader.get_path(ida_loader.PATH_TYPE_IDB),
                "id0_path": ida_loader.get_path(ida_loader.PATH_TYPE_ID0),
            }
        )

    @mcp.resource(
        "ida://idb/processor", description="Processor info: name, registers, bitness, 64-bit flag"
    )
    def idb_processor() -> str:
        if err := _require_db():
            return err
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
        "ida://idb/segments",
        description="All segments with name, address range, size, permissions, class",
    )
    def idb_segments() -> str:
        return _base_resource(_collect_segments, "segments")

    @mcp.resource(
        "ida://idb/segments/search/{pattern}",
        description="Search segments by name regex pattern",
    )
    def idb_segments_search(pattern: str) -> str:
        return _search_resource(pattern, _collect_segments, "segments")

    @mcp.resource(
        "ida://idb/entrypoints", description="All entry points with ordinal, address, name"
    )
    def idb_entrypoints() -> str:
        return _base_resource(_collect_entrypoints, "entries")

    @mcp.resource(
        "ida://idb/entrypoints/search/{pattern}",
        description="Search entry points by name regex pattern",
    )
    def idb_entrypoints_search(pattern: str) -> str:
        return _search_resource(pattern, _collect_entrypoints, "entries")

    @mcp.resource("ida://idb/imports", description="All imports grouped by module")
    def idb_imports() -> str:
        return _base_resource(_collect_imports, "imports")

    @mcp.resource(
        "ida://idb/imports/search/{pattern}",
        description="Search imports by module or symbol name regex pattern",
    )
    def idb_imports_search(pattern: str) -> str:
        return _search_resource(pattern, _collect_imports, "imports")

    @mcp.resource("ida://idb/exports", description="All exported symbols with ordinals")
    def idb_exports() -> str:
        return _base_resource(_collect_exports, "exports")

    @mcp.resource(
        "ida://idb/exports/search/{pattern}",
        description="Search exports by name regex pattern",
    )
    def idb_exports_search(pattern: str) -> str:
        return _search_resource(pattern, _collect_exports, "exports")

    # ==================================================================
    # Tier 2 — Structural Reference
    # ==================================================================

    @mcp.resource("ida://types", description="Local type catalog: ordinal, name, declaration, kind")
    def res_types() -> str:
        return _base_resource(_collect_types, "types")

    @mcp.resource(
        "ida://types/search/{pattern}",
        description="Search local types by name regex pattern",
    )
    def res_types_search(pattern: str) -> str:
        return _search_resource(pattern, _collect_types, "types")

    @mcp.resource("ida://types/{name}", description="Individual type definition by name")
    def res_type_by_name(name: str) -> str:
        if err := _require_db():
            return err
        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.get_named_type(None, name):
            return _json({"error": f"Type not found: {name}", "error_type": "NotFound"})
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

    @mcp.resource("ida://structs", description="Structure/union catalog: name, size, member count")
    def res_structs() -> str:
        return _base_resource(_collect_structs, "structs")

    @mcp.resource(
        "ida://structs/search/{pattern}",
        description="Search structures by name regex pattern",
    )
    def res_structs_search(pattern: str) -> str:
        return _search_resource(pattern, _collect_structs, "structs")

    @mcp.resource(
        "ida://structs/{name}", description="Structure member layout: offset, size, type, name"
    )
    def res_struct_by_name(name: str) -> str:
        if err := _require_db():
            return err
        sid = idc.get_struc_id(name)
        if is_bad_addr(sid):
            return _json({"error": f"Structure not found: {name}", "error_type": "NotFound"})
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

    @mcp.resource("ida://enums", description="Enum catalog: name, member count")
    def res_enums() -> str:
        return _base_resource(_collect_enums, "enums")

    @mcp.resource(
        "ida://enums/search/{pattern}",
        description="Search enums by name regex pattern",
    )
    def res_enums_search(pattern: str) -> str:
        return _search_resource(pattern, _collect_enums, "enums")

    @mcp.resource("ida://enums/{name}", description="Enum members: name, value")
    def res_enum_by_name(name: str) -> str:
        if err := _require_db():
            return err
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(None, name):
            return _json({"error": f"Enum not found: {name}", "error_type": "NotFound"})
        if not tif.is_enum():
            return _json({"error": f"Not an enum: {name}", "error_type": "NotFound"})
        edt = ida_typeinf.enum_type_data_t()
        if not tif.get_enum_details(edt):
            return _json(
                {"error": f"Cannot get enum details: {name}", "error_type": "InternalError"}
            )
        members = [{"name": edt[i].name or "", "value": edt[i].value} for i in range(len(edt))]
        return _json({"name": name, "member_count": len(members), "members": members})

    @mcp.resource("ida://signatures/flirt", description="Applied FLIRT signature files")
    def res_flirt_sigs() -> str:
        if err := _require_db():
            return err
        sigs = []
        n = ida_funcs.get_idasgn_qty()
        for i in range(n):
            desc = ida_funcs.get_idasgn_desc(i)
            if desc:
                name, optlibs = desc
                sigs.append({"index": i, "name": name, "optional_libs": optlibs})
        return _json({"count": len(sigs), "signatures": sigs})

    @mcp.resource("ida://signatures/til", description="Loaded type information libraries")
    def res_type_libs() -> str:
        if err := _require_db():
            return err
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
        "ida://strings",
        description="String table with address, value, length, encoding",
    )
    def res_strings() -> str:
        return _base_resource(_collect_strings, "strings")

    @mcp.resource(
        "ida://strings/search/{pattern}",
        description="Search strings by regex pattern, with address, value, length",
    )
    def res_strings_search(pattern: str) -> str:
        return _search_resource(pattern, _collect_strings, "strings")

    @mcp.resource("ida://functions", description="Function catalog with address, name, size")
    def res_functions() -> str:
        return _base_resource(_collect_functions, "functions")

    @mcp.resource(
        "ida://functions/search/{pattern}",
        description="Search functions by name regex pattern, with address, name, size",
    )
    def res_functions_search(pattern: str) -> str:
        return _search_resource(pattern, _collect_functions, "functions")

    @mcp.resource("ida://names", description="Named locations with address and name")
    def res_names() -> str:
        return _base_resource(_collect_names, "names")

    @mcp.resource(
        "ida://names/search/{pattern}",
        description="Search named locations by name regex pattern, with address and name",
    )
    def res_names_search(pattern: str) -> str:
        return _search_resource(pattern, _collect_names, "names")

    @mcp.resource("ida://bookmarks", description="User-set bookmarked positions")
    def res_bookmarks() -> str:
        if err := _require_db():
            return err
        items = []
        for i in range(1, 1025):
            ea = idc.get_bookmark(i)
            if ea is not None and not is_bad_addr(ea):
                desc = idc.get_bookmark_desc(i)
                items.append(
                    {
                        "slot": i,
                        "address": format_address(ea),
                        "description": desc or "",
                    }
                )
        return _json({"count": len(items), "bookmarks": items})

    @mcp.resource(
        "ida://idb/statistics",
        description="Summary counts: functions, strings, segments, names, coverage",
    )
    def idb_statistics() -> str:
        if err := _require_db():
            return err
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

    @mcp.resource("ida://functions/{addr}", description="Function metadata by address or name")
    def res_function(addr: str) -> str:
        if err := _require_db():
            return err
        try:
            func = resolve_function(addr)
        except IDAError as exc:
            return _ida_error_json(exc)
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
        "ida://functions/{addr}/stackframe", description="Stack frame layout for a function"
    )
    def res_function_stackframe(addr: str) -> str:
        if err := _require_db():
            return err
        try:
            func = resolve_function(addr)
        except IDAError as exc:
            return _ida_error_json(exc)

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
    )
    def res_function_exceptions(addr: str) -> str:
        if err := _require_db():
            return err
        try:
            func = resolve_function(addr)
        except IDAError as exc:
            return _ida_error_json(exc)

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
        "ida://functions/{addr}/vars", description="Decompiled local variables and parameters"
    )
    def res_function_vars(addr: str) -> str:
        if err := _require_db():
            return err
        try:
            cfunc, func = decompile_at(addr)
        except IDAError as exc:
            return _ida_error_json(exc)

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

    @mcp.resource("ida://xrefs/from/{addr}", description="Cross-references from an address")
    def res_xrefs_from(addr: str) -> str:
        if err := _require_db():
            return err
        try:
            ea = resolve_address(addr)
        except IDAError as exc:
            return _ida_error_json(exc)

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

    @mcp.resource("ida://xrefs/to/{addr}", description="Cross-references to an address")
    def res_xrefs_to(addr: str) -> str:
        if err := _require_db():
            return err
        try:
            ea = resolve_address(addr)
        except IDAError as exc:
            return _ida_error_json(exc)

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
