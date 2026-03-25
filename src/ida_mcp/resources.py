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
  bookmarks, statistics (capped at 500 entries).
- **Tier 4 — Per-Entity:** parameterized resources for individual
  functions, stack frames, exceptions, variables, and cross-references.
"""

from __future__ import annotations

import json

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
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import (
    decode_string,
    decompile_at,
    format_address,
    format_permissions,
    get_func_name,
    is_bad_addr,
    resolve_address,
    resolve_function,
    safe_type_size,
    segment_bitness,
    xref_type_name,
)
from ida_mcp.session import session

_RESOURCE_CAP = 500


def _json(obj: object) -> str:
    """Serialize to compact JSON."""
    return json.dumps(obj, separators=(",", ":"))


def _require_db() -> str | None:
    """Return an error JSON string if no database is open, else None."""
    if not session.is_open():
        return _json({"error": "No database is open", "error_type": "NoDatabase"})
    return None


def register(mcp: FastMCP):
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
        if err := _require_db():
            return err
        segments = []
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            if seg is None:
                continue
            segments.append(
                {
                    "name": ida_segment.get_segm_name(seg),
                    "start": format_address(seg.start_ea),
                    "end": format_address(seg.end_ea),
                    "size": seg.end_ea - seg.start_ea,
                    "class": ida_segment.get_segm_class(seg),
                    "permissions": format_permissions(seg.perm),
                    "bitness": segment_bitness(seg.bitness),
                }
            )
        return _json({"count": len(segments), "segments": segments})

    @mcp.resource(
        "ida://idb/entrypoints", description="All entry points with ordinal, address, name"
    )
    def idb_entrypoints() -> str:
        if err := _require_db():
            return err
        entries = []
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal) or ""
            entries.append(
                {
                    "ordinal": ordinal,
                    "address": format_address(ea),
                    "name": name,
                }
            )
        return _json({"count": len(entries), "entries": entries})

    @mcp.resource("ida://idb/imports", description="All imports grouped by module")
    def idb_imports() -> str:
        if err := _require_db():
            return err
        all_imports = []
        current_module = ""

        def _import_cb(ea, name, ordinal):
            all_imports.append(
                {
                    "module": current_module,
                    "address": format_address(ea),
                    "name": name or "",
                    "ordinal": ordinal,
                }
            )
            return True

        for i in range(ida_nalt.get_import_module_qty()):
            current_module = ida_nalt.get_import_module_name(i) or ""
            ida_nalt.enum_import_names(i, _import_cb)

        return _json({"count": len(all_imports), "imports": all_imports})

    @mcp.resource("ida://idb/exports", description="All exported symbols with ordinals")
    def idb_exports() -> str:
        if err := _require_db():
            return err
        exports = []
        for index, ordinal, ea, name in idautils.Entries():
            exports.append(
                {
                    "index": index,
                    "ordinal": ordinal,
                    "address": format_address(ea),
                    "name": name or "",
                }
            )
        return _json({"count": len(exports), "exports": exports})

    # ==================================================================
    # Tier 2 — Structural Reference
    # ==================================================================

    @mcp.resource("ida://types", description="Local type catalog: ordinal, name, declaration, kind")
    def res_types() -> str:
        if err := _require_db():
            return err
        til = ida_typeinf.get_idati()
        count = ida_typeinf.get_ordinal_count(til)
        items = []
        for ordinal in range(1, count + 1):
            name = ida_typeinf.get_numbered_type_name(til, ordinal)
            if not name:
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
        return _json({"count": len(items), "types": items})

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
        if err := _require_db():
            return err
        items = []
        for idx, sid, name in idautils.Structs():
            items.append(
                {
                    "index": idx,
                    "id": sid,
                    "name": name,
                    "size": idc.get_struc_size(sid),
                }
            )
        return _json({"count": len(items), "structs": items})

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
        if err := _require_db():
            return err
        items = []
        limit_ord = ida_typeinf.get_ordinal_limit()
        for ordinal in range(1, limit_ord):
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(None, ordinal) and tif.is_enum():
                items.append(
                    {
                        "ordinal": ordinal,
                        "name": tif.get_type_name() or "",
                        "member_count": tif.get_enum_nmembers(),
                    }
                )
        return _json({"count": len(items), "enums": items})

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
    # Tier 3 — Browsable Collections (capped at 500)
    # ==================================================================

    @mcp.resource(
        "ida://strings",
        description="String table (first 500 entries) with address, value, length, encoding",
    )
    def res_strings() -> str:
        if err := _require_db():
            return err
        ida_strlist.build_strlist()
        total = ida_strlist.get_strlist_qty()
        si = ida_strlist.string_info_t()
        items = []
        for i in range(total):
            if len(items) >= _RESOURCE_CAP:
                break
            if not ida_strlist.get_strlist_item(si, i):
                continue
            value = decode_string(si.ea, si.length, si.type)
            if value is None:
                continue
            items.append(
                {
                    "address": format_address(si.ea),
                    "value": value,
                    "length": si.length,
                }
            )
        return _json(
            {
                "total_count": total,
                "count": len(items),
                "truncated": total > _RESOURCE_CAP,
                "strings": items,
            }
        )

    @mcp.resource(
        "ida://functions", description="Function catalog (first 500) with address, name, size"
    )
    def res_functions() -> str:
        if err := _require_db():
            return err
        total = ida_funcs.get_func_qty()
        items = []
        for i in range(min(total, _RESOURCE_CAP)):
            func = ida_funcs.getn_func(i)
            if func is None:
                continue
            items.append(
                {
                    "address": format_address(func.start_ea),
                    "name": get_func_name(func.start_ea),
                    "size": func.size(),
                }
            )
        return _json(
            {
                "total_count": total,
                "count": len(items),
                "truncated": total > _RESOURCE_CAP,
                "functions": items,
            }
        )

    @mcp.resource("ida://names", description="Named locations (first 500) with address and name")
    def res_names() -> str:
        if err := _require_db():
            return err
        items = []
        truncated = False
        for ea, name in idautils.Names():
            if len(items) >= _RESOURCE_CAP:
                truncated = True
                break
            items.append({"address": format_address(ea), "name": name})
        return _json(
            {
                "count": len(items),
                "truncated": truncated,
                "names": items,
            }
        )

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
        func, err2 = resolve_function(addr)
        if err2:
            return _json(err2)
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
        func, err2 = resolve_function(addr)
        if err2:
            return _json(err2)

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
        func, err2 = resolve_function(addr)
        if err2:
            return _json(err2)

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
        cfunc, func, err2 = decompile_at(addr)
        if err2:
            return _json(err2)

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
        ea, err2 = resolve_address(addr)
        if err2:
            return _json(err2)

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
        ea, err2 = resolve_address(addr)
        if err2:
            return _json(err2)

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
