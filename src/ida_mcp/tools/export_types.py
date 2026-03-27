# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Type export tools — serialize local types as compilable C header declarations."""

from __future__ import annotations

import ida_typeinf
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import compile_filter, is_cancelled, safe_type_size
from ida_mcp.session import session


def _format_udt(name: str, tinfo: ida_typeinf.tinfo_t) -> str:
    """Format a struct or union as a C declaration."""
    keyword = "union" if tinfo.is_union() else "struct"
    udt = ida_typeinf.udt_type_data_t()
    if not tinfo.get_udt_details(udt):
        return f"{keyword} {name}; /* opaque */"

    lines = [f"{keyword} {name} {{"]
    for i in range(udt.size()):
        m = udt[i]
        mtype = str(m.type)
        mname = m.name or f"__field_{i}"
        # Handle bitfields
        if m.is_bitfield():
            lines.append(f"    {mtype} {mname} : {m.size};")
        else:
            lines.append(f"    {mtype} {mname};")
    lines.append("};")
    return "\n".join(lines)


def _format_enum(name: str, tinfo: ida_typeinf.tinfo_t) -> str:
    """Format an enum as a C declaration."""
    edm = ida_typeinf.enum_type_data_t()
    if not tinfo.get_enum_details(edm):
        return f"enum {name}; /* opaque */"

    lines = [f"enum {name} {{"]
    for i in range(edm.size()):
        m = edm[i]
        lines.append(f"    {m.name} = {m.value},")
    lines.append("};")
    return "\n".join(lines)


def _format_typedef(name: str, tinfo: ida_typeinf.tinfo_t) -> str:
    """Format a typedef as a C declaration."""
    return f"typedef {tinfo!s} {name};"


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def export_c_header(
        names: str = "",
        filter_pattern: str = "",
    ) -> dict:
        """Export local types as compilable C header declarations.

        Serializes structs, unions, enums, and typedefs into C syntax.
        Specify types by explicit names (comma-separated), a regex filter,
        or omit both to export all local types.

        Args:
            names: Comma-separated list of type names to export.
            filter_pattern: Regex filter for type names (alternative to names).
        """
        til = ida_typeinf.get_idati()
        count = ida_typeinf.get_ordinal_count(til)

        # Build target name set
        target_names: set[str] | None = None
        if names:
            target_names = {n.strip() for n in names.split(",") if n.strip()}
            if not target_names:
                return {
                    "error": "No valid type names provided.",
                    "error_type": "InvalidArgument",
                }

        pattern, err = compile_filter(filter_pattern)
        if err:
            return err

        declarations: list[str] = []
        exported: list[dict] = []

        for ordinal in range(1, count + 1):
            if is_cancelled():
                break
            tname = ida_typeinf.get_numbered_type_name(til, ordinal)
            if not tname:
                continue

            # Filter by explicit names
            if target_names and tname not in target_names:
                continue

            # Filter by pattern
            if pattern and not pattern.search(tname):
                continue

            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.get_numbered_type(til, ordinal):
                continue

            # Format based on type kind
            if tinfo.is_struct() or tinfo.is_union():
                decl = _format_udt(tname, tinfo)
            elif tinfo.is_enum():
                decl = _format_enum(tname, tinfo)
            else:
                decl = _format_typedef(tname, tinfo)

            declarations.append(decl)
            exported.append(
                {
                    "name": tname,
                    "ordinal": ordinal,
                    "size": safe_type_size(tinfo.get_size()),
                }
            )

        header = "\n\n".join(declarations)

        result: dict = {
            "type_count": len(exported),
            "types": exported,
            "header": header,
        }
        if target_names:
            missing = target_names - {e["name"] for e in exported}
            if missing:
                result["not_found"] = sorted(missing)
        return result
