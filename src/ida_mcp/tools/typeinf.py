# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Type library management tools — local types, TILs, type parsing."""

from __future__ import annotations

import ida_typeinf
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import format_address, paginate_iter, resolve_address, safe_type_size
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def list_local_types(offset: int = 0, limit: int = 100) -> dict:
        """List all local types defined in the database.

        Returns structs, unions, enums, and typedefs from the local type
        library. Large databases may have hundreds or thousands of types —
        use pagination or get_local_type to look up specific types by name.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results (max 500).
        """
        til = ida_typeinf.get_idati()
        count = ida_typeinf.get_ordinal_count(til)

        def _iter():
            for ordinal in range(1, count + 1):
                name = ida_typeinf.get_numbered_type_name(til, ordinal)
                if not name:
                    continue
                tinfo = ida_typeinf.tinfo_t()
                if tinfo.get_numbered_type(til, ordinal):
                    yield {
                        "ordinal": ordinal,
                        "name": name,
                        "type": str(tinfo),
                        "size": safe_type_size(tinfo.get_size()),
                        "is_struct": tinfo.is_struct(),
                        "is_union": tinfo.is_union(),
                        "is_enum": tinfo.is_enum(),
                        "is_typedef": tinfo.is_typedef(),
                    }

        return paginate_iter(_iter(), offset, limit)

    @mcp.tool()
    @session.require_open
    def get_local_type(name: str) -> dict:
        """Get detailed information about a local type by name.

        Returns the full type declaration including fields for structs/unions.
        Use list_local_types to browse available types, then this tool for
        detailed member information. To apply a type at an address, use
        apply_type_at_address.

        Args:
            name: Name of the local type.
        """
        til = ida_typeinf.get_idati()
        ordinal = ida_typeinf.get_type_ordinal(til, name)
        if ordinal == 0:
            return {"error": f"Type not found: {name}", "error_type": "NotFound"}

        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.get_numbered_type(til, ordinal):
            return {"error": f"Cannot load type: {name}", "error_type": "LoadError"}

        is_struct = tinfo.is_struct()
        is_union = tinfo.is_union()
        result = {
            "name": name,
            "ordinal": ordinal,
            "declaration": str(tinfo),
            "size": safe_type_size(tinfo.get_size()),
            "is_struct": is_struct,
            "is_union": is_union,
            "is_enum": tinfo.is_enum(),
        }

        # If it's a struct/union, list members
        if is_struct or is_union:
            udt = ida_typeinf.udt_type_data_t()
            if tinfo.get_udt_details(udt):
                members = []
                for i in range(udt.size()):
                    m = udt[i]
                    members.append(
                        {
                            "name": m.name,
                            "type": str(m.type),
                            "offset_bits": m.offset,
                            "size_bits": m.size,
                        }
                    )
                result["members"] = members

        return result

    @mcp.tool()
    @session.require_open
    def parse_type_declaration(declaration: str) -> dict:
        """Parse a C type declaration and add it to the local type library.

        Named types (structs, enums, typedefs) are saved to the database.
        Anonymous types are parsed but not saved. May merge with existing
        types if the name already exists. After adding a type, use
        apply_type_at_address to apply it at specific addresses.

        Args:
            declaration: C type declaration (e.g. "struct foo { int x; char y; };").
        """
        til = ida_typeinf.get_idati()

        # parse_decls saves named types (structs, enums, typedefs) to the TIL.
        # It returns the number of errors (0 = success).
        count_before = ida_typeinf.get_ordinal_count(til)
        num_errors = ida_typeinf.parse_decls(til, declaration, None, ida_typeinf.HTI_DCL)
        if num_errors:
            # Fall back: try parse_decl for anonymous/simple type expressions
            tinfo = ida_typeinf.tinfo_t()
            result = ida_typeinf.parse_decl(tinfo, til, declaration, ida_typeinf.PT_TYP)
            if result is None:
                return {"error": "Failed to parse declaration", "error_type": "ParseError"}
            return {
                "declaration": str(tinfo),
                "size": safe_type_size(tinfo.get_size()),
                "saved": False,
                "message": "Anonymous type parsed but not saved to local types",
            }

        # Find any newly added named types
        count_after = ida_typeinf.get_ordinal_count(til)
        new_types = []
        for ordinal in range(count_before + 1, count_after + 1):
            name = ida_typeinf.get_numbered_type_name(til, ordinal)
            if name:
                tinfo = ida_typeinf.tinfo_t()
                tinfo.get_numbered_type(til, ordinal)
                new_types.append(
                    {
                        "name": name,
                        "ordinal": ordinal,
                        "declaration": str(tinfo),
                        "size": safe_type_size(tinfo.get_size()),
                    }
                )

        if len(new_types) == 1:
            return {**new_types[0], "saved": True}
        if new_types:
            return {"saved": True, "types": new_types}

        # No new ordinals — type may have been merged with existing
        tinfo = ida_typeinf.tinfo_t()
        ida_typeinf.parse_decl(tinfo, til, declaration, ida_typeinf.PT_TYP)
        return {
            "declaration": str(tinfo),
            "size": safe_type_size(tinfo.get_size()),
            "saved": True,
            "message": "Parsed and saved (type may have merged with existing)",
        }

    @mcp.tool()
    @session.require_open
    def delete_local_type(name: str) -> dict:
        """Delete a local type from the database.

        Args:
            name: Name of the local type to delete.
        """
        til = ida_typeinf.get_idati()
        ordinal = ida_typeinf.get_type_ordinal(til, name)
        if ordinal == 0:
            return {"error": f"Type not found: {name}", "error_type": "NotFound"}

        if not ida_typeinf.del_numbered_type(til, ordinal):
            return {
                "error": f"Failed to delete type: {name}",
                "error_type": "DeleteFailed",
            }
        return {
            "name": name,
            "ordinal": ordinal,
        }

    @mcp.tool()
    @session.require_open
    def delete_local_type_by_ordinal(ordinal: int) -> dict:
        """Delete a local type by its ordinal number.

        Useful for removing unnamed types that cannot be deleted by name.

        Args:
            ordinal: Ordinal number of the type to delete.
        """
        til = ida_typeinf.get_idati()
        count = ida_typeinf.get_ordinal_count(til)
        if ordinal < 1 or ordinal > count:
            return {
                "error": f"Ordinal {ordinal} out of range (1-{count})",
                "error_type": "NotFound",
            }

        name = ida_typeinf.get_numbered_type_name(til, ordinal) or ""
        if not ida_typeinf.del_numbered_type(til, ordinal):
            return {
                "error": f"Failed to delete type at ordinal {ordinal}",
                "error_type": "DeleteFailed",
            }
        return {
            "ordinal": ordinal,
            "name": name,
        }

    @mcp.tool()
    @session.require_open
    def apply_type_at_address(address: str, type_name: str) -> dict:
        """Apply a named type from the local type library at an address.

        Args:
            address: Address to apply the type at.
            type_name: Name of the type to apply.
        """
        ea, err = resolve_address(address)
        if err:
            return err

        til = ida_typeinf.get_idati()
        tinfo = ida_typeinf.tinfo_t()

        # Try to find the type by name
        ordinal = ida_typeinf.get_type_ordinal(til, type_name)
        if ordinal == 0:
            return {"error": f"Type not found: {type_name}", "error_type": "NotFound"}

        if not tinfo.get_numbered_type(til, ordinal):
            return {"error": f"Cannot load type: {type_name}", "error_type": "LoadError"}

        if not ida_typeinf.apply_tinfo(ea, tinfo, ida_typeinf.TINFO_DEFINITE):
            return {
                "error": f"Failed to apply type {type_name!r} at {format_address(ea)}",
                "error_type": "ApplyTypeFailed",
            }
        return {
            "address": format_address(ea),
            "type_name": type_name,
        }
