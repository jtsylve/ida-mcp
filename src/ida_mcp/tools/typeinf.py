# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Type library management tools — local types, TILs, type parsing."""

from __future__ import annotations

import ida_typeinf
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    IDAError,
    Limit,
    Offset,
    async_paginate_iter,
    format_address,
    is_cancelled,
    resolve_address,
    safe_type_size,
)
from ida_mcp.models import PaginatedResult
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class LocalTypeSummary(BaseModel):
    """Brief local type info."""

    ordinal: int = Field(description="Type ordinal.")
    name: str = Field(description="Type name.")
    type: str = Field(description="Type string.")
    size: int | None = Field(description="Type size in bytes, or null if unknown.")
    is_struct: bool = Field(description="Whether type is a struct.")
    is_union: bool = Field(description="Whether type is a union.")
    is_enum: bool = Field(description="Whether type is an enum.")
    is_typedef: bool = Field(description="Whether type is a typedef.")


class LocalTypeListResult(PaginatedResult[LocalTypeSummary]):
    """Paginated list of local types."""

    items: list[LocalTypeSummary] = Field(description="Page of local types.")


class TypeMember(BaseModel):
    """A member of a struct/union type."""

    name: str = Field(description="Member name.")
    type: str = Field(description="Member type.")
    offset_bits: int = Field(description="Member offset in bits.")
    size_bits: int = Field(description="Member size in bits.")


class GetLocalTypeResult(BaseModel):
    """Detailed local type information."""

    name: str = Field(description="Type name.")
    ordinal: int = Field(description="Type ordinal.")
    declaration: str = Field(description="Full type declaration.")
    size: int | None = Field(description="Type size in bytes, or null if unknown.")
    is_struct: bool = Field(description="Whether type is a struct.")
    is_union: bool = Field(description="Whether type is a union.")
    is_enum: bool = Field(description="Whether type is an enum.")
    members: list[TypeMember] | None = Field(
        default=None, description="Members for struct/union/enum types."
    )


class ParsedTypeResult(BaseModel):
    """Result of parsing a type declaration."""

    name: str | None = Field(default=None, description="Type name.")
    ordinal: int | None = Field(default=None, description="Type ordinal.")
    declaration: str | None = Field(default=None, description="Parsed declaration.")
    size: int | None = Field(default=None, description="Type size in bytes.")
    saved: bool = Field(description="Whether the type was saved to local types.")
    message: str | None = Field(default=None, description="Additional info message.")
    types: list[dict] | None = Field(
        default=None, description="Multiple parsed types (for multi-type declarations)."
    )


class DeleteLocalTypeResult(BaseModel):
    """Result of deleting a local type."""

    name: str = Field(description="Deleted type name.")
    ordinal: int = Field(description="Deleted type ordinal.")
    old_declaration: str = Field(description="Previous type declaration.")


class ApplyTypeResult(BaseModel):
    """Result of applying a type at an address."""

    address: str = Field(description="Target address (hex).")
    old_type: str = Field(description="Previous type.")
    type_name: str = Field(description="Applied type name.")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"types"},
    )
    @session.require_open
    async def list_local_types(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> LocalTypeListResult:
        """List all local types defined in the database.

        Returns structs, unions, enums, and typedefs from the local type
        library. Large databases may have hundreds or thousands of types —
        use pagination or get_local_type to look up specific types by name.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        til = ida_typeinf.get_idati()
        count = ida_typeinf.get_ordinal_count(til)

        def _iter():
            for ordinal in range(1, count + 1):
                if is_cancelled():
                    return
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

        return LocalTypeListResult(
            **await async_paginate_iter(
                _iter(), offset, limit, progress_label="Listing local types"
            )
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"types"},
    )
    @session.require_open
    def get_local_type(name: str) -> GetLocalTypeResult:
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
            raise IDAError(f"Type not found: {name}", error_type="NotFound")

        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.get_numbered_type(til, ordinal):
            raise IDAError(f"Cannot load type: {name}", error_type="LoadError")

        is_struct = tinfo.is_struct()
        is_union = tinfo.is_union()

        members = None
        if is_struct or is_union:
            udt = ida_typeinf.udt_type_data_t()
            if tinfo.get_udt_details(udt):
                members = [
                    TypeMember(
                        name=udt[i].name,
                        type=str(udt[i].type),
                        offset_bits=udt[i].offset,
                        size_bits=udt[i].size,
                    )
                    for i in range(udt.size())
                ]

        return GetLocalTypeResult(
            name=name,
            ordinal=ordinal,
            declaration=str(tinfo),
            size=safe_type_size(tinfo.get_size()),
            is_struct=is_struct,
            is_union=is_union,
            is_enum=tinfo.is_enum(),
            members=members,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"types"},
    )
    @session.require_open
    def parse_type_declaration(declaration: str) -> ParsedTypeResult:
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
                raise IDAError("Failed to parse declaration", error_type="ParseError")
            return ParsedTypeResult(
                declaration=str(tinfo),
                size=safe_type_size(tinfo.get_size()),
                saved=False,
                message="Anonymous type parsed but not saved to local types",
            )

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
            return ParsedTypeResult(**new_types[0], saved=True)
        if new_types:
            return ParsedTypeResult(saved=True, types=new_types)

        # No new ordinals — type may have been merged with existing
        tinfo = ida_typeinf.tinfo_t()
        ida_typeinf.parse_decl(tinfo, til, declaration, ida_typeinf.PT_TYP)
        return ParsedTypeResult(
            declaration=str(tinfo),
            size=safe_type_size(tinfo.get_size()),
            saved=True,
            message="Parsed and saved (type may have merged with existing)",
        )

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"types"},
    )
    @session.require_open
    def delete_local_type(name: str) -> DeleteLocalTypeResult:
        """Delete a local type from the database.

        Args:
            name: Name of the local type to delete.
        """
        til = ida_typeinf.get_idati()
        ordinal = ida_typeinf.get_type_ordinal(til, name)
        if ordinal == 0:
            raise IDAError(f"Type not found: {name}", error_type="NotFound")

        tinfo = ida_typeinf.tinfo_t()
        old_declaration = ""
        if tinfo.get_numbered_type(til, ordinal):
            old_declaration = str(tinfo)

        if not ida_typeinf.del_numbered_type(til, ordinal):
            raise IDAError(f"Failed to delete type: {name}", error_type="DeleteFailed")
        return DeleteLocalTypeResult(
            name=name,
            ordinal=ordinal,
            old_declaration=old_declaration,
        )

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"types"},
    )
    @session.require_open
    def delete_local_type_by_ordinal(ordinal: int) -> DeleteLocalTypeResult:
        """Delete a local type by its ordinal number.

        Useful for removing unnamed types that cannot be deleted by name.

        Args:
            ordinal: Ordinal number of the type to delete.
        """
        til = ida_typeinf.get_idati()
        count = ida_typeinf.get_ordinal_count(til)
        if ordinal < 1 or ordinal > count:
            raise IDAError(f"Ordinal {ordinal} out of range (1-{count})", error_type="NotFound")

        name = ida_typeinf.get_numbered_type_name(til, ordinal) or ""
        tinfo = ida_typeinf.tinfo_t()
        old_declaration = ""
        if tinfo.get_numbered_type(til, ordinal):
            old_declaration = str(tinfo)

        if not ida_typeinf.del_numbered_type(til, ordinal):
            raise IDAError(f"Failed to delete type at ordinal {ordinal}", error_type="DeleteFailed")
        return DeleteLocalTypeResult(
            ordinal=ordinal,
            name=name,
            old_declaration=old_declaration,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"types"},
    )
    @session.require_open
    def apply_type_at_address(
        address: Address,
        type_name: str,
    ) -> ApplyTypeResult:
        """Apply a named type from the local type library at an address.

        Args:
            address: Address to apply the type at.
            type_name: Name of the type to apply.
        """
        ea = resolve_address(address)

        til = ida_typeinf.get_idati()
        tinfo = ida_typeinf.tinfo_t()

        # Try to find the type by name
        ordinal = ida_typeinf.get_type_ordinal(til, type_name)
        if ordinal == 0:
            raise IDAError(f"Type not found: {type_name}", error_type="NotFound")

        if not tinfo.get_numbered_type(til, ordinal):
            raise IDAError(f"Cannot load type: {type_name}", error_type="LoadError")

        old_tinfo = ida_typeinf.tinfo_t()
        old_type = ""
        if ida_typeinf.get_tinfo(old_tinfo, ea):
            old_type = str(old_tinfo)

        if not ida_typeinf.apply_tinfo(ea, tinfo, ida_typeinf.TINFO_DEFINITE):
            raise IDAError(
                f"Failed to apply type {type_name!r} at {format_address(ea)}",
                error_type="ApplyTypeFailed",
            )
        return ApplyTypeResult(
            address=format_address(ea),
            old_type=old_type,
            type_name=type_name,
        )
