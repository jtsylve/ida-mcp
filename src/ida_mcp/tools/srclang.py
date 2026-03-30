# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Source language parsing tools — import C/C++ type declarations via compiler parsers."""

from __future__ import annotations

import ida_srclang
import ida_typeinf
from fastmcp import FastMCP

from ida_mcp.helpers import IDAError
from ida_mcp.session import session

_LANG_MAP = {
    "c": ida_srclang.SRCLANG_C,
    "cpp": ida_srclang.SRCLANG_CPP,
    "c++": ida_srclang.SRCLANG_CPP,
    "objc": ida_srclang.SRCLANG_OBJC,
    "objective-c": ida_srclang.SRCLANG_OBJC,
    "swift": ida_srclang.SRCLANG_SWIFT,
    "go": ida_srclang.SRCLANG_GO,
}


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def get_source_parser() -> dict:
        """Get the name of the currently selected source language parser.

        Returns the name of the parser (e.g. "clang") used for parsing
        C/C++ type declarations. Returns empty string if no parser is active.
        """
        name = ida_srclang.get_selected_parser_name()
        return {"parser": name or ""}

    @mcp.tool()
    @session.require_open
    def parse_source_declarations(
        source: str,
        language: str = "c",
        is_path: bool = False,
        parser_name: str = "",
    ) -> dict:
        """Parse C/C++ source declarations and import types into the database.

        Uses an installed compiler parser (e.g. Clang) to parse type
        declarations from inline source code or a file. Successfully parsed
        types are added to the current type library and become available
        for type application.

        Args:
            source: C/C++ source code string, or a file path if is_path=true.
            language: Source language — "c", "cpp"/"c++", "objc", "swift", "go".
                      Ignored if parser_name is specified.
            is_path: If true, source is interpreted as a file path.
            parser_name: Use a specific parser by name instead of auto-selecting
                         by language. Leave empty to auto-select.

        Returns:
            error_count: Number of parse errors (0 = fully clean).
            status: "parsed_ok" or "parsed_with_errors".
        """
        til = ida_typeinf.get_idati()

        if parser_name:
            rc = ida_srclang.parse_decls_with_parser(parser_name, til, source, is_path)
            if rc == -1:
                raise IDAError(f"No parser found with name {parser_name!r}", error_type="NotFound")
        else:
            lang_key = language.lower()
            if lang_key not in _LANG_MAP:
                raise IDAError(
                    f"Unknown language {language!r}. Use: {', '.join(sorted(_LANG_MAP))}",
                    error_type="InvalidArgument",
                )
            lang_id = _LANG_MAP[lang_key]
            rc = ida_srclang.parse_decls_for_srclang(lang_id, til, source, is_path)
            if rc == -1:
                raise IDAError(
                    f"No parser available for language {language!r}", error_type="NotFound"
                )

        return {
            "error_count": rc,
            "status": "parsed_ok" if rc == 0 else "parsed_with_errors",
        }
