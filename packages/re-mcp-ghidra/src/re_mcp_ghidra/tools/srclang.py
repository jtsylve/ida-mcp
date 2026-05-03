# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Source language parsing tools -- import C declarations via Ghidra's CParser."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import ANNO_MUTATE
from re_mcp_ghidra.session import session


class ParseSourceResult(BaseModel):
    """Result of parsing source declarations."""

    status: str = Field(description="Status message.")
    type_name: str = Field(description="Parsed type name, if available.")
    kind: str = Field(description="Type kind (struct, union, enum, typedef, other).")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"types"})
    @session.require_open
    def parse_source_declarations(
        source: str,
        language: str = "c",
    ) -> ParseSourceResult:
        """Parse C source declarations and import types into the program's type manager.

        Uses Ghidra's CParser to parse C type declarations. Parsed types
        are added to the program's data type manager and become available
        for application at addresses.

        Note: Ghidra's built-in parser supports C declarations only.
        The language parameter is accepted for API compatibility but
        currently only "c" is supported.

        Args:
            source: C source code string containing type declarations
                (e.g. "typedef int DWORD;" or "struct point { int x; int y; };").
            language: Source language (only "c" is currently supported).
        """
        from ghidra.app.util.cparser import CParser  # noqa: PLC0415
        from ghidra.program.model.data import (  # noqa: PLC0415
            Enum,
            Structure,
            TypeDef,
            Union,
        )

        if language.lower() != "c":
            raise GhidraError(
                f"Only C declarations are supported, got language={language!r}",
                error_type="InvalidArgument",
            )

        program = session.program
        dtm = program.getDataTypeManager()

        tx_id = program.startTransaction("Parse source declarations")
        try:
            parser = CParser(dtm)
            dt = parser.parse(source)
            if dt is None:
                program.endTransaction(tx_id, False)
                raise GhidraError(
                    f"Failed to parse source: {source!r}",
                    error_type="ParseError",
                )
            dtm.addDataType(dt, None)
            program.endTransaction(tx_id, True)

            kind = "other"
            if isinstance(dt, Structure):
                kind = "struct"
            elif isinstance(dt, Union):
                kind = "union"
            elif isinstance(dt, Enum):
                kind = "enum"
            elif isinstance(dt, TypeDef):
                kind = "typedef"

            return ParseSourceResult(
                status="parsed",
                type_name=dt.getName(),
                kind=kind,
            )
        except GhidraError:
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to parse source: {e}", error_type="ParseError") from e
