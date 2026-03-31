# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Signature generation tools."""

from __future__ import annotations

import idapro
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import ANNO_MUTATE, META_WRITES_FILES, IDAError, tool_timeout
from ida_mcp.session import session


class GenerateSignaturesResult(BaseModel):
    """Result of generating signatures."""

    status: str = Field(description="Status message.")
    only_pat: bool = Field(description="Whether only .pat file was generated.")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"signatures"},
        timeout=tool_timeout("generate_signatures"),
        meta=META_WRITES_FILES,
    )
    @session.require_open
    def generate_signatures(only_pat: bool = False) -> GenerateSignaturesResult:
        """Generate FLIRT signature files (.sig and .pat) from the current database.

        Creates pattern/signature files that can be used to identify the same
        library functions in other binaries.

        Args:
            only_pat: If True, only generate .pat file (no .sig compilation).
        """
        if not hasattr(idapro, "make_signatures"):
            raise IDAError(
                "make_signatures is not available in this idalib version", error_type="NotAvailable"
            )

        try:
            success = idapro.make_signatures(only_pat)
        except Exception as e:
            raise IDAError(str(e), error_type="SignatureGenerationFailed") from e

        if not success:
            raise IDAError("Signature generation failed", error_type="SignatureGenerationFailed")

        return GenerateSignaturesResult(status="ok", only_pat=only_pat)
