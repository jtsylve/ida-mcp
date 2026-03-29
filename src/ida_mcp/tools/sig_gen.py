# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Signature generation tools."""

from __future__ import annotations

import idapro
from fastmcp import FastMCP

from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def generate_signatures(only_pat: bool = False) -> dict:
        """Generate FLIRT signature files (.sig and .pat) from the current database.

        Creates pattern/signature files that can be used to identify the same
        library functions in other binaries.

        Args:
            only_pat: If True, only generate .pat file (no .sig compilation).
        """
        if not hasattr(idapro, "make_signatures"):
            return {
                "error": "make_signatures is not available in this idalib version",
                "error_type": "NotAvailable",
            }

        try:
            success = idapro.make_signatures(only_pat)
        except Exception as e:
            return {"error": str(e), "error_type": "SignatureGenerationFailed"}

        if not success:
            return {
                "error": "Signature generation failed",
                "error_type": "SignatureGenerationFailed",
            }

        return {"status": "ok", "only_pat": only_pat}
