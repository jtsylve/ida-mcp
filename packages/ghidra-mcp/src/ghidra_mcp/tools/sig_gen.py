# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Signature generation tools (stub -- IDA-specific feature)."""

from __future__ import annotations

from fastmcp import FastMCP

from ghidra_mcp.exceptions import GhidraError
from ghidra_mcp.helpers import ANNO_READ_ONLY
from ghidra_mcp.session import session


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"signatures"})
    @session.require_open
    def generate_signatures() -> None:
        """Generate FLIRT-style signatures (not available in Ghidra).

        FLIRT signature generation (.sig/.pat) is an IDA-specific feature.
        Ghidra uses Function ID (FID) databases for a similar purpose, but
        FID database creation is done through the Ghidra GUI or separate
        tooling, not through the headless API.

        Consider using ``apply_function_id`` to apply existing Function ID
        databases, or ``list_data_type_archives`` to explore available type
        archives.
        """
        raise GhidraError(
            "FLIRT signature generation is an IDA-specific feature. "
            "Ghidra uses Function ID (FID) databases instead. "
            "Use apply_function_id to apply existing FID databases.",
            error_type="NotAvailable",
        )
