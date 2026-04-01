# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""IDA MCP error types and shared constants.

Separated from ``helpers`` so that modules which cannot load idalib (e.g.
the supervisor process) can still raise structured errors and share timeout
configuration.
"""

from __future__ import annotations

import json

# ToolError is not re-exported from the top-level fastmcp package as of v3.1;
# if FastMCP reorganizes its internals this import path may need updating.
from fastmcp.exceptions import ToolError

# ---------------------------------------------------------------------------
# Tool timeout constants (seconds)
# ---------------------------------------------------------------------------
# Used by worker tool decorators (@mcp.tool(timeout=...)) for FastMCP's
# built-in timeout enforcement, and by the supervisor for MCP transport
# read timeouts and reaper thresholds.
#
# Tools not listed here use DEFAULT_TOOL_TIMEOUT.

DEFAULT_TOOL_TIMEOUT: float = 120.0

SLOW_TOOL_TIMEOUTS: dict[str, float] = {
    "open_database": 600.0,
    "wait_for_analysis": 600.0,
    "export_all_disassembly": 300.0,
    "export_all_pseudocode": 300.0,
    "generate_signatures": 300.0,
    "save_database": 300.0,
}


def tool_timeout(name: str) -> float:
    """Return the timeout in seconds for the named tool."""
    return SLOW_TOOL_TIMEOUTS.get(name, DEFAULT_TOOL_TIMEOUT)


class IDAError(ToolError):
    """Raised when an IDA operation fails.

    Subclasses ``ToolError`` so fastmcp automatically returns ``isError=True``
    with the message as text content.  The *error_type* attribute preserves the
    existing error taxonomy (e.g. ``InvalidAddress``, ``NotFound``).

    Optional *details* carry structured context (valid values, available names,
    etc.).  ``__str__`` returns a JSON object so the MCP error text is
    machine-parseable — the supervisor's ``parse_result`` decodes it
    transparently.
    """

    def __init__(self, message: str, error_type: str = "Error", **details: object):
        super().__init__(message)
        self.error_type = error_type
        self.details = details

    def __str__(self) -> str:
        d: dict[str, object] = {"error": self.args[0], "error_type": self.error_type}
        if self.details:
            d.update(self.details)
        return json.dumps(d, separators=(",", ":"))
