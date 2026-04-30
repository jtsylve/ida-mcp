# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Base error types for re-mcp backends."""

from __future__ import annotations

import json

from fastmcp.exceptions import ToolError


class BackendError(ToolError):
    """Base error for all backend operations.

    Subclasses ``ToolError`` so FastMCP automatically returns ``isError=True``
    with the message as text content.  The *error_type* attribute preserves
    an error taxonomy (e.g. ``InvalidAddress``, ``NotFound``).

    ``__str__`` returns a JSON object so the MCP error text is
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
