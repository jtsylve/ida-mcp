# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""IDA MCP error types.

Separated from ``helpers`` so that modules which cannot load idalib (e.g.
the supervisor process) can still raise structured errors.
"""

from __future__ import annotations

import json

from fastmcp.exceptions import ToolError


class IDAError(ToolError):
    """Raised when an IDA operation fails.

    Subclasses ``ToolError`` so fastmcp automatically returns ``isError=True``
    with the message as text content.  The *error_type* attribute preserves the
    existing error taxonomy (e.g. ``InvalidAddress``, ``NotFound``).

    Optional *details* carry structured context (valid values, available names,
    etc.).  ``__str__`` returns a JSON object so the MCP error text is
    machine-parseable — the supervisor's ``_parse_result`` decodes it
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
