# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Ghidra MCP error types and validation utilities.

Separated from ``helpers`` so that modules that cannot load Ghidra (e.g.
the supervisor process) can still raise structured errors and validate
parameters before spawning worker processes.
"""

from __future__ import annotations

from re_mcp.exceptions import BackendError


class GhidraError(BackendError):
    """Raised when a Ghidra operation fails.

    Subclasses ``BackendError`` so FastMCP automatically returns ``isError=True``
    with the message as text content.  The *error_type* attribute preserves the
    error taxonomy (e.g. ``InvalidAddress``, ``NotFound``).
    """


GHIDRA_PROJECT_EXTENSIONS: frozenset[str] = frozenset((".gpr",))
