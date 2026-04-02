# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""FastMCP context helpers safe to import without idalib.

This module has no ``ida_*`` dependencies, so both the supervisor and
worker processes can import from it freely.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastmcp.server.context import Context


def try_get_context() -> Context | None:
    """Return the current FastMCP ``Context``, or ``None`` outside a request.

    Safe to call anywhere -- never raises.  Use this in shared helpers that
    want to report progress or log without requiring a context parameter.
    """
    try:
        from fastmcp.server.dependencies import get_context  # noqa: PLC0415

        return get_context()
    except (RuntimeError, ImportError):
        return None
