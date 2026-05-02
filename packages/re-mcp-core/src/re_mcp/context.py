# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""FastMCP context helpers safe to import without a backend.

This module has no backend-specific dependencies, so both the supervisor
and worker processes can import from it freely.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastmcp.server.context import Context

log = logging.getLogger(__name__)


def try_get_context() -> Context | None:
    """Return the current FastMCP ``Context``, or ``None`` outside a request.

    Safe to call anywhere — never raises.  Use this in shared helpers that
    want to report progress or log without requiring a context parameter.
    """
    try:
        from fastmcp.server.dependencies import get_context  # noqa: PLC0415

        return get_context()
    except (RuntimeError, ImportError):
        return None


def try_get_session_id() -> str | None:
    """Return the current MCP session ID, or ``None`` outside a request.

    Convenience wrapper around :func:`try_get_context` — avoids the
    repetitive ``ctx = try_get_context(); sid = ctx.session_id if ctx else None``
    pattern in management tools and backend ``open_database`` implementations.
    """
    ctx = try_get_context()
    return ctx.session_id if ctx else None


async def notify_resources_changed() -> None:
    """Notify the client that the resource list has changed."""
    import mcp.types as types  # noqa: PLC0415

    ctx = try_get_context()
    if ctx is None:
        return
    try:
        await ctx.send_notification(types.ResourceListChangedNotification())
    except Exception:
        log.debug("Failed to send ResourceListChanged notification", exc_info=True)
