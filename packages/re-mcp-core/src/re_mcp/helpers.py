# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Shared utilities for address parsing, formatting, pagination, and tool annotations.

Backend-agnostic helpers consumed by both the supervisor and backend
helper modules.  Nothing here imports ``ida_*``, ``ghidra``, or any
other backend-specific package, so this module is safe to import
everywhere.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import functools
import logging
import re
import threading
from collections.abc import Callable, Iterable
from typing import Annotated, Any

from pydantic import Field

from re_mcp.exceptions import BackendError

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Main-thread dispatch for single-threaded backends (idalib, Ghidra/JVM)
# ---------------------------------------------------------------------------

_main_executor: concurrent.futures.Executor | None = None


def set_main_executor(executor: concurrent.futures.Executor) -> None:
    """Set the executor that dispatches work to the main (backend) thread."""
    global _main_executor  # noqa: PLW0603
    _main_executor = executor


async def dispatch_to_main(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Dispatch a sync function to the main thread and await the result.

    When no executor is configured (tests, standalone mode) or the caller
    is already on the main thread, the function is called directly to avoid
    deadlock.
    """
    if _main_executor is None or threading.current_thread() is threading.main_thread():
        return fn(*args, **kwargs)
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_main_executor, functools.partial(fn, *args, **kwargs))


# ---------------------------------------------------------------------------
# Reusable Annotated type aliases for tool parameters
# ---------------------------------------------------------------------------

Address = Annotated[str, Field(description="Address (hex string, decimal, or symbol name).")]
Offset = Annotated[int, Field(description="Pagination offset.", ge=0)]
Limit = Annotated[int, Field(description="Maximum number of results.", ge=1)]
FilterPattern = Annotated[str, Field(description="Optional regex to filter results.")]
HexBytes = Annotated[str, Field(description="Hex string of bytes (e.g. '90 90 90' or '909090').")]

# ---------------------------------------------------------------------------
# MCP tool annotation presets (readOnlyHint, destructiveHint, etc.)
# ---------------------------------------------------------------------------

ANNO_READ_ONLY: dict[str, bool] = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
ANNO_MUTATE: dict[str, bool] = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
ANNO_MUTATE_NON_IDEMPOTENT: dict[str, bool] = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": False,
}
ANNO_DESTRUCTIVE: dict[str, bool] = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": False,
}

# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

_COUNT_AHEAD = 10_000


# ---------------------------------------------------------------------------
# Address parsing & formatting
# ---------------------------------------------------------------------------


def parse_address(addr: str | int) -> int:
    """Parse a numeric address from various formats.

    Accepts:
    - Hex with prefix: "0x401000"
    - Decimal (pure digits): "4198400"
    - Bare hex (fallback): "4010a0"

    Symbol name resolution is backend-specific and not handled here.
    Backend helpers extend this with symbol lookup when needed.
    """
    if isinstance(addr, int):
        return addr

    addr = addr.strip()
    if not addr:
        raise ValueError("Empty address")

    if addr.lower().startswith("0x"):
        return int(addr, 16)

    if addr.isdigit():
        return int(addr)

    if HEX_RE.match(addr):
        return int(addr, 16)

    raise ValueError(f"Cannot parse address: {addr!r}")


def format_address(ea: int) -> str:
    """Format an address as a hex string."""
    return f"0x{ea:X}"


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


def paginate(items: list, offset: int = 0, limit: int = 100) -> dict:
    """Apply pagination to a list of items."""
    offset = max(0, offset)
    limit = max(1, limit)
    total = len(items)
    sliced = items[offset : offset + limit]
    return {
        "items": sliced,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": offset + limit < total,
    }


def paginate_iter(items: Iterable[Any], offset: int = 0, limit: int = 100) -> dict:
    """Apply pagination to an iterable without materializing the full list.

    Unlike ``paginate``, this consumes a generator/iterator one item at a time,
    keeping only the current page in memory.  Use for large collections where
    building a complete list would be wasteful.

    After the requested page is collected the iterator is consumed for at most
    ``_COUNT_AHEAD`` additional items to determine *has_more* and provide a
    bounded *total*.  If the iterator is longer than that, *total* reports the
    items seen so far and *has_more* is ``True``.
    """
    offset = max(0, offset)
    limit = max(1, limit)
    result: list = []
    total = 0
    it = iter(items)

    for item in it:
        if total >= offset:
            result.append(item)
            total += 1
            if len(result) >= limit:
                break
            continue
        total += 1

    has_more = False
    for _item in it:
        total += 1
        if total - offset - limit >= _COUNT_AHEAD:
            has_more = True
            break
    else:
        has_more = offset + limit < total

    return {
        "items": result,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": has_more,
    }


async def async_paginate_iter(
    items: Iterable[Any],
    offset: int = 0,
    limit: int = 100,
) -> dict:
    """Async version of :func:`paginate_iter`.

    Dispatches the entire iteration to the main (backend) thread via
    :func:`dispatch_to_main`, so lazy iterators that make backend API
    calls execute safely.
    """
    return await dispatch_to_main(paginate_iter, items, offset, limit)


# ---------------------------------------------------------------------------
# Filter compilation
# ---------------------------------------------------------------------------


def compile_filter(pattern: str) -> re.Pattern | None:
    """Compile an optional regex filter pattern.

    Returns the compiled pattern, or ``None`` if *pattern* is empty (match everything).
    Raises :class:`BackendError` with ``error_type="InvalidArgument"`` on bad regex.
    """
    if not pattern:
        return None
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        raise BackendError(f"Invalid regex: {e}", error_type="InvalidArgument") from e
