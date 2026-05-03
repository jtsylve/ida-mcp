# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Shared worker-server infrastructure for re-mcp backends.

Provides :class:`MainThreadExecutor` (runs callables on the main thread via a
work queue), :func:`auto_title` (snake_case to Title Case), and
:class:`BackendServer` (FastMCP subclass that dispatches sync tools/resources
to the main thread).

Each backend subclasses :class:`BackendServer` with a backend-specific
``_UPPERCASE_WORDS`` set and a ``_dispatch`` import that resolves to the
backend's ``call_<backend>`` function.
"""

from __future__ import annotations

import concurrent.futures
import functools
import inspect
import logging
import queue
from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP
from fastmcp.tools.function_tool import FunctionTool

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Main-thread executor
# ---------------------------------------------------------------------------


class MainThreadExecutor(concurrent.futures.Executor):
    """Execute callables on the main thread via a work queue.

    The main thread calls :meth:`run_forever` which blocks, pulling work
    items from the queue and running them.  Other threads submit work via
    the standard :meth:`submit` interface.  ``asyncio``'s
    ``loop.run_in_executor`` works directly with this.

    Uses ``queue.get(timeout=1.0)`` so that POSIX signals (SIGTERM,
    SIGUSR1) are delivered between iterations on the main thread.
    """

    _SENTINEL = object()

    def __init__(self) -> None:
        self._queue: queue.Queue = queue.Queue()

    def submit(
        self, fn: Callable[..., Any], /, *args: Any, **kwargs: Any
    ) -> concurrent.futures.Future[Any]:
        f: concurrent.futures.Future = concurrent.futures.Future()
        self._queue.put((f, functools.partial(fn, *args, **kwargs)))
        return f

    def run_forever(self) -> None:
        """Block on the main thread, processing submitted work items."""
        while True:
            try:
                item = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            if item is self._SENTINEL:
                break
            f, fn = item
            if f.cancelled():
                continue
            try:
                result = fn()
            except BaseException as e:
                if not f.cancelled():
                    f.set_exception(e)
                if isinstance(e, (KeyboardInterrupt, SystemExit)):
                    raise
            else:
                if not f.cancelled():
                    f.set_result(result)

    def shutdown(self, wait: bool = True, *, cancel_futures: bool = False) -> None:
        self._queue.put(self._SENTINEL)


# ---------------------------------------------------------------------------
# Auto-titling helpers
# ---------------------------------------------------------------------------

# Common uppercase words shared across all backends.
_BASE_UPPERCASE_WORDS = frozenset(
    {
        "abi",
        "asm",
        "cfg",
        "elf",
        "exe",
        "io",
        "mcp",
        "pdb",
        "pe",
    }
)


def auto_title(name: str, uppercase_words: frozenset[str] = _BASE_UPPERCASE_WORDS) -> str:
    """Convert a snake_case tool name to a human-friendly title.

    ``get_xrefs_to`` -> ``"Get Xrefs To"``
    ``get_cfg_edges`` -> ``"Get CFG Edges"``
    """
    words = [w for w in name.split("_") if w]
    return " ".join(w.upper() if w in uppercase_words else w.title() for w in words)


def ensure_title(
    kwargs: dict[str, Any],
    name: str | None,
    fn: Callable[..., Any] | None,
    uppercase_words: frozenset[str] = _BASE_UPPERCASE_WORDS,
) -> None:
    """Set ``title`` in *kwargs* if not already present."""
    if "title" in kwargs and kwargs["title"] is not None:
        return
    tool_name = name or (fn.__name__ if fn else None)
    if tool_name:
        kwargs["title"] = auto_title(tool_name, uppercase_words)


# ---------------------------------------------------------------------------
# BackendServer (FastMCP subclass)
# ---------------------------------------------------------------------------


class BackendServer(FastMCP):
    """FastMCP subclass that dispatches sync tool/resource execution to the main thread.

    Subclasses must set :attr:`_uppercase_words` and implement :meth:`_dispatch`
    to point at the backend's main-thread dispatch function (e.g. ``call_ida``).
    """

    _uppercase_words: frozenset[str] = _BASE_UPPERCASE_WORDS

    async def _dispatch(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Dispatch *fn* to the main (backend) thread.

        Subclasses override this to import and call the backend-specific
        dispatch function (e.g. ``call_ida``, ``call_ghidra``).
        """
        raise NotImplementedError

    def _wrap_sync(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap a sync function so it runs on the main thread.

        Async functions are returned unchanged.
        """
        if inspect.iscoroutinefunction(fn):
            return fn

        server = self

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            return await server._dispatch(fn, *args, **kwargs)

        return wrapper

    def resource(self, uri: str, **kwargs: Any) -> Callable[[Callable[..., Any]], Any]:
        decorator = super().resource(uri, **kwargs)

        @functools.wraps(decorator)
        def wrapping_decorator(fn: Callable[..., Any]) -> Any:
            return decorator(self._wrap_sync(fn))

        return wrapping_decorator

    def tool(
        self, name_or_fn: str | Callable[..., Any] | None = None, **kwargs: Any
    ) -> Callable[[Callable[..., Any]], FunctionTool] | FunctionTool:
        uwords = self._uppercase_words

        if callable(name_or_fn):
            ensure_title(kwargs, None, name_or_fn, uwords)
            return super().tool(self._wrap_sync(name_or_fn), **kwargs)

        has_name = isinstance(name_or_fn, str)
        if has_name:
            ensure_title(kwargs, name_or_fn, None, uwords)
            dec = super().tool(name_or_fn, **kwargs)
        else:
            kwargs = {**kwargs}
            dec = None

        server = self

        def wrapping_decorator(fn: Callable[..., Any]) -> FunctionTool:
            d = dec
            if d is None:
                ensure_title(kwargs, None, fn, uwords)
                d = super(BackendServer, server).tool(None, **kwargs)
            return d(server._wrap_sync(fn))

        return wrapping_decorator
