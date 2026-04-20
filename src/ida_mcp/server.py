# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""IDA Pro MCP worker process.

Each worker manages a single idalib database and exposes IDA's analysis
capabilities as MCP tools.  The supervisor (``supervisor.py``) spawns
workers and routes tool calls to the correct one.  This module can also
run standalone via the ``ida-mcp-worker`` entry point.

**Threading model:** idalib is thread-affine — the ``idapro`` import and
all subsequent IDA API calls must happen on the **main OS thread** (idalib
also registers signal handlers, which Python restricts to the main thread).

The MCP server's asyncio event loop runs on a **daemon background thread**.
All sync tool functions are dispatched to the main thread via
:func:`~ida_mcp.helpers.call_ida` (backed by a :class:`MainThreadExecutor`).
Async tools (like ``wait_for_analysis``) run on the event-loop thread and
dispatch individual IDA calls to the main thread as needed.

This separation ensures that IDA's auto-analysis engine gets dedicated
main-thread CPU time (no event-loop overhead), while the MCP server
remains responsive for incoming requests.
"""

from __future__ import annotations

import concurrent.futures
import functools
import importlib
import inspect
import logging
import pkgutil
import queue
import threading
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

    def submit(self, fn, /, *args, **kwargs):  # type: ignore[override]
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
                # Future may have been cancelled between the check above
                # and now; ignore InvalidStateError in that case.
                if not f.cancelled():
                    f.set_exception(e)
                # Let KeyboardInterrupt/SystemExit propagate so the
                # main-thread loop exits and main() can handle cleanup.
                if isinstance(e, (KeyboardInterrupt, SystemExit)):
                    raise
            else:
                if not f.cancelled():
                    f.set_result(result)

    def shutdown(self, wait: bool = True, *, cancel_futures: bool = False) -> None:
        self._queue.put(self._SENTINEL)


# ---------------------------------------------------------------------------
# Sync → main-thread wrapper
# ---------------------------------------------------------------------------


def _wrap_sync(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a sync function so it is dispatched to the main (idalib) thread.

    Async functions are returned unchanged — they run on the MCP event-loop
    thread and must use :func:`~ida_mcp.helpers.call_ida` for individual
    IDA API calls.
    """
    if inspect.iscoroutinefunction(fn):
        return fn

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        from ida_mcp.helpers import call_ida  # noqa: PLC0415

        return await call_ida(fn, *args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Auto-titling helpers
# ---------------------------------------------------------------------------

_UPPERCASE_WORDS = frozenset(
    {
        "abi",
        "asm",
        "cfg",
        "elf",
        "exe",
        "flirt",
        "ida",
        "idc",
        "ids",
        "io",
        "mcp",
        "pat",
    }
)


def _auto_title(name: str) -> str:
    """Convert a snake_case tool name to a human-friendly title.

    ``get_xrefs_to`` -> ``"Get Xrefs To"``
    ``get_cfg_edges`` -> ``"Get CFG Edges"``
    """
    words = [w for w in name.split("_") if w]
    return " ".join(w.upper() if w in _UPPERCASE_WORDS else w.title() for w in words)


def _ensure_title(kwargs: dict[str, Any], name: str | None, fn: Callable[..., Any] | None) -> None:
    """Set ``title`` in *kwargs* if not already present."""
    if "title" in kwargs and kwargs["title"] is not None:
        return
    tool_name = name or (fn.__name__ if fn else None)
    if tool_name:
        kwargs["title"] = _auto_title(tool_name)


# ---------------------------------------------------------------------------
# IDAServer (FastMCP subclass)
# ---------------------------------------------------------------------------


class IDAServer(FastMCP):
    """FastMCP subclass that dispatches sync tool/resource execution to the main thread."""

    def resource(self, uri: str, **kwargs: Any) -> Callable[[Callable[..., Any]], Any]:
        """Wrap sync resource functions so they run on the main (idalib) thread."""
        decorator = super().resource(uri, **kwargs)

        @functools.wraps(decorator)
        def wrapping_decorator(fn: Callable[..., Any]) -> Any:
            return decorator(_wrap_sync(fn))

        return wrapping_decorator

    def tool(
        self, name_or_fn: str | Callable[..., Any] | None = None, **kwargs: Any
    ) -> Callable[[Callable[..., Any]], FunctionTool] | FunctionTool:
        if callable(name_or_fn):
            # @mcp.tool  (no parentheses)
            _ensure_title(kwargs, None, name_or_fn)
            return super().tool(_wrap_sync(name_or_fn), **kwargs)

        # @mcp.tool()  or  @mcp.tool("name")  — returns a decorator.
        # When name is given we can inject the title now; otherwise we
        # defer until the decorated function is known.
        has_name = isinstance(name_or_fn, str)
        if has_name:
            _ensure_title(kwargs, name_or_fn, None)
            dec = super().tool(name_or_fn, **kwargs)
        else:
            # Copy kwargs so the closure owns its own dict — _ensure_title
            # mutates it when the decorated function is finally known.
            kwargs = {**kwargs}
            dec = None

        def wrapping_decorator(fn: Callable[..., Any]) -> FunctionTool:
            d = dec
            if d is None:
                _ensure_title(kwargs, None, fn)
                d = super(IDAServer, self).tool(None, **kwargs)
            return d(_wrap_sync(fn))

        return wrapping_decorator


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    """Entry point for the ``ida-mcp-worker`` script.

    Bootstrap idalib on the main thread, register all tools and resources,
    start the MCP server on a daemon thread, then enter the main-thread
    work loop that processes IDA tool calls.
    """
    import ida_mcp  # noqa: PLC0415

    ida_mcp.configure_logging()

    # bootstrap() loads idalib — must happen before any ida_* imports,
    # and is deferred to main() so that importing this module for its
    # pure helpers (e.g. _auto_title) doesn't trigger idalib init.
    ida_mcp.bootstrap()

    from ida_mcp import resources as ida_resources  # noqa: PLC0415
    from ida_mcp import tools as tools_pkg  # noqa: PLC0415
    from ida_mcp.helpers import set_main_executor  # noqa: PLC0415

    executor = MainThreadExecutor()
    set_main_executor(executor)

    mcp = IDAServer(
        "IDA Pro",
        instructions=(
            "IDA Pro binary analysis server. Use open_database to load a binary "
            "before calling other tools. Addresses can be specified as hex strings "
            '(e.g. "0x401000"), bare hex ("4010a0"), decimal, or symbol names '
            '(e.g. "main"). Use convert_number for base conversions instead of '
            "computing them yourself."
        ),
        on_duplicate="error",
    )

    ida_resources.register(mcp)
    tool_count = 0
    for _finder, module_name, _ispkg in pkgutil.iter_modules(tools_pkg.__path__):
        mod = importlib.import_module(f"ida_mcp.tools.{module_name}")
        if hasattr(mod, "register"):
            log.debug("Registering tool module: %s", module_name)
            mod.register(mcp)
            tool_count += 1
    log.info("Worker ready: registered %d tool modules", tool_count)

    # Start the MCP server on a daemon thread — it creates its own
    # asyncio event loop via anyio.run().  When the server exits (e.g.
    # stdin closes), shut down the executor so the main thread unblocks.
    #
    # daemon=True so that a hard signal (SIGKILL, unhandled SIGTERM) won't
    # hang waiting for the thread.  We join explicitly below so that under
    # normal shutdown the anyio event loop finishes tearing down stdio
    # before Python interpreter finalization runs — avoiding the
    # ``_enter_buffered_busy`` fatal error on the stdin BufferedReader.
    def _run_mcp() -> None:
        try:
            mcp.run(transport="stdio")
        finally:
            executor.shutdown()

    mcp_thread = threading.Thread(target=_run_mcp, daemon=True, name="mcp-server")
    mcp_thread.start()
    log.info("MCP server started on daemon thread")

    # Main thread: process IDA work dispatched from the MCP thread.
    try:
        executor.run_forever()
    except (KeyboardInterrupt, SystemExit):
        log.info("Main thread shutting down")
    finally:
        mcp_thread.join(timeout=5)

        from ida_mcp.session import session  # noqa: PLC0415

        if session.is_open():
            log.info("Saving database on shutdown: %s", session.current_path)
            try:
                session.close(save=True)
            except Exception:
                log.exception("Failed to save database on shutdown")


if __name__ == "__main__":
    main()
