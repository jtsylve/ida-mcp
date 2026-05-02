# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Ghidra MCP worker process.

Each worker manages a single Ghidra program and exposes analysis
capabilities as MCP tools.  The supervisor spawns workers and routes
tool calls to the correct one.

**Threading model:** pyhidra/JPype starts the JVM on the main thread.
The MCP server's asyncio event loop runs on a daemon background thread.
All sync tool functions are dispatched to the main thread via
:func:`~ghidra_mcp.helpers.call_ghidra`.
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
    """Execute callables on the main thread via a work queue."""

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
# Sync → main-thread wrapper
# ---------------------------------------------------------------------------


def _wrap_sync(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a sync function so it is dispatched to the main thread."""
    if inspect.iscoroutinefunction(fn):
        return fn

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        from ghidra_mcp.helpers import call_ghidra  # noqa: PLC0415

        return await call_ghidra(fn, *args, **kwargs)

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
        "ghidra",
        "io",
        "mcp",
        "pdb",
        "pe",
    }
)


def _auto_title(name: str) -> str:
    """Convert a snake_case tool name to a human-friendly title."""
    words = [w for w in name.split("_") if w]
    return " ".join(w.upper() if w in _UPPERCASE_WORDS else w.title() for w in words)


def _ensure_title(kwargs: dict[str, Any], name: str | None, fn: Callable[..., Any] | None) -> None:
    if "title" in kwargs and kwargs["title"] is not None:
        return
    tool_name = name or (fn.__name__ if fn else None)
    if tool_name:
        kwargs["title"] = _auto_title(tool_name)


# ---------------------------------------------------------------------------
# GhidraServer (FastMCP subclass)
# ---------------------------------------------------------------------------


class GhidraServer(FastMCP):
    """FastMCP subclass that dispatches sync tool/resource execution to the main thread."""

    def resource(self, uri: str, **kwargs: Any) -> Callable[[Callable[..., Any]], Any]:
        decorator = super().resource(uri, **kwargs)

        @functools.wraps(decorator)
        def wrapping_decorator(fn: Callable[..., Any]) -> Any:
            return decorator(_wrap_sync(fn))

        return wrapping_decorator

    def tool(
        self, name_or_fn: str | Callable[..., Any] | None = None, **kwargs: Any
    ) -> Callable[[Callable[..., Any]], FunctionTool] | FunctionTool:
        if callable(name_or_fn):
            _ensure_title(kwargs, None, name_or_fn)
            return super().tool(_wrap_sync(name_or_fn), **kwargs)

        has_name = isinstance(name_or_fn, str)
        if has_name:
            _ensure_title(kwargs, name_or_fn, None)
            dec = super().tool(name_or_fn, **kwargs)
        else:
            kwargs = {**kwargs}
            dec = None

        def wrapping_decorator(fn: Callable[..., Any]) -> FunctionTool:
            d = dec
            if d is None:
                _ensure_title(kwargs, None, fn)
                d = super(GhidraServer, self).tool(None, **kwargs)
            return d(_wrap_sync(fn))

        return wrapping_decorator


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    """Entry point for the ``ghidra-mcp-worker`` script."""
    import ghidra_mcp  # noqa: PLC0415

    ghidra_mcp.configure_logging()
    ghidra_mcp.bootstrap()

    from ghidra_mcp import resources as ghidra_resources  # noqa: PLC0415
    from ghidra_mcp import tools as tools_pkg  # noqa: PLC0415
    from ghidra_mcp.helpers import set_main_executor  # noqa: PLC0415

    executor = MainThreadExecutor()
    set_main_executor(executor)

    mcp = GhidraServer(
        "Ghidra",
        instructions=(
            "Ghidra binary analysis server. Use open_database to load a binary "
            "before calling other tools. Addresses can be specified as hex strings "
            '(e.g. "0x401000"), bare hex ("4010a0"), decimal, or symbol names '
            '(e.g. "main").'
        ),
        on_duplicate="error",
    )

    ghidra_resources.register(mcp)
    tool_count = 0
    for _finder, module_name, _ispkg in pkgutil.iter_modules(tools_pkg.__path__):
        mod = importlib.import_module(f"ghidra_mcp.tools.{module_name}")
        if hasattr(mod, "register"):
            log.debug("Registering tool module: %s", module_name)
            mod.register(mcp)
            tool_count += 1
    log.info("Worker ready: registered %d tool modules", tool_count)

    def _run_mcp() -> None:
        try:
            mcp.run(transport="stdio")
        finally:
            executor.shutdown()

    mcp_thread = threading.Thread(target=_run_mcp, daemon=True, name="mcp-server")
    mcp_thread.start()
    log.info("MCP server started on daemon thread")

    try:
        executor.run_forever()
    except (KeyboardInterrupt, SystemExit):
        log.info("Main thread shutting down")
    finally:
        mcp_thread.join(timeout=5)

        from ghidra_mcp.session import session  # noqa: PLC0415

        if session.is_open():
            log.info("Saving database on shutdown: %s", session.current_path)
            try:
                session.close(save=True)
            except Exception:
                log.exception("Failed to save database on shutdown")


if __name__ == "__main__":
    main()
