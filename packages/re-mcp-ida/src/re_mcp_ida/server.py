# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""IDA Pro MCP worker process.

Each worker manages a single idalib database and exposes IDA's analysis
capabilities as MCP tools.  The supervisor (``re_mcp.supervisor``) spawns
workers and routes tool calls to the correct one.  This module can also
run standalone via the ``re-mcp-ida-worker`` entry point.

**Threading model:** idalib is thread-affine — the ``idapro`` import and
all subsequent IDA API calls must happen on the **main OS thread** (idalib
also registers signal handlers, which Python restricts to the main thread).

The MCP server's asyncio event loop runs on a **daemon background thread**.
All sync tool functions are dispatched to the main thread via
:func:`~re_mcp_ida.helpers.call_ida` (backed by a :class:`MainThreadExecutor`).
Async tools (like ``wait_for_analysis``) run on the event-loop thread and
dispatch individual IDA calls to the main thread as needed.

This separation ensures that IDA's auto-analysis engine gets dedicated
main-thread CPU time (no event-loop overhead), while the MCP server
remains responsive for incoming requests.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
import threading
from collections.abc import Callable
from typing import Any

from re_mcp.server import BackendServer, MainThreadExecutor

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# IDA-specific uppercase words for auto-titling
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


# ---------------------------------------------------------------------------
# IDAServer (BackendServer subclass)
# ---------------------------------------------------------------------------


class IDAServer(BackendServer):
    """FastMCP subclass that dispatches sync tool/resource execution to the main thread."""

    _uppercase_words = _UPPERCASE_WORDS

    async def _dispatch(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        from re_mcp_ida.helpers import call_ida  # noqa: PLC0415

        return await call_ida(fn, *args, **kwargs)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    """Entry point for the ``re-mcp-ida-worker`` script.

    Bootstrap idalib on the main thread, register all tools and resources,
    start the MCP server on a daemon thread, then enter the main-thread
    work loop that processes IDA tool calls.
    """
    import re_mcp_ida  # noqa: PLC0415

    re_mcp_ida.configure_logging()

    # bootstrap() loads idalib — must happen before any ida_* imports,
    # and is deferred to main() so that importing this module for its
    # class definitions doesn't trigger idalib init.
    re_mcp_ida.bootstrap()

    from re_mcp_ida import resources as ida_resources  # noqa: PLC0415
    from re_mcp_ida import tools as tools_pkg  # noqa: PLC0415
    from re_mcp_ida.helpers import set_main_executor  # noqa: PLC0415

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
        mod = importlib.import_module(f"re_mcp_ida.tools.{module_name}")
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

        from re_mcp_ida.session import session  # noqa: PLC0415

        if session.is_open():
            log.info("Saving database on shutdown: %s", session.current_path)
            try:
                session.close(save=True)
            except Exception:
                log.exception("Failed to save database on shutdown")


if __name__ == "__main__":
    main()
