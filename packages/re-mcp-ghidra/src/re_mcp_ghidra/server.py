# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Ghidra MCP worker process.

Each worker manages a single Ghidra program and exposes analysis
capabilities as MCP tools.  The supervisor spawns workers and routes
tool calls to the correct one.

**Threading model:** pyghidra/JPype starts the JVM on the main thread.
The MCP server's asyncio event loop runs on a daemon background thread.
All sync tool functions are dispatched to the main thread via
:func:`~re_mcp_ghidra.helpers.call_ghidra`.
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
# Ghidra-specific uppercase words for auto-titling
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


# ---------------------------------------------------------------------------
# GhidraServer (BackendServer subclass)
# ---------------------------------------------------------------------------


class GhidraServer(BackendServer):
    """FastMCP subclass that dispatches sync tool/resource execution to the main thread."""

    _uppercase_words = _UPPERCASE_WORDS

    async def _dispatch(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        from re_mcp_ghidra.helpers import call_ghidra  # noqa: PLC0415

        return await call_ghidra(fn, *args, **kwargs)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    """Entry point for the ``re-mcp-ghidra-worker`` script."""
    import re_mcp_ghidra  # noqa: PLC0415

    re_mcp_ghidra.configure_logging()
    re_mcp_ghidra.bootstrap()

    from re_mcp_ghidra import resources as ghidra_resources  # noqa: PLC0415
    from re_mcp_ghidra import tools as tools_pkg  # noqa: PLC0415
    from re_mcp_ghidra.helpers import set_main_executor  # noqa: PLC0415

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
        mod = importlib.import_module(f"re_mcp_ghidra.tools.{module_name}")
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

        from re_mcp_ghidra.session import session  # noqa: PLC0415

        if session.is_open():
            log.info("Saving database on shutdown: %s", session.current_path)
            try:
                session.close(save=True)
            except Exception:
                log.exception("Failed to save database on shutdown")


if __name__ == "__main__":
    main()
