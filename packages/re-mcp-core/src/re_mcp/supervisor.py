# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Multi-database supervisor for re-mcp backends.

Spawns one worker subprocess per open database and proxies MCP tool calls
and resource reads to the appropriate worker via the ``WorkerPoolProvider``.

All tools except management tools (``open_database``, ``close_database``,
``save_database``, ``list_databases``, ``wait_for_analysis``,
``list_targets``) require the ``database`` parameter (the stem ID
returned by ``open_database`` or ``list_databases``).

The supervisor never imports backend-specific modules directly — it loads
the backend via the :class:`Backend` protocol.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import signal
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastmcp import FastMCP
from fastmcp.server.context import Context

if TYPE_CHECKING:
    from fastmcp.server.auth.auth import AuthProvider
    from fastmcp.server.lifespan import Lifespan
    from fastmcp.server.server import LifespanCallable

from re_mcp.backend import Backend, get_backend
from re_mcp.context import notify_resources_changed, try_get_session_id
from re_mcp.transforms import ToolTransform, run_with_heartbeat
from re_mcp.worker_provider import (
    WorkerPoolProvider,
    parse_result,
    require_success,
)

log = logging.getLogger(__name__)

_HANDLED_SIGNALS = ("SIGINT", "SIGTERM", "SIGHUP")


# ---------------------------------------------------------------------------
# ProxyMCP
# ---------------------------------------------------------------------------


_UNSET: object = object()


class ProxyMCP(FastMCP):
    """MCP server that proxies tool calls to per-database worker processes."""

    def __init__(
        self,
        *,
        backend: type[Backend],
        auth: AuthProvider | None = None,
        lifespan: LifespanCallable | Lifespan | None | object = _UNSET,
    ):
        info = backend.info()
        transform = ToolTransform(
            pinned=info.pinned_tools,
            env_prefix=info.env_prefix,
        )
        super().__init__(
            info.display_name,
            instructions=backend.build_instructions(transform),
            on_duplicate="error",
            lifespan=self._lifespan_signal_handlers if lifespan is _UNSET else lifespan,
            auth=auth,
        )
        self._backend = backend
        self._backend_info = info
        self._worker_pool = WorkerPoolProvider(backend=backend)
        self.add_provider(self._worker_pool)
        self._register_generic_management_tools()
        backend.register_management_tools(self, self._worker_pool)
        self._register_supervisor_resources()
        backend.register_prompts(self)
        self.add_transform(transform)

    @property
    def worker_pool(self) -> WorkerPoolProvider:
        return self._worker_pool

    @staticmethod
    @asynccontextmanager
    async def _lifespan_signal_handlers(_app: FastMCP) -> AsyncIterator[None]:
        loop = asyncio.get_running_loop()
        _install_signal_handlers(loop)
        try:
            yield
        finally:
            for sig_name in _HANDLED_SIGNALS:
                sig = getattr(signal, sig_name, None)
                if sig is not None:
                    with contextlib.suppress(NotImplementedError, OSError, ValueError):
                        loop.remove_signal_handler(sig)

    # ------------------------------------------------------------------
    # Generic management tools
    # ------------------------------------------------------------------

    def _register_generic_management_tools(self):
        pool = self._worker_pool

        @self.tool(annotations={"title": "Close Database"})
        async def close_database(
            save: bool = True,
            force: bool = False,
            database: str = "",
        ) -> dict:
            """Close a database and terminate its worker process.

            Specify *database* when multiple are open. Fails if the DB is
            not attached to the current session unless force=True. When other
            sessions still use the DB, detaches this session but keeps the
            worker alive.
            """
            worker = pool.resolve_worker(database)
            result = await pool.close_for_session(
                worker, try_get_session_id(), save=save, force=force
            )
            if result.get("status") != "detached":
                await notify_resources_changed()
            return result

        @self.tool(annotations={"title": "Save Database"})
        async def save_database(
            outfile: str = "",
            flags: int = -1,
            force: bool = False,
            database: str = "",
            ctx: Context | None = None,
        ) -> dict:
            """Save the current database to disk (may take minutes for large DBs).

            Specify *database* when multiple are open. Fails if the DB is
            not attached to the current session unless force=True. Progress
            notifications are sent every 5s during long saves.
            """
            worker = pool.resolve_worker(database)
            if not force:
                pool.check_attached(worker, try_get_session_id())

            proxy_task = asyncio.create_task(
                pool.proxy_to_worker(worker, "save_database", {"outfile": outfile, "flags": flags})
            )
            await run_with_heartbeat(proxy_task, ctx)
            result = proxy_task.result()
            result_data = parse_result(result)
            result_data["database"] = worker.database_id
            require_success(result, result_data, "Save failed")
            return result_data

        @self.tool(annotations={"title": "List Databases"})
        async def list_databases() -> dict:
            """List all open databases with metadata (includes opening/analyzing status)."""
            return pool.build_database_list(caller_session_id=try_get_session_id())

        @self.tool(annotations={"title": "Wait for Analysis"})
        async def wait_for_analysis(
            database: str = "",
            databases: list[str] | None = None,
        ) -> dict:
            """Block until database(s) finish opening and optional auto-analysis.

            **Single:** pass ``database`` to wait for one DB.
            **Multi:** pass ``databases`` list — returns when **at least one**
            is ready. Work on the ready one, call again for the rest.

            While analysis runs, the backend thread is blocked — tool calls queue.

            Args:
                database: Single database ID to wait for.
                databases: List of database IDs (returns when first is ready).
            """
            if databases:
                return await pool.wait_for_ready_multi(databases)
            return await pool.wait_for_ready(database)

        @self.tool(annotations={"title": "List Targets"})
        async def list_targets() -> dict:
            """List available targets (processors, loaders, languages, etc.)."""
            return self._backend.list_targets()

    # ------------------------------------------------------------------
    # Supervisor-owned resources
    # ------------------------------------------------------------------

    def _register_supervisor_resources(self):
        pool = self._worker_pool
        scheme = self._backend_info.uri_scheme

        @self.resource(
            f"{scheme}://databases",
            description="All open databases with worker status (supervisor-level)",
        )
        async def databases_resource() -> str:
            return json.dumps(pool.build_database_list(include_state=True), separators=(",", ":"))


def _install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    """Register signal handlers on the running event loop."""

    def _handler(sig: signal.Signals) -> None:
        log.info("Received %s; initiating shutdown", sig.name)
        loop.stop()

    for sig_name in _HANDLED_SIGNALS:
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, _handler, sig)
        except (NotImplementedError, OSError, ValueError):
            log.debug("Could not install handler for %s", sig_name, exc_info=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    import argparse  # noqa: PLC0415

    from re_mcp import configure_logging, get_version  # noqa: PLC0415

    backend_name = os.environ.get("RE_MCP_BACKEND")

    parser = argparse.ArgumentParser(
        prog="re-mcp",
        description="Reverse-engineering MCP server",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {get_version()}")
    parser.add_argument(
        "--backend",
        default=backend_name,
        help="Backend name (auto-detected if only one is installed)",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser(
        "proxy",
        help="Stdio proxy to a persistent HTTP daemon",
    )

    serve_cmd = sub.add_parser("serve", help="Start persistent streamable HTTP daemon")
    serve_cmd.add_argument("--port", type=int, default=0, help="Port to bind (0 = auto)")
    serve_cmd.add_argument("--host", default="127.0.0.1", help="Host to bind (default 127.0.0.1)")

    def _nonneg_int(value: str) -> int:
        n = int(value)
        if n < 0:
            raise argparse.ArgumentTypeError("must be >= 0")
        return n

    serve_cmd.add_argument(
        "--idle-timeout",
        type=_nonneg_int,
        default=0,
        help="Auto-shutdown after N seconds with no connections (0 = disabled).",
    )

    sub.add_parser(
        "stdio",
        help="Direct stdio mode — workers die on disconnect (default when no command given)",
    )
    sub.add_parser("stop", help="Stop the running daemon")
    sub.add_parser("backends", help="List installed backends")

    args = parser.parse_args()

    if args.command == "backends":
        from re_mcp.backend import discover_backends  # noqa: PLC0415

        backends = discover_backends()
        if not backends:
            print("No backends installed.")
        else:
            for name in sorted(backends):
                info = backends[name].info()
                print(f"  {name}: {info.display_name}")
        return

    try:
        backend = get_backend(args.backend)
    except RuntimeError as exc:
        parser.error(str(exc))

    deprecation_msg = os.environ.pop("_RE_MCP_DEPRECATED_CLI", None)
    if deprecation_msg:
        configure_logging(env_prefix=backend.info().env_prefix)
        log.warning(deprecation_msg)

    if args.command == "serve":
        from re_mcp.daemon import serve  # noqa: PLC0415

        serve(backend=backend, host=args.host, port=args.port, idle_timeout=args.idle_timeout)
    elif args.command == "stop":
        from re_mcp.proxy import stop  # noqa: PLC0415

        if stop(backend=backend):
            print("Daemon stopped.")
        else:
            print("No daemon is running.")
    elif args.command == "proxy":
        from re_mcp.proxy import main as proxy_main  # noqa: PLC0415

        proxy_main(backend=backend)
    else:
        configure_logging(env_prefix=backend.info().env_prefix)
        ProxyMCP(backend=backend).run(transport="stdio")


if __name__ == "__main__":
    main()
