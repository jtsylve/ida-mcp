# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Multi-database supervisor for the IDA MCP server.

Spawns one worker subprocess per open database and proxies MCP tool calls
and resource reads to the appropriate worker via the ``WorkerPoolProvider``.
Prompts are registered directly on the supervisor.

All tools except management tools (``open_database``, ``close_database``,
``save_database``, ``list_databases``, ``wait_for_analysis``,
``list_targets``) require the ``database`` parameter (the stem ID
returned by ``open_database`` or ``list_databases``).

The supervisor never imports ``idapro`` or any ``ida_*`` module.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import platform as plat
import signal
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import mcp.types as types
from fastmcp import FastMCP
from fastmcp.server.context import Context

if TYPE_CHECKING:
    from fastmcp.server.auth.auth import AuthProvider
    from fastmcp.server.lifespan import Lifespan
    from fastmcp.server.server import LifespanCallable

from ida_mcp import find_ida_dir
from ida_mcp.context import try_get_context
from ida_mcp.exceptions import (
    IDAError,
    build_ida_args,
    check_fat_binary,
    check_processor_ambiguity,
)
from ida_mcp.prompts import register_all as register_prompts
from ida_mcp.transforms import IDAToolTransform, run_with_heartbeat
from ida_mcp.worker_provider import (
    WorkerPoolProvider,
    parse_result,
    require_success,
)

log = logging.getLogger(__name__)

# Signals handled by the supervisor lifespan.  Defined once so install and
# teardown iterate the same set.
_HANDLED_SIGNALS = ("SIGINT", "SIGTERM", "SIGHUP")

# Shared lib extension for the current platform.
_DYLIB_EXT = {"Darwin": ".dylib", "Windows": ".dll"}.get(plat.system(), ".so")


def _list_module_names(directory: str) -> list[str]:
    """List IDA plugin module names (stem of .dylib/.so/.dll and .py files)."""
    if not os.path.isdir(directory):
        return []
    names: set[str] = set()
    for entry in os.listdir(directory):
        stem, ext = os.path.splitext(entry)
        if ext in (_DYLIB_EXT, ".py"):
            names.add(stem)
    return sorted(names)


def _list_targets() -> dict:
    """Enumerate available processors and loaders from the IDA installation."""
    ida_dir = find_ida_dir()
    if ida_dir is None:
        raise IDAError("IDA Pro installation not found", error_type="NotFound")
    return {
        "processors": _list_module_names(os.path.join(ida_dir, "procs")),
        "loaders": _list_module_names(os.path.join(ida_dir, "loaders")),
    }


def _session_id() -> str | None:
    """Extract the session ID from the current FastMCP context, or ``None``."""
    ctx = try_get_context()
    return ctx.session_id if ctx else None


# ---------------------------------------------------------------------------
# ProxyMCP
# ---------------------------------------------------------------------------


_UNSET: object = object()


class ProxyMCP(FastMCP):
    """MCP server that proxies tool calls to per-database worker processes."""

    def __init__(
        self,
        *,
        auth: AuthProvider | None = None,
        lifespan: LifespanCallable | Lifespan | None | object = _UNSET,
    ):
        transform = IDAToolTransform()
        super().__init__(
            "IDA Pro",
            instructions=self._build_instructions(transform),
            on_duplicate="error",
            lifespan=self._lifespan_signal_handlers if lifespan is _UNSET else lifespan,
            auth=auth,
        )
        self._worker_pool = WorkerPoolProvider()
        self.add_provider(self._worker_pool)
        self._register_management_tools()
        self._register_supervisor_resources()
        register_prompts(self)
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
    # Instructions
    # ------------------------------------------------------------------

    @staticmethod
    def _build_instructions(transform: IDAToolTransform) -> str:
        has_tool_search = transform._enable_tool_search
        has_batch = transform._enable_batch
        has_execute = transform._enable_execute

        sections: list[str] = []

        sections.append("IDA Pro binary analysis server with multi-database support.")

        sections.append(
            "## Opening databases\n"
            "open_database returns immediately — call wait_for_analysis "
            "before using other tools. Multiple databases load concurrently; "
            "pass databases=[...] to wait_for_analysis to wait for several "
            "at once (returns when at least one is ready).\n\n"
            "file_path accepts raw binaries or existing .i64/.idb databases. "
            "The binary must be in a writable directory. "
            "Fat Mach-O binaries require explicit fat_arch=."
        )

        sections.append(
            "## Addressing\n"
            "All tools except management tools require the database "
            "parameter (stem ID from open_database/list_databases). "
            'Addresses accept hex ("0x401000"), bare hex ("4010a0"), '
            'decimal, or symbol names ("main").'
        )

        sections.append(
            "## Resources\n"
            "Paginated read-only access via URIs: "
            "ida://<database>/idb/imports, .../exports, .../entrypoints. "
            "Each has a /search/{pattern} variant for regex filtering."
        )

        call_lines = ["## Call patterns"]
        if has_tool_search:
            call_lines.append("ONE pinned tool → call the tool directly.")
            call_lines.append("ONE hidden tool → **call**(tool, arguments, database).")
        else:
            call_lines.append("ONE tool → call the tool directly.")
        if has_batch:
            call_lines.append("N independent calls → **batch** (per-item errors).")
        if has_execute:
            call_lines.append("Chaining/filtering → **execute** with invoke().")
            call_lines.append("Cross-database parallel → execute with asyncio.gather.")
        sections.append("\n".join(call_lines))

        if has_tool_search:
            callable_via = ["**call**"]
            if has_batch:
                callable_via.append("**batch**")
            if has_execute:
                callable_via.append("**execute**")
            sections.append(
                "## Tool discovery\n"
                "Common tools are pinned (always visible). Use "
                "search_tools(pattern) to find hidden tools, then "
                "get_schema(tools=[...]) for parameter details. "
                "Hidden tools are callable via "
                + ", ".join(callable_via)
                + " (they are not in the client tool list, so "
                "direct calls will fail with 'No such tool')."
            )

        sections.append(
            "## Session trust\n"
            "If your prompt states a database is already open by ID, "
            "trust it — do not re-verify with open/list/wait calls."
        )

        sections.append(
            "## Workflows\n"
            "- **Triage:** get_database_info → list_functions + get_strings.\n"
            "- **String search:** find_code_by_string(pattern) combines "
            "string search + xref + function resolution.\n"
            "- **Function analysis:** decompile_function, "
            "disassemble_function, get_call_graph(depth=1).\n"
            "- **Name search:** list_functions/list_names accept "
            "filter_pattern. Use search_bytes/search_text/"
            "find_immediate for binary content.\n"
            "- **Types:** parse_type_declaration → apply_type_at_address "
            "for named types; set_type for inline; "
            "set_function_type for prototypes.\n"
            "- **Multi-pattern search:** get_strings, list_functions, "
            "list_names, list_demangled_names accept filters=[...] "
            "for single-pass multi-pattern search.\n"
            "- **Pointer tables:** read_pointer_table for vtables, "
            "dispatch tables (auto-dereferences + string detection).\n"
            "- **Firmware:** set processor/loader explicitly. "
            'ARM defaults to AArch64 — use "arm:ARMv7-M" for Cortex-M. '
            "Use rebase_program (delta, not absolute) + create_segment + "
            "reanalyze_range after setup."
        )

        return "\n\n".join(sections)

    # ------------------------------------------------------------------
    # Management tools
    # ------------------------------------------------------------------

    def _register_management_tools(self):
        pool = self._worker_pool

        async def _notify_resources_changed() -> None:
            """Notify the client that the resource list has changed."""
            ctx = try_get_context()
            if ctx is None:
                return
            try:
                await ctx.send_notification(types.ResourceListChangedNotification())
            except Exception:
                log.debug("Failed to send ResourceListChanged notification", exc_info=True)

        @self.tool(annotations={"title": "Open Database"})
        async def open_database(
            file_path: str,
            run_auto_analysis: bool = False,
            keep_open: bool = True,
            database_id: str = "",
            force_new: bool = False,
            processor: str = "",
            loader: str = "",
            base_address: str = "",
            fat_arch: str = "",
            options: str = "",
        ) -> dict:
            """Open a binary or existing IDA database (.i64/.idb) for analysis.

            Returns immediately with ``"opening": true`` — call
            wait_for_analysis before using other tools on this database.
            Re-opening an already-open database returns the existing worker.

            **Multiple binaries:** use a separate subagent per binary.
            Each agent calls open_database then wait_for_analysis. Do NOT
            serialize open+wait calls — that blocks parallel loading.

            **force_new=True** is destructive: deletes existing .i64/.idb
            and all prior analysis. Use only for stale/incompatible DBs.

            **Fat Mach-O:** requires explicit *fat_arch* (e.g. ``arm64``).
            Error lists available slices. Use distinct *database_id* per
            slice for concurrent analysis. *fat_arch* must be omitted for
            non-fat files and existing databases.

            Args:
                file_path: Path to the binary file or IDA database.
                run_auto_analysis: Run IDA auto-analysis after opening.
                keep_open: Keep other open databases (default True).
                database_id: Custom ID (must match [a-z][a-z0-9_]{0,31}).
                force_new: Delete existing DB files and start fresh.
                processor: IDA processor module (e.g. ``metapc``, ``arm``,
                           ``mips``). Auto-detected when omitted.
                           **ARM:** defaults to AArch64 — use
                           ``arm:ARMv7-M`` for Cortex-M, ``arm:ARMv7-A``
                           for 32-bit. Use list_targets to see options.
                loader: IDA loader (e.g. "ELF", "PE", "Binary file").
                        Auto-detected when omitted. See list_targets.
                base_address: Base address for raw binaries (hex/decimal,
                              16-byte aligned). Ignored for structured formats.
                fat_arch: Mach-O fat slice (``x86_64``, ``arm64``, etc.).
                          Required for fat binaries; must be omitted for
                          thin files and existing databases.
                options: Extra IDA CLI arguments. Do not duplicate
                         processor/loader/base_address flags here.
            """
            # Fail fast on ambiguous processor / fat binary / bad arg
            # combinations before spawning (or reusing) a worker.  The
            # worker re-runs these checks for standalone safety, so we
            # discard the returned values — but catching errors here
            # means misconfigured args fail even when dedup would
            # otherwise return an existing worker.
            check_processor_ambiguity(processor, file_path, force_new, fat_arch)
            fat_slice_index = check_fat_binary(file_path, fat_arch, force_new)
            build_ida_args(
                processor=processor,
                loader=loader,
                base_address=base_address,
                fat_slice_index=fat_slice_index,
                options=options,
            )

            ctx = try_get_context()
            sid = ctx.session_id if ctx else None
            pool.ensure_session_cleanup(ctx)
            if not keep_open:
                await pool.detach_all(sid)

            mcp_session = ctx.session if ctx else None
            result = await pool.spawn_worker(
                file_path,
                run_auto_analysis,
                database_id,
                session_id=sid,
                mcp_session=mcp_session,
                force_new=force_new,
                processor=processor,
                loader=loader,
                base_address=base_address,
                fat_arch=fat_arch,
                options=options,
            )
            await _notify_resources_changed()
            return result

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
            result = await pool.close_for_session(worker, _session_id(), save=save, force=force)
            if result.get("status") != "detached":
                await _notify_resources_changed()
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
                pool.check_attached(worker, _session_id())

            # Run the proxy call as a background task and send heartbeat progress
            # notifications every 5 s while waiting.  IDA's save_database blocks
            # the worker's main thread for an extended period on large databases;
            # without heartbeats the MCP client's per-request timeout can fire and
            # disconnect the server, especially when other agents have queued
            # requests on the same worker.
            proxy_task = asyncio.create_task(
                pool.proxy_to_worker(worker, "save_database", {"outfile": outfile, "flags": flags})
            )
            await run_with_heartbeat(proxy_task, ctx)
            result = proxy_task.result()  # re-raises any exception from the task
            result_data = parse_result(result)
            result_data["database"] = worker.database_id
            require_success(result, result_data, "Save failed")
            return result_data

        @self.tool(annotations={"title": "List Databases"})
        async def list_databases() -> dict:
            """List all open databases with metadata (includes opening/analyzing status)."""
            return pool.build_database_list(caller_session_id=_session_id())

        @self.tool(annotations={"title": "Wait for Analysis"})
        async def wait_for_analysis(
            database: str = "",
            databases: list[str] = [],  # noqa: B006
        ) -> dict:
            """Block until database(s) finish opening and optional auto-analysis.

            **Single:** pass ``database`` to wait for one DB.
            **Multi:** pass ``databases`` list — returns when **at least one**
            is ready. Work on the ready one, call again for the rest.

            While analysis runs, the IDA thread is blocked — tool calls queue.

            Args:
                database: Single database ID to wait for.
                databases: List of database IDs (returns when first is ready).
            """
            if databases:
                return await pool.wait_for_ready_multi(databases)
            return await pool.wait_for_ready(database)

        @self.tool(annotations={"title": "List Targets"})
        async def list_targets() -> dict:
            """List available processor modules and loaders for open_database."""
            return _list_targets()

    # ------------------------------------------------------------------
    # Supervisor-owned resources
    # ------------------------------------------------------------------

    def _register_supervisor_resources(self):
        pool = self._worker_pool

        @self.resource(
            "ida://databases",
            description="All open databases with worker status (supervisor-level)",
        )
        async def databases_resource() -> str:
            return json.dumps(pool.build_database_list(include_state=True), separators=(",", ":"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    """Register signal handlers on the running event loop.

    Uses :meth:`loop.add_signal_handler` so callbacks execute inside the
    event loop rather than between arbitrary bytecodes.  This lets
    ``loop.stop()`` trigger a clean unwind through the async exit stacks
    (provider lifespan → session disconnect callbacks → worker cleanup).

    SIGKILL and ``os._exit()`` are still undetectable from inside the
    process — those need an external watchdog.
    """

    def _handler(sig: signal.Signals) -> None:
        log.info("Received %s; initiating shutdown", sig.name)
        loop.stop()

    for sig_name in _HANDLED_SIGNALS:
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue  # e.g. SIGHUP on Windows
        try:
            loop.add_signal_handler(sig, _handler, sig)
        except (NotImplementedError, OSError, ValueError):
            log.debug("Could not install handler for %s", sig_name, exc_info=True)


def main():
    import argparse  # noqa: PLC0415

    from ida_mcp import (  # noqa: PLC0415
        configure_logging,
        get_version,
    )

    parser = argparse.ArgumentParser(
        prog="ida-mcp",
        description="IDA Pro MCP server",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {get_version()}")
    sub = parser.add_subparsers(dest="command")

    # Default mode: stdio proxy that auto-spawns a persistent daemon
    sub.add_parser(
        "proxy",
        help="Stdio proxy to a persistent HTTP daemon (default when no command given)",
    )

    # Daemon mode: persistent HTTP server
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
        help="Auto-shutdown after N seconds with no connections (0 = disabled)."
        " The proxy overrides this to IDA_MCP_IDLE_TIMEOUT (default 300s).",
    )

    # Direct stdio mode: single-session, no daemon
    sub.add_parser("stdio", help="Direct stdio mode (no daemon, workers die on disconnect)")

    # Stop command: gracefully shut down a running daemon
    sub.add_parser("stop", help="Stop the running daemon")

    args = parser.parse_args()

    if args.command == "serve":
        from ida_mcp.daemon import serve  # noqa: PLC0415

        serve(host=args.host, port=args.port, idle_timeout=args.idle_timeout)
    elif args.command == "stop":
        from ida_mcp.proxy import stop  # noqa: PLC0415

        if stop():
            print("Daemon stopped.")
        else:
            print("No daemon is running.")
    elif args.command == "stdio":
        configure_logging()
        ProxyMCP().run(transport="stdio")
    else:
        from ida_mcp.proxy import main as proxy_main  # noqa: PLC0415

        proxy_main()


if __name__ == "__main__":
    main()
