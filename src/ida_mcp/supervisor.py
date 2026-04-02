# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Multi-database supervisor for the IDA MCP server.

Spawns one worker subprocess per open database and proxies MCP tool calls
and resource reads to the appropriate worker via the ``WorkerPoolProvider``.
Prompts are registered directly on the supervisor.

All tools require the ``database`` parameter (the stem ID returned by
``open_database``) except ``open_database``, ``list_databases``, and
``show_all_tools``.

The supervisor never imports ``idapro`` or any ``ida_*`` module.
"""

from __future__ import annotations

import json
import logging

import mcp.types as types
from fastmcp import FastMCP

from ida_mcp.context import try_get_context
from ida_mcp.prompts import register_all as register_prompts
from ida_mcp.worker_provider import (
    WorkerPoolProvider,
    parse_result,
    require_success,
)

log = logging.getLogger(__name__)


def _session_id() -> str | None:
    """Extract the session ID from the current FastMCP context, or ``None``."""
    ctx = try_get_context()
    return ctx.session_id if ctx else None


# ---------------------------------------------------------------------------
# ProxyMCP
# ---------------------------------------------------------------------------


class ProxyMCP(FastMCP):
    """MCP server that proxies tool calls to per-database worker processes."""

    def __init__(self):
        super().__init__(
            "IDA Pro",
            instructions=(
                "IDA Pro binary analysis server with multi-database support. "
                "Use open_database to load a binary. The binary must be in a "
                "writable directory (IDA creates a .i64 database alongside it); "
                "copy read-only files (e.g. /bin/ls) to a writable location first. "
                "Previously open databases are kept open by default. "
                "All tools except open_database and list_databases "
                "require the database parameter "
                "(the stem ID returned by open_database or list_databases). "
                "Resource URIs include the database ID: ida://<database>/… "
                "(e.g. ida://mybin/idb/entrypoints, ida://mybin/idb/imports, "
                "ida://mybin/idb/exports). Use list_databases to "
                "see all open databases. "
                'Addresses can be specified as hex strings (e.g. "0x401000"), '
                'bare hex ("4010a0"), decimal, or symbol names (e.g. "main"). '
                "Use convert_number for base conversions. "
                "\n\n"
                "Recommended workflows:\n"
                "- Finding code by string literal: get_strings → find target "
                "address → get_xrefs_to(address) → decompile_function. "
                "This is much faster than search_text or search_bytes for "
                "string-based lookups.\n"
                "- Understanding a function: get_function for metadata, then "
                "disassemble_function (fast) or decompile_function (readable). "
                "Use get_call_graph(depth=1) for direct callers/callees.\n"
                "- Searching for patterns: use list_functions/list_names with "
                "filter_pattern for name-based searches. Reserve search_bytes, "
                "search_text, and find_immediate for when you need to scan "
                "binary content — and specify start_address to avoid scanning "
                "from the beginning of large binaries.\n"
                "- Batch analysis: prefer list_functions with filters + "
                "individual decompile_function calls over export_all_pseudocode.\n"
                "- Type workflow: list_local_types → get_local_type(name) → "
                "apply_type_at_address or parse_type_declaration → "
                "apply_type_at_address.\n"
                "- Opening with analysis: open_database(run_auto_analysis=True) "
                "returns immediately while analysis runs in the background. "
                "Other tools on the database will fail until analysis finishes. "
                "Call wait_for_analysis on each database to block until "
                "analysis completes — do not poll list_databases."
            ),
            on_duplicate="error",
        )
        self._worker_pool = WorkerPoolProvider()
        self.add_provider(self._worker_pool)
        self._register_management_tools()
        self._register_supervisor_resources()
        register_prompts(self)

    # ------------------------------------------------------------------
    # Management tools
    # ------------------------------------------------------------------

    def _register_management_tools(self):
        pool = self._worker_pool

        async def _notify_lists_changed() -> None:
            """Send tool and resource list-changed notifications to the client."""
            pool.invalidate_capabilities()
            ctx = try_get_context()
            if ctx is None:
                return
            for notification in (
                types.ToolListChangedNotification(),
                types.ResourceListChangedNotification(),
            ):
                try:
                    await ctx.send_notification(notification)
                except Exception:
                    log.debug(
                        "Failed to send %s notification",
                        type(notification).__name__,
                        exc_info=True,
                    )

        @self.tool(annotations={"title": "Open Database"})
        async def open_database(
            file_path: str,
            run_auto_analysis: bool = False,
            keep_open: bool = True,
            database_id: str = "",
        ) -> dict:
            """Open a binary file for analysis with IDA Pro.

            By default, previously open databases are kept open.
            Set keep_open=False to save and close databases owned by the
            current session first.
            Use database_id to assign a custom identifier (must match [a-z][a-z0-9_]{0,31}).

            When run_auto_analysis=True, the database opens immediately and
            analysis runs in the background.  The response includes
            ``"analyzing": true``.  Other tools on this database will fail
            until analysis finishes.  Call wait_for_analysis on the database
            to block until analysis completes — do not poll list_databases.
            You can open multiple databases in parallel and then call
            wait_for_analysis on each one.

            If the database is already open, the existing worker is reused and
            run_auto_analysis is ignored (analysis is not restarted).
            """
            ctx = try_get_context()
            sid = ctx.session_id if ctx else None
            pool.ensure_session_cleanup(ctx)
            if not keep_open:
                await pool.detach_all(sid, save=True)

            mcp_session = ctx.session if ctx else None
            result = await pool.spawn_worker(
                file_path,
                run_auto_analysis,
                database_id,
                session_id=sid,
                mcp_session=mcp_session,
            )
            await _notify_lists_changed()
            return result

        @self.tool(annotations={"title": "Close Database"})
        async def close_database(
            save: bool = True,
            force: bool = False,
            database: str = "",
        ) -> dict:
            """Close a database and terminate its worker process.

            When multiple databases are open, specify which one with the database parameter.
            If the database is not attached to the current session, this will fail unless
            force=True.  (The attachment check is skipped when no session context is
            available or the database has no tracked sessions.)
            When other sessions are still using the database, this detaches the current
            session but keeps the worker alive.
            """
            worker = pool.resolve_worker(database)
            result = await pool.close_for_session(worker, _session_id(), save=save, force=force)
            if result.get("status") != "detached":
                await _notify_lists_changed()
            return result

        @self.tool(annotations={"title": "Save Database"})
        async def save_database(
            outfile: str = "",
            flags: int = -1,
            force: bool = False,
            database: str = "",
        ) -> dict:
            """Save the current database.

            When multiple databases are open, specify which one with the database parameter.
            If the database is not attached to the current session, this will fail unless
            force=True.  (The attachment check is skipped when no session context is
            available or the database has no tracked sessions.)
            """
            worker = pool.resolve_worker(database)
            if not force:
                pool.check_attached(worker, _session_id())
            result = await pool.proxy_to_worker(
                worker,
                "save_database",
                {"outfile": outfile, "flags": flags},
            )
            result_data = parse_result(result)
            result_data["database"] = worker.database_id
            require_success(result, result_data, "Save failed")
            return result_data

        @self.tool(annotations={"title": "List Databases"})
        async def list_databases() -> dict:
            """List all currently open databases with metadata.

            Includes an ``"analyzing"`` flag when background analysis is running.
            To wait for completion, call wait_for_analysis instead of polling
            this tool.
            """
            return pool.build_database_list(caller_session_id=_session_id())

        @self.tool(annotations={"title": "Show All Tools"})
        async def show_all_tools(show_all: bool = True) -> dict:
            """Disable or re-enable capability-based tool filtering.

            By default, tools that require capabilities not supported by any
            open database (e.g. decompiler, assembler) are hidden from the
            tool list.  Clients that do not handle tool-list-changed
            notifications can call this to show all tools regardless of
            current database capabilities.  Tools called against a database
            that lacks the required capability will still return a clear error.
            """
            pool.filter_by_capability = not show_all
            await _notify_lists_changed()
            return {
                "filter_by_capability": pool.filter_by_capability,
                "status": "Tool filtering "
                + ("enabled" if pool.filter_by_capability else "disabled"),
            }

    # ------------------------------------------------------------------
    # Supervisor-owned resources
    # ------------------------------------------------------------------

    def _register_supervisor_resources(self):
        pool = self._worker_pool

        @self.resource(
            "ida://databases",
            description="All open databases with worker status (supervisor-level)",
        )
        def databases_resource() -> str:
            return json.dumps(pool.build_database_list(include_state=True), separators=(",", ":"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    proxy = ProxyMCP()
    proxy.run(transport="stdio")


if __name__ == "__main__":
    main()
