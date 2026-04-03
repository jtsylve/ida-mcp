# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Multi-database supervisor for the IDA MCP server.

Spawns one worker subprocess per open database and proxies MCP tool calls
and resource reads to the appropriate worker via the ``WorkerPoolProvider``.
Prompts are registered directly on the supervisor.

All tools except management tools (``open_database``, ``close_database``,
``save_database``, ``list_databases``, ``wait_for_analysis``) require the
``database`` parameter (the stem ID returned by ``open_database``).

The supervisor never imports ``idapro`` or any ``ida_*`` module.
"""

from __future__ import annotations

import json
import logging

import mcp.types as types
from fastmcp import FastMCP
from fastmcp.server.transforms.search import RegexSearchTransform

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
            tasks=True,
            instructions=(
                "IDA Pro binary analysis server with multi-database support.\n\n"
                #
                # --- Opening databases ---
                #
                "## Opening databases\n"
                "open_database returns immediately — the worker spawns in "
                "the background. Call wait_for_analysis(database) to block "
                "until the database is ready. You can open multiple databases "
                "in parallel and call wait_for_analysis on each one — they "
                "load concurrently. With run_auto_analysis=True, "
                "wait_for_analysis also waits for IDA's auto-analysis.\n\n"
                "file_path can be a raw binary or an existing IDA database "
                "(.i64/.idb) — when a database is passed, the original binary "
                "does not need to be present. "
                "The binary must be in a writable directory (IDA creates a "
                ".i64 database alongside it); copy read-only files to a "
                "writable location first.\n\n"
                #
                # --- Addressing ---
                #
                "## Addressing\n"
                "All tools except management tools (open_database, "
                "close_database, list_databases, wait_for_analysis, "
                "save_database) require the database parameter — the stem ID "
                "returned by open_database.\n\n"
                'Addresses accept hex strings ("0x401000"), bare hex '
                '("4010a0"), decimal, or symbol names ("main").\n\n'
                #
                # --- Resources ---
                #
                "## Resources\n"
                "Resources provide paginated, read-only access to database "
                "contents. URIs include the database ID: "
                "ida://<database>/idb/imports, ida://<database>/idb/exports, "
                "ida://<database>/idb/entrypoints. Each also has a "
                "/search/{pattern} variant for regex filtering.\n\n"
                #
                # --- Tool discovery ---
                #
                "## Tool discovery\n"
                "The most common tools are listed directly. Additional tools "
                "are discoverable via search_tools — use a keyword regex "
                "(e.g. 'patch|assemble', 'snapshot', 'operand') to find tools "
                "by topic, or '.*' to list all available tools.\n\n"
                #
                # --- Workflows ---
                #
                "## Recommended workflows\n"
                "- Finding code by string: get_strings → get_xrefs_to(addr) "
                "→ decompile_function. Much faster than search_text.\n"
                "- Understanding a function: decompile_function for "
                "pseudocode, disassemble_function for assembly, "
                "get_call_graph(depth=1) for callers/callees.\n"
                "- Name-based search: list_functions and list_names accept "
                "filter_pattern. Reserve search_bytes/search_text/"
                "find_immediate for scanning binary content.\n"
                "- Improving the database: rename functions/variables, "
                "set types and comments, create structs/enums, apply FLIRT "
                "signatures and type libraries. Each improvement propagates "
                "through decompilation and makes further analysis easier.\n"
                "- Types: parse_type_declaration or parse_source_declarations "
                "to define types, then apply_type_at_address to apply them. "
                "Use set_function_type to fix function prototypes.\n"
                "- Batch: prefer list_functions with filters + individual "
                "decompile_function calls over export_all_pseudocode."
            ),
            on_duplicate="error",
        )
        self._worker_pool = WorkerPoolProvider()
        self.add_provider(self._worker_pool)
        self._register_management_tools()
        self._register_supervisor_resources()
        register_prompts(self)
        self.add_transform(
            RegexSearchTransform(
                max_results=10000,
                always_visible=[
                    # Management
                    "open_database",
                    "close_database",
                    "list_databases",
                    "wait_for_analysis",
                    "save_database",
                    # Core analysis
                    "decompile_function",
                    "disassemble_function",
                    "get_function",
                    "list_functions",
                    "get_call_graph",
                    "create_function",
                    # Cross-references
                    "get_xrefs_to",
                    "get_xrefs_from",
                    # Strings & search
                    "get_strings",
                    "search_text",
                    "search_bytes",
                    "find_immediate",
                    # Navigation & metadata
                    "get_database_info",
                    "get_segments",
                    "list_names",
                    "convert_number",
                    # Data
                    "read_bytes",
                    "make_data",
                    "make_code",
                    # Types
                    "list_local_types",
                    "get_local_type",
                    "parse_type_declaration",
                    "apply_type_at_address",
                    "parse_source_declarations",
                    # Structures
                    "list_structures",
                    "get_structure",
                    "create_structure",
                    "add_struct_member",
                    "retype_struct_member",
                    # Enums
                    "list_enums",
                    "create_enum",
                    "add_enum_member",
                    # Function types
                    "get_function_type",
                    "set_function_type",
                    # Decompiler
                    "rename_decompiler_variable",
                    "retype_decompiler_variable",
                    "set_decompiler_comment",
                    # Annotation
                    "rename_address",
                    "rename_function",
                    "get_comment",
                    "set_comment",
                    "set_function_comment",
                    # Signatures & type libraries
                    "apply_flirt_signature",
                    "load_type_library",
                    # Utility
                    "demangle_name",
                ],
            )
        )

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
        ) -> dict:
            """Open a binary or existing IDA database for analysis.

            *file_path* can be a raw binary **or** an existing ``.i64`` /
            ``.idb`` database.  When a database is passed, the original
            binary does not need to be present.

            Returns immediately — the worker subprocess is spawned and the
            database is opened in the background.  The response includes
            ``"opening": true``.  The database is not ready for tool calls
            until wait_for_analysis returns successfully.

            **Recommended workflow for multiple binaries:** launch a
            separate subagent or background task for each binary.  Each
            agent calls open_database and then wait_for_analysis itself.
            Calling open_database on an already-open or already-opening
            database is safe — it returns the existing worker.  This lets
            all databases load and analyze in parallel without blocking
            the caller.  Do NOT call open_database + wait_for_analysis
            on every database sequentially in the main context — that
            serializes the wait and wastes time, especially for large
            binaries.

            By default, previously open databases are kept open.
            Set keep_open=False to save and close databases owned by the
            current session first.
            Use database_id to assign a custom identifier (must match [a-z][a-z0-9_]{0,31}).

            When run_auto_analysis=True, wait_for_analysis also waits for
            IDA's auto-analysis to complete after the database is opened.

            If the database is already open, the existing worker is reused and
            run_auto_analysis is ignored (analysis is not restarted).

            **WARNING — destructive:** Setting force_new=True permanently
            deletes any existing IDA database files (.i64, .idb, etc.)
            before opening, discarding all prior analysis, renames,
            comments, and type annotations.  Use only when a previous
            database is stale or incompatible (IDA error code 4).
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
                force_new=force_new,
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
                await _notify_resources_changed()
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

            Includes ``"opening"`` / ``"analyzing"`` flags for databases that
            are being loaded or analyzed.  Call wait_for_analysis to block
            until a database is ready.
            """
            return pool.build_database_list(caller_session_id=_session_id())

        @self.tool(annotations={"title": "Wait for Analysis"})
        async def wait_for_analysis(database: str = "") -> dict:
            """Wait for a database to finish opening and/or auto-analysis.

            Blocks until the database is ready for tool calls.  Call this
            after open_database to wait for the worker to start and for
            any background auto-analysis to complete.

            Each subagent or background task should call open_database
            followed by wait_for_analysis for its own binary, so all
            databases load in parallel without blocking each other.
            """
            return await pool.wait_for_ready(database)

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


def main():
    from ida_mcp import configure_logging  # noqa: PLC0415

    configure_logging()
    proxy = ProxyMCP()
    proxy.run(transport="stdio")


if __name__ == "__main__":
    main()
