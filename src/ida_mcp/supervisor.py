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
import json
import logging
import os
import platform as plat

import mcp.types as types
from fastmcp import FastMCP
from fastmcp.server.context import Context

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


class ProxyMCP(FastMCP):
    """MCP server that proxies tool calls to per-database worker processes."""

    def __init__(self):
        super().__init__(
            "IDA Pro",
            instructions=self._build_instructions(),
            on_duplicate="error",
        )
        self._worker_pool = WorkerPoolProvider()
        self.add_provider(self._worker_pool)
        self._register_management_tools()
        self._register_supervisor_resources()
        register_prompts(self)
        self.add_transform(IDAToolTransform())

    # ------------------------------------------------------------------
    # Instructions
    # ------------------------------------------------------------------

    @staticmethod
    def _build_instructions() -> str:
        return (
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
            "**Multi-database wait:** pass databases=[...] to "
            "wait_for_analysis to wait for several at once. It returns "
            "as soon as at least one is ready — start working on it "
            "while others load. Call again for the remaining ones.\n\n"
            "**Important:** while analysis is running, the IDA thread is "
            "blocked — tool calls will queue until analysis completes. "
            "Always call wait_for_analysis before using other tools.\n\n"
            "file_path can be a raw binary or an existing IDA database "
            "(.i64/.idb) — when a database is passed, the original binary "
            "does not need to be present. "
            "The binary must be in a writable directory (IDA creates a "
            ".i64 database alongside it); copy read-only files to a "
            "writable location first.\n\n"
            "**Fat Mach-O binaries:** universal binaries require an "
            'explicit fat_arch= (e.g. "x86_64", "arm64", "arm64e"). '
            "Without it, open_database raises AmbiguousFatBinary with "
            "the available slices listed in the error's available field. "
            "To analyze multiple slices from the same file concurrently, "
            "call open_database once per slice with distinct database_id "
            "values.\n\n"
            #
            # --- Addressing ---
            #
            "## Addressing\n"
            "All tools except management tools (open_database, "
            "close_database, save_database, list_databases, "
            "wait_for_analysis, list_targets) require the database parameter — the stem ID "
            "returned by open_database or list_databases.\n\n"
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
            # --- Tool selection ---
            #
            "## Choosing the right call pattern\n"
            "ONE target? → Call the tool directly. Never wrap in execute.\n\n"
            "Multiple independent calls (same or different tools)? → "
            "Use **batch** (up to 50 operations per request, sequential "
            "with per-item error collection and progress reporting). "
            "Prefer batch over execute — it is simpler.\n\n"
            "Conditional logic, filtering results, or chaining tool A "
            "output into tool B? → Use **execute** with "
            "`await call_tool(name, params)` for Python control flow. "
            "Call get_schema(tools=[...]) first to look up parameter "
            "names and return fields for any tool you plan to call.\n\n"
            "Cross-database parallel queries? → Use execute with "
            "`asyncio.gather` and explicit `database` params. Note: "
            "calls to the same database are serialized by the worker, "
            "so asyncio.gather only helps for cross-database work.\n\n"
            #
            # --- Tool discovery ---
            #
            "## Tool discovery\n"
            "Common analysis tools are pinned and always visible. "
            "Additional tools are discoverable via search_tools(pattern) "
            "and callable directly by name, or through execute/batch. "
            "Hidden tools work identically to pinned tools — no special "
            "syntax required.\n\n"
            "Use get_schema(tools=[...]) to see parameter names, types, and "
            "return shapes for any tool before calling it. Supports "
            "detail='brief' | 'detailed' (default) | 'full'. Works for "
            "both pinned and hidden tools.\n\n"
            "Management tools (open_database, close_database, save_database, "
            "list_databases, wait_for_analysis, list_targets) are always visible "
            "and called directly — not through execute or batch.\n\n"
            #
            # --- Session trust ---
            #
            "## Database session trust\n"
            "If your prompt states a database is already open by ID, "
            "trust it. Do NOT call open_database, list_databases, or "
            "wait_for_analysis to verify — the database is shared "
            "across the session.\n\n"
            "## Recommended workflows\n"
            "- Starting analysis: get_database_info for metadata, "
            "then list_functions and get_strings for initial exploration.\n"
            "- Finding code by string: use find_code_by_string(pattern) "
            "to find functions referencing matching strings in one call. "
            "Or manually: get_strings → get_xrefs_to → decompile_function.\n"
            "- Understanding a function: decompile_function for "
            "pseudocode, disassemble_function for assembly, "
            "get_call_graph(depth=1) for callers/callees.\n"
            "- Name-based search: list_functions and list_names accept "
            "filter_pattern. Reserve search_bytes/search_text/"
            "find_immediate for scanning binary content.\n"
            "- Improving the database: rename, retype, and comment "
            "iteratively — each change propagates through decompilation. "
            "Load FLIRT signatures and type libraries for bulk identification.\n"
            "- Types: parse_type_declaration to define types, then "
            "apply_type_at_address to apply a named type by lookup. "
            "Use set_type for inline type strings (anonymous or simple). "
            "Use set_function_type to fix function prototypes.\n"
            "- Batch operations: get_strings, list_functions, list_names, "
            "and list_demangled_names accept a filters=[...] parameter "
            "for multi-pattern single-pass search — prefer this over loops "
            "or the execute meta-tool when gathering multiple patterns.\n"
            "- Pointer tables: use read_pointer_table to read vtables, "
            "dispatch tables, and token dictionaries — auto-dereferences "
            "pointers and detects strings at targets.\n"
            "- Raw binary / firmware: open with processor and loader "
            "set explicitly. **ARM gotcha:** the arm module defaults "
            'to AArch64 for raw binaries — use "arm:ARMv7-M" for '
            'Cortex-M, not just "arm". Use list_targets to see '
            "available processors and loaders. "
            "After opening, use rebase_program to shift all addresses by "
            "the required delta (it takes a delta, not an absolute address), "
            "create_segment for memory-mapped regions (MMIO, "
            "SRAM), and reanalyze_range after setup changes."
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
            processor: str = "",
            loader: str = "",
            base_address: str = "",
            fat_arch: str = "",
            options: str = "",
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

            **Processor and loader selection:** by default IDA auto-detects
            the processor and file format from the binary's headers.  Use
            *processor* and *loader* to override when auto-detection picks
            the wrong option (e.g. a raw firmware blob with no headers).

            **Fat Mach-O binaries:** universal ("fat") Mach-O files pack
            multiple architecture slices (e.g. ``x86_64`` + ``arm64``) into
            a single file.  In headless mode IDA would silently pick a
            default slice, so open_database refuses to open a fat binary
            without an explicit *fat_arch*.  The error lists available
            slices in its ``available`` detail — there is no separate
            "list slices" call.  To analyze multiple slices from the same
            file concurrently, call open_database once per slice with
            distinct ``database_id`` values.  Conversely, *fat_arch* must
            be omitted when the file is not a fat Mach-O (thin binary,
            ELF, firmware blob, ...) and when *file_path* points at an
            existing ``.i64``/``.idb`` (the stored database already pins
            a slice); either combination is rejected with
            ``InvalidArgument`` rather than silently ignored, so a typo
            cannot produce a confusingly suffixed sidecar on disk or a
            reopen that unexpectedly does not swap slices.

            Args:
                file_path: Path to the binary file or IDA database.
                run_auto_analysis: Wait for IDA auto-analysis after opening.
                keep_open: Keep previously open databases (default True).
                database_id: Custom database identifier.
                force_new: Delete existing database files and start fresh.
                processor: Optional.  IDA processor module, optionally
                           with a variant after a colon.  IDA auto-detects
                           from file headers when omitted, but may guess
                           wrong for raw binaries.  Use list_targets to see
                           available module names.  **ARM gotcha:** the
                           ``arm`` module defaults to AArch64 (64-bit) for
                           raw binaries — use ``arm:ARMv7-M`` for Cortex-M
                           firmware, ``arm:ARMv7-A`` for 32-bit A-profile,
                           or ``arm:ARMv7-R`` for R-profile.  Other
                           examples: ``metapc`` (x86/x64), ``ppc``,
                           ``mips``, ``mipsl``.
                loader: Optional.  IDA loader name (e.g. "ELF", "PE",
                        "Mach-O", "Binary file").  IDA auto-detects when
                        omitted.  Use list_targets to see available loaders.
                base_address: Optional.  Base loading address for the binary
                              (hex or decimal, e.g. "0x20040000").  Must be
                              16-byte aligned.  Primarily useful for raw
                              binary files; structured formats contain their
                              own base addresses.
                fat_arch: Optional.  Architecture slice name to extract
                          from a Mach-O fat (universal) binary —
                          ``x86_64``, ``arm64``, ``arm64e``, etc.  Required
                          when opening a fat binary; must be omitted for
                          thin / non-Mach-O files **and** for existing
                          ``.i64``/``.idb`` database paths — either
                          combination raises ``InvalidArgument``.  Cannot
                          be combined with *loader* either, since both
                          map to IDA's ``-T`` flag and fat_arch
                          implicitly selects the Fat Mach-O loader.
                options: Optional.  Additional IDA command-line arguments.
                         Processor, loader, and base address flags are added
                         automatically from the other parameters — do not
                         duplicate them here.
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
            ctx: Context | None = None,
        ) -> dict:
            """Save the current database.

            When multiple databases are open, specify which one with the database parameter.
            If the database is not attached to the current session, this will fail unless
            force=True.  (The attachment check is skipped when no session context is
            available or the database has no tracked sessions.)

            **Note:** saving a large database (e.g. kernelcache, dyld shared cache) can
            take several minutes.  Progress notifications are sent every 5 seconds to keep
            the connection alive during long saves.
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
            """List all currently open databases with metadata.

            Includes ``"opening"`` / ``"analyzing"`` flags for databases that
            are being loaded or analyzed.  Call wait_for_analysis to block
            until a database is ready.
            """
            return pool.build_database_list(caller_session_id=_session_id())

        @self.tool(annotations={"title": "Wait for Analysis"})
        async def wait_for_analysis(
            database: str = "",
            databases: list[str] = [],  # noqa: B006
        ) -> dict:
            """Wait for one or more databases to finish opening/analysis.

            **Single mode** — provide ``database`` (a single ID) to block
            until that database is ready.

            **Multi mode** — provide ``databases`` (a list of IDs) to wait
            for several at once.  Returns as soon as **at least one**
            database is ready — start working on the ready one while
            the others continue loading.  Call again for the remaining.

            While analysis is running, the IDA thread is blocked —
            tool calls will queue until analysis completes.

            Args:
                database: Single database ID to wait for.
                databases: List of database IDs to wait for (multi mode).
            """
            if databases:
                return await pool.wait_for_ready_multi(databases)
            return await pool.wait_for_ready(database)

        @self.tool(annotations={"title": "List Targets"})
        async def list_targets() -> dict:
            """List available processor modules and loaders for open_database.

            Returns the names that can be passed as the ``processor`` or
            ``loader`` parameter to open_database.  These are discovered
            from the IDA Pro installation directory.
            """
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


def main():
    from ida_mcp import configure_logging  # noqa: PLC0415

    configure_logging()
    proxy = ProxyMCP()
    proxy.run(transport="stdio")


if __name__ == "__main__":
    main()
