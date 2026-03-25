# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Multi-database supervisor for the IDA MCP server.

Spawns one worker subprocess per open database and proxies MCP tool calls,
resource reads, and prompt requests to the appropriate worker.
Single-database usage is fully backward compatible — the ``database``
parameter is optional and auto-resolves when only one database is open.

The supervisor never imports ``idapro`` or any ``ida_*`` module.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import copy
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.fastmcp import FastMCP
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.shared.exceptions import McpError

from ida_mcp.prompts import register_all as register_prompts

log = logging.getLogger(__name__)

_max_workers_env = os.environ.get("IDA_MCP_MAX_WORKERS")
MAX_WORKERS: int | None = min(max(int(_max_workers_env), 1), 8) if _max_workers_env else None
IDLE_TIMEOUT = int(os.environ.get("IDA_MCP_IDLE_TIMEOUT", "1800"))
DEFAULT_CALL_TIMEOUT = timedelta(seconds=120)
SLOW_TOOL_TIMEOUTS: dict[str, timedelta] = {
    "open_database": timedelta(seconds=600),
    "wait_for_analysis": timedelta(seconds=600),
    "export_all_disassembly": timedelta(seconds=300),
    "export_all_pseudocode": timedelta(seconds=300),
    "generate_signatures": timedelta(seconds=300),
}

_VALID_CUSTOM_ID = re.compile(r"^[a-z][a-z0-9_]{0,31}$")

_MCP_CONNECTION_CLOSED = -32000
_MCP_REQUEST_TIMEOUT = 408


# ---------------------------------------------------------------------------
# Database ID helpers
# ---------------------------------------------------------------------------


def _canonical_path(path: str) -> str:
    """Resolve a file path to its canonical form."""
    return os.path.realpath(os.path.expanduser(path))


def _normalize_id(stem: str) -> str:
    """Normalize a filename stem into a valid database ID."""
    normalized = re.sub(r"[^a-z0-9_]", "_", stem.lower())
    normalized = re.sub(r"_+", "_", normalized)
    normalized = normalized.strip("_")
    if normalized and normalized[0].isdigit():
        normalized = "db_" + normalized
    if not normalized:
        normalized = "db"
    return normalized[:32]


# ---------------------------------------------------------------------------
# Worker state
# ---------------------------------------------------------------------------


class WorkerState(Enum):
    STARTING = auto()
    IDLE = auto()
    BUSY = auto()
    STUCK = auto()
    DEAD = auto()


_INACTIVE_STATES = frozenset({WorkerState.DEAD, WorkerState.STARTING})


@dataclass
class Worker:
    database_id: str
    file_path: str
    session: ClientSession | None = None
    _task: asyncio.Task[None] | None = None
    _stop: asyncio.Event = field(default_factory=asyncio.Event)
    _save_on_close: bool = True
    state: WorkerState = WorkerState.STARTING
    metadata: dict[str, Any] = field(default_factory=dict)
    last_activity: float = field(default_factory=time.monotonic)
    busy_since: float | None = None


# ---------------------------------------------------------------------------
# ProxyMCP
# ---------------------------------------------------------------------------


class ProxyMCP(FastMCP):
    """MCP server that proxies tool calls to per-database worker processes."""

    _MANAGEMENT_TOOLS = frozenset(
        {
            "open_database",
            "close_database",
            "save_database",
            "list_databases",
        }
    )

    def __init__(self):
        super().__init__(
            "IDA Pro",
            instructions=(
                "IDA Pro binary analysis server with multi-database support. "
                "Use open_database to load a binary. Multiple databases can be "
                "open simultaneously — pass keep_open=True to keep previous "
                "databases open. When multiple databases are open, pass the "
                "database parameter to specify which database to target. "
                "Omit database when only one is open. Use list_databases to "
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
                "apply_type_at_address."
            ),
        )
        self._workers: dict[str, Worker] = {}  # canonical path -> Worker
        self._id_to_path: dict[str, str] = {}  # database_id -> canonical path
        self._lock = asyncio.Lock()
        self._worker_tool_schemas: list[types.Tool] = []
        self._augmented_worker_tools: list[types.Tool] = []
        self._worker_resources: list[types.Resource] = []
        self._worker_resource_templates: list[types.ResourceTemplate] = []
        self._own_resource_uris: frozenset[str] | None = None
        self._own_resource_template_pats: list[re.Pattern[str]] | None = None
        self._reaper_task: asyncio.Task[None] | None = None
        self._register_management_tools()
        self._register_supervisor_resources()
        register_prompts(self)

    # ------------------------------------------------------------------
    # Tool schema bootstrap
    # ------------------------------------------------------------------

    @staticmethod
    def _worker_params() -> StdioServerParameters:
        """Build StdioServerParameters for spawning a worker subprocess."""
        return StdioServerParameters(
            command=sys.executable,
            args=["-m", "ida_mcp.server"],
        )

    @staticmethod
    def _parse_result(result: types.CallToolResult) -> dict[str, Any]:
        """Extract the JSON dict from a CallToolResult's first text block."""
        if result.content and isinstance(result.content[0], types.TextContent):
            return json.loads(result.content[0].text)
        return {"error": "Empty or non-text result from worker", "error_type": "InternalError"}

    async def _bootstrap_worker_schemas(self):
        """Spawn a temporary worker to discover tool and resource schemas.

        Runs in a dedicated task so the stdio_client's anyio task group
        is entered and exited in the same task.
        """

        async def _do_bootstrap():
            params = self._worker_params()
            async with contextlib.AsyncExitStack() as stack:
                read, write = await stack.enter_async_context(stdio_client(params))
                session = await stack.enter_async_context(ClientSession(read, write))
                await session.initialize()
                tools_result = await session.list_tools()
                resources_result = await session.list_resources()
                templates_result = await session.list_resource_templates()
                return (
                    tools_result.tools,
                    resources_result.resources,
                    templates_result.resourceTemplates,
                )

        tools, resources, templates = await asyncio.get_running_loop().create_task(_do_bootstrap())
        self._worker_tool_schemas = tools
        self._worker_resources = resources
        self._worker_resource_templates = templates

    # ------------------------------------------------------------------
    # list_tools / call_tool overrides
    # ------------------------------------------------------------------

    async def list_tools(self) -> list[types.Tool]:
        """Return management tools + worker tools with injected database param."""
        if not self._worker_tool_schemas:
            await self._bootstrap_worker_schemas()

        mgmt = await super().list_tools()

        if not self._augmented_worker_tools:
            mgmt_names = {t.name for t in mgmt}
            self._augmented_worker_tools = [
                self._augment_schema(tool)
                for tool in self._worker_tool_schemas
                if tool.name not in mgmt_names
            ]

        return mgmt + self._augmented_worker_tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        """Route to management handler or resolve worker and proxy."""
        if name in self._MANAGEMENT_TOOLS:
            return await super().call_tool(name, arguments)

        database = arguments.pop("database", None)
        worker_or_error = self._resolve_worker(database)
        if isinstance(worker_or_error, types.CallToolResult):
            return worker_or_error

        worker = worker_or_error
        timeout = SLOW_TOOL_TIMEOUTS.get(name, DEFAULT_CALL_TIMEOUT)
        try:
            now = time.monotonic()
            worker.state = WorkerState.BUSY
            worker.busy_since = now
            worker.last_activity = now
            result = await worker.session.call_tool(name, arguments, read_timeout_seconds=timeout)
            worker.state = WorkerState.IDLE
            worker.busy_since = None
            worker.last_activity = time.monotonic()
            return self._enrich_result(result, worker.database_id)

        except McpError as exc:
            return await self._handle_worker_error(exc, worker, name)

        except (anyio.ClosedResourceError, anyio.EndOfStream, BrokenPipeError, OSError):
            await self._mark_worker_dead(worker)
            return self._error_result(
                f"Worker connection lost during '{name}'.",
                "WorkerCrashed",
                worker.database_id,
            )

        except Exception as exc:
            await self._mark_worker_dead(worker)
            return self._error_result(
                f"Unexpected error during '{name}': {exc}",
                "InternalError",
                worker.database_id,
            )

    # ------------------------------------------------------------------
    # Resource overrides
    # ------------------------------------------------------------------

    async def list_resources(self) -> list[types.Resource]:
        """Return supervisor resources + worker resources."""
        if not self._worker_tool_schemas:
            await self._bootstrap_worker_schemas()
        own = await super().list_resources()
        return own + list(self._worker_resources)

    async def list_resource_templates(self) -> list[types.ResourceTemplate]:
        """Return worker resource templates."""
        if not self._worker_tool_schemas:
            await self._bootstrap_worker_schemas()
        own = await super().list_resource_templates()
        return own + list(self._worker_resource_templates)

    async def read_resource(self, uri: str | types.AnyUrl) -> list[ReadResourceContents]:
        """Route resource reads to supervisor or appropriate worker."""
        uri_str = str(uri)

        # Cache supervisor resource URIs on first call (they don't change after init).
        if self._own_resource_uris is None:
            own_resources = await super().list_resources()
            own_templates = await super().list_resource_templates()
            self._own_resource_uris = frozenset(str(r.uri) for r in own_resources)
            self._own_resource_template_pats = [
                self._compile_uri_template(str(t.uriTemplate)) for t in own_templates
            ]

        is_own = uri_str in self._own_resource_uris or any(
            p.match(uri_str) for p in self._own_resource_template_pats
        )
        if is_own:
            return list(await super().read_resource(uri))

        # Route to worker
        worker_or_error = self._resolve_worker(None)
        if isinstance(worker_or_error, types.CallToolResult):
            parsed = self._parse_result(worker_or_error)
            raise McpError(
                types.ErrorData(
                    code=-32602,
                    message=parsed.get("error", "No database available"),
                )
            )

        worker = worker_or_error
        try:
            worker.last_activity = time.monotonic()
            result = await worker.session.read_resource(uri)
            contents = []
            for item in result.contents:
                if isinstance(item, types.TextResourceContents):
                    contents.append(
                        ReadResourceContents(content=item.text, mime_type=item.mimeType)
                    )
                elif isinstance(item, types.BlobResourceContents):
                    contents.append(
                        ReadResourceContents(
                            content=base64.b64decode(item.blob), mime_type=item.mimeType
                        )
                    )
            return contents

        except McpError:
            raise
        except Exception as exc:
            raise McpError(
                types.ErrorData(code=-32603, message=f"Resource read failed: {exc}")
            ) from exc

    @staticmethod
    def _compile_uri_template(template: str) -> re.Pattern[str]:
        """Compile a URI template into a regex pattern for matching."""
        parts = re.split(r"\{[^}]+\}", template)
        escaped = [re.escape(p) for p in parts]
        return re.compile("^" + "[^/]+".join(escaped) + "$")

    # ------------------------------------------------------------------
    # Schema injection
    # ------------------------------------------------------------------

    @staticmethod
    def _augment_schema(tool: types.Tool) -> types.Tool:
        """Deep-copy tool schema and add optional 'database' property."""
        schema = copy.deepcopy(tool.inputSchema)
        props = schema.setdefault("properties", {})
        props["database"] = {
            "type": "string",
            "description": (
                "Database to target (stem ID or path). Omit when only one database is open."
            ),
        }
        return tool.model_copy(update={"inputSchema": schema})

    # ------------------------------------------------------------------
    # Worker resolution
    # ------------------------------------------------------------------

    def _available_databases(self) -> list[dict[str, str]]:
        """Return a summary list of alive workers for error messages."""
        return [
            {"database": w.database_id, "file_path": w.file_path} for w in self._alive_workers()
        ]

    def _resolve_worker(self, database: str | None) -> Worker | types.CallToolResult:
        """Resolve which worker to target."""
        if not self._workers:
            return self._error_result("No database is open. Use open_database first.", "NoDatabase")

        if not database:
            alive = self._alive_workers()
            if len(alive) == 1:
                return alive[0]
            if not alive:
                return self._error_result("No database is ready.", "NoDatabase")
            return self._error_result(
                "Multiple databases are open. Specify the 'database' parameter.",
                "AmbiguousDatabase",
                available_databases=self._available_databases(),
            )

        # Try stem lookup, then path lookup
        path = self._id_to_path.get(database)
        if path is None:
            path = _canonical_path(database)
        worker = self._workers.get(path)
        if worker is None or worker.state in _INACTIVE_STATES:
            return self._error_result(
                f"Database not found: '{database}'.",
                "NotFound",
                available_databases=self._available_databases(),
            )
        return worker

    # ------------------------------------------------------------------
    # Error / enrichment helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _error_result(
        message: str,
        error_type: str,
        database: str | None = None,
        **extra: Any,
    ) -> types.CallToolResult:
        """Construct a proper MCP error result."""
        error_dict: dict[str, Any] = {"error": message, "error_type": error_type, **extra}
        if database:
            error_dict["database"] = database
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(error_dict))],
            isError=True,
        )

    @staticmethod
    def _enrich_result(result: types.CallToolResult, database_id: str) -> types.CallToolResult:
        """Inject 'database' field into the worker's CallToolResult."""
        new_content = []
        enriched = False
        for block in result.content:
            item = block
            if not enriched and isinstance(block, types.TextContent):
                try:
                    data = json.loads(block.text)
                    if isinstance(data, dict):
                        data["database"] = database_id
                        item = types.TextContent(type="text", text=json.dumps(data))
                        enriched = True
                except (json.JSONDecodeError, TypeError):
                    pass
            new_content.append(item)

        sc = result.structuredContent
        if sc is not None and isinstance(sc, dict):
            sc = {**sc, "database": database_id}

        return types.CallToolResult(
            content=new_content,
            structuredContent=sc,
            isError=result.isError,
        )

    async def _handle_worker_error(
        self, exc: McpError, worker: Worker, tool_name: str
    ) -> types.CallToolResult:
        """Handle McpError from worker call."""
        code = exc.error.code
        if code == _MCP_CONNECTION_CLOSED:
            await self._mark_worker_dead(worker)
            return self._error_result(
                f"Worker crashed during '{tool_name}'.",
                "WorkerCrashed",
                worker.database_id,
            )
        if code == _MCP_REQUEST_TIMEOUT:
            worker.state = WorkerState.STUCK
            return self._error_result(
                f"Tool '{tool_name}' timed out.",
                "CallTimeout",
                worker.database_id,
            )
        # Worker is still alive — restore it to IDLE so it can serve future calls.
        worker.state = WorkerState.IDLE
        worker.busy_since = None
        return self._error_result(
            f"Worker error: {exc.error.message}",
            "WorkerError",
            worker.database_id,
        )

    # ------------------------------------------------------------------
    # Worker lifecycle
    # ------------------------------------------------------------------

    def _unique_id(self, base_id: str) -> str:
        """Return *base_id* or *base_id_N* to avoid collisions."""
        if base_id not in self._id_to_path:
            return base_id
        for i in range(2, 100):
            candidate = f"{base_id}_{i}"
            if candidate not in self._id_to_path:
                return candidate
        # Unreachable in practice (MAX_WORKERS <= 8), but return a unique
        # suffix rather than silently colliding with an existing ID.
        return f"{base_id}_{int(time.monotonic() * 1000) % 100_000}"

    async def _worker_lifecycle(
        self,
        worker: Worker,
        canonical: str,
        run_auto_analysis: bool,
        ready: asyncio.Future[types.CallToolResult],
    ) -> None:
        """Background task that owns the worker's stdio_client connection.

        The stdio_client async context manager creates an anyio task group
        that MUST live in the same task for its entire lifetime.  Running
        this in a dedicated ``asyncio.Task`` (rather than inline in a
        request handler) prevents anyio cancel-scope violations.
        """
        params = self._worker_params()
        async with contextlib.AsyncExitStack() as stack:
            try:
                read, write = await stack.enter_async_context(stdio_client(params))
                session = await stack.enter_async_context(ClientSession(read, write))
                await session.initialize()

                result = await session.call_tool(
                    "open_database",
                    {"file_path": canonical, "run_auto_analysis": run_auto_analysis},
                    read_timeout_seconds=SLOW_TOOL_TIMEOUTS["open_database"],
                )

                worker.session = session
                ready.set_result(result)

            except BaseException as exc:
                if not ready.done():
                    ready.set_exception(exc)
                return

            # Keep this task alive so the stdio_client task group persists.
            # The _stop event is set by _terminate_worker.
            with contextlib.suppress(asyncio.CancelledError):
                await worker._stop.wait()

            # Graceful shutdown: close_database on the worker
            if worker.session and worker.state != WorkerState.DEAD:
                try:
                    async with asyncio.timeout(60):
                        await worker.session.call_tool(
                            "close_database", {"save": worker._save_on_close}
                        )
                except Exception:
                    log.debug(
                        "close_database on worker %s failed", worker.database_id, exc_info=True
                    )

    async def _spawn_worker(
        self,
        file_path: str,
        run_auto_analysis: bool = False,
        database_id: str = "",
    ) -> dict[str, Any]:
        """Spawn a worker subprocess and open a database in it."""
        canonical = _canonical_path(file_path)

        async with self._lock:
            existing = self._workers.get(canonical)
            active_count = self._active_count()
            if existing and existing.state != WorkerState.DEAD:
                return {
                    "status": "already_open",
                    "database": existing.database_id,
                    "file_path": existing.file_path,
                    **existing.metadata,
                    "database_count": active_count,
                }

            if MAX_WORKERS is not None and active_count >= MAX_WORKERS:
                return {
                    "error": f"Maximum databases ({MAX_WORKERS}) reached. Close one first.",
                    "error_type": "ResourceExhausted",
                    "max_databases": MAX_WORKERS,
                }

            if database_id:
                if not _VALID_CUSTOM_ID.match(database_id):
                    return {
                        "error": (
                            f"Invalid database_id '{database_id}'. "
                            "Must match [a-z][a-z0-9_]{0,31}."
                        ),
                        "error_type": "InvalidArgument",
                    }
                if database_id in self._id_to_path:
                    return {
                        "error": f"Database ID '{database_id}' already in use.",
                        "error_type": "DuplicateId",
                    }
                db_id = database_id
            else:
                stem = Path(canonical).stem
                base_id = _normalize_id(stem)
                db_id = self._unique_id(base_id)

            worker = Worker(database_id=db_id, file_path=canonical)
            self._workers[canonical] = worker
            self._id_to_path[db_id] = canonical

        # Spawn the worker lifecycle in a dedicated background task so that
        # the stdio_client's anyio task group stays in one task.
        loop = asyncio.get_running_loop()
        ready: asyncio.Future[types.CallToolResult] = loop.create_future()
        task = loop.create_task(
            self._worker_lifecycle(worker, canonical, run_auto_analysis, ready),
            name=f"worker-{db_id}",
        )
        worker._task = task

        async def _abort_spawn():
            task.cancel()
            with contextlib.suppress(Exception):
                await task
            async with self._lock:
                self._workers.pop(canonical, None)
                self._id_to_path.pop(db_id, None)

        try:
            result = await ready
        except BaseException:
            await _abort_spawn()
            raise

        result_data = self._parse_result(result)

        if result.isError or "error" in result_data:
            await _abort_spawn()
            return result_data

        meta_keys = ("processor", "bitness", "file_type", "function_count", "segment_count")
        metadata = {k: result_data[k] for k in meta_keys if k in result_data}

        async with self._lock:
            worker.state = WorkerState.IDLE
            worker.metadata = metadata
            worker.last_activity = time.monotonic()

        self._ensure_reaper()

        return {
            "status": "ok",
            "database": db_id,
            "file_path": canonical,
            **metadata,
            "database_count": self._active_count(),
        }

    async def _terminate_worker(self, canonical_path: str, save: bool = True) -> dict[str, Any]:
        """Close a database and terminate its worker process."""
        async with self._lock:
            worker = self._workers.pop(canonical_path, None)
            if worker:
                self._id_to_path.pop(worker.database_id, None)

        if worker is None:
            return {"error": "Worker not found.", "error_type": "NotFound"}

        db_id = worker.database_id

        worker._save_on_close = save
        worker._stop.set()

        if worker._task:
            try:
                async with asyncio.timeout(65):
                    await worker._task
            except (TimeoutError, asyncio.CancelledError):
                worker._task.cancel()
                with contextlib.suppress(Exception):
                    await worker._task
            except Exception:
                log.debug("Worker task for %s failed", db_id, exc_info=True)

        return {"status": "closed", "database": db_id}

    @staticmethod
    async def _force_stop_worker(worker: Worker) -> None:
        """Signal a worker to stop and cancel its background task."""
        worker._stop.set()
        if worker._task:
            worker._task.cancel()
            with contextlib.suppress(Exception):
                await worker._task

    async def _mark_worker_dead(self, worker: Worker):
        """Mark a worker as dead and clean up its resources."""
        worker.state = WorkerState.DEAD
        async with self._lock:
            self._workers.pop(worker.file_path, None)
            self._id_to_path.pop(worker.database_id, None)
        await self._force_stop_worker(worker)

    async def _shutdown_all(self, *, save: bool = True):
        """Terminate all workers concurrently with a total deadline."""
        paths = list(self._workers.keys())
        if not paths:
            return

        async def terminate(path: str):
            await self._terminate_worker(path, save=save)

        try:
            async with asyncio.timeout(15):
                async with anyio.create_task_group() as tg:
                    for path in paths:
                        tg.start_soon(terminate, path)
        except BaseException:
            # Force-cancel remaining worker tasks, then re-raise so callers
            # (and the event loop) see KeyboardInterrupt / SystemExit / etc.
            async with self._lock:
                remaining = list(self._workers.values())
                self._workers.clear()
                self._id_to_path.clear()
            for worker in remaining:
                await self._force_stop_worker(worker)
            raise

    def _alive_workers(self) -> list[Worker]:
        """Return workers that are not DEAD or STARTING."""
        return [w for w in self._workers.values() if w.state not in _INACTIVE_STATES]

    def _active_count(self) -> int:
        """Return the number of workers that are not DEAD or STARTING."""
        return sum(1 for w in self._workers.values() if w.state not in _INACTIVE_STATES)

    def _build_database_list(self, *, include_state: bool = False) -> dict[str, Any]:
        """Build a database summary dict from alive workers."""
        alive = self._alive_workers()
        databases = []
        for w in alive:
            entry: dict[str, Any] = {"database": w.database_id, "file_path": w.file_path}
            if include_state:
                entry["state"] = w.state.name.lower()
            entry.update(w.metadata)
            databases.append(entry)
        result: dict[str, Any] = {"databases": databases, "database_count": len(alive)}
        if MAX_WORKERS is not None:
            result["max_databases"] = MAX_WORKERS
        return result

    # ------------------------------------------------------------------
    # Idle / stuck reaper
    # ------------------------------------------------------------------

    def _ensure_reaper(self):
        """Start the background reaper task if not already running."""
        if self._reaper_task is None or self._reaper_task.done():
            self._reaper_task = asyncio.get_running_loop().create_task(self._reaper_loop())

    async def _reaper_loop(self):
        """Periodically check for idle or stuck workers."""
        try:
            while True:
                await asyncio.sleep(30)
                now = time.monotonic()
                to_terminate: list[str] = []

                for path, worker in list(self._workers.items()):
                    if worker.state == WorkerState.DEAD:
                        continue
                    # Stuck detection: BUSY for >5 minutes
                    if (
                        worker.state == WorkerState.BUSY
                        and worker.busy_since
                        and now - worker.busy_since > 300
                    ):
                        log.warning("Worker %s stuck for >5m, terminating", worker.database_id)
                        worker.state = WorkerState.STUCK
                        to_terminate.append(path)
                        continue
                    # Idle timeout
                    if (
                        IDLE_TIMEOUT > 0
                        and worker.state == WorkerState.IDLE
                        and now - worker.last_activity > IDLE_TIMEOUT
                    ):
                        log.info(
                            "Worker %s idle for >%ds, terminating",
                            worker.database_id,
                            IDLE_TIMEOUT,
                        )
                        to_terminate.append(path)

                for path in to_terminate:
                    try:
                        await self._terminate_worker(path, save=True)
                    except Exception:
                        log.debug("Reaper terminate failed for %s", path, exc_info=True)

                # Stop reaper if no workers remain
                if not self._workers:
                    return
        except asyncio.CancelledError:
            return

    # ------------------------------------------------------------------
    # Management tools
    # ------------------------------------------------------------------

    def _register_management_tools(self):
        @self.tool()
        async def open_database(
            file_path: str,
            run_auto_analysis: bool = False,
            keep_open: bool = False,
            database_id: str = "",
        ) -> dict:
            """Open a binary file for analysis with IDA Pro.

            By default, any previously open database is saved and closed first.
            Set keep_open=True to keep existing databases open (multi-database mode).
            Use database_id to assign a custom identifier (must match [a-z][a-z0-9_]{0,31}).
            """
            if not keep_open:
                for path in list(self._workers):
                    await self._terminate_worker(path, save=True)

            return await self._spawn_worker(file_path, run_auto_analysis, database_id)

        @self.tool()
        async def close_database(
            save: bool = True,
            database: str = "",
        ) -> dict:
            """Close a database and terminate its worker process.

            When multiple databases are open, specify which one with the database parameter.
            """
            worker_or_error = self._resolve_worker(database)
            if isinstance(worker_or_error, types.CallToolResult):
                return self._parse_result(worker_or_error)
            return await self._terminate_worker(worker_or_error.file_path, save=save)

        @self.tool()
        async def save_database(
            outfile: str = "",
            flags: int = -1,
            database: str = "",
        ) -> dict:
            """Save the current database.

            When multiple databases are open, specify which one with the database parameter.
            """
            worker_or_error = self._resolve_worker(database)
            if isinstance(worker_or_error, types.CallToolResult):
                return self._parse_result(worker_or_error)
            result = await worker_or_error.session.call_tool(
                "save_database", {"outfile": outfile, "flags": flags}
            )
            return self._parse_result(result)

        @self.tool()
        async def list_databases() -> dict:
            """List all currently open databases with metadata."""
            return self._build_database_list()

    # ------------------------------------------------------------------
    # Supervisor-owned resources
    # ------------------------------------------------------------------

    def _register_supervisor_resources(self):
        @self.resource(
            "ida://databases",
            description="All open databases with worker status (supervisor-level)",
        )
        def databases_resource() -> str:
            return json.dumps(self._build_database_list(include_state=True), separators=(",", ":"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    proxy = ProxyMCP()
    proxy.run(transport="stdio")


if __name__ == "__main__":
    main()
