# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Multi-database supervisor for the IDA MCP server.

Spawns one worker subprocess per open database and proxies MCP tool calls
and resource reads to the appropriate worker.  Prompts are registered
directly on the supervisor.
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
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
from fastmcp import Client, FastMCP
from fastmcp.client import StdioTransport

# FastMCP internal imports — not part of the public API as of v3.1.
from fastmcp.exceptions import ToolError
from fastmcp.resources.resource import Resource as FastMCPResource
from fastmcp.resources.template import ResourceTemplate as FastMCPResourceTemplate
from fastmcp.tools.tool import Tool as FastMCPTool
from fastmcp.tools.tool import ToolResult
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.shared.exceptions import McpError

from ida_mcp.exceptions import (
    DEFAULT_TOOL_TIMEOUT,
    IDAError,
    tool_timeout,
)
from ida_mcp.prompts import register_all as register_prompts

log = logging.getLogger(__name__)

_max_workers_env = os.environ.get("IDA_MCP_MAX_WORKERS")
MAX_WORKERS: int | None = min(max(int(_max_workers_env), 1), 8) if _max_workers_env else None
IDLE_TIMEOUT = int(os.environ.get("IDA_MCP_IDLE_TIMEOUT", "1800"))


def _tool_timedelta(name: str) -> timedelta:
    """Return the timeout for a tool as a timedelta."""
    return timedelta(seconds=tool_timeout(name))


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
_NON_LIVE_STATES = frozenset({WorkerState.DEAD, WorkerState.STARTING, WorkerState.STUCK})


@dataclass
class Worker:
    database_id: str
    file_path: str
    client: Client | None = None
    _exit_stack: contextlib.AsyncExitStack | None = None
    pid: int | None = None
    _state: WorkerState = WorkerState.STARTING
    metadata: dict[str, Any] = field(default_factory=dict)
    last_activity: float = field(default_factory=time.monotonic)
    _semaphore: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(1))
    _busy_since: float | None = None
    _busy_timeout: float = DEFAULT_TOOL_TIMEOUT

    @property
    def state(self) -> WorkerState:
        """Derive effective state from lifecycle state and busy flag."""
        if self._state in _NON_LIVE_STATES:
            return self._state
        return WorkerState.BUSY if self._busy_since is not None else WorkerState.IDLE

    @state.setter
    def state(self, value: WorkerState) -> None:
        self._state = value

    @property
    def busy_duration(self) -> float | None:
        """Seconds since the worker became busy, or None if idle."""
        return time.monotonic() - self._busy_since if self._busy_since is not None else None

    @property
    def stuck_threshold(self) -> float:
        """Seconds a tool is allowed to run before the reaper kills the worker."""
        return self._busy_timeout + 60

    def _signal_cancel(self):
        """Send SIGUSR1 to the worker to set IDA's cancellation flag."""
        if self.pid is not None and hasattr(signal, "SIGUSR1"):
            with contextlib.suppress(OSError):
                os.kill(self.pid, signal.SIGUSR1)

    @contextlib.asynccontextmanager
    async def dispatch(self, timeout: float | None = None):
        """Acquire the per-worker semaphore and track busy state.

        Use this for any I/O to the worker subprocess (tool calls, resource
        reads, saves) so that requests to the same worker are serialized
        and the busy_since / last_activity bookkeeping stays consistent.

        *timeout* (seconds) tells the reaper how long this operation is
        expected to take.  The reaper will only kill the worker if it
        exceeds this timeout plus a safety margin.

        When the handler's ``CancelScope`` is cancelled by the MCP framework
        (via ``notifications/cancelled``), ``CancelledError`` propagates
        through the ``yield``, the ``except`` block sends SIGUSR1 to the
        worker to set IDA's cancellation flag, and the semaphore is released
        so the next request can proceed.
        """
        async with self._semaphore:
            now = time.monotonic()
            self._busy_since = now
            self._busy_timeout = timeout if timeout is not None else DEFAULT_TOOL_TIMEOUT
            self.last_activity = now
            try:
                yield
            except BaseException:
                # Handler was cancelled (or another error) — signal the
                # worker so batch loops checking user_cancelled() can
                # break early rather than running to completion.
                self._signal_cancel()
                raise
            finally:
                self._busy_since = None
                self.last_activity = time.monotonic()


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
        self._worker_tool_schemas: list[FastMCPTool] = []
        self._augmented_worker_tools: list[FastMCPTool] = []
        self._worker_resources: list[FastMCPResource] = []
        self._worker_resource_templates: list[FastMCPResourceTemplate] = []
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
    def _worker_transport() -> StdioTransport:
        """Build a StdioTransport for spawning a worker subprocess."""
        return StdioTransport(
            command=sys.executable,
            args=["-m", "ida_mcp.server"],
            env=dict(os.environ),
            # Terminate the subprocess when the Client context exits.
            # We manage worker lifetime explicitly via _close_client.
            keep_alive=False,
        )

    @staticmethod
    def _parse_result(result: types.CallToolResult) -> dict[str, Any]:
        """Extract the JSON dict from a CallToolResult.

        Checks ``structuredContent`` first (if it's a dict), then falls back
        to JSON-decoding the first ``TextContent`` block.  When the content
        is not valid JSON, wrap the text in an error dict so callers always
        receive a consistent shape.
        """
        sc = getattr(result, "structuredContent", None)
        if isinstance(sc, dict):
            return sc

        if result.content and isinstance(result.content[0], types.TextContent):
            text = result.content[0].text
            try:
                parsed = json.loads(text)
            except (json.JSONDecodeError, TypeError):
                if result.isError:
                    return {"error": text, "error_type": "WorkerError"}
                return {
                    "error": f"Non-JSON result from worker: {text}",
                    "error_type": "InternalError",
                }
            if not isinstance(parsed, dict):
                return {
                    "error": f"Expected JSON object from worker, got {type(parsed).__name__}",
                    "error_type": "InternalError",
                }
            return parsed
        return {"error": "Empty or non-text result from worker", "error_type": "InternalError"}

    @staticmethod
    def _require_success(
        result: types.CallToolResult,
        result_data: dict[str, Any],
        default_message: str = "Worker operation failed",
    ) -> None:
        """Raise :class:`IDAError` if *result* indicates failure."""
        if result.isError or "error" in result_data:
            details = {k: v for k, v in result_data.items() if k not in ("error", "error_type")}
            raise IDAError(
                result_data.get("error", default_message),
                error_type=result_data.get("error_type", "WorkerError"),
                **details,
            )

    async def _bootstrap_worker_schemas(self):
        """Spawn a temporary worker to discover tool and resource schemas."""
        async with Client(self._worker_transport()) as client:
            tools = (await client.list_tools_mcp()).tools
            resources = (await client.list_resources_mcp()).resources
            templates = (await client.list_resource_templates_mcp()).resourceTemplates

        # Convert from mcp.types.* to FastMCP equivalents so they satisfy the
        # FastMCP protocol layer (which calls .to_mcp_tool() etc.).
        self._worker_tool_schemas = [
            FastMCPTool(
                name=t.name,
                description=t.description,
                parameters=t.inputSchema,
                annotations=t.annotations,
            )
            for t in tools
        ]
        self._worker_resources = [
            FastMCPResource(
                uri=str(r.uri),
                name=r.name,
                description=r.description,
                mime_type=r.mimeType,
                annotations=r.annotations,
            )
            for r in resources
        ]
        self._worker_resource_templates = [
            FastMCPResourceTemplate(
                uri_template=str(t.uriTemplate),
                name=t.name,
                description=t.description,
                mime_type=t.mimeType,
                annotations=t.annotations,
                parameters={},
            )
            for t in templates
        ]

    # ------------------------------------------------------------------
    # list_tools / call_tool overrides
    # ------------------------------------------------------------------

    async def list_tools(self, **kwargs: Any) -> list[FastMCPTool]:
        """Return management tools + worker tools with injected database param."""
        if not self._worker_tool_schemas:
            await self._bootstrap_worker_schemas()

        # Always skip middleware: FastMCP's middleware chain calls
        # self.list_tools(run_middleware=False) via call_next, which would
        # re-enter this override and double-count the augmented worker tools.
        mgmt = list(await super().list_tools(**kwargs, run_middleware=False))

        if not self._augmented_worker_tools:
            mgmt_names = {t.name for t in mgmt}
            self._augmented_worker_tools = [
                self._augment_schema(tool)
                for tool in self._worker_tool_schemas
                if tool.name not in mgmt_names
            ]

        return mgmt + self._augmented_worker_tools

    async def call_tool(self, name: str, arguments: dict[str, Any], **kwargs: Any) -> ToolResult:
        """Route to management handler or resolve worker and proxy.

        Requests to the same worker are serialized via a per-worker semaphore
        (idalib is single-threaded), but requests to *different* workers run
        fully in parallel.
        """
        if name in self._MANAGEMENT_TOOLS:
            return await super().call_tool(name, arguments, **kwargs)

        database = arguments.pop("database", None)
        worker = self._resolve_worker(database)
        timeout = _tool_timedelta(name)
        result = await self._proxy_to_worker(worker, name, arguments, timeout)
        enriched = self._enrich_result(result, worker.database_id)

        # Worker returned an error — raise so FastMCP marks isError=True.
        # Use ToolError (not IDAError) to pass the already-formatted text
        # through without double-encoding.
        if enriched.isError:
            text = enriched.content[0].text if enriched.content else "Worker error"
            raise ToolError(text)

        return ToolResult(
            content=enriched.content,
            structured_content=enriched.structuredContent,
        )

    # ------------------------------------------------------------------
    # Resource overrides
    # ------------------------------------------------------------------

    async def list_resources(self, **kwargs: Any) -> list[FastMCPResource]:
        """Return supervisor resources + worker resources."""
        if not self._worker_tool_schemas:
            await self._bootstrap_worker_schemas()
        own = list(await super().list_resources(**kwargs))
        return own + self._worker_resources

    async def list_resource_templates(self, **kwargs: Any) -> list[FastMCPResourceTemplate]:
        """Return worker resource templates."""
        if not self._worker_tool_schemas:
            await self._bootstrap_worker_schemas()
        own = list(await super().list_resource_templates(**kwargs))
        return own + self._worker_resource_templates

    async def read_resource(
        self, uri: str | types.AnyUrl, **kwargs: Any
    ) -> list[ReadResourceContents]:
        """Route resource reads to supervisor or appropriate worker."""
        uri_str = str(uri)

        # Cache supervisor resource URIs on first call (they don't change after init).
        if self._own_resource_uris is None:
            own_resources = await super().list_resources()
            own_templates = await super().list_resource_templates()
            self._own_resource_uris = frozenset(str(r.uri) for r in own_resources)
            self._own_resource_template_pats = [
                self._compile_uri_template(str(t.uri_template)) for t in own_templates
            ]

        is_own = uri_str in self._own_resource_uris or any(
            p.match(uri_str) for p in self._own_resource_template_pats
        )
        if is_own:
            return list(await super().read_resource(uri, **kwargs))

        # Route to worker
        try:
            worker = self._resolve_worker(None)
        except IDAError as exc:
            # Use the human-readable message, not IDAError.__str__ (which is JSON).
            raise McpError(types.ErrorData(code=-32602, message=exc.args[0])) from exc
        async with worker.dispatch():
            client = worker.client
            if client is None:
                await self._mark_worker_dead(worker)
                raise McpError(
                    types.ErrorData(
                        code=_MCP_CONNECTION_CLOSED,
                        message="Worker closed before resource read could start.",
                    )
                )
            try:
                result = await client.read_resource_mcp(uri)
            except McpError as exc:
                if exc.error.code in (_MCP_CONNECTION_CLOSED, _MCP_REQUEST_TIMEOUT):
                    await self._mark_worker_dead(worker)
                raise
            except (anyio.ClosedResourceError, anyio.EndOfStream, BrokenPipeError, OSError) as exc:
                await self._mark_worker_dead(worker)
                raise McpError(
                    types.ErrorData(
                        code=_MCP_CONNECTION_CLOSED,
                        message=f"Worker connection lost during resource read: {exc}",
                    )
                ) from exc
            except Exception as exc:
                raise McpError(
                    types.ErrorData(code=-32603, message=f"Resource read failed: {exc}")
                ) from exc

        contents = []
        for item in result.contents:
            if isinstance(item, types.TextResourceContents):
                contents.append(ReadResourceContents(content=item.text, mime_type=item.mimeType))
            elif isinstance(item, types.BlobResourceContents):
                contents.append(
                    ReadResourceContents(
                        content=base64.b64decode(item.blob), mime_type=item.mimeType
                    )
                )
        return contents

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
    def _augment_schema(tool: FastMCPTool) -> FastMCPTool:
        """Deep-copy tool schema and add optional 'database' property."""
        schema = copy.deepcopy(tool.parameters)
        props = schema.setdefault("properties", {})
        props["database"] = {
            "type": "string",
            "description": (
                "Database to target (stem ID or path). Omit when only one database is open."
            ),
        }
        return tool.model_copy(update={"parameters": schema})

    # ------------------------------------------------------------------
    # Worker resolution
    # ------------------------------------------------------------------

    def _available_databases(self) -> list[dict[str, str]]:
        """Return a summary list of alive workers for error messages."""
        return [
            {"database": w.database_id, "file_path": w.file_path} for w in self._alive_workers()
        ]

    def _resolve_worker(self, database: str | None) -> Worker:
        """Resolve which worker to target.  Raises :class:`IDAError` on failure."""
        if not self._workers:
            raise IDAError("No database is open. Use open_database first.", error_type="NoDatabase")

        if not database:
            alive = self._alive_workers()
            if len(alive) == 1:
                return alive[0]
            if not alive:
                raise IDAError("No database is ready.", error_type="NoDatabase")
            raise IDAError(
                "Multiple databases are open. Specify the 'database' parameter.",
                error_type="AmbiguousDatabase",
                available_databases=self._available_databases(),
            )

        # Try stem lookup, then path lookup
        path = self._id_to_path.get(database)
        if path is None:
            path = _canonical_path(database)
        worker = self._workers.get(path)
        if worker is None or worker.state in _INACTIVE_STATES:
            raise IDAError(
                f"Database not found: '{database}'.",
                error_type="NotFound",
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
            content=[
                types.TextContent(type="text", text=json.dumps(error_dict, separators=(",", ":")))
            ],
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
                        item = types.TextContent(
                            type="text", text=json.dumps(data, separators=(",", ":"))
                        )
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
        """Handle McpError from worker call.

        Inflight bookkeeping is handled by the ``dispatch()`` context manager;
        this method only needs to handle terminal state transitions.
        """
        code = exc.error.code
        if code == _MCP_CONNECTION_CLOSED:
            await self._mark_worker_dead(worker)
            return self._error_result(
                f"Worker crashed during '{tool_name}'.",
                "WorkerCrashed",
                worker.database_id,
            )
        if code == _MCP_REQUEST_TIMEOUT:
            await self._mark_worker_dead(worker)
            return self._error_result(
                f"Tool '{tool_name}' timed out — worker terminated.",
                "CallTimeout",
                worker.database_id,
            )
        return self._error_result(
            f"Worker error: {exc.error.message}",
            "WorkerError",
            worker.database_id,
        )

    async def _proxy_to_worker(
        self,
        worker: Worker,
        tool_name: str,
        arguments: dict[str, Any],
        timeout: timedelta | None = None,
    ) -> types.CallToolResult:
        """Dispatch a tool call to a worker with standard error handling.

        Acquires the per-worker semaphore, sends the call, and translates
        any transport or protocol error into a structured ``CallToolResult``.

        *timeout* controls the MCP transport read timeout and the reaper
        threshold.  Tool-level timeouts are enforced by FastMCP's built-in
        ``timeout=`` parameter on the worker; this is a safety net for
        transport-level hangs.
        """
        if timeout is None:
            timeout = _tool_timedelta(tool_name)
        async with worker.dispatch(timeout=timeout.total_seconds()):
            client = worker.client
            if client is None:
                await self._mark_worker_dead(worker)
                return self._error_result(
                    f"Worker closed before '{tool_name}' could start.",
                    "WorkerCrashed",
                    worker.database_id,
                )
            try:
                return await client.call_tool_mcp(tool_name, arguments, timeout=timeout)

            except McpError as exc:
                return await self._handle_worker_error(exc, worker, tool_name)

            except (anyio.ClosedResourceError, anyio.EndOfStream, BrokenPipeError, OSError):
                await self._mark_worker_dead(worker)
                return self._error_result(
                    f"Worker connection lost during '{tool_name}'.",
                    "WorkerCrashed",
                    worker.database_id,
                )

            except Exception as exc:
                await self._mark_worker_dead(worker)
                return self._error_result(
                    f"Unexpected error during '{tool_name}': {exc}",
                    "InternalError",
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
                raise IDAError(
                    f"Maximum databases ({MAX_WORKERS}) reached. Close one first.",
                    error_type="ResourceExhausted",
                    max_databases=MAX_WORKERS,
                )

            if database_id:
                if not _VALID_CUSTOM_ID.match(database_id):
                    raise IDAError(
                        f"Invalid database_id '{database_id}'. Must match [a-z][a-z0-9_]{{0,31}}.",
                        error_type="InvalidArgument",
                    )
                if database_id in self._id_to_path:
                    raise IDAError(
                        f"Database ID '{database_id}' already in use.",
                        error_type="DuplicateId",
                    )
                db_id = database_id
            else:
                stem = Path(canonical).stem
                base_id = _normalize_id(stem)
                db_id = self._unique_id(base_id)

            worker = Worker(database_id=db_id, file_path=canonical)
            self._workers[canonical] = worker
            self._id_to_path[db_id] = canonical

        # Connect to the worker and open the database.  We manage the
        # Client via an AsyncExitStack so it outlives this method and
        # persists until _close_client tears it down.  Cross-task __aexit__
        # is safe: Client runs the transport in a background task and
        # __aexit__ merely signals that task to stop and awaits it, so
        # the transport enter/exit always happen in the same task.
        client = Client(self._worker_transport())
        stack = contextlib.AsyncExitStack()

        async def _abort_spawn():
            # On failure the subprocess's atexit handler (session.close)
            # will save/close the database if open_database partially
            # succeeded, so we only need to tear down the transport here.
            with contextlib.suppress(Exception):
                await stack.aclose()
            async with self._lock:
                self._workers.pop(canonical, None)
                self._id_to_path.pop(db_id, None)

        try:
            await stack.enter_async_context(client)
            result = await client.call_tool_mcp(
                "open_database",
                {"file_path": canonical, "run_auto_analysis": run_auto_analysis},
                timeout=_tool_timedelta("open_database"),
            )
        except BaseException:
            await _abort_spawn()
            raise

        result_data = self._parse_result(result)

        try:
            self._require_success(result, result_data, "Worker failed to open database")
        except IDAError:
            await _abort_spawn()
            raise

        meta_keys = ("processor", "bitness", "file_type", "function_count", "segment_count")
        metadata = {k: result_data[k] for k in meta_keys if k in result_data}

        async with self._lock:
            worker.client = client
            worker._exit_stack = stack
            worker.state = WorkerState.IDLE
            worker.pid = result_data.get("pid")
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
            raise IDAError("Worker not found.", error_type="NotFound")

        db_id = worker.database_id

        if worker.client and worker.state != WorkerState.DEAD:
            try:
                async with asyncio.timeout(60):
                    async with worker.dispatch():
                        await worker.client.call_tool_mcp("close_database", {"save": save})
            except Exception:  # including TimeoutError — always proceed to _close_client
                log.debug("close_database on worker %s failed", db_id, exc_info=True)

        await self._close_client(worker)
        return {"status": "closed", "database": db_id}

    @staticmethod
    async def _close_client(worker: Worker) -> None:
        """Close the worker's Client connection and transport."""
        worker.state = WorkerState.DEAD
        if worker._exit_stack:
            with contextlib.suppress(Exception):
                await worker._exit_stack.aclose()
            worker._exit_stack = None
            worker.client = None

    async def _mark_worker_dead(self, worker: Worker):
        """Mark a worker as dead and clean up its resources."""
        async with self._lock:
            self._workers.pop(worker.file_path, None)
            self._id_to_path.pop(worker.database_id, None)
        await self._close_client(worker)

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
                await self._close_client(worker)
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
                    # Stuck detection: busy longer than the tool's timeout + margin
                    busy_dur = worker.busy_duration
                    stuck_threshold = worker.stuck_threshold
                    if busy_dur is not None and busy_dur > stuck_threshold:
                        log.warning(
                            "Worker %s stuck for %.0fs (threshold %.0fs), terminating",
                            worker.database_id,
                            busy_dur,
                            stuck_threshold,
                        )
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
            worker = self._resolve_worker(database)
            return await self._terminate_worker(worker.file_path, save=save)

        @self.tool()
        async def save_database(
            outfile: str = "",
            flags: int = -1,
            database: str = "",
        ) -> dict:
            """Save the current database.

            When multiple databases are open, specify which one with the database parameter.
            """
            worker = self._resolve_worker(database)
            result = await self._proxy_to_worker(
                worker,
                "save_database",
                {"outfile": outfile, "flags": flags},
                timeout=_tool_timedelta("save_database"),
            )
            result_data = self._parse_result(result)
            self._require_success(result, result_data, "Save failed")
            return result_data

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
