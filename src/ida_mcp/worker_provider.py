# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Worker pool provider — owns worker lifecycle and exposes tools/resources.

Implements ``Provider`` so that FastMCP's native provider chain handles
tool lookup, middleware, and error handling instead of manual overrides.
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
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
from fastmcp import Client
from fastmcp.client import StdioTransport
from fastmcp.exceptions import ResourceError, ToolError
from fastmcp.resources.base import ResourceContent, ResourceResult
from fastmcp.resources.template import ResourceTemplate
from fastmcp.server.providers.base import Provider
from fastmcp.server.tasks.config import TaskConfig
from fastmcp.tools.base import Tool, ToolResult
from fastmcp.utilities.components import get_fastmcp_metadata
from fastmcp.utilities.versions import VersionSpec
from mcp.shared.exceptions import McpError
from pydantic import PrivateAttr

from ida_mcp.context import try_get_context
from ida_mcp.exceptions import (
    DEFAULT_TOOL_TIMEOUT,
    IDAError,
    tool_timeout,
)

log = logging.getLogger(__name__)


_max_workers_env = os.environ.get("IDA_MCP_MAX_WORKERS")
# Clamp to [1, 8] when set; None means unlimited.
MAX_WORKERS: int | None = min(max(int(_max_workers_env), 1), 8) if _max_workers_env else None
IDLE_TIMEOUT = int(os.environ.get("IDA_MCP_IDLE_TIMEOUT", "1800"))

_VALID_CUSTOM_ID = re.compile(r"^[a-z][a-z0-9_]{0,31}$")

_IDA_SCHEME = "ida://"

_MCP_CONNECTION_CLOSED = -32000
_MCP_METHOD_NOT_FOUND = -32001
_MCP_REQUEST_TIMEOUT = 408

# Tags that correspond to per-database capabilities.
_CAPABILITY_TAGS: frozenset[str] = frozenset({"decompiler", "assembler"})


def tool_timedelta(name: str) -> timedelta:
    """Return the timeout for a tool as a timedelta."""
    return timedelta(seconds=tool_timeout(name))


def _capabilities_satisfied(tags: set[str], available_caps: set[str]) -> bool:
    """Return True if every capability-tag in *tags* is in *available_caps*."""
    cap_tags = tags & _CAPABILITY_TAGS
    return not cap_tags or cap_tags <= available_caps


_RFC6570_QUERY_RE = re.compile(r"\{\?([^}]+)\}")


def expand_uri_template(template: str, params: dict[str, Any]) -> str:
    """Expand a URI template with simple and RFC 6570 query parameters.

    Handles ``{key}`` path parameters and ``{?key1,key2}`` query parameters.
    """

    def _expand_query(m: re.Match[str]) -> str:
        names = [n.strip() for n in m.group(1).split(",")]
        pairs = [f"{n}={params[n]}" for n in names if n in params]
        return f"?{'&'.join(pairs)}" if pairs else ""

    # First expand RFC 6570 query expressions
    uri = _RFC6570_QUERY_RE.sub(_expand_query, template)
    # Then expand simple path parameters
    for key, value in params.items():
        uri = uri.replace(f"{{{key}}}", str(value))
    return uri


def prefix_uri(uri: str, database_id: str) -> str:
    """Insert a database ID into an ``ida://`` URI."""
    if uri.startswith(_IDA_SCHEME):
        return f"{_IDA_SCHEME}{database_id}/{uri[len(_IDA_SCHEME) :]}"
    return uri


def extract_db_prefix(uri: str) -> tuple[str | None, str]:
    """Extract a database ID prefix from a resource URI.

    Returns ``(database_id, worker_uri)``.
    """
    if not uri.startswith(_IDA_SCHEME):
        return None, uri
    rest = uri[len(_IDA_SCHEME) :]
    slash = rest.find("/")
    if slash <= 0:
        return None, uri
    database_id = rest[:slash]
    worker_uri = f"{_IDA_SCHEME}{rest[slash + 1 :]}"
    return database_id, worker_uri


def _canonical_path(path: str) -> str:
    return os.path.realpath(os.path.expanduser(path))


def _normalize_id(stem: str) -> str:
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
    _sessions: set[str] = field(default_factory=set)

    # ------------------------------------------------------------------
    # Session tracking
    # ------------------------------------------------------------------

    def attach(self, session_id: str | None) -> None:
        """Register a session as using this worker. ``None`` is a no-op."""
        if session_id is not None:
            self._sessions.add(session_id)

    def detach(self, session_id: str | None) -> bool:
        """Unregister a session. Returns ``True`` if no sessions remain.

        ``None`` is a no-op; returns ``True`` only when the session set is empty.
        """
        if session_id is not None:
            self._sessions.discard(session_id)
        return len(self._sessions) == 0

    def is_attached(self, session_id: str | None) -> bool:
        """``True`` if *session_id* is registered, or if *session_id* is ``None``."""
        if session_id is None:
            return True
        return session_id in self._sessions

    @property
    def session_count(self) -> int:
        """Number of sessions currently attached to this worker."""
        return len(self._sessions)

    # ------------------------------------------------------------------
    # State helpers
    # ------------------------------------------------------------------

    @property
    def state(self) -> WorkerState:
        if self._state in _NON_LIVE_STATES:
            return self._state
        return WorkerState.BUSY if self._busy_since is not None else WorkerState.IDLE

    @state.setter
    def state(self, value: WorkerState) -> None:
        self._state = value

    @property
    def busy_duration(self) -> float | None:
        return time.monotonic() - self._busy_since if self._busy_since is not None else None

    @property
    def stuck_threshold(self) -> float:
        return self._busy_timeout + 60

    def _signal_cancel(self):
        if self.pid is not None and hasattr(signal, "SIGUSR1"):
            with contextlib.suppress(OSError):
                os.kill(self.pid, signal.SIGUSR1)

    @contextlib.asynccontextmanager
    async def dispatch(self, timeout: float | None = None):
        """Acquire semaphore, track busy state, signal on cancellation."""
        async with self._semaphore:
            now = time.monotonic()
            self._busy_since = now
            self._busy_timeout = timeout if timeout is not None else DEFAULT_TOOL_TIMEOUT
            self.last_activity = now
            try:
                yield
            except BaseException:
                self._signal_cancel()
                raise
            finally:
                self._busy_since = None
                self.last_activity = time.monotonic()


# ---------------------------------------------------------------------------
# RoutingTool
# ---------------------------------------------------------------------------


class RoutingTool(Tool):
    """A Tool that routes calls to the correct worker subprocess."""

    task_config: TaskConfig = TaskConfig(mode="forbidden")
    _provider: WorkerPoolProvider = PrivateAttr()

    def __init__(self, provider: WorkerPoolProvider, mcp_tool: types.Tool, **kwargs: Any):
        # Build parameters with injected 'database' field
        parameters = copy.deepcopy(mcp_tool.inputSchema)
        props = parameters.setdefault("properties", {})
        props["database"] = {
            "type": "string",
            "description": "Database to target (stem ID from open_database / list_databases).",
        }
        required = parameters.setdefault("required", [])
        if "database" not in required:
            required.append("database")

        meta = mcp_tool.meta
        tags = set(get_fastmcp_metadata(meta).get("tags", []))
        # Strip fastmcp internal key from meta passed to constructor
        clean_meta = {k: v for k, v in (meta or {}).items() if k != "fastmcp"} or None

        super().__init__(
            name=mcp_tool.name,
            title=mcp_tool.title,
            description=mcp_tool.description,
            parameters=parameters,
            annotations=mcp_tool.annotations,
            output_schema=mcp_tool.outputSchema,
            icons=mcp_tool.icons,
            meta=clean_meta,
            tags=tags,
            **kwargs,
        )
        self._provider = provider

    async def run(self, arguments: dict[str, Any], **kwargs: Any) -> ToolResult:
        """Extract database, resolve worker, dispatch call."""
        arguments = dict(arguments)  # don't mutate caller's dict
        database = arguments.pop("database", None)
        worker = self._provider.resolve_worker(database)

        # Implicitly attach the calling session so the reference count
        # reflects actual usage, not just explicit open_database calls.
        if ctx := try_get_context():
            worker.attach(ctx.session_id)

        result = await self._provider.proxy_to_worker(worker, self.name, arguments)
        enriched = _enrich_result(result, worker.database_id)

        if enriched.isError:
            text = enriched.content[0].text if enriched.content else "Worker error"
            raise ToolError(text)

        return ToolResult(
            content=enriched.content,
            structured_content=enriched.structuredContent,
        )


# ---------------------------------------------------------------------------
# RoutingTemplate
# ---------------------------------------------------------------------------


class RoutingTemplate(ResourceTemplate):
    """A ResourceTemplate that routes reads to the correct worker subprocess."""

    task_config: TaskConfig = TaskConfig(mode="forbidden")
    _provider: WorkerPoolProvider = PrivateAttr()
    _backend_uri_template: str = PrivateAttr()

    def __init__(
        self,
        provider: WorkerPoolProvider,
        backend_uri_template: str,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self._provider = provider
        self._backend_uri_template = backend_uri_template

    async def _read(
        self,
        uri: str,
        params: dict[str, Any],
        task_meta: Any = None,
    ) -> ResourceResult:
        """Route resource read to the correct worker."""
        params = dict(params)
        database = params.pop("database", None)

        if database is None:
            # Try extracting from the URI itself
            database, _ = extract_db_prefix(uri)

        if database is None:
            raise ResourceError(
                f"Resource URI must include the database ID: ida://<database>/... (got '{uri}')"
            )

        worker = self._provider.resolve_worker(database)

        # Implicitly attach the calling session (mirrors RoutingTool.run).
        if ctx := try_get_context():
            worker.attach(ctx.session_id)

        # Reconstruct backend URI from template + remaining params
        backend_uri = expand_uri_template(self._backend_uri_template, params)

        async with worker.dispatch():
            client = worker.client
            if client is None:
                await self._provider.mark_worker_dead(worker)
                raise ResourceError("Worker closed before resource read could start.")
            try:
                result = await client.read_resource_mcp(backend_uri)
            except McpError as exc:
                if exc.error.code in (_MCP_CONNECTION_CLOSED, _MCP_REQUEST_TIMEOUT):
                    await self._provider.mark_worker_dead(worker)
                raise
            except (anyio.ClosedResourceError, anyio.EndOfStream, BrokenPipeError, OSError) as exc:
                await self._provider.mark_worker_dead(worker)
                raise ResourceError(f"Worker connection lost during resource read: {exc}") from exc
            except Exception as exc:
                raise ResourceError(f"Resource read failed: {exc}") from exc

        contents = []
        for item in result.contents:
            if isinstance(item, types.TextResourceContents):
                contents.append(ResourceContent(item.text, mime_type=item.mimeType))
            elif isinstance(item, types.BlobResourceContents):
                contents.append(
                    ResourceContent(base64.b64decode(item.blob), mime_type=item.mimeType)
                )
        return ResourceResult(contents=contents)


# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------


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


def parse_result(result: types.CallToolResult) -> dict[str, Any]:
    """Extract the JSON dict from a CallToolResult."""
    sc = result.structuredContent
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


def require_success(
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


# ---------------------------------------------------------------------------
# WorkerPoolProvider
# ---------------------------------------------------------------------------


class WorkerPoolProvider(Provider):
    """Provider that manages worker subprocesses and exposes their tools/resources."""

    def __init__(self) -> None:
        super().__init__()
        self._workers: dict[str, Worker] = {}  # canonical path -> Worker
        self._id_to_path: dict[str, str] = {}  # database_id -> canonical path
        self._lock = asyncio.Lock()
        self._routing_tools: dict[str, RoutingTool] = {}  # name -> RoutingTool
        self._routing_templates: list[RoutingTemplate] = []
        self._base_tool_schemas: list[types.Tool] = []  # raw MCP schemas from bootstrap
        self._filter_by_capability: bool = True
        self._cached_capabilities: set[str] | None = None
        self._reaper_task: asyncio.Task[None] | None = None
        self._bootstrapped = False

    # ------------------------------------------------------------------
    # Transport factory
    # ------------------------------------------------------------------

    @staticmethod
    def _worker_transport() -> StdioTransport:
        return StdioTransport(
            command=sys.executable,
            args=["-m", "ida_mcp.server"],
            env=dict(os.environ),
            keep_alive=False,
        )

    # ------------------------------------------------------------------
    # Bootstrap: discover tool/resource schemas from a temp worker
    # ------------------------------------------------------------------

    async def _bootstrap(self) -> None:
        """Spawn a temporary worker to discover tool and resource schemas."""
        if self._bootstrapped:
            return

        async with Client(self._worker_transport()) as client:
            tools = (await client.list_tools_mcp()).tools
            resources = (await client.list_resources_mcp()).resources
            templates = (await client.list_resource_templates_mcp()).resourceTemplates

        self._base_tool_schemas = tools

        # Build RoutingTool instances
        for t in tools:
            rt = RoutingTool(provider=self, mcp_tool=t)
            self._routing_tools[rt.name] = rt

        # Build RoutingTemplate instances from all worker resources and templates
        uri_entries: list[tuple[str, types.Resource | types.ResourceTemplate]] = [
            (str(r.uri), r) for r in resources
        ] + [(str(t.uriTemplate), t) for t in templates]

        for uri, entry in uri_entries:
            prefixed_uri = prefix_uri(uri, "{database}")
            tags = set(get_fastmcp_metadata(entry.meta).get("tags", []))
            self._routing_templates.append(
                RoutingTemplate(
                    provider=self,
                    backend_uri_template=uri,
                    uri_template=prefixed_uri,
                    name=entry.name,
                    description=entry.description,
                    mime_type=getattr(entry, "mimeType", None) or "text/plain",
                    annotations=entry.annotations,
                    tags=tags,
                    parameters={},
                )
            )

        self._bootstrapped = True

    # ------------------------------------------------------------------
    # Provider interface: tools
    # ------------------------------------------------------------------

    async def _list_tools(self) -> Sequence[Tool]:
        await self._bootstrap()

        if not self._filter_by_capability:
            return list(self._routing_tools.values())

        available_caps = self._aggregate_capabilities()
        return [
            t
            for t in self._routing_tools.values()
            if _capabilities_satisfied(t.tags, available_caps)
        ]

    async def _get_tool(self, name: str, version: VersionSpec | None = None) -> Tool | None:
        await self._bootstrap()

        tool = self._routing_tools.get(name)
        if tool is None:
            return None

        # Version filtering
        if version is not None and not version.matches(tool.version):
            return None

        # Capability gating: consistent with _list_tools
        if self._filter_by_capability:
            available_caps = self._aggregate_capabilities()
            if not _capabilities_satisfied(tool.tags, available_caps):
                return None

        return tool

    # ------------------------------------------------------------------
    # Provider interface: resource templates
    # ------------------------------------------------------------------

    async def _list_resource_templates(self) -> Sequence[ResourceTemplate]:
        await self._bootstrap()

        if not self._filter_by_capability:
            return list(self._routing_templates)

        available_caps = self._aggregate_capabilities()
        return [
            t for t in self._routing_templates if _capabilities_satisfied(t.tags, available_caps)
        ]

    async def _get_resource_template(
        self, uri: str, version: VersionSpec | None = None
    ) -> ResourceTemplate | None:
        await self._bootstrap()

        available_caps = self._aggregate_capabilities()
        for t in self._routing_templates:
            if t.matches(uri) is not None:
                if version is not None and not version.matches(t.version):
                    continue
                if self._filter_by_capability and not _capabilities_satisfied(
                    t.tags, available_caps
                ):
                    continue
                return t
        return None

    # ------------------------------------------------------------------
    # Provider lifespan: reaper startup/shutdown
    # ------------------------------------------------------------------

    @asynccontextmanager
    async def lifespan(self) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if self._reaper_task and not self._reaper_task.done():
                self._reaper_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self._reaper_task
            await self.shutdown_all(save=True)

    # ------------------------------------------------------------------
    # Worker resolution
    # ------------------------------------------------------------------

    def _available_databases(self) -> list[dict[str, str]]:
        return [
            {"database": w.database_id, "file_path": w.file_path} for w in self._alive_workers()
        ]

    def check_attached(self, worker: Worker, session_id: str | None) -> None:
        """Raise :class:`IDAError` if *session_id* is not attached to *worker*.

        Pass-through when *session_id* is ``None`` (no context available) or
        when the worker has no tracked sessions (backward compat).
        """
        if session_id is None or worker.session_count == 0:
            return
        if not worker.is_attached(session_id):
            raise IDAError(
                f"Database '{worker.database_id}' is not attached to the current session. "
                "Use force=True to override.",
                error_type="NotAttached",
                database=worker.database_id,
            )

    def resolve_worker(self, database: str | None) -> Worker:
        """Resolve which worker to target. Raises :class:`IDAError` on failure."""
        if not self._workers:
            raise IDAError("No database is open. Use open_database first.", error_type="NoDatabase")

        if not database:
            raise IDAError(
                "The 'database' parameter is required. Use list_databases to see open databases.",
                error_type="MissingDatabase",
                available_databases=self._available_databases(),
            )

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
    # Worker lifecycle
    # ------------------------------------------------------------------

    def _unique_id(self, base_id: str) -> str:
        if base_id not in self._id_to_path:
            return base_id
        for i in range(2, 100):
            candidate = f"{base_id}_{i}"
            if candidate not in self._id_to_path:
                return candidate
        return f"{base_id}_{int(time.monotonic() * 1000) % 100_000}"

    async def spawn_worker(
        self,
        file_path: str,
        run_auto_analysis: bool = False,
        database_id: str = "",
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Spawn a worker subprocess and open a database in it."""
        canonical = _canonical_path(file_path)
        stale_worker: Worker | None = None

        async with self._lock:
            existing = self._workers.get(canonical)
            active_count = len(self._alive_workers())
            if existing:
                if existing.state not in _NON_LIVE_STATES:
                    # Worker is genuinely alive (IDLE or BUSY).
                    existing.attach(session_id)
                    return {
                        "status": "already_open",
                        "database": existing.database_id,
                        "file_path": existing.file_path,
                        **existing.metadata,
                        "database_count": active_count,
                        "session_count": existing.session_count,
                    }
                if existing.state == WorkerState.STARTING:
                    # A previous open_database call is still in progress.
                    raise IDAError(
                        f"Database at '{file_path}' is currently being loaded. "
                        "Please wait for the initial open_database call to complete.",
                        error_type="AlreadyLoading",
                    )
                # DEAD or STUCK — clean up stale entry before replacing.
                self._workers.pop(canonical, None)
                self._id_to_path.pop(existing.database_id, None)
                active_count = len(self._alive_workers())
                stale_worker = existing

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
            worker.attach(session_id)
            self._workers[canonical] = worker
            self._id_to_path[db_id] = canonical

        # Force-stop stale worker (outside the lock) before spawning a replacement.
        if stale_worker is not None:
            await self._close_client(stale_worker)

        client = Client(self._worker_transport())
        stack = contextlib.AsyncExitStack()

        async def _abort_spawn():
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await stack.aclose()
            async with self._lock:
                self._workers.pop(canonical, None)
                self._id_to_path.pop(db_id, None)

        try:
            await stack.enter_async_context(client)
            result = await client.call_tool_mcp(
                "open_database",
                {"file_path": canonical, "run_auto_analysis": run_auto_analysis},
                timeout=tool_timedelta("open_database"),
            )
        except BaseException:
            await _abort_spawn()
            raise

        result_data = parse_result(result)

        try:
            require_success(result, result_data, "Worker failed to open database")
        except IDAError:
            await _abort_spawn()
            raise

        meta_keys = (
            "processor",
            "bitness",
            "file_type",
            "function_count",
            "segment_count",
            "capabilities",
        )
        metadata = {k: result_data[k] for k in meta_keys if k in result_data}

        async with self._lock:
            worker.client = client
            worker._exit_stack = stack
            worker.state = WorkerState.IDLE
            worker.pid = result_data.get("pid")
            worker.metadata = metadata
            worker.last_activity = time.monotonic()

        self.invalidate_capabilities()
        self._ensure_reaper()

        return {
            "status": "ok",
            "database": db_id,
            "file_path": canonical,
            **metadata,
            "database_count": len(self._alive_workers()),
            "session_count": worker.session_count,
        }

    async def terminate_worker(self, canonical_path: str, save: bool = True) -> dict[str, Any]:
        """Close a database and terminate its worker process."""
        async with self._lock:
            worker = self._workers.pop(canonical_path, None)
            if worker:
                self._id_to_path.pop(worker.database_id, None)
        self.invalidate_capabilities()

        if worker is None:
            raise IDAError("Worker not found.", error_type="NotFound")

        return await self._shutdown_worker(worker, save=save)

    async def _shutdown_worker(self, worker: Worker, *, save: bool = True) -> dict[str, Any]:
        """Send close_database to a worker and tear down its client.

        The caller must have already removed the worker from ``_workers`` /
        ``_id_to_path`` (typically under ``_lock``).
        """
        db_id = worker.database_id

        try:
            if worker.client and worker.state != WorkerState.DEAD:
                try:
                    async with asyncio.timeout(60):
                        async with worker.dispatch():
                            await worker.client.call_tool_mcp("close_database", {"save": save})
                except Exception:
                    log.debug("close_database on worker %s failed", db_id, exc_info=True)
        finally:
            await self._close_client(worker)
        return {"status": "closed", "database": db_id}

    async def close_for_session(
        self,
        worker: Worker,
        session_id: str | None,
        *,
        save: bool = True,
        force: bool = False,
    ) -> dict[str, Any]:
        """Detach *session_id* and conditionally terminate *worker*.

        Atomically checks attachment, detaches, and decides whether to
        terminate — all under ``_lock`` — so a concurrent ``attach()`` from
        ``RoutingTool.run()`` cannot sneak in between detach and terminate.

        Returns ``{"status": "closed", ...}`` when the worker was terminated,
        or ``{"status": "detached", ...}`` when other sessions still hold it.
        """
        if not force:
            self.check_attached(worker, session_id)

        async with self._lock:
            no_sessions_left = worker.detach(session_id)
            should_terminate = force or session_id is None or no_sessions_left

            if should_terminate:
                self._workers.pop(worker.file_path, None)
                self._id_to_path.pop(worker.database_id, None)

        if should_terminate:
            self.invalidate_capabilities()
            return await self._shutdown_worker(worker, save=save)

        return {
            "status": "detached",
            "database": worker.database_id,
            "remaining_sessions": worker.session_count,
        }

    @staticmethod
    async def _close_client(worker: Worker) -> None:
        worker.state = WorkerState.DEAD
        if worker._exit_stack:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await worker._exit_stack.aclose()
            worker._exit_stack = None
            worker.client = None

    async def mark_worker_dead(self, worker: Worker) -> None:
        async with self._lock:
            self._workers.pop(worker.file_path, None)
            self._id_to_path.pop(worker.database_id, None)
        self.invalidate_capabilities()
        await self._close_client(worker)

    async def shutdown_all(self, *, save: bool = True) -> None:
        """Terminate all workers concurrently with a total deadline."""
        paths = list(self._workers.keys())
        if not paths:
            return

        async def terminate(path: str):
            await self.terminate_worker(path, save=save)

        async def _force_close_remaining():
            async with self._lock:
                remaining = list(self._workers.values())
                self._workers.clear()
                self._id_to_path.clear()
                self.invalidate_capabilities()
            for worker in remaining:
                await self._close_client(worker)

        try:
            async with asyncio.timeout(15):
                async with anyio.create_task_group() as tg:
                    for path in paths:
                        tg.start_soon(terminate, path)
        except TimeoutError:
            log.warning("Shutdown timed out after 15s, force-closing remaining workers")
            await _force_close_remaining()
        except BaseException:
            await _force_close_remaining()
            raise

    async def detach_all(self, session_id: str | None, *, save: bool = True) -> None:
        """Detach *session_id* from all workers.

        Workers whose session set becomes empty are terminated.  When
        *session_id* is ``None``, falls back to :meth:`shutdown_all` for
        backward compatibility.
        """
        if session_id is None:
            await self.shutdown_all(save=save)
            return

        # Atomically detach and collect workers to terminate so a
        # concurrent attach() cannot sneak in between detach and the
        # terminate decision.
        to_terminate: list[Worker] = []
        async with self._lock:
            for path, worker in list(self._workers.items()):
                if worker.state in _INACTIVE_STATES:
                    continue
                if worker.is_attached(session_id):
                    no_sessions_left = worker.detach(session_id)
                    if no_sessions_left:
                        self._workers.pop(path, None)
                        self._id_to_path.pop(worker.database_id, None)
                        to_terminate.append(worker)

        if to_terminate:
            self.invalidate_capabilities()
        for worker in to_terminate:
            try:
                await self._shutdown_worker(worker, save=save)
            except Exception:
                log.warning("detach_all: terminate failed for %s", worker.file_path, exc_info=True)

    def _alive_workers(self) -> list[Worker]:
        return [w for w in self._workers.values() if w.state not in _INACTIVE_STATES]

    def _aggregate_capabilities(self) -> set[str]:
        if self._cached_capabilities is not None:
            return self._cached_capabilities
        caps: set[str] = set()
        for w in self._alive_workers():
            for k, v in w.metadata.get("capabilities", {}).items():
                if v:
                    caps.add(k)
        self._cached_capabilities = caps
        return caps

    def invalidate_capabilities(self) -> None:
        """Invalidate the cached capability set (call after worker add/remove)."""
        self._cached_capabilities = None

    @property
    def filter_by_capability(self) -> bool:
        """Whether tool/resource listings are filtered by aggregate capabilities."""
        return self._filter_by_capability

    @filter_by_capability.setter
    def filter_by_capability(self, value: bool) -> None:
        self._filter_by_capability = value

    def build_database_list(
        self,
        *,
        include_state: bool = False,
        caller_session_id: str | None = None,
    ) -> dict[str, Any]:
        alive = self._alive_workers()
        databases = []
        for w in alive:
            entry: dict[str, Any] = {"database": w.database_id, "file_path": w.file_path}
            if include_state:
                entry["state"] = w.state.name.lower()
            entry.update(w.metadata)
            entry["session_count"] = w.session_count
            if caller_session_id is not None:
                entry["attached"] = w.is_attached(caller_session_id)
            databases.append(entry)
        result: dict[str, Any] = {"databases": databases, "database_count": len(alive)}
        if MAX_WORKERS is not None:
            result["max_databases"] = MAX_WORKERS
        return result

    # ------------------------------------------------------------------
    # Tool proxying
    # ------------------------------------------------------------------

    async def proxy_to_worker(
        self,
        worker: Worker,
        tool_name: str,
        arguments: dict[str, Any],
        timeout: timedelta | None = None,
    ) -> types.CallToolResult:
        """Dispatch a tool call to a worker with standard error handling."""
        if timeout is None:
            timeout = tool_timedelta(tool_name)
        async with worker.dispatch(timeout=timeout.total_seconds()):
            client = worker.client
            if client is None:
                await self.mark_worker_dead(worker)
                return _error_result(
                    f"Worker closed before '{tool_name}' could start.",
                    "WorkerCrashed",
                    worker.database_id,
                )
            try:
                return await client.call_tool_mcp(tool_name, arguments, timeout=timeout)

            except McpError as exc:
                return await self._handle_worker_error(exc, worker, tool_name)

            except (anyio.ClosedResourceError, anyio.EndOfStream, BrokenPipeError, OSError):
                await self.mark_worker_dead(worker)
                return _error_result(
                    f"Worker connection lost during '{tool_name}'.",
                    "WorkerCrashed",
                    worker.database_id,
                )

            except Exception as exc:
                await self.mark_worker_dead(worker)
                return _error_result(
                    f"Unexpected error during '{tool_name}': {exc}",
                    "InternalError",
                    worker.database_id,
                )

    async def _handle_worker_error(
        self, exc: McpError, worker: Worker, tool_name: str
    ) -> types.CallToolResult:
        code = exc.error.code
        if code == _MCP_CONNECTION_CLOSED:
            await self.mark_worker_dead(worker)
            return _error_result(
                f"Worker crashed during '{tool_name}'.",
                "WorkerCrashed",
                worker.database_id,
            )
        if code == _MCP_REQUEST_TIMEOUT:
            await self.mark_worker_dead(worker)
            return _error_result(
                f"Tool '{tool_name}' timed out — worker terminated.",
                "CallTimeout",
                worker.database_id,
            )
        if code == _MCP_METHOD_NOT_FOUND:
            tool_caps: set[str] = set()
            for t in self._base_tool_schemas:
                if t.name == tool_name:
                    tool_caps = set(get_fastmcp_metadata(t.meta).get("tags", [])) & _CAPABILITY_TAGS
                    break
            if tool_caps:
                caps = worker.metadata.get("capabilities", {})
                missing = sorted(k for k in tool_caps if not caps.get(k, False))
                if missing:
                    return _error_result(
                        f"Tool '{tool_name}' is not available for database "
                        f"'{worker.database_id}'. This database does not support: "
                        f"{', '.join(missing)}. "
                        f"Use list_databases to check per-database capabilities.",
                        "CapabilityUnavailable",
                        worker.database_id,
                        missing_capabilities=missing,
                    )
        return _error_result(
            f"Worker error: {exc.error.message}",
            "WorkerError",
            worker.database_id,
        )

    # ------------------------------------------------------------------
    # Reaper
    # ------------------------------------------------------------------

    def _ensure_reaper(self) -> None:
        if self._reaper_task is None or self._reaper_task.done():
            self._reaper_task = asyncio.get_running_loop().create_task(self._reaper_loop())

    async def _reaper_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(30)
                now = time.monotonic()
                to_terminate: list[str] = []

                for path, worker in list(self._workers.items()):
                    if worker.state == WorkerState.DEAD:
                        continue
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
                        await self.terminate_worker(path, save=True)
                    except Exception:
                        log.debug("Reaper terminate failed for %s", path, exc_info=True)

                if not self._workers:
                    return
        except asyncio.CancelledError:
            return
