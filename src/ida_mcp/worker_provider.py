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
from collections.abc import AsyncIterator, Coroutine, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import TYPE_CHECKING, Any

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

if TYPE_CHECKING:
    from fastmcp.server.context import Context
    from mcp.server.session import ServerSession

from ida_mcp.context import try_get_context
from ida_mcp.exceptions import IDAError
from ida_mcp.transforms import MANAGEMENT_TOOLS

log = logging.getLogger(__name__)


_max_workers_env = os.environ.get("IDA_MCP_MAX_WORKERS")
# Clamp to [1, 8] when set; None means unlimited.
MAX_WORKERS: int | None = min(max(int(_max_workers_env), 1), 8) if _max_workers_env else None

_VALID_CUSTOM_ID = re.compile(r"^[a-z][a-z0-9_]{0,31}$")

_IDA_SCHEME = "ida://"

_MCP_CONNECTION_CLOSED = -32000
_MCP_METHOD_NOT_FOUND = -32001
_MCP_REQUEST_TIMEOUT = 408

# Metadata keys copied from the worker's open_database / get_database_info result.
_WORKER_META_KEYS = (
    "processor",
    "bitness",
    "file_type",
    "function_count",
    "segment_count",
    "capabilities",
)


# Worker tools that the supervisor exposes as its own management tools.
# Excluded from RoutingTool wrapping during bootstrap to avoid duplicates.
# Derived from MANAGEMENT_TOOLS (transforms.py) minus list_databases
# and list_targets (supervisor-only, not proxied to workers).
_MANAGEMENT_TOOLS = MANAGEMENT_TOOLS - {"list_databases", "list_targets"}

_RFC6570_QUERY_RE = re.compile(r"\{\?([^}]+)\}")


async def _kill_pid(pid: int | None) -> None:
    """Best-effort kill and reap of a worker process by PID.

    Sends SIGTERM, waits briefly, then SIGKILL.  Always calls
    ``os.waitpid`` to prevent zombies.  No-op when *pid* is ``None``
    or the process is already gone.
    """
    if pid is None:
        return
    # Check if still alive.
    try:
        os.kill(pid, 0)
    except OSError:
        # Already dead — reap just in case.
        with contextlib.suppress(ChildProcessError, OSError):
            os.waitpid(pid, os.WNOHANG)
        return
    # SIGTERM → brief wait → SIGKILL.
    with contextlib.suppress(OSError):
        os.kill(pid, signal.SIGTERM)
    await asyncio.sleep(0.5)
    try:
        os.kill(pid, 0)
    except OSError:
        pass  # dead
    else:
        with contextlib.suppress(OSError):
            os.kill(pid, signal.SIGKILL)
    # Reap to prevent zombie.
    with contextlib.suppress(ChildProcessError, OSError):
        os.waitpid(pid, os.WNOHANG)


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
    """Canonical key for a database: the resolved ``.i64`` path.

    Accepts a raw binary path or an existing ``.i64``/``.idb`` path.
    Always resolves to the ``.i64`` so that either input maps to the
    same worker.
    """
    resolved = os.path.realpath(os.path.expanduser(path))
    _, ext = os.path.splitext(resolved)
    if ext.lower() in (".i64", ".idb"):
        # Normalize .idb → .i64 for consistent keying.
        resolved = os.path.splitext(resolved)[0] + ".i64"
    else:
        # Binary path — the database lives alongside it.
        resolved = resolved + ".i64"
    return resolved


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
    DEAD = auto()


_INACTIVE_STATES = frozenset({WorkerState.DEAD, WorkerState.STARTING})


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
    _active_calls: int = 0
    _sessions: set[str] = field(default_factory=set)
    _analysis_task: asyncio.Task[None] | None = None
    _analysis_error: str | None = None
    _ready_event: asyncio.Event = field(default_factory=asyncio.Event)
    _spawn_task: asyncio.Task[None] | None = None
    _spawn_error: str | None = None

    # ------------------------------------------------------------------
    # Session tracking
    # ------------------------------------------------------------------

    def attach(self, session_id: str | None) -> None:
        """Register a session as using this worker. ``None`` is a no-op."""
        if session_id is not None:
            self._sessions.add(session_id)

    def detach(self, session_id: str | None) -> bool:
        """Unregister a session. Returns ``True`` if no sessions remain.

        ``None`` is a no-op; returns ``True`` only when the session set is
        already empty.  Callers that pass ``None`` (no context) use separate
        ``session_id is None`` checks to decide termination, so this return
        value is not load-bearing for the ``None`` case.
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
        if self._state in _INACTIVE_STATES:
            return self._state
        return WorkerState.BUSY if self._active_calls > 0 else WorkerState.IDLE

    @state.setter
    def state(self, value: WorkerState) -> None:
        self._state = value

    @property
    def active_calls(self) -> int:
        """Number of tool calls currently in flight to this worker."""
        return self._active_calls

    @property
    def analyzing(self) -> bool:
        """True if a background analysis task is running."""
        return self._analysis_task is not None and not self._analysis_task.done()

    @property
    def analysis_error(self) -> str | None:
        """Error message from the last background analysis, or ``None``."""
        return self._analysis_error

    @property
    def opening(self) -> bool:
        """True if the worker is still being spawned/opened in the background."""
        return self._state == WorkerState.STARTING and not self._ready_event.is_set()

    @property
    def spawn_error(self) -> str | None:
        """Error message from a failed background spawn, or ``None``."""
        return self._spawn_error

    async def wait_ready(self) -> None:
        """Block until the worker has finished opening (or failed)."""
        await self._ready_event.wait()

    def start_analysis(self, coro: Coroutine[Any, Any, None]) -> None:
        """Start a background analysis coroutine as an ``asyncio.Task``."""
        self._analysis_error = None
        self._analysis_task = asyncio.create_task(
            coro, name=f"background-analysis-{self.database_id}"
        )

    def record_analysis_error(self, message: str) -> None:
        """Record a background analysis error message."""
        self._analysis_error = message

    async def cancel_analysis(self) -> None:
        """Cancel a running background analysis task, if any."""
        task = self._analysis_task
        if task is None:
            return
        try:
            if not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        finally:
            if self._analysis_task is task:
                self._analysis_task = None

    def _signal_cancel(self):
        if self.pid is not None and hasattr(signal, "SIGUSR1"):
            with contextlib.suppress(OSError):
                os.kill(self.pid, signal.SIGUSR1)

    @asynccontextmanager
    async def dispatch(self):
        """Track active calls and signal cancellation on error."""
        self._active_calls += 1
        self.last_activity = time.monotonic()
        try:
            yield
        except BaseException:
            self._signal_cancel()
            raise
        finally:
            self._active_calls -= 1
            self.last_activity = time.monotonic()


# ---------------------------------------------------------------------------
# RoutingTool
# ---------------------------------------------------------------------------


class RoutingTool(Tool):
    """A Tool that routes calls to the correct worker subprocess."""

    task_config: TaskConfig = TaskConfig(mode="optional")
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

        # During background analysis, block all tools except
        # wait_for_analysis — the IDA thread is occupied by auto_wait().
        if worker.analyzing and self.name != "wait_for_analysis":
            raise ToolError(
                f"Database '{worker.database_id}' is being analyzed in the background. "
                "Tools are blocked during analysis — call "
                "wait_for_analysis to block until analysis completes, then retry."
            )

        # Implicitly attach the calling session so the reference count
        # reflects actual usage, not just explicit open_database calls.
        # Safe without _lock: close_for_session removes the worker from
        # _workers (under _lock) before terminating, so resolve_worker()
        # above would already have failed for a worker being shut down.
        self._provider.attach_current_session(worker)

        result = await self._provider.proxy_to_worker(worker, self.name, arguments)
        enriched = _enrich_result(result, worker.database_id)

        if enriched.isError:
            raise ToolError(_extract_error_text(enriched))

        return ToolResult(
            content=enriched.content,
            structured_content=enriched.structuredContent,
        )


# ---------------------------------------------------------------------------
# RoutingTemplate
# ---------------------------------------------------------------------------


class RoutingTemplate(ResourceTemplate):
    """A ResourceTemplate that routes reads to the correct worker subprocess."""

    task_config: TaskConfig = TaskConfig(mode="optional")
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
        # No check_attached gate — resources are read-only, so allowing
        # access to databases the session didn't explicitly open is safe
        # and avoids surprising errors on resource reads.
        self._provider.attach_current_session(worker)

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


def _unwrap_auto_wrapped(data: dict[str, Any]) -> dict[str, Any]:
    """Unwrap FastMCP's automatic Union-type wrapping.

    FastMCP wraps non-object JSON schemas (e.g. Union return types) in
    ``{"result": <actual_data>}`` for MCP compliance.  This creates an
    inconsistency where ``list_functions`` returns ``{"items": ...}``
    directly but ``get_strings`` returns ``{"result": {"items": ...}}``.

    Unwrap so all tools return a flat dict.
    """
    if len(data) == 1 and isinstance(data.get("result"), dict):
        return data["result"]
    return data


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
                    data = _unwrap_auto_wrapped(data)
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
        # Don't unwrap here — structuredContent must match the outputSchema
        # (which requires {"result": ...} for Union return types).  Inject
        # database inside the wrapper when present.
        if len(sc) == 1 and isinstance(sc.get("result"), dict):
            sc = {"result": {**sc["result"], "database": database_id}}
        else:
            sc = {**sc, "database": database_id}

    return types.CallToolResult(
        content=new_content,
        structuredContent=sc,
        isError=result.isError,
    )


def _extract_error_text(result: types.CallToolResult, default: str = "Worker error") -> str:
    """Extract human-readable error text from a ``CallToolResult``."""
    first = result.content[0] if result.content else None
    return first.text if isinstance(first, types.TextContent) else default


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
        self._bootstrapped = False
        self._registered_sessions: set[str] = set()

    # ------------------------------------------------------------------
    # Transport factory
    # ------------------------------------------------------------------

    @staticmethod
    def _worker_transport() -> StdioTransport:
        env = dict(os.environ)
        # Worker stderr goes to a log file when IDA_MCP_WORKER_LOG is set,
        # otherwise it inherits the supervisor's stderr (visible to MCP clients).
        log_file = env.get("IDA_MCP_WORKER_LOG")
        return StdioTransport(
            command=sys.executable,
            args=["-m", "ida_mcp.server"],
            env=env,
            keep_alive=False,
            log_file=Path(log_file) if log_file else None,
        )

    # ------------------------------------------------------------------
    # Bootstrap: discover tool/resource schemas from a temp worker
    # ------------------------------------------------------------------

    async def _bootstrap(self) -> None:
        """Spawn a temporary worker to discover tool and resource schemas."""
        if self._bootstrapped:
            return

        log.debug("Bootstrap: spawning temporary worker to discover schemas")
        async with Client(self._worker_transport()) as client:
            log.debug("Bootstrap: temporary worker connected, listing tools/resources")
            tools = (await client.list_tools_mcp()).tools
            resources = (await client.list_resources_mcp()).resources
            templates = (await client.list_resource_templates_mcp()).resourceTemplates
        log.debug(
            "Bootstrap: discovered %d tools, %d resources, %d templates",
            len(tools),
            len(resources),
            len(templates),
        )

        # Build RoutingTool instances (skip tools promoted to management level).
        for t in tools:
            if t.name in _MANAGEMENT_TOOLS:
                continue
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
        return list(self._routing_tools.values())

    async def _get_tool(self, name: str, version: VersionSpec | None = None) -> Tool | None:
        await self._bootstrap()

        tool = self._routing_tools.get(name)
        if tool is None:
            return None

        if version is not None and not version.matches(tool.version):
            return None

        return tool

    # ------------------------------------------------------------------
    # Provider interface: resource templates
    # ------------------------------------------------------------------

    async def _list_resource_templates(self) -> Sequence[ResourceTemplate]:
        await self._bootstrap()
        return list(self._routing_templates)

    async def _get_resource_template(
        self, uri: str, version: VersionSpec | None = None
    ) -> ResourceTemplate | None:
        await self._bootstrap()

        for t in self._routing_templates:
            if t.matches(uri) is not None:
                if version is not None and not version.matches(t.version):
                    continue
                return t
        return None

    # ------------------------------------------------------------------
    # Provider lifespan
    # ------------------------------------------------------------------

    @asynccontextmanager
    async def lifespan(self) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await self.shutdown_all(save=True)

    # ------------------------------------------------------------------
    # Worker resolution
    # ------------------------------------------------------------------

    def _available_databases(self) -> list[dict[str, str]]:
        return [
            {"database": w.database_id, "file_path": w.file_path}
            for w in self._workers.values()
            if w.state != WorkerState.DEAD
        ]

    def attach_current_session(self, worker: Worker) -> None:
        """Attach the current request's session to *worker* and register cleanup.

        No-op when there is no active request context.
        """
        if ctx := try_get_context():
            worker.attach(ctx.session_id)
            self.ensure_session_cleanup(ctx)

    def ensure_session_cleanup(self, ctx: Context | None) -> None:
        """Register a one-time disconnect callback for *ctx*'s session.

        When the MCP session disconnects, all workers it was attached to are
        automatically detached (and terminated if no other sessions remain).
        No-op if *ctx* is ``None`` or the session was already registered.
        """
        if ctx is None:
            return
        sid = ctx.session_id
        if sid is None or sid in self._registered_sessions:
            return

        pool = self  # capture for closure

        async def _on_disconnect():
            pool._registered_sessions.discard(sid)
            await pool.detach_all(sid, save=True)

        try:
            # session._exit_stack is a FastMCP internal (not public API).
            # If the internal layout changes this will fall through to the
            # except branch and session cleanup becomes manual-only.
            ctx.session._exit_stack.push_async_callback(_on_disconnect)
        except Exception:
            log.warning("Could not register session cleanup for %s", sid, exc_info=True)
            return

        self._registered_sessions.add(sid)

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

    def _lookup_worker(self, database: str | None) -> Worker:
        """Find a worker by database ID or path, regardless of state.

        Raises :class:`IDAError` if no matching worker exists.
        """
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
        if worker is None:
            raise IDAError(
                f"Database not found: '{database}'.",
                error_type="NotFound",
                available_databases=self._available_databases(),
            )
        return worker

    def resolve_worker(self, database: str | None) -> Worker:
        """Resolve which worker to target. Raises :class:`IDAError` on failure.

        Rejects workers in STARTING or DEAD states — use ``_lookup_worker``
        when you need to find a worker regardless of state.
        """
        worker = self._lookup_worker(database)
        if worker.state in _INACTIVE_STATES:
            if worker.state == WorkerState.STARTING:
                raise IDAError(
                    f"Database '{database}' is still opening. "
                    "Call wait_for_analysis to block until it is ready.",
                    error_type="NotReady",
                )
            raise IDAError(
                f"Database not found: '{database}'.",
                error_type="NotFound",
                available_databases=self._available_databases(),
            )
        return worker

    async def wait_for_ready(self, database: str | None) -> dict[str, Any]:
        """Wait for a database to finish opening and/or analysis.

        Returns a summary dict when the database is ready for tool calls.
        Callers should wrap with ``asyncio.timeout`` if a deadline is needed.
        """
        log.debug("wait_for_ready: database=%s", database)
        worker = self._lookup_worker(database)

        # Wait for the background spawn to complete.
        if worker.opening:
            log.debug("wait_for_ready: worker %s still opening, waiting...", worker.database_id)
            await worker.wait_ready()

        # Check for spawn failure.
        if worker.spawn_error:
            raise IDAError(
                f"Database '{worker.database_id}' failed to open: {worker.spawn_error}",
                error_type="SpawnFailed",
            )

        # If analysis is running, await the background task directly
        # rather than making a redundant proxy call that would race with it.
        task = worker._analysis_task
        if task is not None and not task.done():
            await asyncio.shield(task)

        if worker.analysis_error:
            raise IDAError(
                f"Analysis failed for '{worker.database_id}': {worker.analysis_error}",
                error_type="AnalysisFailed",
            )

        return self._worker_status(worker, status="ready")

    def _worker_status(self, worker: Worker, *, status: str | None = None) -> dict[str, Any]:
        """Build a status dict for a worker without blocking.

        When *status* is provided it is used as-is; otherwise the status
        is inferred from the worker's current state.
        """
        if status is None:
            status = "ready"
            if worker.spawn_error:
                status = "error"
            elif worker.opening:
                status = "opening"
            elif worker.analyzing:
                status = "analyzing"
            elif worker.analysis_error:
                status = "error"
        result: dict[str, Any] = {
            "status": status,
            "database": worker.database_id,
            "file_path": worker.file_path,
            **worker.metadata,
            "session_count": worker.session_count,
        }
        error = worker.spawn_error or worker.analysis_error
        if error:
            result["error"] = error
        return result

    async def wait_for_ready_multi(
        self,
        databases: Sequence[str],
    ) -> dict[str, Any]:
        """Wait for multiple databases to become ready.

        Returns as soon as **at least one** database is ready (or all
        have failed).  The caller can start working on the ready one
        and call again for the rest.  Wrap with ``asyncio.timeout``
        if a deadline is needed.

        Returns ``{"databases": [...], "ready": [...], "pending": [...]}``.
        """
        if not databases:
            return {"databases": [], "ready": [], "pending": []}

        workers = [self._lookup_worker(db) for db in databases]

        async def _wait_one(w: Worker) -> None:
            """Wait for a single worker to finish spawning and analysis."""
            if w.opening:
                await w.wait_ready()
            if w.spawn_error:
                return
            task = w._analysis_task
            if task is not None and not task.done():
                await asyncio.shield(task)

        tasks = {w.database_id: asyncio.create_task(_wait_one(w)) for w in workers}
        try:
            await asyncio.wait(
                tasks.values(),
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            to_cancel = [t for t in tasks.values() if not t.done()]
            for t in to_cancel:
                t.cancel()
            if to_cancel:
                await asyncio.gather(*to_cancel, return_exceptions=True)

        # Build response.
        all_status = [self._worker_status(w) for w in workers]
        ready = [s["database"] for s in all_status if s["status"] == "ready"]
        pending = [s["database"] for s in all_status if s["status"] in ("opening", "analyzing")]

        return {
            "databases": all_status,
            "ready": ready,
            "pending": pending,
        }

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
        mcp_session: ServerSession | None = None,
        force_new: bool = False,
        processor: str = "",
        loader: str = "",
        base_address: str = "",
        options: str = "",
    ) -> dict[str, Any]:
        """Spawn a worker subprocess and open a database in it."""
        # Resolve the real path but keep the original extension so the worker
        # can distinguish "raw binary" from "existing .i64/.idb database".
        # _canonical_path always normalises to .i64 for dedup keying only.
        resolved = os.path.realpath(os.path.expanduser(file_path))
        canonical = _canonical_path(file_path)
        log.debug(
            "spawn_worker: file_path=%s resolved=%s canonical=%s db_id=%s session=%s force_new=%s",
            file_path,
            resolved,
            canonical,
            database_id or "(auto)",
            session_id,
            force_new,
        )
        stale_worker: Worker | None = None

        async with self._lock:
            existing = self._workers.get(canonical)
            active_count = self._active_count()
            if existing:
                if existing.state not in _INACTIVE_STATES:
                    # Worker is genuinely alive (IDLE or BUSY).
                    existing.attach(session_id)
                    result = {
                        "status": "already_open",
                        "database": existing.database_id,
                        "file_path": existing.file_path,
                        **existing.metadata,
                        "database_count": active_count,
                        "session_count": existing.session_count,
                    }
                    if existing.analyzing:
                        result["analyzing"] = True
                    if existing.analysis_error:
                        result["analysis_error"] = existing.analysis_error
                    return result
                if existing.state == WorkerState.STARTING:
                    # A previous open_database call is still in progress.
                    existing.attach(session_id)
                    return {
                        "status": "already_opening",
                        "database": existing.database_id,
                        "file_path": existing.file_path,
                        "opening": True,
                    }
                # DEAD — clean up stale entry before replacing.
                self._workers.pop(canonical, None)
                self._id_to_path.pop(existing.database_id, None)
                active_count = self._active_count()
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

        # Launch the heavy work (process spawn + DB open + optional analysis)
        # in a background task so open_database returns immediately.
        # Pass `resolved` (the user's original path) to the worker so it can
        # distinguish raw binaries from existing .i64/.idb databases.
        # `canonical` is only used for internal dedup keying.
        worker._spawn_task = asyncio.create_task(
            self._background_spawn(
                worker,
                resolved,
                canonical,
                db_id,
                run_auto_analysis=run_auto_analysis,
                force_new=force_new,
                stale_worker=stale_worker,
                mcp_session=mcp_session,
                processor=processor,
                loader=loader,
                base_address=base_address,
                options=options,
            ),
            name=f"background-spawn-{db_id}",
        )

        return {
            "status": "opening",
            "database": db_id,
            "file_path": canonical,
            "opening": True,
        }

    async def _background_spawn(
        self,
        worker: Worker,
        file_path: str,
        canonical: str,
        db_id: str,
        *,
        run_auto_analysis: bool,
        force_new: bool,
        stale_worker: Worker | None,
        mcp_session: ServerSession | None,
        processor: str = "",
        loader: str = "",
        base_address: str = "",
        options: str = "",
    ) -> None:
        """Spawn a worker subprocess and open the database in the background.

        *file_path* is the resolved (but extension-preserving) path passed to
        the worker so it can distinguish raw binaries from existing databases.
        *canonical* is the ``.i64``-normalised key used for internal lookup.

        Sets ``worker._ready_event`` when the database is open and the worker
        is ready to accept tool calls (or on failure).
        """
        client = Client(self._worker_transport())
        stack = contextlib.AsyncExitStack()

        async def _cleanup_stack(label: str) -> None:
            """Close the async exit stack and kill the worker process."""
            try:
                await asyncio.shield(stack.aclose())
            except Exception:
                log.debug("stack cleanup failed during %s for %s", label, db_id, exc_info=True)
            await _kill_pid(worker.pid)

        async def _remove():
            """Remove the worker entry entirely (used on cancellation)."""
            await _cleanup_stack("_remove")
            async with self._lock:
                self._workers.pop(canonical, None)
                self._id_to_path.pop(db_id, None)

        async def _mark_failed():
            """Close resources but keep the worker entry as DEAD so callers see the error."""
            await _cleanup_stack("_mark_failed")
            async with self._lock:
                worker.state = WorkerState.DEAD

        try:
            # Force-stop stale worker before spawning a replacement.
            if stale_worker is not None:
                log.debug("Closing stale worker for %s before respawning", db_id)
                await self._close_client(stale_worker)

            log.info("Spawning worker subprocess for %s (path=%s)", db_id, canonical)
            await self._session_log(mcp_session, "info", f"Opening database {db_id}...")

            await stack.enter_async_context(client)
            log.debug(
                "Worker subprocess connected for %s, sending open_database(%s)", db_id, file_path
            )
            open_args: dict[str, Any] = {
                "file_path": file_path,
                "run_auto_analysis": False,
                "force_new": force_new,
            }
            if processor:
                open_args["processor"] = processor
            if loader:
                open_args["loader"] = loader
            if base_address:
                open_args["base_address"] = base_address
            if options:
                open_args["options"] = options
            result = await client.call_tool_mcp("open_database", open_args)

            result_data = parse_result(result)
            log.debug("Worker open_database result for %s: %s", db_id, result_data)
            require_success(result, result_data, "Worker failed to open database")
            metadata = {k: result_data[k] for k in _WORKER_META_KEYS if k in result_data}

            async with self._lock:
                worker.client = client
                worker._exit_stack = stack
                worker.state = WorkerState.IDLE
                worker.pid = result_data.get("pid")
                worker.metadata = metadata
                worker.last_activity = time.monotonic()

            log.info("Database %s opened successfully (pid=%s)", db_id, worker.pid)
            await self._session_log(mcp_session, "info", f"Database {db_id} opened successfully")

        except asyncio.CancelledError:
            log.debug("Background spawn cancelled for %s", db_id)
            await _remove()
            worker._spawn_error = "Spawn cancelled"
            worker._ready_event.set()
            raise
        except Exception as exc:
            log.warning("Background spawn failed for %s: %s", db_id, exc, exc_info=True)
            await _mark_failed()
            worker._spawn_error = str(exc)
            worker._ready_event.set()
            await self._session_log(mcp_session, "error", f"Failed to open {db_id}: {exc}")
            return

        # Signal that the worker is ready for tool calls.
        worker._ready_event.set()

        # Chain into background analysis if requested.
        if run_auto_analysis:
            worker.start_analysis(self._background_analysis(worker, mcp_session))

    @staticmethod
    async def _session_log(
        mcp_session: ServerSession | None,
        level: str,
        msg: str,
    ) -> None:
        """Send a log message to the MCP client, if a session is available."""
        if mcp_session is None:
            return
        try:
            await mcp_session.send_log_message(level=level, data=msg, logger="ida")
        except Exception:
            log.debug("Failed to send client log: %s", msg, exc_info=True)

    @staticmethod
    async def _session_notify(
        mcp_session: ServerSession | None,
        notification: Any,
    ) -> None:
        """Send a notification to the MCP client, if a session is available."""
        if mcp_session is None:
            return
        try:
            await mcp_session.send_notification(notification)
        except Exception:
            log.debug("Failed to send notification", exc_info=True)

    async def _background_analysis(
        self,
        worker: Worker,
        mcp_session: ServerSession | None = None,
    ) -> None:
        """Run auto-analysis on a worker in the background.

        Dispatches ``wait_for_analysis`` through the normal proxy path,
        then refreshes worker metadata.
        """
        db_id = worker.database_id

        try:
            await self._session_log(mcp_session, "info", f"Auto-analysis started for {db_id}")

            result = await self.proxy_to_worker(
                worker,
                "wait_for_analysis",
                {},
            )

            if result.isError:
                err_text = _extract_error_text(result, "unknown error")
                worker.record_analysis_error(err_text)
                log.warning("Background analysis failed for %s: %s", db_id, err_text)
                await self._session_log(
                    mcp_session, "warning", f"Auto-analysis failed for {db_id}: {err_text}"
                )
                return

            # Refresh metadata (function_count etc. change after analysis).
            info_result = await self.proxy_to_worker(worker, "get_database_info", {})
            if not info_result.isError:
                info_data = parse_result(info_result)
                for k in _WORKER_META_KEYS:
                    if k in info_data:
                        worker.metadata[k] = info_data[k]

            func_count = worker.metadata.get("function_count", "?")
            log.info("Background analysis complete for %s: %s functions", db_id, func_count)
            await self._session_log(
                mcp_session, "info", f"Auto-analysis complete for {db_id}: {func_count} functions"
            )
            await self._session_notify(mcp_session, types.ResourceListChangedNotification())

        except asyncio.CancelledError:
            log.debug("Background analysis cancelled for %s", db_id)
            raise
        except Exception as exc:
            log.warning("Background analysis failed for %s", db_id, exc_info=True)
            err_msg = f"Background analysis failed: {exc}"
            worker.record_analysis_error(err_msg)
            await self._session_log(
                mcp_session, "warning", f"Auto-analysis failed for {db_id}: {exc}"
            )

    async def terminate_worker(self, canonical_path: str, save: bool = True) -> dict[str, Any]:
        """Close a database and terminate its worker process."""
        async with self._lock:
            worker = self._workers.pop(canonical_path, None)
            if worker:
                self._id_to_path.pop(worker.database_id, None)

        if worker is None:
            raise IDAError("Worker not found.", error_type="NotFound")

        return await self._shutdown_worker(worker, save=save)

    async def _shutdown_worker(self, worker: Worker, *, save: bool = True) -> dict[str, Any]:
        """Send close_database to a worker and tear down its client.

        Expects that the caller has already removed the worker from
        ``_workers`` / ``_id_to_path`` (under ``_lock``), so this method
        only performs I/O cleanup.
        """
        db_id = worker.database_id

        # Cancel background spawn / analysis before shutting down the worker.
        spawn_task = worker._spawn_task
        if spawn_task is not None and not spawn_task.done():
            spawn_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await spawn_task
        await worker.cancel_analysis()

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

        Checks attachment, detaches, and decides whether to terminate — all
        atomically under ``_lock`` — so a concurrent ``attach()`` from
        ``RoutingTool.run()`` cannot sneak in between any of these steps.

        Returns ``{"status": "closed", ...}`` when the worker was terminated,
        or ``{"status": "detached", ...}`` when other sessions still hold it.
        """
        async with self._lock:
            if not force:
                self.check_attached(worker, session_id)
            no_sessions_left = worker.detach(session_id)
            should_terminate = force or session_id is None or no_sessions_left

            if should_terminate:
                self._workers.pop(worker.file_path, None)
                self._id_to_path.pop(worker.database_id, None)

        if should_terminate:
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
            try:
                # Shield from external cancellation so cleanup always completes.
                await asyncio.shield(worker._exit_stack.aclose())
            except Exception:
                log.debug("exit stack cleanup failed for %s", worker.database_id, exc_info=True)
            worker._exit_stack = None
            worker.client = None
        # Fallback: if transport cleanup didn't kill the process, do it directly.
        await _kill_pid(worker.pid)

    async def mark_worker_dead(self, worker: Worker) -> None:
        async with self._lock:
            self._workers.pop(worker.file_path, None)
            self._id_to_path.pop(worker.database_id, None)

        await self._close_client(worker)

    async def shutdown_all(self, *, save: bool = True) -> None:
        """Terminate all workers concurrently with a 30-second deadline."""
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

            for worker in remaining:
                spawn_task = worker._spawn_task
                if spawn_task is not None and not spawn_task.done():
                    spawn_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await spawn_task
                await worker.cancel_analysis()
                await self._close_client(worker)

        try:
            async with asyncio.timeout(30):
                async with anyio.create_task_group() as tg:
                    for path in paths:
                        tg.start_soon(terminate, path)
        except TimeoutError:
            log.warning("Shutdown timed out after 30s, force-closing remaining workers")
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
                if worker.state == WorkerState.DEAD:
                    continue
                if not worker.is_attached(session_id):
                    continue
                no_sessions_left = worker.detach(session_id)
                if no_sessions_left:
                    self._workers.pop(path, None)
                    self._id_to_path.pop(worker.database_id, None)
                    to_terminate.append(worker)

        for worker in to_terminate:
            try:
                await self._shutdown_worker(worker, save=save)
            except Exception:
                log.warning("detach_all: terminate failed for %s", worker.file_path, exc_info=True)

    def _alive_workers(self) -> list[Worker]:
        return [w for w in self._workers.values() if w.state not in _INACTIVE_STATES]

    def _active_count(self) -> int:
        """Count workers that are not DEAD (includes STARTING)."""
        return sum(1 for w in self._workers.values() if w.state != WorkerState.DEAD)

    def build_database_list(
        self,
        *,
        include_state: bool = False,
        caller_session_id: str | None = None,
    ) -> dict[str, Any]:
        # Include all non-DEAD workers (STARTING, IDLE, BUSY).
        visible = [w for w in self._workers.values() if w.state != WorkerState.DEAD]
        databases = []
        for w in visible:
            entry: dict[str, Any] = {"database": w.database_id, "file_path": w.file_path}
            if include_state:
                entry["state"] = w.state.name.lower()
            entry.update(w.metadata)
            entry["session_count"] = w.session_count
            if w.opening:
                entry["opening"] = True
            if w.spawn_error:
                entry["spawn_error"] = w.spawn_error
            if w.analyzing:
                entry["analyzing"] = True
            if w.analysis_error:
                entry["analysis_error"] = w.analysis_error
            if caller_session_id is not None:
                entry["attached"] = w.is_attached(caller_session_id)
            databases.append(entry)
        result: dict[str, Any] = {"databases": databases, "database_count": len(visible)}
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
    ) -> types.CallToolResult:
        """Dispatch a tool call to a worker with standard error handling."""
        log.debug("proxy_to_worker: %s -> %s(%s)", worker.database_id, tool_name, arguments)
        async with worker.dispatch():
            client = worker.client
            if client is None:
                log.warning("Worker %s has no client for %s", worker.database_id, tool_name)
                await self.mark_worker_dead(worker)
                return _error_result(
                    f"Worker closed before '{tool_name}' could start.",
                    "WorkerCrashed",
                    worker.database_id,
                )
            try:
                result = await client.call_tool_mcp(tool_name, arguments)
                log.debug("proxy_to_worker: %s.%s completed", worker.database_id, tool_name)
                return result

            except McpError as exc:
                log.debug(
                    "Worker %s raised McpError on %s: %s",
                    worker.database_id,
                    tool_name,
                    exc,
                )
                return await self._handle_worker_error(exc, worker, tool_name)

            except (anyio.ClosedResourceError, anyio.EndOfStream, BrokenPipeError, OSError) as exc:
                log.warning(
                    "Worker %s connection lost during %s: %s",
                    worker.database_id,
                    tool_name,
                    exc,
                )
                await self.mark_worker_dead(worker)
                return _error_result(
                    f"Worker connection lost during '{tool_name}'.",
                    "WorkerCrashed",
                    worker.database_id,
                )

            except Exception as exc:
                log.error(
                    "Unexpected error in worker %s during %s: %s",
                    worker.database_id,
                    tool_name,
                    exc,
                    exc_info=True,
                )
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
        return _error_result(
            f"Worker error: {exc.error.message}",
            "WorkerError",
            worker.database_id,
        )
