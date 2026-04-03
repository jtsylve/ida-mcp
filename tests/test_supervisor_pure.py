# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Unit tests for supervisor / worker_provider pure utility functions.

These tests cover prefix_uri, extract_db_prefix, and capability-based
tool/resource filtering — all functions that can run without idalib loaded.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock

import mcp.types as types
import pytest
from fastmcp.exceptions import ToolError
from fastmcp.resources.template import ResourceTemplate as FastMCPResourceTemplate

from ida_mcp.exceptions import IDAError
from ida_mcp.worker_provider import (
    _MANAGEMENT_TOOLS,
    RoutingTemplate,
    RoutingTool,
    Worker,
    WorkerPoolProvider,
    WorkerState,
    expand_uri_template,
    extract_db_prefix,
    prefix_uri,
)

# ---------------------------------------------------------------------------
# Fake MCP context helpers for session cleanup tests
# ---------------------------------------------------------------------------


class _FakeExitStack:
    def __init__(self):
        self.callbacks: list = []

    def push_async_callback(self, cb, *args, **kwargs):
        self.callbacks.append(cb)


class _FakeSession:
    def __init__(self):
        self._exit_stack = _FakeExitStack()


class _FakeCtx:
    def __init__(self, sid: str | None):
        self.session_id = sid
        self.session = _FakeSession()


# ---------------------------------------------------------------------------
# prefix_uri
# ---------------------------------------------------------------------------


def test_prefix_uri_basic():
    assert prefix_uri("ida://idb/metadata", "mybin") == "ida://mybin/idb/metadata"


def test_prefix_uri_nested_path():
    assert prefix_uri("ida://functions/0x401000", "db1") == "ida://db1/functions/0x401000"


def test_prefix_uri_non_ida_scheme():
    assert prefix_uri("https://example.com", "mybin") == "https://example.com"


def test_prefix_uri_template_placeholder():
    assert prefix_uri("ida://types/{name}", "{database}") == "ida://{database}/types/{name}"


# ---------------------------------------------------------------------------
# extract_db_prefix
# ---------------------------------------------------------------------------


def test_extract_db_prefix_basic():
    db, worker_uri = extract_db_prefix("ida://mybin/idb/metadata")
    assert db == "mybin"
    assert worker_uri == "ida://idb/metadata"


def test_extract_db_prefix_nested():
    db, worker_uri = extract_db_prefix("ida://db1/functions/0x401000")
    assert db == "db1"
    assert worker_uri == "ida://functions/0x401000"


def test_extract_db_prefix_non_ida_scheme():
    db, uri = extract_db_prefix("https://example.com/path")
    assert db is None
    assert uri == "https://example.com/path"


def test_extract_db_prefix_no_path_segment():
    """URI like ``ida://databases`` has no slash after the first segment."""
    db, uri = extract_db_prefix("ida://databases")
    assert db is None
    assert uri == "ida://databases"


def test_extract_db_prefix_empty_segment():
    """URI like ``ida:///path`` has an empty segment before the slash."""
    db, uri = extract_db_prefix("ida:///path")
    assert db is None
    assert uri == "ida:///path"


def test_extract_roundtrip():
    """prefix_uri and extract_db_prefix are inverses for ida:// URIs."""
    original = "ida://idb/segments"
    db_id = "testdb"
    prefixed = prefix_uri(original, db_id)
    extracted_db, extracted_uri = extract_db_prefix(prefixed)
    assert extracted_db == db_id
    assert extracted_uri == original


# ---------------------------------------------------------------------------
# expand_uri_template
# ---------------------------------------------------------------------------


def test_expand_uri_template_path_params():
    """Simple {key} path parameters are expanded."""
    result = expand_uri_template("ida://functions/{addr}", {"addr": "0x1000"})
    assert result == "ida://functions/0x1000"


def test_expand_uri_template_query_params():
    """RFC 6570 {?key1,key2} query parameters are expanded."""
    result = expand_uri_template("ida://functions{?offset,limit}", {"offset": 0, "limit": 100})
    assert result == "ida://functions?offset=0&limit=100"


def test_expand_uri_template_query_params_partial():
    """Only provided query params appear in the result."""
    result = expand_uri_template("ida://functions{?offset,limit}", {"limit": 50})
    assert result == "ida://functions?limit=50"


def test_expand_uri_template_query_params_empty():
    """No query params provided → no query string appended."""
    result = expand_uri_template("ida://functions{?offset,limit}", {})
    assert result == "ida://functions"


def test_expand_uri_template_mixed():
    """Path and query parameters together."""
    result = expand_uri_template(
        "ida://idb/segments/search/{pattern}{?offset,limit}",
        {"pattern": "text", "offset": 0, "limit": 10},
    )
    assert result == "ida://idb/segments/search/text?offset=0&limit=10"


def test_expand_uri_template_no_params():
    """Template with no parameters returns unchanged."""
    result = expand_uri_template("ida://idb/metadata", {})
    assert result == "ida://idb/metadata"


# ---------------------------------------------------------------------------
# Capability-based filtering helpers
# ---------------------------------------------------------------------------


def _make_mcp_tool(name: str, tags: set[str] | None = None) -> types.Tool:
    """Create a minimal MCP Tool schema for testing.

    Uses ``model_construct`` because ``types.Tool(...)`` validates away the
    ``meta`` field in some mcp-sdk versions, but the real wire path
    (``list_tools_mcp``) preserves it.
    """
    meta = None
    if tags:
        meta = {"fastmcp": {"tags": list(tags)}}
    return types.Tool.model_construct(
        name=name,
        description=f"{name} tool",
        inputSchema={"type": "object", "properties": {}},
        meta=meta,
    )


def _make_resource_template(
    uri_template: str, name: str, tags: set[str] | None = None
) -> FastMCPResourceTemplate:
    """Create a minimal FastMCPResourceTemplate for testing."""
    return FastMCPResourceTemplate(
        uri_template=uri_template,
        name=name,
        description=f"{name} resource",
        parameters={},
        tags=tags or set(),
    )


def _add_worker(
    pool: WorkerPoolProvider,
    db_id: str,
    capabilities: dict[str, bool],
) -> Worker:
    """Add a mock worker with the given capabilities to a WorkerPoolProvider."""
    canonical = f"/tmp/{db_id}"
    worker = Worker(database_id=db_id, file_path=canonical)
    worker.state = WorkerState.IDLE
    worker.metadata = {"capabilities": capabilities}
    pool._workers[canonical] = worker
    pool._id_to_path[db_id] = canonical
    return worker


# Ensures _setup_pool always has at least one tool so tool visibility
# tests don't need to worry about empty-pool edge cases.
_SENTINEL_TOOL = _make_mcp_tool("_sentinel")


def _setup_pool(
    tools: list[types.Tool],
    resource_templates: list[FastMCPResourceTemplate] | None = None,
) -> WorkerPoolProvider:
    """Create a WorkerPoolProvider with pre-populated schemas (skipping bootstrap)."""
    pool = WorkerPoolProvider()
    all_tools = [_SENTINEL_TOOL, *tools]
    pool._bootstrapped = True

    # Build RoutingTool instances (skip management tools like the real bootstrap)
    for t in all_tools:
        if t.name in _MANAGEMENT_TOOLS:
            continue
        rt = RoutingTool(provider=pool, mcp_tool=t)
        pool._routing_tools[rt.name] = rt

    # Use RoutingTemplate for resource templates if provided
    if resource_templates:
        pool._routing_templates = []
        for tmpl in resource_templates:
            pool._routing_templates.append(
                RoutingTemplate(
                    provider=pool,
                    backend_uri_template=tmpl.uri_template,
                    uri_template=tmpl.uri_template,
                    name=tmpl.name,
                    description=tmpl.description,
                    parameters={},
                    tags=tmpl.tags,
                )
            )

    return pool


# ---------------------------------------------------------------------------
# Capability filtering — tools
# ---------------------------------------------------------------------------


class TestToolVisibility:
    """All tools are always visible regardless of worker capabilities."""

    @pytest.mark.asyncio
    async def test_all_tools_visible_regardless_of_capabilities(self):
        pool = _setup_pool(
            [
                _make_mcp_tool("get_segments"),
                _make_mcp_tool("decompile_function", tags={"decompiler"}),
                _make_mcp_tool("assemble_instruction", tags={"assembler"}),
            ]
        )
        _add_worker(pool, "sparc", {"decompiler": False, "assembler": False})

        tools = await pool._list_tools()
        tool_names = {t.name for t in tools}
        assert "get_segments" in tool_names
        assert "decompile_function" in tool_names
        assert "assemble_instruction" in tool_names

    @pytest.mark.asyncio
    async def test_all_tools_visible_with_no_workers(self):
        pool = _setup_pool(
            [
                _make_mcp_tool("get_segments"),
                _make_mcp_tool("decompile_function", tags={"decompiler"}),
            ]
        )

        tools = await pool._list_tools()
        tool_names = {t.name for t in tools}
        assert "get_segments" in tool_names
        assert "decompile_function" in tool_names

    @pytest.mark.asyncio
    async def test_all_resource_templates_visible_regardless_of_capabilities(self):
        pool = _setup_pool(
            tools=[],
            resource_templates=[
                _make_resource_template(
                    "ida://{database}/functions/{addr}/vars",
                    "function_vars",
                    tags={"decompiler"},
                ),
                _make_resource_template(
                    "ida://{database}/functions/{addr}",
                    "function_detail",
                ),
            ],
        )
        _add_worker(pool, "sparc", {"decompiler": False})

        templates = await pool._list_resource_templates()
        names = {t.name for t in templates}
        assert "function_detail" in names
        assert "function_vars" in names


# ---------------------------------------------------------------------------
# Worker session tracking
# ---------------------------------------------------------------------------


class TestWorkerSessionTracking:
    """Test Worker.attach / detach / is_attached / session_count."""

    def test_attach_adds_session(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        w.attach("session_a")
        assert w.session_count == 1
        assert w.is_attached("session_a")

    def test_attach_is_idempotent(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        w.attach("session_a")
        w.attach("session_a")
        assert w.session_count == 1

    def test_attach_none_is_noop(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        w.attach(None)
        assert w.session_count == 0

    def test_detach_removes_session(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        w.attach("session_a")
        w.attach("session_b")
        no_left = w.detach("session_a")
        assert not no_left
        assert w.session_count == 1
        assert not w.is_attached("session_a")
        assert w.is_attached("session_b")

    def test_detach_last_returns_true(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        w.attach("session_a")
        no_left = w.detach("session_a")
        assert no_left
        assert w.session_count == 0

    def test_detach_none_is_noop_returns_false_when_sessions_remain(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        w.attach("session_a")
        no_left = w.detach(None)
        assert not no_left  # session_a still there
        assert w.session_count == 1

    def test_detach_none_empty_returns_true(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        no_left = w.detach(None)
        assert no_left

    def test_detach_unknown_session_is_safe(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        w.attach("session_a")
        no_left = w.detach("session_z")
        assert not no_left  # session_a still there

    def test_is_attached_none_always_true(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        assert w.is_attached(None)

    def test_is_attached_false_for_unknown(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        w.attach("session_a")
        assert not w.is_attached("session_z")

    def test_session_count_multiple(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        w.attach("a")
        w.attach("b")
        w.attach("c")
        assert w.session_count == 3


# ---------------------------------------------------------------------------
# check_attached
# ---------------------------------------------------------------------------


class TestCheckAttached:
    """Test WorkerPoolProvider.check_attached."""

    def test_attached_session_passes(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("session_a")
        pool.check_attached(worker, "session_a")  # should not raise

    def test_unattached_session_raises(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("session_a")
        with pytest.raises(IDAError, match="NotAttached"):
            pool.check_attached(worker, "session_b")

    def test_none_session_passes(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("session_a")
        pool.check_attached(worker, None)  # backward compat, should not raise

    def test_empty_sessions_passes(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        # No sessions attached — backward compat
        pool.check_attached(worker, "session_x")  # should not raise


# ---------------------------------------------------------------------------
# build_database_list with session info
# ---------------------------------------------------------------------------


class TestBuildDatabaseListSessions:
    """Test session_count and attached fields in build_database_list."""

    def test_session_count_present(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {"decompiler": True})
        worker.attach("s1")
        worker.attach("s2")

        result = pool.build_database_list()
        db_entry = result["databases"][0]
        assert db_entry["session_count"] == 2
        assert "attached" not in db_entry  # no caller_session_id

    def test_attached_true_when_caller_attached(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("s1")

        result = pool.build_database_list(caller_session_id="s1")
        db_entry = result["databases"][0]
        assert db_entry["attached"] is True

    def test_attached_false_when_caller_not_attached(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("s1")

        result = pool.build_database_list(caller_session_id="s2")
        db_entry = result["databases"][0]
        assert db_entry["attached"] is False

    def test_session_count_zero_no_sessions(self):
        pool = _setup_pool([])
        _add_worker(pool, "db1", {})

        result = pool.build_database_list()
        db_entry = result["databases"][0]
        assert db_entry["session_count"] == 0

    @pytest.mark.asyncio
    async def test_analyzing_flag_present_when_task_running(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.start_analysis(asyncio.sleep(3600))

        result = pool.build_database_list()
        db_entry = result["databases"][0]
        assert db_entry.get("analyzing") is True
        assert "analysis_error" not in db_entry

        await worker.cancel_analysis()

    def test_analyzing_flag_absent_when_no_analysis(self):
        pool = _setup_pool([])
        _add_worker(pool, "db1", {})

        result = pool.build_database_list()
        db_entry = result["databases"][0]
        assert "analyzing" not in db_entry

    def test_analysis_error_present_after_failure(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.record_analysis_error("something went wrong")

        result = pool.build_database_list()
        db_entry = result["databases"][0]
        assert db_entry["analysis_error"] == "something went wrong"


# ---------------------------------------------------------------------------
# Worker background analysis state
# ---------------------------------------------------------------------------


class TestWorkerAnalysisState:
    """Test Worker analysis task lifecycle: start, cancel, error tracking."""

    def test_analyzing_false_initially(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        assert not w.analyzing
        assert w.analysis_error is None

    @pytest.mark.asyncio
    async def test_analyzing_true_while_task_running(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        w.start_analysis(asyncio.sleep(3600))
        assert w.analyzing
        await w.cancel_analysis()

    @pytest.mark.asyncio
    async def test_analyzing_false_after_task_completes(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        w.start_analysis(asyncio.sleep(0))
        await w._analysis_task
        assert not w.analyzing

    @pytest.mark.asyncio
    async def test_cancel_analysis_clears_task(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        w.start_analysis(asyncio.sleep(3600))
        assert w.analyzing
        await w.cancel_analysis()
        assert not w.analyzing
        assert w._analysis_task is None

    @pytest.mark.asyncio
    async def test_cancel_analysis_noop_when_no_task(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        await w.cancel_analysis()  # should not raise

    @pytest.mark.asyncio
    async def test_cancel_analysis_noop_when_already_done(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        w.start_analysis(asyncio.sleep(0))
        await w._analysis_task
        assert not w.analyzing
        await w.cancel_analysis()  # should not raise

    def test_record_analysis_error(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        assert w.analysis_error is None
        w.record_analysis_error("oops")
        assert w.analysis_error == "oops"

    @pytest.mark.asyncio
    async def test_start_analysis_clears_previous_error(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        w.record_analysis_error("old error")
        w.start_analysis(asyncio.sleep(0))
        assert w.analysis_error is None
        await w.cancel_analysis()

    @pytest.mark.asyncio
    async def test_start_analysis_names_task(self):
        w = Worker(database_id="mydb", file_path="/tmp/mydb")
        w.start_analysis(asyncio.sleep(3600))
        assert w._analysis_task is not None
        assert w._analysis_task.get_name() == "background-analysis-mydb"
        await w.cancel_analysis()


# ---------------------------------------------------------------------------
# RoutingTool fast-fail during analysis
# ---------------------------------------------------------------------------


class TestRoutingToolAnalysisFastFail:
    """Test that RoutingTool.run() rejects calls during background analysis."""

    @pytest.mark.asyncio
    async def test_tool_rejected_during_analysis(self):
        pool = _setup_pool([_make_mcp_tool("list_functions")])
        worker = _add_worker(pool, "db1", {})
        worker.start_analysis(asyncio.sleep(3600))

        rt = pool._routing_tools["list_functions"]
        with pytest.raises(ToolError, match="being analyzed"):
            await rt.run({"database": "db1"})

        await worker.cancel_analysis()

    def test_management_tools_excluded_from_routing(self):
        """Management tools should not be wrapped as RoutingTools."""
        pool = _setup_pool([_make_mcp_tool(name) for name in _MANAGEMENT_TOOLS])
        for name in _MANAGEMENT_TOOLS:
            assert name not in pool._routing_tools

    @pytest.mark.asyncio
    async def test_tool_allowed_when_not_analyzing(self):
        """Tools should not be rejected when analysis is not running."""
        pool = _setup_pool([_make_mcp_tool("list_functions")])
        _add_worker(pool, "db1", {})

        rt = pool._routing_tools["list_functions"]
        # Will fail (no real worker client), but should NOT fail with
        # the "being analyzed" error.
        try:
            await rt.run({"database": "db1"})
        except Exception as exc:
            assert "being analyzed" not in str(exc)


# ---------------------------------------------------------------------------
# _background_analysis
# ---------------------------------------------------------------------------


def _ok_result(data: dict) -> types.CallToolResult:
    """Build a non-error CallToolResult with JSON text content."""
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(data))],
        isError=False,
    )


def _error_call_result(msg: str) -> types.CallToolResult:
    """Build an error CallToolResult."""
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=msg)],
        isError=True,
    )


class TestBackgroundAnalysis:
    """Test WorkerPoolProvider._background_analysis coroutine."""

    @pytest.mark.asyncio
    async def test_happy_path_refreshes_metadata(self):
        """Successful analysis refreshes worker metadata from get_database_info."""
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.metadata["function_count"] = 5

        wait_result = _ok_result({"status": "analysis_complete"})
        info_result = _ok_result(
            {
                "processor": "pc",
                "bitness": 64,
                "file_type": "ELF",
                "function_count": 500,
                "segment_count": 10,
            }
        )

        pool.proxy_to_worker = AsyncMock(side_effect=[wait_result, info_result])

        await pool._background_analysis(worker, mcp_session=None)

        assert worker.metadata["function_count"] == 500
        assert worker.metadata["segment_count"] == 10
        assert worker.analysis_error is None

    @pytest.mark.asyncio
    async def test_happy_path_sends_notifications(self):
        """Successful analysis sends log messages and list-changed notifications."""
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})

        wait_result = _ok_result({"status": "analysis_complete"})
        info_result = _ok_result({"function_count": 42})
        pool.proxy_to_worker = AsyncMock(side_effect=[wait_result, info_result])

        session = AsyncMock()
        await pool._background_analysis(worker, mcp_session=session)

        # Two send_log_message calls: start + complete
        assert session.send_log_message.call_count == 2
        # One send_notification call: ResourceListChanged (tool list is static)
        assert session.send_notification.call_count == 1

    @pytest.mark.asyncio
    async def test_wait_for_analysis_error_records_error(self):
        """When wait_for_analysis returns an error, it's recorded on the worker."""
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})

        pool.proxy_to_worker = AsyncMock(return_value=_error_call_result("Analysis timed out"))

        await pool._background_analysis(worker, mcp_session=None)

        assert worker.analysis_error == "Analysis timed out"
        # proxy_to_worker called only once (no get_database_info after failure)
        assert pool.proxy_to_worker.call_count == 1

    @pytest.mark.asyncio
    async def test_unexpected_exception_records_error(self):
        """An unexpected exception is recorded as analysis_error."""
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})

        pool.proxy_to_worker = AsyncMock(side_effect=RuntimeError("boom"))

        await pool._background_analysis(worker, mcp_session=None)

        assert worker.analysis_error is not None
        assert "boom" in worker.analysis_error

    @pytest.mark.asyncio
    async def test_cancellation_propagates(self):
        """CancelledError is re-raised, not swallowed."""
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})

        pool.proxy_to_worker = AsyncMock(side_effect=asyncio.CancelledError)

        with pytest.raises(asyncio.CancelledError):
            await pool._background_analysis(worker, mcp_session=None)

    @pytest.mark.asyncio
    async def test_metadata_refresh_failure_non_fatal(self):
        """If get_database_info fails, analysis still succeeds."""
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.metadata["function_count"] = 5

        wait_result = _ok_result({"status": "analysis_complete"})
        info_result = _error_call_result("get_database_info failed")
        pool.proxy_to_worker = AsyncMock(side_effect=[wait_result, info_result])

        await pool._background_analysis(worker, mcp_session=None)

        # Metadata unchanged since info call failed
        assert worker.metadata["function_count"] == 5
        assert worker.analysis_error is None


# ---------------------------------------------------------------------------
# close_for_session
# ---------------------------------------------------------------------------


class TestCloseForSession:
    """Test WorkerPoolProvider.close_for_session."""

    @pytest.mark.asyncio
    async def test_terminate_when_last_session(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("s1")

        result = await pool.close_for_session(worker, "s1")
        assert result["status"] == "closed"
        assert "db1" not in pool._id_to_path

    @pytest.mark.asyncio
    async def test_detach_when_other_sessions_remain(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("s1")
        worker.attach("s2")

        result = await pool.close_for_session(worker, "s1")
        assert result["status"] == "detached"
        assert result["remaining_sessions"] == 1
        assert not worker.is_attached("s1")
        assert worker.is_attached("s2")
        # Worker still in pool
        assert "db1" in pool._id_to_path

    @pytest.mark.asyncio
    async def test_terminate_when_force(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("s1")
        worker.attach("s2")

        result = await pool.close_for_session(worker, "s1", force=True)
        assert result["status"] == "closed"
        assert "db1" not in pool._id_to_path

    @pytest.mark.asyncio
    async def test_terminate_when_session_none(self):
        """None session falls back to legacy terminate behavior."""
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("s1")

        result = await pool.close_for_session(worker, None)
        assert result["status"] == "closed"

    @pytest.mark.asyncio
    async def test_unattached_session_raises(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("s1")

        with pytest.raises(IDAError, match="NotAttached"):
            await pool.close_for_session(worker, "s2")

    @pytest.mark.asyncio
    async def test_unattached_session_with_force_terminates(self):
        """force=True always terminates, even if the caller isn't attached."""
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("s1")

        result = await pool.close_for_session(worker, "s2", force=True)
        assert result["status"] == "closed"
        assert "db1" not in pool._id_to_path


# ---------------------------------------------------------------------------
# detach_all
# ---------------------------------------------------------------------------


class TestDetachAll:
    """Test WorkerPoolProvider.detach_all."""

    @pytest.mark.asyncio
    async def test_terminates_workers_with_no_remaining_sessions(self):
        pool = _setup_pool([])
        w1 = _add_worker(pool, "db1", {})
        w1.attach("s1")
        w2 = _add_worker(pool, "db2", {})
        w2.attach("s1")

        await pool.detach_all("s1")
        # Both workers should be removed (no sessions left)
        assert "db1" not in pool._id_to_path
        assert "db2" not in pool._id_to_path

    @pytest.mark.asyncio
    async def test_keeps_workers_with_remaining_sessions(self):
        pool = _setup_pool([])
        w1 = _add_worker(pool, "db1", {})
        w1.attach("s1")
        w1.attach("s2")
        w2 = _add_worker(pool, "db2", {})
        w2.attach("s1")

        await pool.detach_all("s1")
        # db1 still has s2, so should remain
        assert "db1" in pool._id_to_path
        assert w1.session_count == 1
        # db2 had only s1, so should be terminated
        assert "db2" not in pool._id_to_path

    @pytest.mark.asyncio
    async def test_none_session_delegates_to_shutdown_all(self):
        pool = _setup_pool([])
        _add_worker(pool, "db1", {})
        _add_worker(pool, "db2", {})

        await pool.detach_all(None)
        assert len(pool._alive_workers()) == 0

    @pytest.mark.asyncio
    async def test_skips_inactive_workers(self):
        pool = _setup_pool([])
        w1 = _add_worker(pool, "db1", {})
        w1.attach("s1")
        w2 = _add_worker(pool, "db2", {})
        w2.attach("s1")
        w2.state = WorkerState.DEAD

        await pool.detach_all("s1")
        # db1 terminated, db2 skipped (already dead)
        assert "db1" not in pool._id_to_path

    @pytest.mark.asyncio
    async def test_skips_unattached_workers(self):
        pool = _setup_pool([])
        w1 = _add_worker(pool, "db1", {})
        w1.attach("s1")
        w2 = _add_worker(pool, "db2", {})
        w2.attach("s2")

        await pool.detach_all("s1")
        # db1 terminated (s1 was sole session)
        assert "db1" not in pool._id_to_path
        # db2 untouched (s1 was never attached)
        assert "db2" in pool._id_to_path
        assert w2.session_count == 1


# ---------------------------------------------------------------------------
# ensure_session_cleanup
# ---------------------------------------------------------------------------


class TestEnsureSessionCleanup:
    """Test WorkerPoolProvider.ensure_session_cleanup."""

    def test_none_ctx_is_noop(self):
        pool = _setup_pool([])
        pool.ensure_session_cleanup(None)  # should not raise
        assert len(pool._registered_sessions) == 0

    def test_registers_session(self):
        pool = _setup_pool([])
        ctx = _FakeCtx("s1")
        pool.ensure_session_cleanup(ctx)
        assert "s1" in pool._registered_sessions
        assert len(ctx.session._exit_stack.callbacks) == 1

    def test_idempotent(self):
        pool = _setup_pool([])
        ctx = _FakeCtx("s1")
        pool.ensure_session_cleanup(ctx)
        pool.ensure_session_cleanup(ctx)
        assert len(ctx.session._exit_stack.callbacks) == 1

    @pytest.mark.asyncio
    async def test_callback_calls_detach_all(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("s1")

        ctx = _FakeCtx("s1")
        pool.ensure_session_cleanup(ctx)

        # Simulate disconnect by calling the registered callback
        await ctx.session._exit_stack.callbacks[0]()
        assert "s1" not in pool._registered_sessions
        assert "db1" not in pool._id_to_path

    def test_push_failure_does_not_leak_sid(self):
        """If push_async_callback fails, sid must not stay in _registered_sessions."""
        pool = _setup_pool([])
        ctx = _FakeCtx("s1")
        # Break the exit stack so push_async_callback raises
        ctx.session._exit_stack = None
        pool.ensure_session_cleanup(ctx)
        assert "s1" not in pool._registered_sessions

    def test_push_failure_allows_retry(self):
        """After a failed push, a second call with a working ctx should succeed."""
        pool = _setup_pool([])

        broken_ctx = _FakeCtx("s1")
        broken_ctx.session._exit_stack = None
        pool.ensure_session_cleanup(broken_ctx)

        # Retry with a working context for the same session
        good_ctx = _FakeCtx("s1")
        pool.ensure_session_cleanup(good_ctx)
        assert "s1" in pool._registered_sessions
        assert len(good_ctx.session._exit_stack.callbacks) == 1

    def test_none_session_id_is_noop(self):
        pool = _setup_pool([])
        pool.ensure_session_cleanup(_FakeCtx(None))
        assert len(pool._registered_sessions) == 0


# ---------------------------------------------------------------------------
# Worker.opening / spawn_error / wait_ready
# ---------------------------------------------------------------------------


class TestWorkerOpeningState:
    """Test Worker properties for the non-blocking open_database flow."""

    def test_opening_true_when_starting_and_event_not_set(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        assert w.opening is True

    def test_opening_false_after_event_set(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        w._ready_event.set()
        assert w.opening is False

    def test_opening_false_when_idle(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        w.state = WorkerState.IDLE
        assert w.opening is False

    def test_spawn_error_initially_none(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        assert w.spawn_error is None

    def test_spawn_error_set_and_readable(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        w._spawn_error = "Connection refused"
        assert w.spawn_error == "Connection refused"

    @pytest.mark.asyncio
    async def test_wait_ready_returns_immediately_when_set(self):
        w = Worker(database_id="db", file_path="/tmp/db")
        w._ready_event.set()
        await w.wait_ready()  # should not block


# ---------------------------------------------------------------------------
# wait_for_ready
# ---------------------------------------------------------------------------


class TestWaitForReady:
    """Test WorkerPoolProvider.wait_for_ready."""

    @pytest.mark.asyncio
    async def test_ready_worker_returns_immediately(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker._ready_event.set()

        result = await pool.wait_for_ready("db1")
        assert result["status"] == "ready"
        assert result["database"] == "db1"

    @pytest.mark.asyncio
    async def test_spawn_failure_raises(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.state = WorkerState.STARTING
        worker._spawn_error = "Connection refused"
        worker._ready_event.set()

        with pytest.raises(IDAError, match="failed to open"):
            await pool.wait_for_ready("db1")

    @pytest.mark.asyncio
    async def test_waits_for_opening_then_returns(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.state = WorkerState.STARTING

        async def _set_ready():
            await asyncio.sleep(0.01)
            worker.state = WorkerState.IDLE
            worker._ready_event.set()

        task = asyncio.create_task(_set_ready())
        result = await pool.wait_for_ready("db1")
        await task
        assert result["status"] == "ready"

    @pytest.mark.asyncio
    async def test_waits_for_analysis_after_opening(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker._ready_event.set()

        # Simulate a short analysis task
        worker.start_analysis(asyncio.sleep(0.01))
        result = await pool.wait_for_ready("db1")
        assert result["status"] == "ready"


# ---------------------------------------------------------------------------
# resolve_worker with STARTING state
# ---------------------------------------------------------------------------


class TestResolveWorkerStarting:
    """Test that resolve_worker rejects STARTING workers with a clear message."""

    def test_starting_worker_raises_not_ready(self):
        pool = _setup_pool([])
        canonical = "/tmp/db1"
        worker = Worker(database_id="db1", file_path=canonical)
        pool._workers[canonical] = worker
        pool._id_to_path["db1"] = canonical

        with pytest.raises(IDAError, match="still opening"):
            pool.resolve_worker("db1")

    def test_lookup_worker_finds_starting_worker(self):
        pool = _setup_pool([])
        canonical = "/tmp/db1"
        worker = Worker(database_id="db1", file_path=canonical)
        pool._workers[canonical] = worker
        pool._id_to_path["db1"] = canonical

        found = pool._lookup_worker("db1")
        assert found is worker


# ---------------------------------------------------------------------------
# build_database_list includes opening workers
# ---------------------------------------------------------------------------


class TestBuildDatabaseListOpening:
    """Test that build_database_list shows STARTING workers."""

    def test_opening_worker_shown_with_flag(self):
        pool = _setup_pool([])
        canonical = "/tmp/db1"
        worker = Worker(database_id="db1", file_path=canonical)
        pool._workers[canonical] = worker
        pool._id_to_path["db1"] = canonical

        result = pool.build_database_list()
        assert result["database_count"] == 1
        db_entry = result["databases"][0]
        assert db_entry["database"] == "db1"
        assert db_entry["opening"] is True

    def test_spawn_error_shown(self):
        pool = _setup_pool([])
        canonical = "/tmp/db1"
        worker = Worker(database_id="db1", file_path=canonical)
        worker._spawn_error = "Failed"
        worker._ready_event.set()
        pool._workers[canonical] = worker
        pool._id_to_path["db1"] = canonical

        result = pool.build_database_list()
        db_entry = result["databases"][0]
        assert db_entry["spawn_error"] == "Failed"
