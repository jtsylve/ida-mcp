# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Unit tests for supervisor / worker_provider pure utility functions.

These tests cover prefix_uri, extract_db_prefix, and capability-based
tool/resource filtering — all functions that can run without idalib loaded.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import signal
from unittest.mock import AsyncMock, MagicMock

import jsonschema
import mcp.types as types
import pytest
from fastmcp.exceptions import ToolError
from fastmcp.exceptions import ValidationError as FastMCPValidationError
from fastmcp.resources.template import ResourceTemplate as FastMCPResourceTemplate
from fastmcp.tools.base import ToolResult
from fastmcp.tools.tool import Tool as FastMCPTool
from pydantic import BaseModel as PydanticBaseModel
from pydantic import ValidationError as PydanticValidationError

from ida_mcp.exceptions import IDAError
from ida_mcp.supervisor import ProxyMCP
from ida_mcp.transforms import (
    MANAGEMENT_TOOLS,
    META_TOOLS,
    BatchOperation,
    IDAToolTransform,
    _format_default,
    _format_return_type,
    _format_validation_error,
    _has_processing_logic,
    _render_type_annotation,
    _signature_line,
    _type_label,
    _unwrap_tool_result,
    unwrap_auto_wrapped,
)
from ida_mcp.worker_provider import (
    _MANAGEMENT_TOOLS,
    RoutingTemplate,
    RoutingTool,
    Worker,
    WorkerPoolProvider,
    WorkerState,
    _canonical_path,
    _enrich_result,
    _fixup_output_schema,
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

    def push_async_exit(self, cb):
        """Mirror ``contextlib.AsyncExitStack.push_async_exit``.

        The real stack invokes the callback with ``(exc_type, exc, tb)``;
        tests simulate that by calling ``callbacks[0](None, None, None)``
        for a clean unwind or passing an exception instance.
        """
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
# _canonical_path — dedup key construction
# ---------------------------------------------------------------------------


def test_canonical_path_raw_binary(tmp_path):
    """A raw binary path canonicalises to ``<realpath>.i64``."""
    raw = tmp_path / "firmware.bin"
    raw.write_bytes(b"\x00")
    expected = os.path.realpath(str(raw)) + ".i64"
    assert _canonical_path(str(raw)) == expected


def test_canonical_path_idb_normalizes_extension(tmp_path):
    """``.idb`` and ``.i64`` inputs both canonicalise to the ``.i64`` key."""
    idb = tmp_path / "project.idb"
    i64 = tmp_path / "project.i64"
    assert _canonical_path(str(idb)) == _canonical_path(str(i64))


def test_canonical_path_dedups_symlinks(tmp_path):
    """Two symlinks pointing at the same binary share a dedup key."""
    real = tmp_path / "real_binary"
    real.write_bytes(b"\x00")
    link_a = tmp_path / "link_a"
    link_b = tmp_path / "link_b"
    link_a.symlink_to(real)
    link_b.symlink_to(real)

    assert _canonical_path(str(link_a)) == _canonical_path(str(link_b))
    assert _canonical_path(str(link_a)) == _canonical_path(str(real))


def test_canonical_path_fat_arch_separates_slices(tmp_path):
    """Different fat slices of the same binary get distinct keys so they
    dedup to separate workers (and per-slice sidecar files on disk)."""
    fat = tmp_path / "universal"
    fat.write_bytes(b"\x00")
    x86 = _canonical_path(str(fat), fat_arch="x86_64")
    arm = _canonical_path(str(fat), fat_arch="arm64")
    default = _canonical_path(str(fat))
    assert x86 != arm
    assert x86 != default
    assert arm != default
    assert x86.endswith(".x86_64.i64")
    assert arm.endswith(".arm64.i64")


def test_canonical_path_fat_arch_dedups_symlinked_slices(tmp_path):
    """The slice suffix is appended after realpath resolution, so two
    symlinks plus the same ``fat_arch`` still collapse to one key."""
    real = tmp_path / "universal_real"
    real.write_bytes(b"\x00")
    link = tmp_path / "universal_link"
    link.symlink_to(real)
    assert _canonical_path(str(link), fat_arch="arm64") == _canonical_path(
        str(real), fat_arch="arm64"
    )


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

    @pytest.mark.asyncio
    async def test_terminate_false_detaches_without_removing(self):
        """terminate=False detaches the session but leaves the worker registered.

        Used by the session-disconnect path so that a session cycle does not
        kill databases that may still be opened by other agents.
        """
        pool = _setup_pool([])
        w1 = _add_worker(pool, "db1", {})
        w1.attach("s1")
        w2 = _add_worker(pool, "db2", {})
        w2.attach("s1")
        w2.attach("s2")

        await pool.detach_all("s1", terminate=False)

        # Both workers are still registered despite s1 being detached.
        assert "db1" in pool._id_to_path
        assert "db2" in pool._id_to_path
        assert w1.session_count == 0
        # w2 still holds s2
        assert w2.session_count == 1
        assert w2.is_attached("s2")


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
        """Session disconnect detaches the session but does NOT terminate the worker.

        Workers are kept alive across MCP session cycles so that parallel
        agents sharing one MCP session can survive reconnects.  Termination
        only happens via explicit close_database / keep_open=False / shutdown.
        """
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("s1")

        ctx = _FakeCtx("s1")
        pool.ensure_session_cleanup(ctx)

        # Simulate a clean disconnect (exc_type/exc/tb all None) by invoking
        # the registered callback with the __aexit__ signature.
        await ctx.session._exit_stack.callbacks[0](None, None, None)
        assert "s1" not in pool._registered_sessions
        # Worker is detached but NOT removed — it survives the session cycle.
        assert worker.session_count == 0
        assert "db1" in pool._id_to_path

    def test_push_failure_does_not_leak_sid(self):
        """If push_async_exit fails, sid must not stay in _registered_sessions."""
        pool = _setup_pool([])
        ctx = _FakeCtx("s1")
        # Break the exit stack so push_async_exit raises
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

    @pytest.mark.asyncio
    async def test_callback_logs_clean_reason(self, caplog):
        """Clean unwind (None exception) logs reason='clean'."""
        pool = _setup_pool([])
        ctx = _FakeCtx("sclean")
        pool.ensure_session_cleanup(ctx)
        with caplog.at_level(logging.INFO, logger="ida_mcp.worker_provider"):
            await ctx.session._exit_stack.callbacks[0](None, None, None)
        assert any("disconnected (clean)" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_callback_logs_cancelled_reason(self, caplog):
        """CancelledError unwind logs reason='cancelled'."""
        pool = _setup_pool([])
        ctx = _FakeCtx("scancel")
        pool.ensure_session_cleanup(ctx)
        exc = asyncio.CancelledError()
        with caplog.at_level(logging.INFO, logger="ida_mcp.worker_provider"):
            await ctx.session._exit_stack.callbacks[0](type(exc), exc, None)
        assert any("disconnected (cancelled)" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_callback_logs_transport_exception_reason(self, caplog):
        """Transport-level exception unwind logs the exception type and message."""
        pool = _setup_pool([])
        ctx = _FakeCtx("stransport")
        pool.ensure_session_cleanup(ctx)
        exc = BrokenPipeError("stdio EOF")
        with caplog.at_level(logging.INFO, logger="ida_mcp.worker_provider"):
            await ctx.session._exit_stack.callbacks[0](type(exc), exc, None)
        assert any("disconnected (BrokenPipeError: stdio EOF)" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_callback_does_not_suppress_exception(self):
        """The callback must return False so AsyncExitStack propagates the unwind exception."""
        pool = _setup_pool([])
        ctx = _FakeCtx("ssuppress")
        pool.ensure_session_cleanup(ctx)
        exc = RuntimeError("boom")
        result = await ctx.session._exit_stack.callbacks[0](type(exc), exc, None)
        assert result is False


# ---------------------------------------------------------------------------
# Death watcher
# ---------------------------------------------------------------------------


class TestDeathWatcher:
    """Tests for _spawn_death_watcher / _close_client watcher lifecycle."""

    @pytest.mark.asyncio
    async def test_spawn_sets_death_watcher(self):
        """_spawn_death_watcher creates an asyncio task on the worker."""
        pool = _setup_pool([])
        w = Worker(database_id="db1", file_path="/tmp/db1")
        w.pid = 99999
        assert w._death_watcher is None
        pool._spawn_death_watcher(w)
        assert w._death_watcher is not None
        assert not w._death_watcher.done()
        w._death_watcher.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await w._death_watcher

    @pytest.mark.asyncio
    async def test_spawn_noop_when_pid_is_none(self):
        """No watcher created when the worker has no PID."""
        pool = _setup_pool([])
        w = Worker(database_id="db1", file_path="/tmp/db1")
        assert w.pid is None
        pool._spawn_death_watcher(w)
        assert w._death_watcher is None

    @pytest.mark.asyncio
    async def test_close_client_cancels_watcher(self):
        """_close_client cancels the death watcher before killing the process."""
        pool = _setup_pool([])
        w = Worker(database_id="db1", file_path="/tmp/db1")
        w.pid = None  # avoid actually killing a process

        # Create a long-running fake watcher task.
        async def _forever():
            await asyncio.sleep(3600)

        w._death_watcher = asyncio.create_task(_forever())
        assert not w._death_watcher.done()

        await pool._close_client(w)

        assert w._death_watcher is None
        assert w.state == WorkerState.DEAD

    @pytest.mark.asyncio
    async def test_watcher_silent_on_intentional_shutdown(self, caplog):
        """When state is DEAD before the process exits, the watcher stays silent."""
        pool = _setup_pool([])
        w = Worker(database_id="db1", file_path="/tmp/db1")
        # Use a PID that definitely doesn't exist.
        w.pid = 2**30
        w.state = WorkerState.DEAD

        pool._spawn_death_watcher(w)
        # Let the watcher run one poll cycle.
        await asyncio.sleep(0.1)
        # Give the task a moment to finish; it should exit silently.
        with caplog.at_level(logging.WARNING, logger="ida_mcp.worker_provider"):
            w._death_watcher.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await w._death_watcher
        assert not any("exited unexpectedly" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Signal handler installation
# ---------------------------------------------------------------------------


class TestSignalHandlers:
    """Tests for _install_signal_handlers."""

    @pytest.mark.asyncio
    async def test_installs_on_running_loop(self):
        """Signal handlers are installed on the given loop."""
        from ida_mcp.supervisor import _install_signal_handlers  # noqa: PLC0415

        loop = asyncio.get_running_loop()
        _install_signal_handlers(loop)
        try:
            # SIGTERM handler should be installed — removing it should
            # return True (handler was present).
            assert loop.remove_signal_handler(signal.SIGTERM) is True
        finally:
            # Clean up remaining handlers.
            for sig_name in ("SIGINT", "SIGHUP"):
                sig = getattr(signal, sig_name, None)
                if sig is not None:
                    with contextlib.suppress(Exception):
                        loop.remove_signal_handler(sig)


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


# ---------------------------------------------------------------------------
# unwrap_auto_wrapped / _enrich_result unwrapping
# ---------------------------------------------------------------------------


class TestUnwrapAutoWrapped:
    """FastMCP wraps Union return types in {"result": ...}.  We unwrap."""

    def test_unwraps_single_result_key(self):
        data = {"result": {"items": [1, 2], "total": 2}}
        assert unwrap_auto_wrapped(data) == {"items": [1, 2], "total": 2}

    def test_preserves_flat_dict(self):
        data = {"items": [1, 2], "total": 2, "has_more": False}
        assert unwrap_auto_wrapped(data) is data

    def test_preserves_result_alongside_other_keys(self):
        """A dict with 'result' plus other keys is NOT auto-wrapped."""
        data = {"result": {"x": 1}, "extra": True}
        assert unwrap_auto_wrapped(data) is data

    def test_preserves_result_with_non_dict_value(self):
        """A dict with 'result' mapping to a non-dict is NOT unwrapped."""
        data = {"result": "some_string"}
        assert unwrap_auto_wrapped(data) is data


class TestUnwrapToolResult:
    """_unwrap_tool_result peels the FastMCP Union wrapper for execute/batch."""

    def test_unwraps_structured_content_with_result_wrapper(self):
        tr = ToolResult(structured_content={"result": {"items": [1, 2], "total": 2}})
        assert _unwrap_tool_result(tr) == {"items": [1, 2], "total": 2}

    def test_returns_flat_structured_content_as_is(self):
        tr = ToolResult(structured_content={"items": [1, 2], "total": 2})
        assert _unwrap_tool_result(tr) == {"items": [1, 2], "total": 2}

    def test_falls_back_to_text_content(self):
        tr = ToolResult(
            content=[types.TextContent(type="text", text="hello")],
        )
        assert _unwrap_tool_result(tr) == "hello"

    def test_preserves_result_with_extra_keys(self):
        data = {"result": {"x": 1}, "extra": True}
        tr = ToolResult(structured_content=data)
        assert _unwrap_tool_result(tr) == data


class TestEnrichResultUnwrap:
    """_enrich_result should inject database while preserving schema structure."""

    def test_wrapped_result_unwraps_both(self):
        """Union-typed results unwrap both structuredContent and text.

        The outputSchema is also unwrapped by _fixup_output_schema, so
        both channels must match the unwrapped form.
        """
        raw = types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps({"result": {"items": ["a"], "total": 1}}),
                )
            ],
            structuredContent={"result": {"items": ["a"], "total": 1}},
            isError=False,
        )
        enriched = _enrich_result(raw, "mydb")

        expected = {"items": ["a"], "total": 1, "database": "mydb"}

        # Both channels are unwrapped consistently
        assert enriched.structuredContent == expected
        text_data = json.loads(enriched.content[0].text)
        assert text_data == expected

    def test_flat_result_stays_flat(self):
        """Non-Union tool results are left alone (just database added)."""
        raw = types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps({"items": ["a"], "total": 1}),
                )
            ],
            structuredContent={"items": ["a"], "total": 1},
            isError=False,
        )
        enriched = _enrich_result(raw, "mydb")

        assert enriched.structuredContent == {
            "items": ["a"],
            "total": 1,
            "database": "mydb",
        }


# ---------------------------------------------------------------------------
# _fixup_output_schema
# ---------------------------------------------------------------------------


class TestFixupOutputSchema:
    """_fixup_output_schema should unwrap Union schemas and inject database."""

    def test_none_returns_none(self):
        assert _fixup_output_schema(None) is None

    def test_flat_schema_gets_database(self):
        """Non-wrapped schema just gets database injected."""
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
            },
            "required": ["name"],
        }
        result = _fixup_output_schema(schema)
        assert result["properties"]["database"] == {
            "type": "string",
            "description": "Database identifier.",
        }
        # Original fields preserved
        assert result["properties"]["name"] == {"type": "string"}
        assert result["type"] == "object"

    def test_wrapped_schema_unwraps(self):
        """Union-typed schema with x-fastmcp-wrap-result is unwrapped."""
        schema = {
            "type": "object",
            "properties": {
                "result": {
                    "anyOf": [
                        {"$ref": "#/$defs/TypeA"},
                        {"$ref": "#/$defs/TypeB"},
                    ]
                }
            },
            "required": ["result"],
            "x-fastmcp-wrap-result": True,
            "$defs": {
                "TypeA": {
                    "type": "object",
                    "properties": {"items": {"type": "array"}},
                    "required": ["items"],
                },
                "TypeB": {
                    "type": "object",
                    "properties": {"groups": {"type": "array"}},
                    "required": ["groups"],
                },
            },
        }
        result = _fixup_output_schema(schema)

        # Wrapper removed — anyOf at top level
        assert "anyOf" in result
        assert "x-fastmcp-wrap-result" not in result
        assert "properties" not in result

        # $defs preserved with database injected into each variant
        assert "database" in result["$defs"]["TypeA"]["properties"]
        assert "database" in result["$defs"]["TypeB"]["properties"]

    def test_wrapped_scalar_result_keeps_wrapper(self):
        """Wrapped scalar results keep their ``{"result": ...}`` wrapper.

        ``unwrap_auto_wrapped`` only unwraps when ``result`` is a dict, so
        the runtime payload for a scalar tool is ``{"result": "foo",
        "database": "db"}``.  The schema must match that exactly —
        unwrapping it to ``{"type": "string"}`` would make clients reject
        every such response.
        """
        schema = {
            "type": "object",
            "properties": {"result": {"type": "string"}},
            "x-fastmcp-wrap-result": True,
        }
        result = _fixup_output_schema(schema)
        assert result == {
            "type": "object",
            "properties": {
                "result": {"type": "string"},
                "database": {"type": "string", "description": "Database identifier."},
            },
        }

    def test_wrapped_array_result_keeps_wrapper(self):
        """Arrays are not dicts either — the wrapper is preserved."""
        schema = {
            "type": "object",
            "properties": {"result": {"type": "array", "items": {"type": "integer"}}},
            "x-fastmcp-wrap-result": True,
        }
        result = _fixup_output_schema(schema)
        assert result["properties"]["result"] == {
            "type": "array",
            "items": {"type": "integer"},
        }
        assert "database" in result["properties"]

    def test_wrapped_mixed_union_keeps_wrapper(self):
        """A ``Model | str`` union stays wrapped — not every branch is an object."""
        schema = {
            "type": "object",
            "properties": {
                "result": {
                    "anyOf": [
                        {"$ref": "#/$defs/Obj"},
                        {"type": "string"},
                    ]
                }
            },
            "x-fastmcp-wrap-result": True,
            "$defs": {
                "Obj": {"type": "object", "properties": {"x": {"type": "integer"}}},
            },
        }
        result = _fixup_output_schema(schema)
        # Wrapper preserved
        assert "anyOf" in result["properties"]["result"]
        assert "database" in result["properties"]

    def test_wrapped_ref_to_object_unwraps_and_injects_into_target(self):
        """A ``$ref``-only wrap whose target is an object gets unwrapped;
        ``database`` is injected into the target $def, not sprayed across
        all $defs."""
        schema = {
            "type": "object",
            "properties": {"result": {"$ref": "#/$defs/Payload"}},
            "x-fastmcp-wrap-result": True,
            "$defs": {
                "Payload": {
                    "type": "object",
                    "properties": {"items": {"type": "array"}},
                },
                "Unrelated": {
                    "type": "object",
                    "properties": {"other": {"type": "string"}},
                },
            },
        }
        result = _fixup_output_schema(schema)
        assert result["$ref"] == "#/$defs/Payload"
        assert "database" in result["$defs"]["Payload"]["properties"]
        # Unrelated defs are not touched.
        assert "database" not in result["$defs"]["Unrelated"]["properties"]

    def test_wrapped_object_without_composition_unwrapped_and_injected(self):
        """Wrapped object schema (no $ref/allOf/etc.) is unwrapped and gets database."""
        schema = {
            "type": "object",
            "properties": {
                "result": {
                    "type": "object",
                    "properties": {"count": {"type": "integer"}},
                }
            },
            "x-fastmcp-wrap-result": True,
        }
        result = _fixup_output_schema(schema)
        assert result["type"] == "object"
        assert "count" in result["properties"]
        assert "database" in result["properties"]

    def test_wrapped_empty_result_keeps_wrapper(self):
        """An empty ``result`` schema gives no object guarantee, so the
        wrapper is preserved and ``database`` is added as a sibling."""
        schema = {
            "type": "object",
            "properties": {"result": {}},
            "x-fastmcp-wrap-result": True,
        }
        result = _fixup_output_schema(schema)
        assert result == {
            "type": "object",
            "properties": {
                "result": {},
                "database": {"type": "string", "description": "Database identifier."},
            },
        }

    def test_allof_composition_variant_gets_database(self):
        """$defs variant using allOf composition (no explicit type/properties) gets database."""
        schema = {
            "type": "object",
            "properties": {
                "result": {
                    "anyOf": [
                        {"$ref": "#/$defs/Composed"},
                        {"$ref": "#/$defs/Plain"},
                    ]
                }
            },
            "x-fastmcp-wrap-result": True,
            "$defs": {
                "Composed": {
                    "allOf": [
                        {"$ref": "#/$defs/Base"},
                        {
                            "type": "object",
                            "properties": {"extra": {"type": "string"}},
                        },
                    ]
                },
                "Plain": {
                    "type": "object",
                    "properties": {"items": {"type": "array"}},
                },
                "Base": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            },
        }
        result = _fixup_output_schema(schema)

        # Plain variant: database injected directly into properties
        assert "database" in result["$defs"]["Plain"]["properties"]

        # Composed variant: database injected via allOf (no top-level properties)
        composed = result["$defs"]["Composed"]
        assert any(
            "database" in item.get("properties", {})
            for item in composed.get("allOf", [])
            if isinstance(item, dict)
        )

        # Base is referenced only transitively via Composed's allOf — it
        # is not itself a top-level variant, so it must not be mutated.
        # The database field reaches payloads built from Base through the
        # allOf conjunct added to Composed.
        assert "database" not in result["$defs"]["Base"]["properties"]

    def test_does_not_mutate_input(self):
        """Input schema is not modified."""
        schema = {
            "type": "object",
            "properties": {"x": {"type": "integer"}},
        }
        original = json.dumps(schema, sort_keys=True)
        _fixup_output_schema(schema)
        assert json.dumps(schema, sort_keys=True) == original

    @pytest.mark.parametrize(
        "schema",
        [
            # Plain object — no wrapping.
            {"type": "object", "properties": {"x": {"type": "integer"}}},
            # Wrapped scalar — wrapper is preserved.
            {
                "type": "object",
                "properties": {"result": {"type": "string"}},
                "x-fastmcp-wrap-result": True,
            },
            # Wrapped array — wrapper is preserved.
            {
                "type": "object",
                "properties": {"result": {"type": "array", "items": {"type": "integer"}}},
                "x-fastmcp-wrap-result": True,
            },
            # Wrapped Union of objects — unwrapped to anyOf, the regression case
            # (list_functions / list_names / get_strings).  Pre-fix this returned
            # ``{"anyOf": [...], "$defs": {...}}`` with no top-level ``type``,
            # which Claude Code's MCP client validator rejected, dropping the
            # entire tools/list response.
            {
                "type": "object",
                "properties": {
                    "result": {
                        "anyOf": [
                            {"$ref": "#/$defs/Single"},
                            {"$ref": "#/$defs/Batch"},
                        ]
                    }
                },
                "x-fastmcp-wrap-result": True,
                "$defs": {
                    "Single": {"type": "object", "properties": {"items": {"type": "array"}}},
                    "Batch": {"type": "object", "properties": {"groups": {"type": "array"}}},
                },
            },
            # Wrapped $ref to an object — unwrapped to a $ref schema.
            {
                "type": "object",
                "properties": {"result": {"$ref": "#/$defs/Payload"}},
                "x-fastmcp-wrap-result": True,
                "$defs": {
                    "Payload": {"type": "object", "properties": {"x": {"type": "integer"}}},
                },
            },
            # Wrapped inline object — unwrapped in place.
            {
                "type": "object",
                "properties": {
                    "result": {
                        "type": "object",
                        "properties": {"count": {"type": "integer"}},
                    }
                },
                "x-fastmcp-wrap-result": True,
            },
            # Wrapped empty result — wrapper is preserved.
            {
                "type": "object",
                "properties": {"result": {}},
                "x-fastmcp-wrap-result": True,
            },
        ],
    )
    def test_top_level_type_is_object(self, schema):
        """Every fixup result must declare ``"type": "object"`` at the top.

        MCP requires outputSchema to be an object schema, and Claude Code's
        client validator rejects the entire tools/list response on the first
        violation — silently dropping every tool the server advertises.
        """
        result = _fixup_output_schema(schema)
        assert result is not None
        assert result.get("type") == "object", (
            f"outputSchema missing top-level type:object — would cause Claude "
            f"Code to drop all tools.  Got: {result!r}"
        )


class TestFixupEnrichConsistency:
    """_fixup_output_schema and _enrich_result must stay in sync.

    The fixup transforms what the client sees; _enrich_result transforms
    what the client receives.  A divergence would make clients reject
    valid tool results.  This class validates live payloads against the
    fixed schema for each supported wrapper shape.
    """

    @staticmethod
    def _validate(schema: dict, payload: dict) -> None:
        jsonschema.validate(instance=payload, schema=schema)

    def _run(self, output_schema: dict, worker_payload: dict) -> None:
        fixed = _fixup_output_schema(output_schema)
        raw = types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(worker_payload))],
            structuredContent=worker_payload,
        )
        enriched = _enrich_result(raw, "mydb")
        self._validate(fixed, enriched.structuredContent)
        self._validate(fixed, json.loads(enriched.content[0].text))

    def test_flat_object_schema_validates(self):
        schema = {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        }
        self._run(schema, {"name": "foo"})

    def test_wrapped_union_validates_each_variant(self):
        schema = {
            "type": "object",
            "properties": {
                "result": {
                    "anyOf": [
                        {"$ref": "#/$defs/Single"},
                        {"$ref": "#/$defs/Batch"},
                    ]
                }
            },
            "required": ["result"],
            "x-fastmcp-wrap-result": True,
            "$defs": {
                "Single": {
                    "type": "object",
                    "properties": {
                        "items": {"type": "array"},
                        "total": {"type": "integer"},
                    },
                    "required": ["items", "total"],
                },
                "Batch": {
                    "type": "object",
                    "properties": {
                        "groups": {"type": "array"},
                        "cancelled": {"type": "boolean"},
                    },
                    "required": ["groups", "cancelled"],
                },
            },
        }
        # Worker emits the wrapped form; _enrich_result should unwrap it
        # and the fixed schema should accept the unwrapped payload.
        self._run(schema, {"result": {"items": ["a"], "total": 1}})
        self._run(schema, {"result": {"groups": [], "cancelled": False}})

    def test_wrapped_plain_object_validates(self):
        schema = {
            "type": "object",
            "properties": {
                "result": {
                    "type": "object",
                    "properties": {"count": {"type": "integer"}},
                    "required": ["count"],
                }
            },
            "x-fastmcp-wrap-result": True,
        }
        self._run(schema, {"result": {"count": 42}})

    def test_wrapped_scalar_payload_validates(self):
        """Scalar-wrapped schema + scalar payload: both keep the wrapper."""
        schema = {
            "type": "object",
            "properties": {"result": {"type": "string"}},
            "x-fastmcp-wrap-result": True,
        }
        # unwrap_auto_wrapped leaves ``{"result": "foo"}`` alone (not a
        # dict), so _enrich_result sends the wrapped form with database
        # added as a sibling.  The fixed schema must accept that shape.
        self._run(schema, {"result": "foo"})

    def test_wrapped_array_payload_validates(self):
        """Array-wrapped schema + array payload: both keep the wrapper."""
        schema = {
            "type": "object",
            "properties": {"result": {"type": "array", "items": {"type": "integer"}}},
            "x-fastmcp-wrap-result": True,
        }
        self._run(schema, {"result": [1, 2, 3]})


# ---------------------------------------------------------------------------
# _has_processing_logic
# ---------------------------------------------------------------------------


class TestHasProcessingLogic:
    """Pure function — no IDA context needed."""

    def test_for_loop(self):
        assert _has_processing_logic("for x in items:\n    pass") is True

    def test_while_loop(self):
        assert _has_processing_logic("while True:\n    break") is True

    def test_if_statement(self):
        assert _has_processing_logic("if x > 0:\n    return x") is True

    def test_asyncio_gather(self):
        assert _has_processing_logic("await asyncio.gather(a(), b())") is True

    def test_re_usage(self):
        assert _has_processing_logic("re.findall(r'\\d+', text)") is True

    def test_json_usage(self):
        assert _has_processing_logic("json.loads(data)") is True

    def test_math_usage(self):
        assert _has_processing_logic("math.floor(x)") is True

    def test_int_conversion(self):
        assert _has_processing_logic("int(addr, 16)") is True

    def test_len_call(self):
        assert _has_processing_logic("len(results)") is True

    def test_sorted_call(self):
        assert _has_processing_logic("sorted(items)") is True

    def test_list_comprehension(self):
        assert _has_processing_logic("[x for x in items]") is True

    def test_zip_call(self):
        assert _has_processing_logic("list(zip(a, b))") is True

    def test_enumerate_call(self):
        assert _has_processing_logic("for i, v in enumerate(items):") is True

    def test_any_call(self):
        assert _has_processing_logic("any(x > 0 for x in items)") is True

    def test_all_call(self):
        assert _has_processing_logic("all(x > 0 for x in items)") is True

    def test_sum_call(self):
        assert _has_processing_logic("sum(x['count'] for x in items)") is True

    def test_min_call(self):
        assert _has_processing_logic("min(sizes)") is True

    def test_max_call(self):
        assert _has_processing_logic("max(sizes)") is True

    def test_asyncio_create_task(self):
        assert _has_processing_logic("asyncio.create_task(foo())") is True

    def test_plain_single_call(self):
        assert _has_processing_logic("r = await invoke('foo', {})\nreturn r") is False

    def test_return_only(self):
        assert _has_processing_logic("return result") is False

    def test_empty_string(self):
        assert _has_processing_logic("") is False


# ---------------------------------------------------------------------------
# IDAToolTransform.search_tools
# ---------------------------------------------------------------------------


class _FakeTool:
    """Minimal stand-in for a FastMCP Tool used in catalog mocks."""

    def __init__(
        self,
        name: str,
        description: str = "",
        tags: set[str] | None = None,
    ):
        self.name = name
        self.description = description
        self.tags = tags or set()
        self.parameters: dict = {"type": "object", "properties": {}}
        self.output_schema: dict | None = None
        self.return_type = None


def _make_transform_with_catalog(
    tools: list,
    **kwargs,
) -> IDAToolTransform:
    transform = IDAToolTransform(**kwargs)
    transform.get_tool_catalog = AsyncMock(return_value=tools)  # type: ignore[method-assign]
    return transform


class TestSearchTools:
    """Tests for the search_tools meta-tool on IDAToolTransform."""

    @pytest.mark.asyncio
    async def test_matches_by_name(self):
        tools = [_FakeTool("foo_tool", "does foo"), _FakeTool("bar_tool", "does bar")]
        transform = _make_transform_with_catalog(tools)
        fn = transform._get_search_tool().fn
        result = await fn(pattern="foo", ctx=MagicMock())
        assert isinstance(result, str)
        assert "foo_tool" in result
        assert "bar_tool" not in result

    @pytest.mark.asyncio
    async def test_matches_by_description(self):
        tools = [_FakeTool("tool_a", "encryption helper"), _FakeTool("tool_b", "xref finder")]
        transform = _make_transform_with_catalog(tools)
        fn = transform._get_search_tool().fn
        result = await fn(pattern="encrypt", ctx=MagicMock())
        assert "tool_a" in result
        assert "tool_b" not in result

    @pytest.mark.asyncio
    async def test_matches_by_tag(self):
        tools = [
            _FakeTool("tool_a", "", tags={"crypto", "analysis"}),
            _FakeTool("tool_b", "", tags={"xref"}),
        ]
        transform = _make_transform_with_catalog(tools)
        fn = transform._get_search_tool().fn
        result = await fn(pattern="crypto", ctx=MagicMock())
        assert "tool_a" in result
        assert "tool_b" not in result

    @pytest.mark.asyncio
    async def test_match_all_pattern(self):
        tools = [_FakeTool("alpha"), _FakeTool("beta"), _FakeTool("gamma")]
        transform = _make_transform_with_catalog(tools)
        fn = transform._get_search_tool().fn
        result = await fn(pattern=".*", ctx=MagicMock())
        assert "alpha" in result
        assert "beta" in result
        assert "gamma" in result

    @pytest.mark.asyncio
    async def test_pinned_tools_excluded_from_results(self):
        """Pinned tools must not appear in search_tools output."""
        pinned_name = next(iter(MANAGEMENT_TOOLS))
        tools = [_FakeTool(pinned_name), _FakeTool("hidden_tool")]
        transform = _make_transform_with_catalog(tools)
        fn = transform._get_search_tool().fn
        result = await fn(pattern=".*", ctx=MagicMock())
        assert pinned_name not in result
        assert "hidden_tool" in result

    @pytest.mark.asyncio
    async def test_max_results_cap_includes_hint(self):
        tools = [_FakeTool(f"tool_{i}") for i in range(20)]
        transform = _make_transform_with_catalog(tools, max_search_results=5)
        fn = transform._get_search_tool().fn
        result = await fn(pattern=".*", ctx=MagicMock())
        assert "capped at 5" in result

    @pytest.mark.asyncio
    async def test_invalid_regex_raises_ida_error(self):
        transform = _make_transform_with_catalog([])
        fn = transform._get_search_tool().fn
        with pytest.raises(IDAError, match="Invalid regex pattern"):
            await fn(pattern="[invalid(", ctx=MagicMock())

    @pytest.mark.asyncio
    async def test_brief_shows_first_line_only(self):
        """Brief mode should show only the first line of multi-line descriptions."""
        tools = [_FakeTool("my_tool", "short summary.\n\nDetailed paragraph follows.")]
        transform = _make_transform_with_catalog(tools)
        fn = transform._get_search_tool().fn
        result = await fn(pattern="my_tool", ctx=MagicMock())
        assert "short summary" in result
        assert "Detailed paragraph" not in result

    @pytest.mark.asyncio
    async def test_case_insensitive_matching(self):
        tools = [_FakeTool("MySpecialTool", "Does UPPERCASE things")]
        transform = _make_transform_with_catalog(tools)
        fn = transform._get_search_tool().fn
        result = await fn(pattern="myspecial", ctx=MagicMock())
        assert "MySpecialTool" in result

    @pytest.mark.asyncio
    async def test_no_match_returns_no_match_string(self):
        tools = [_FakeTool("alpha"), _FakeTool("beta")]
        transform = _make_transform_with_catalog(tools)
        fn = transform._get_search_tool().fn
        result = await fn(pattern="zzz_no_match", ctx=MagicMock())
        assert "No tools matched" in result

    @pytest.mark.asyncio
    async def test_detail_brief_is_default(self):
        tools = [_FakeTool("my_tool", "does something")]
        transform = _make_transform_with_catalog(tools)
        fn = transform._get_search_tool().fn
        result_default = await fn(pattern="my_tool", ctx=MagicMock())
        result_brief = await fn(pattern="my_tool", detail="brief", ctx=MagicMock())
        assert result_default == result_brief

    @pytest.mark.asyncio
    async def test_detail_detailed_includes_parameters(self):
        """detail='detailed' should include parameter names in the output."""

        async def my_tool(x: str) -> str:
            """does something"""
            return x

        real_tool = FastMCPTool.from_function(fn=my_tool, name="my_tool")
        transform = _make_transform_with_catalog([real_tool])
        fn = transform._get_search_tool().fn
        result = await fn(pattern="my_tool", detail="detailed", ctx=MagicMock())
        assert "my_tool" in result
        assert "x" in result  # parameter name must appear in detailed output

    @pytest.mark.asyncio
    async def test_detail_full_returns_json(self):
        """detail='full' should return valid JSON (uses real Tool)."""

        async def my_tool(x: str) -> str:
            """does something"""
            return x

        real_tool = FastMCPTool.from_function(fn=my_tool, name="my_tool")
        transform = _make_transform_with_catalog([real_tool])
        fn = transform._get_search_tool().fn
        result = await fn(pattern="my_tool", detail="full", ctx=MagicMock())
        parsed = json.loads(result)
        assert any(t.get("name") == "my_tool" for t in parsed)


# ---------------------------------------------------------------------------
# IDAToolTransform.get_schema — on-demand parameter schemas
# ---------------------------------------------------------------------------


class TestGetSchema:
    """Tests for the get_schema meta-tool on IDAToolTransform."""

    @pytest.mark.asyncio
    async def test_known_tool_returns_schema(self):
        """A known tool name returns its schema in the output."""

        async def my_tool(x: str) -> str:
            """does something useful"""
            return x

        real_tool = FastMCPTool.from_function(fn=my_tool, name="my_tool")
        transform = _make_transform_with_catalog([real_tool])
        fn = transform._get_schema_tool().fn
        result = await fn(tools=["my_tool"], ctx=MagicMock())
        assert isinstance(result, str)
        assert "my_tool" in result

    @pytest.mark.asyncio
    async def test_unknown_tool_reports_not_found(self):
        """An unknown tool name produces a 'Tools not found' message."""
        transform = _make_transform_with_catalog([])
        fn = transform._get_schema_tool().fn
        result = await fn(tools=["nonexistent_tool"], ctx=MagicMock())
        assert "Tools not found" in result
        assert "nonexistent_tool" in result

    @pytest.mark.asyncio
    async def test_mixed_known_and_unknown(self):
        """Known tools are returned and unknown tools are reported separately."""

        async def my_tool(x: str) -> str:
            """does something"""
            return x

        real_tool = FastMCPTool.from_function(fn=my_tool, name="my_tool")
        transform = _make_transform_with_catalog([real_tool])
        fn = transform._get_schema_tool().fn
        result = await fn(tools=["my_tool", "ghost_tool"], ctx=MagicMock())
        assert "my_tool" in result
        assert "Tools not found" in result
        assert "ghost_tool" in result

    @pytest.mark.asyncio
    async def test_empty_tools_list(self):
        """Empty tools list returns sentinel message."""
        transform = _make_transform_with_catalog([])
        fn = transform._get_schema_tool().fn
        result = await fn(tools=[], ctx=MagicMock())
        assert "no tool names provided" in result

    @pytest.mark.asyncio
    async def test_meta_tool_self_lookup(self):
        """get_schema can look up get_schema itself (meta-tool self-reference)."""
        transform = _make_transform_with_catalog([])
        fn = transform._get_schema_tool().fn
        result = await fn(tools=["get_schema"], ctx=MagicMock())
        assert "get_schema" in result
        assert "Tools not found" not in result

    @pytest.mark.asyncio
    async def test_meta_tool_search_tools_lookup(self):
        """get_schema can look up search_tools by name."""
        transform = _make_transform_with_catalog([])
        fn = transform._get_schema_tool().fn
        result = await fn(tools=["search_tools"], ctx=MagicMock())
        assert "search_tools" in result
        assert "Tools not found" not in result

    @pytest.mark.asyncio
    async def test_meta_tool_execute_lookup_when_enabled(self):
        """get_schema can look up execute when it is enabled."""
        transform = _make_transform_with_catalog([], enable_execute=True)
        fn = transform._get_schema_tool().fn
        result = await fn(tools=["execute"], ctx=MagicMock())
        assert "execute" in result
        assert "Tools not found" not in result

    @pytest.mark.asyncio
    async def test_meta_tool_execute_not_found_when_disabled(self):
        """get_schema reports execute as not found when execute is disabled."""
        transform = _make_transform_with_catalog([], enable_execute=False, enable_batch=False)
        fn = transform._get_schema_tool().fn
        result = await fn(tools=["execute"], ctx=MagicMock())
        assert "Tools not found" in result
        assert "execute" in result

    @pytest.mark.asyncio
    async def test_detail_brief_shows_signature(self):
        """detail='brief' returns a one-line Python-style signature plus summary."""

        async def my_tool(offset_param: str, limit_param: int) -> str:
            """one-line description.

            Detailed paragraph that should be omitted in brief mode.
            """
            return offset_param

        real_tool = FastMCPTool.from_function(fn=my_tool, name="my_tool")
        transform = _make_transform_with_catalog([real_tool])
        fn = transform._get_schema_tool().fn
        result = await fn(tools=["my_tool"], detail="brief", ctx=MagicMock())
        assert "my_tool(" in result
        assert "offset_param: str" in result
        assert "limit_param: int" in result
        assert "-> str" in result
        assert "one-line description" in result
        # Signature and summary on a single line, separated by em dash.
        for line in result.splitlines():
            if "my_tool(" in line:
                assert "—" in line
                assert "one-line description" in line
                break
        else:
            pytest.fail("signature line not found")
        # Multi-line descriptions collapse to the first line.
        assert "Detailed paragraph" not in result

    @pytest.mark.asyncio
    async def test_detail_default_is_detailed(self):
        """Default detail level for get_schema is 'detailed' (not 'brief')."""

        async def my_tool(x: str) -> str:
            """does something"""
            return x

        real_tool = FastMCPTool.from_function(fn=my_tool, name="my_tool")
        transform = _make_transform_with_catalog([real_tool])
        fn = transform._get_schema_tool().fn
        result_default = await fn(tools=["my_tool"], ctx=MagicMock())
        result_detailed = await fn(tools=["my_tool"], detail="detailed", ctx=MagicMock())
        assert result_default == result_detailed
        # 'detailed' mode includes parameter names
        assert "x" in result_default

    @pytest.mark.asyncio
    async def test_detail_full_returns_json(self):
        """detail='full' returns valid JSON."""

        async def my_tool(x: str) -> str:
            """does something"""
            return x

        real_tool = FastMCPTool.from_function(fn=my_tool, name="my_tool")
        transform = _make_transform_with_catalog([real_tool])
        fn = transform._get_schema_tool().fn
        result = await fn(tools=["my_tool"], detail="full", ctx=MagicMock())
        parsed = json.loads(result)
        assert any(t.get("name") == "my_tool" for t in parsed)

    @pytest.mark.asyncio
    async def test_get_tool_returns_get_schema(self):
        """get_tool('get_schema') returns the get_schema tool."""
        transform = _make_transform_with_catalog([])
        call_next = AsyncMock(return_value=None)
        tool = await transform.get_tool("get_schema", call_next)
        assert tool is not None
        assert tool.name == "get_schema"

    @pytest.mark.asyncio
    async def test_transform_tools_includes_get_schema(self):
        """get_schema appears in the visible tool listing from transform_tools."""
        transform = _make_transform_with_catalog([])
        out = await transform.transform_tools([])
        names = [t.name for t in out]
        assert "get_schema" in names


class TestSignatureRendering:
    """Tests for the signature-line helpers used by detail='brief'."""

    def test_type_label_primitive(self):
        assert _type_label({"type": "string"}) == "str"
        assert _type_label({"type": "integer"}) == "int"
        assert _type_label({"type": "boolean"}) == "bool"
        assert _type_label({"type": "number"}) == "float"

    def test_type_label_array_and_nested(self):
        assert _type_label({"type": "array", "items": {"type": "string"}}) == "list[str]"
        assert (
            _type_label({"type": "array", "items": {"type": "array", "items": {"type": "integer"}}})
            == "list[list[int]]"
        )

    def test_type_label_ref(self):
        assert _type_label({"$ref": "#/$defs/FunctionFilter"}) == "FunctionFilter"

    def test_type_label_nullable_anyof(self):
        schema = {"anyOf": [{"type": "string"}, {"type": "null"}]}
        assert _type_label(schema) == "str | None"

    def test_type_label_union_non_nullable(self):
        schema = {"anyOf": [{"type": "string"}, {"type": "integer"}]}
        assert _type_label(schema) == "str | int"

    def test_type_label_list_of_types(self):
        assert _type_label({"type": ["string", "null"]}) == "str | None"
        assert _type_label({"type": ["string", "integer"]}) == "str | int"
        assert _type_label({"type": ["string"]}) == "str"

    def test_type_label_missing_type(self):
        assert _type_label({}) == "any"
        assert _type_label(None) == "any"

    def test_render_type_annotation_basic(self):
        assert _render_type_annotation(str) == "str"
        assert _render_type_annotation(int) == "int"
        assert _render_type_annotation(None) == "None"

    def test_render_type_annotation_union_and_optional(self):
        assert _render_type_annotation(str | int) == "str | int"
        assert _render_type_annotation(str | None) == "str | None"

    def test_render_type_annotation_uses_bare_class_name(self):
        class Foo:
            pass

        # User-defined classes render as bare name, not module-qualified path.
        assert _render_type_annotation(Foo) == "Foo"
        assert _render_type_annotation(Foo | None) == "Foo | None"

    def test_render_type_annotation_generic(self):
        assert _render_type_annotation(list[str]) == "list[str]"
        assert _render_type_annotation(dict[str, int]) == "dict[str, int]"

    def test_format_default_string_escaping(self):
        # Strings round-trip via json.dumps — embedded quotes must be escaped.
        assert _format_default('he"llo') == '"he\\"llo"'
        assert _format_default("plain") == '"plain"'
        assert _format_default("") == '""'

    def test_format_default_short_string_passes_through(self):
        # Short strings fit without truncation so enum-like defaults stay
        # readable in the rendered signature.
        assert _format_default("Ordinary Function") == '"Ordinary Function"'

    def test_format_default_long_string_truncates_with_ellipsis(self):
        # Truncation preserves the leading characters so the default's shape
        # stays inspectable — the review caller should be able to tell
        # ``"/usr/local/..."`` apart from ``"https://..."``.
        rendered = _format_default("x" * 40)
        assert rendered.startswith('"')
        assert rendered.endswith('…"')
        # 32-char budget: 31 characters of payload + the ellipsis.
        assert len(rendered) == 32 + 2  # surrounding quotes

    def test_type_label_allof_single_ref_unwraps(self):
        # Pydantic v2 emits ``allOf: [{"$ref": ...}]`` when attaching extra
        # metadata (e.g. a description) to a referenced model.  The label
        # must still resolve to the model name instead of falling back to
        # ``object``.
        schema = {"allOf": [{"$ref": "#/$defs/FunctionFilter"}], "description": "A filter."}
        assert _type_label(schema) == "FunctionFilter"

    def test_type_label_allof_multiple_intersects_as_union(self):
        # Multi-element ``allOf`` has no clean Python rendering; joining the
        # branches keeps both types visible to the caller.
        schema = {"allOf": [{"type": "string"}, {"type": "null"}]}
        assert _type_label(schema) == "str | None"

    def test_format_return_type_peels_fastmcp_wrapper(self):
        # FastMCP wraps non-object returns (e.g. unions) in
        # ``{"result": ...}`` with the ``x-fastmcp-wrap-result`` marker.
        # ``_format_return_type`` must peel that wrapper when no Python
        # annotation is available, otherwise every wrapped tool reports
        # ``dict`` as its return type.
        tool = _FakeTool("t", "doc")
        tool.return_type = None
        tool.output_schema = {
            "type": "object",
            "x-fastmcp-wrap-result": True,
            "properties": {"result": {"type": "string"}},
        }
        assert _format_return_type(tool) == "str"

    def test_format_return_type_falls_back_to_schema_when_no_annotation(self):
        tool = _FakeTool("t", "doc")
        tool.return_type = None
        tool.output_schema = {"$ref": "#/$defs/DecompilationResult"}
        assert _format_return_type(tool) == "DecompilationResult"

    def test_format_return_type_none_when_nothing_available(self):
        tool = _FakeTool("t", "doc")
        tool.return_type = None
        tool.output_schema = None
        assert _format_return_type(tool) == "None"

    def test_format_default_primitives(self):
        assert _format_default(42) == "42"
        assert _format_default(True) == "True"
        assert _format_default(False) == "False"
        assert _format_default(None) == "None"
        assert _format_default([]) == "[]"
        assert _format_default({}) == "{}"

    def test_signature_line_required_and_optional(self):
        async def a_tool(x: str, y: int = 3) -> str:
            """doc"""
            return x

        real_tool = FastMCPTool.from_function(fn=a_tool, name="a_tool")
        sig = _signature_line(real_tool)
        assert sig.startswith("a_tool(")
        assert "x: str" in sig
        assert "y: int = 3" in sig
        assert sig.endswith("-> str")

    def test_signature_line_distinguishes_missing_default_from_none(self):
        """Optional param with no declared default renders as ``= ...``,
        while an explicit ``default=None`` renders as ``= None``.

        Prevents the signature from advertising a concrete default the tool
        does not actually have.
        """
        tool_with_none_default = _FakeTool("t1", "doc")
        tool_with_none_default.parameters = {
            "type": "object",
            "properties": {"x": {"type": "string", "default": None}},
            "required": [],
        }
        assert "x: str = None" in _signature_line(tool_with_none_default)

        tool_without_default = _FakeTool("t2", "doc")
        tool_without_default.parameters = {
            "type": "object",
            "properties": {"x": {"type": "string"}},
            "required": [],
        }
        assert "x: str = ..." in _signature_line(tool_without_default)

    def test_format_return_type_from_annotation(self):
        async def a_tool(x: str) -> list[int]:
            """doc"""
            return [1]

        real_tool = FastMCPTool.from_function(fn=a_tool, name="a_tool")
        # Either the typing-introspected form or the schema fallback is acceptable.
        rendered = _format_return_type(real_tool)
        assert "int" in rendered


# ---------------------------------------------------------------------------
# IDAToolTransform.execute — single-call hint injection
# ---------------------------------------------------------------------------


class TestExecuteHint:
    """execute injects a hint when code makes exactly one invoke with no processing."""

    def _make_ctx(self, structured_content=None) -> MagicMock:
        tool_result = MagicMock()
        tool_result.structured_content = structured_content
        tool_result.content = []
        ctx = MagicMock()
        ctx.fastmcp = MagicMock()
        ctx.fastmcp.call_tool = AsyncMock(return_value=tool_result)
        return ctx

    @pytest.mark.asyncio
    async def test_hint_injected_into_dict_result(self):
        """Single call with dict result gets _hint key appended."""
        ctx = self._make_ctx(structured_content={"items": [1, 2], "total": 2})
        transform = IDAToolTransform()
        fn = transform._get_execute_tool().fn
        result = await fn(
            code="r = await invoke('list_functions', {})\nreturn r",
            database="db",
            ctx=ctx,
        )
        assert isinstance(result, dict)
        assert "_hint" in result

    @pytest.mark.asyncio
    async def test_hint_injected_into_str_result(self):
        """Single call with string result gets hint appended after newlines."""
        ctx = self._make_ctx(structured_content=None)
        ctx.fastmcp.call_tool.return_value.content = [MagicMock(text="some output", spec=["text"])]
        transform = IDAToolTransform()
        fn = transform._get_execute_tool().fn
        result = await fn(
            code="r = await invoke('list_functions', {})\nreturn r",
            database="db",
            ctx=ctx,
        )
        assert isinstance(result, str)
        assert "Hint:" in result

    @pytest.mark.asyncio
    async def test_no_hint_when_processing_logic_present(self):
        """Single call with processing logic (e.g. for loop) does not get hint."""
        ctx = self._make_ctx(structured_content={"items": []})
        transform = IDAToolTransform()
        fn = transform._get_execute_tool().fn
        result = await fn(
            code=(
                "r = await invoke('list_functions', {})\nfor x in r['items']:\n    pass\nreturn r"
            ),
            database="db",
            ctx=ctx,
        )
        assert isinstance(result, dict)
        assert "_hint" not in result

    @pytest.mark.asyncio
    async def test_no_hint_when_multiple_calls(self):
        """Multiple calls suppress the hint even with no processing logic."""
        ctx = self._make_ctx(structured_content={"items": []})
        transform = IDAToolTransform()
        fn = transform._get_execute_tool().fn
        result = await fn(
            code=(
                "a = await invoke('list_functions', {})\n"
                "b = await invoke('get_strings', {})\n"
                "return b"
            ),
            database="db",
            ctx=ctx,
        )
        assert isinstance(result, dict)
        assert "_hint" not in result


# ---------------------------------------------------------------------------
# IDAToolTransform.execute — blocked-tool enforcement
# ---------------------------------------------------------------------------


class TestExecuteBlockedTools:
    """execute must refuse lifecycle/meta tools; save_database and list_databases are allowed."""

    def _make_ctx(self) -> MagicMock:
        ctx = MagicMock()
        ctx.fastmcp = MagicMock()
        ctx.fastmcp.call_tool = AsyncMock()
        return ctx

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "tool_name",
        sorted(MANAGEMENT_TOOLS - {"save_database", "list_databases"}),
    )
    async def test_blocks_lifecycle_management_tools(self, tool_name: str):
        """Lifecycle tools (open/close/wait/list_targets) are blocked."""
        transform = IDAToolTransform()
        fn = transform._get_execute_tool().fn
        ctx = self._make_ctx()

        with pytest.raises(IDAError, match="cannot be called via execute"):
            await fn(
                code=f"return await invoke('{tool_name}', {{}})",
                database="db",
                ctx=ctx,
            )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool_name", ["save_database", "list_databases"])
    async def test_allows_save_and_list_databases(self, tool_name: str):
        """save_database and list_databases are useful inside execute blocks."""
        transform = IDAToolTransform()
        fn = transform._get_execute_tool().fn
        ctx = self._make_ctx()
        ctx.fastmcp.call_tool.return_value = MagicMock(
            content=[MagicMock(type="text", text='{"ok": true}')],
            isError=False,
        )

        # Should not raise
        await fn(
            code=f"return await invoke('{tool_name}', {{}})",
            database="db",
            ctx=ctx,
        )

    @pytest.mark.asyncio
    async def test_blocks_search_tools_meta(self):
        """search_tools is also blocked inside execute."""
        transform = IDAToolTransform()
        fn = transform._get_execute_tool().fn
        ctx = self._make_ctx()

        with pytest.raises(IDAError, match="cannot be called via execute"):
            await fn(
                code="return await invoke('search_tools', {'pattern': '.*'})",
                database="db",
                ctx=ctx,
            )

    @pytest.mark.asyncio
    async def test_blocks_execute_meta(self):
        """execute itself is blocked inside execute (no recursion)."""
        transform = IDAToolTransform()
        fn = transform._get_execute_tool().fn
        ctx = self._make_ctx()

        with pytest.raises(IDAError, match="cannot be called via execute"):
            await fn(
                code="return await invoke('execute', {'code': 'return 1'})",
                database="db",
                ctx=ctx,
            )

    @pytest.mark.asyncio
    async def test_user_code_error_surfaces_as_ida_error(self):
        """Python errors in user code are wrapped in IDAError."""
        transform = IDAToolTransform()
        fn = transform._get_execute_tool().fn
        ctx = self._make_ctx()

        with pytest.raises(IDAError):
            await fn(code="return undefined_variable", database="db", ctx=ctx)

    @pytest.mark.asyncio
    async def test_execute_without_ctx_raises_ida_error(self):
        """execute with ctx=None raises IDAError instead of AttributeError."""
        transform = IDAToolTransform()
        fn = transform._get_execute_tool().fn

        with pytest.raises(IDAError, match="execute requires an MCP context"):
            await fn(code="return 1", database="db", ctx=None)

    @pytest.mark.asyncio
    async def test_syntax_error_wrapped_as_ida_error(self):
        """Invalid Python syntax is reported as IDAError with error_type=SyntaxError."""
        transform = IDAToolTransform()
        fn = transform._get_execute_tool().fn
        ctx = self._make_ctx()

        with pytest.raises(IDAError) as exc:
            await fn(code="return (unterminated", database="db", ctx=ctx)
        assert exc.value.error_type == "SyntaxError"


# ---------------------------------------------------------------------------
# IDAToolTransform.batch — runtime behavior
# ---------------------------------------------------------------------------


class TestBatchMetaTool:
    """batch meta-tool runtime behavior tests."""

    def _make_ctx(self, results=None) -> MagicMock:
        """Build a mock MCP context.

        *results* is a list of return values (or exceptions) for successive
        ``ctx.fastmcp.call_tool`` invocations.
        """
        ctx = MagicMock()
        ctx.fastmcp = MagicMock()
        ctx.report_progress = AsyncMock()
        if results is None:
            tool_result = MagicMock()
            tool_result.structured_content = {"ok": True}
            tool_result.content = []
            ctx.fastmcp.call_tool = AsyncMock(return_value=tool_result)
        else:
            side_effects = []
            for r in results:
                if isinstance(r, Exception):
                    side_effects.append(r)
                else:
                    m = MagicMock()
                    m.structured_content = r
                    m.content = []
                    side_effects.append(m)
            ctx.fastmcp.call_tool = AsyncMock(side_effect=side_effects)
        return ctx

    def _op(self, tool: str, **params) -> BatchOperation:
        return BatchOperation(tool=tool, params=params)

    @pytest.mark.asyncio
    async def test_successful_operations(self):
        """All operations succeed — succeeded count matches, no errors."""
        ctx = self._make_ctx(results=[{"a": 1}, {"b": 2}])
        transform = IDAToolTransform()
        fn = transform._get_batch_tool().fn
        result = await fn(
            operations=[
                self._op("get_comment", address="0x1"),
                self._op("get_comment", address="0x2"),
            ],
            database="db",
            ctx=ctx,
        )
        assert result.succeeded == 2
        assert result.failed == 0
        assert not result.cancelled
        assert len(result.results) == 2
        assert result.results[0].result == {"a": 1}
        assert result.results[1].result == {"b": 2}

    @pytest.mark.asyncio
    async def test_error_collection(self):
        """Partial failures raise BatchFailed with per-item results in payload."""
        ctx = self._make_ctx(
            results=[
                IDAError("bad address"),
                {"ok": True},
            ]
        )
        transform = IDAToolTransform()
        fn = transform._get_batch_tool().fn
        with pytest.raises(IDAError, match="BatchFailed") as exc_info:
            await fn(
                operations=[
                    self._op("get_comment", address="bad"),
                    self._op("get_comment", address="0x1"),
                ],
                database="db",
                stop_on_error=False,
                ctx=ctx,
            )
        # The error payload contains the full BatchResult as JSON inside the "error" key.
        envelope = json.loads(str(exc_info.value))
        payload = json.loads(envelope["error"])
        assert payload["succeeded"] == 1
        assert payload["failed"] == 1

    @pytest.mark.asyncio
    async def test_stop_on_error(self):
        """stop_on_error=True stops after first failure and raises BatchFailed."""
        ctx = self._make_ctx(
            results=[
                IDAError("fail"),
                {"ok": True},
            ]
        )
        transform = IDAToolTransform()
        fn = transform._get_batch_tool().fn
        with pytest.raises(IDAError, match="BatchFailed"):
            await fn(
                operations=[
                    self._op("get_comment", address="bad"),
                    self._op("get_comment", address="0x1"),
                ],
                database="db",
                stop_on_error=True,
                ctx=ctx,
            )

    @pytest.mark.asyncio
    async def test_database_auto_injection(self):
        """database is auto-injected into operation params."""
        ctx = self._make_ctx(results=[{"ok": True}])
        transform = IDAToolTransform()
        fn = transform._get_batch_tool().fn
        await fn(
            operations=[self._op("get_comment", address="0x1")],
            database="mydb",
            ctx=ctx,
        )
        call_args = ctx.fastmcp.call_tool.call_args
        assert call_args[0][1]["database"] == "mydb"

    @pytest.mark.asyncio
    async def test_database_explicit_override(self):
        """Explicit database in params is preserved (not overwritten)."""
        ctx = self._make_ctx(results=[{"ok": True}])
        transform = IDAToolTransform()
        fn = transform._get_batch_tool().fn
        await fn(
            operations=[
                BatchOperation(tool="get_comment", params={"address": "0x1", "database": "other"})
            ],
            database="mydb",
            ctx=ctx,
        )
        call_args = ctx.fastmcp.call_tool.call_args
        assert call_args[0][1]["database"] == "other"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "tool_name", sorted(MANAGEMENT_TOOLS - {"save_database", "list_databases"})
    )
    async def test_blocks_lifecycle_management_tools(self, tool_name: str):
        """Lifecycle tools (open/close/wait/list_targets) are blocked inside batch."""
        ctx = self._make_ctx()
        transform = IDAToolTransform()
        fn = transform._get_batch_tool().fn
        with pytest.raises(IDAError, match="BatchFailed"):
            await fn(
                operations=[self._op(tool_name)],
                database="db",
                ctx=ctx,
            )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool_name", ["save_database", "list_databases"])
    async def test_allows_save_and_list_databases(self, tool_name: str):
        """save_database and list_databases are useful inside batch."""
        ctx = self._make_ctx()
        ctx.fastmcp.call_tool.return_value = MagicMock(
            content=[MagicMock(type="text", text='{"ok": true}')],
            isError=False,
        )
        transform = IDAToolTransform()
        fn = transform._get_batch_tool().fn
        result = await fn(
            operations=[self._op(tool_name)],
            database="db",
            ctx=ctx,
        )
        assert result.failed == 0
        assert result.succeeded == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool_name", sorted(META_TOOLS))
    async def test_blocks_meta_tools(self, tool_name: str):
        """Meta-tools (search_tools, execute, batch, call) are blocked inside batch."""
        ctx = self._make_ctx()
        transform = IDAToolTransform()
        fn = transform._get_batch_tool().fn
        with pytest.raises(IDAError, match="BatchFailed"):
            await fn(
                operations=[self._op(tool_name)],
                database="db",
                ctx=ctx,
            )

    @pytest.mark.asyncio
    async def test_progress_reporting(self):
        """report_progress is called for each operation."""
        ctx = self._make_ctx(results=[{"a": 1}, {"b": 2}, {"c": 3}])
        transform = IDAToolTransform()
        fn = transform._get_batch_tool().fn
        await fn(
            operations=[self._op("t1"), self._op("t2"), self._op("t3")],
            database="db",
            ctx=ctx,
        )
        calls = ctx.report_progress.call_args_list
        assert len(calls) == 3
        assert calls[0][0] == (1, 3)
        assert calls[1][0] == (2, 3)
        assert calls[2][0] == (3, 3)

    @pytest.mark.asyncio
    async def test_empty_operations(self):
        """Empty operations list returns zero counts."""
        ctx = self._make_ctx()
        transform = IDAToolTransform()
        fn = transform._get_batch_tool().fn
        result = await fn(operations=[], database="db", ctx=ctx)
        assert result.succeeded == 0
        assert result.failed == 0
        assert len(result.results) == 0
        assert not result.cancelled

    @pytest.mark.asyncio
    async def test_without_ctx_raises_ida_error(self):
        """batch with ctx=None raises IDAError."""
        transform = IDAToolTransform()
        fn = transform._get_batch_tool().fn
        with pytest.raises(IDAError, match="batch requires an MCP context"):
            await fn(operations=[], database="db", ctx=None)

    @pytest.mark.asyncio
    async def test_client_cancellation_returns_partial_results(self):
        """asyncio.CancelledError mid-batch yields cancelled=True with results so far.

        CancelledError is a ``BaseException`` (not ``Exception``) on Py 3.8+
        so it bypasses the inner per-item handler and is caught by the outer
        ``except asyncio.CancelledError`` in ``batch``.  Bypass the helper
        (which only supports ``Exception`` side-effects) and build the mock
        directly.
        """
        ctx = MagicMock()
        ctx.fastmcp = MagicMock()
        ctx.report_progress = AsyncMock()
        first = MagicMock()
        first.structured_content = {"first": True}
        first.content = []
        ctx.fastmcp.call_tool = AsyncMock(side_effect=[first, asyncio.CancelledError()])

        transform = IDAToolTransform()
        fn = transform._get_batch_tool().fn
        result = await fn(
            operations=[self._op("tool_a"), self._op("tool_b"), self._op("tool_c")],
            database="db",
            ctx=ctx,
        )
        assert result.cancelled is True
        assert result.succeeded == 1
        # Third operation never ran.
        assert len(result.results) == 1
        assert result.results[0].tool == "tool_a"

    @pytest.mark.asyncio
    async def test_result_indices_match_input_order(self):
        """Result indices correspond to input operation positions."""
        ctx = self._make_ctx(results=[{"first": True}, {"second": True}])
        transform = IDAToolTransform()
        fn = transform._get_batch_tool().fn
        result = await fn(
            operations=[self._op("tool_a"), self._op("tool_b")],
            database="db",
            ctx=ctx,
        )
        assert result.results[0].index == 0
        assert result.results[0].tool == "tool_a"
        assert result.results[1].index == 1
        assert result.results[1].tool == "tool_b"


# ---------------------------------------------------------------------------
# IDAToolTransform — runtime disable flags for execute/batch
# ---------------------------------------------------------------------------


class TestMetaToolDisableFlags:
    """execute and batch can be disabled at runtime via constructor or env."""

    @pytest.mark.asyncio
    async def test_transform_tools_omits_disabled_execute(self):
        transform = IDAToolTransform(enable_execute=False)
        out = await transform.transform_tools([])
        names = [t.name for t in out]
        assert "execute" not in names
        assert "batch" in names
        assert "search_tools" in names

    @pytest.mark.asyncio
    async def test_transform_tools_omits_disabled_batch(self):
        transform = IDAToolTransform(enable_batch=False)
        out = await transform.transform_tools([])
        names = [t.name for t in out]
        assert "batch" not in names
        assert "execute" in names

    @pytest.mark.asyncio
    async def test_get_tool_returns_none_when_disabled(self):
        transform = IDAToolTransform(enable_execute=False, enable_batch=False)
        call_next = AsyncMock(return_value=None)
        assert await transform.get_tool("execute", call_next) is None
        assert await transform.get_tool("batch", call_next) is None
        # search_tools and get_schema are available when tool_search is enabled (default).
        assert await transform.get_tool("search_tools", call_next) is not None
        assert await transform.get_tool("get_schema", call_next) is not None

    @pytest.mark.asyncio
    async def test_env_var_disables_execute(self, monkeypatch):
        monkeypatch.setenv("IDA_MCP_DISABLE_EXECUTE", "true")
        monkeypatch.delenv("IDA_MCP_DISABLE_BATCH", raising=False)
        transform = IDAToolTransform()
        names = [t.name for t in await transform.transform_tools([])]
        assert "execute" not in names
        assert "batch" in names

    @pytest.mark.asyncio
    async def test_env_var_disables_batch(self, monkeypatch):
        monkeypatch.setenv("IDA_MCP_DISABLE_BATCH", "1")
        monkeypatch.delenv("IDA_MCP_DISABLE_EXECUTE", raising=False)
        transform = IDAToolTransform()
        names = [t.name for t in await transform.transform_tools([])]
        assert "batch" not in names
        assert "execute" in names

    @pytest.mark.asyncio
    async def test_constructor_arg_overrides_env(self, monkeypatch):
        monkeypatch.setenv("IDA_MCP_DISABLE_EXECUTE", "true")
        transform = IDAToolTransform(enable_execute=True)
        names = [t.name for t in await transform.transform_tools([])]
        assert "execute" in names

    @pytest.mark.asyncio
    async def test_unknown_env_value_defaults_to_enabled(self, monkeypatch):
        monkeypatch.setenv("IDA_MCP_DISABLE_EXECUTE", "maybe")
        transform = IDAToolTransform()
        names = [t.name for t in await transform.transform_tools([])]
        assert "execute" in names

    @pytest.mark.asyncio
    async def test_execute_description_omits_batch_when_disabled(self):
        """When batch is disabled, execute's description must not advertise it."""
        transform = IDAToolTransform(enable_batch=False)
        out = await transform.transform_tools([])
        execute_tool = next(t for t in out if t.name == "execute")
        desc = execute_tool.description or ""
        assert "batch** meta-tool" not in desc
        assert "search_tools, get_schema, execute, batch" not in desc
        assert "search_tools, get_schema, execute" in desc

    @pytest.mark.asyncio
    async def test_execute_description_mentions_batch_when_enabled(self):
        transform = IDAToolTransform(enable_batch=True)
        out = await transform.transform_tools([])
        execute_tool = next(t for t in out if t.name == "execute")
        desc = execute_tool.description or ""
        assert "batch** meta-tool" in desc
        assert "search_tools, get_schema, execute, batch" in desc

    @pytest.mark.asyncio
    async def test_disable_tool_search_exposes_all_tools(self):
        async def hidden_tool(x: int) -> int:
            return x

        fake = FastMCPTool.from_function(fn=hidden_tool, name="hidden_tool")
        transform = IDAToolTransform(enable_tool_search=False)
        out = await transform.transform_tools([fake])
        names = [t.name for t in out]
        assert "hidden_tool" in names
        assert "search_tools" not in names
        assert "get_schema" not in names
        assert "call" in names
        assert "execute" in names

    @pytest.mark.asyncio
    async def test_disable_tool_search_get_tool_returns_none(self):
        transform = IDAToolTransform(enable_tool_search=False)
        call_next = AsyncMock(return_value=None)
        assert await transform.get_tool("search_tools", call_next) is None
        assert await transform.get_tool("get_schema", call_next) is None
        assert await transform.get_tool("call", call_next) is not None

    @pytest.mark.asyncio
    async def test_env_var_disables_tool_search(self, monkeypatch):
        monkeypatch.setenv("IDA_MCP_DISABLE_TOOL_SEARCH", "yes")
        transform = IDAToolTransform()
        names = [t.name for t in await transform.transform_tools([])]
        assert "search_tools" not in names
        assert "get_schema" not in names

    @pytest.mark.asyncio
    async def test_constructor_arg_overrides_tool_search_env(self, monkeypatch):
        monkeypatch.setenv("IDA_MCP_DISABLE_TOOL_SEARCH", "true")
        transform = IDAToolTransform(enable_tool_search=True)
        names = [t.name for t in await transform.transform_tools([])]
        assert "search_tools" in names
        assert "get_schema" in names

    @pytest.mark.asyncio
    async def test_execute_description_omits_tool_search_when_disabled(self):
        """When tool_search is disabled, execute description omits search_tools/get_schema."""
        transform = IDAToolTransform(enable_tool_search=False)
        out = await transform.transform_tools([])
        execute_tool = next(t for t in out if t.name == "execute")
        desc = execute_tool.description or ""
        assert "search_tools" not in desc
        assert "get_schema" not in desc
        assert "execute, batch, call" in desc

    @pytest.mark.asyncio
    async def test_execute_description_all_disabled_except_execute(self):
        """When both batch and tool_search are disabled, only execute and call remain."""
        transform = IDAToolTransform(enable_tool_search=False, enable_batch=False)
        out = await transform.transform_tools([])
        execute_tool = next(t for t in out if t.name == "execute")
        desc = execute_tool.description or ""
        assert "search_tools" not in desc
        assert "get_schema" not in desc
        assert "batch** meta-tool" not in desc
        assert "use `batch`" not in desc
        assert "execute, call" in desc


class TestBuildInstructions:
    """ProxyMCP._build_instructions reflects transform feature flags."""

    def test_default_includes_all_sections(self):
        transform = IDAToolTransform()
        text = ProxyMCP._build_instructions(transform)
        assert "## Tool discovery" in text
        assert "## Call patterns" in text
        assert "**batch**" in text
        assert "**execute**" in text

    def test_batch_disabled_omits_batch_from_call_patterns(self):
        transform = IDAToolTransform(enable_batch=False)
        text = ProxyMCP._build_instructions(transform)
        assert "**batch**" not in text
        assert "**execute**" in text

    def test_execute_disabled_omits_execute_from_call_patterns(self):
        transform = IDAToolTransform(enable_execute=False)
        text = ProxyMCP._build_instructions(transform)
        assert "execute" not in text
        assert "**batch**" in text

    def test_tool_search_disabled_omits_discovery_section(self):
        transform = IDAToolTransform(enable_tool_search=False)
        text = ProxyMCP._build_instructions(transform)
        assert "## Tool discovery" not in text
        assert "pinned" not in text
        assert "hidden" not in text
        assert "ONE tool → call the tool directly." in text

    def test_tool_search_enabled_includes_discovery(self):
        transform = IDAToolTransform(enable_tool_search=True)
        text = ProxyMCP._build_instructions(transform)
        assert "## Tool discovery" in text
        assert "search_tools" in text
        assert "get_schema" in text
        assert "ONE pinned tool" in text

    def test_all_disabled_minimal_call_patterns(self):
        transform = IDAToolTransform(
            enable_batch=False,
            enable_execute=False,
            enable_tool_search=False,
        )
        text = ProxyMCP._build_instructions(transform)
        assert "## Tool discovery" not in text
        assert "batch" not in text
        assert "execute" not in text
        assert "ONE tool → call the tool directly." in text

    def test_tool_discovery_callable_via_reflects_flags(self):
        transform = IDAToolTransform(enable_batch=False)
        text = ProxyMCP._build_instructions(transform)
        assert "## Tool discovery" in text
        assert "**call**" in text
        assert "**batch**" not in text
        assert "**execute**" in text


# ---------------------------------------------------------------------------
# _format_validation_error — descriptive error for bad tool arguments
# ---------------------------------------------------------------------------


class TestFormatValidationError:
    """_format_validation_error produces helpful messages for agents."""

    @pytest.mark.asyncio
    async def test_pydantic_validation_error_includes_field_details(self):
        """Pydantic field-level errors are listed individually."""

        class Params(PydanticBaseModel):
            address: str
            count: int

        try:
            Params.model_validate({"count": "not_an_int"})
        except PydanticValidationError as exc:
            msg = await _format_validation_error(exc, "rename_function", ctx=None)

        assert "Invalid arguments for tool 'rename_function'" in msg
        assert "address" in msg
        assert "get_schema" in msg
        assert "rename_function" in msg

    @pytest.mark.asyncio
    async def test_fastmcp_validation_error(self):
        """FastMCP ValidationError (non-Pydantic) is also handled."""
        exc = FastMCPValidationError("missing required field 'address'")
        msg = await _format_validation_error(exc, "some_tool", ctx=None)

        assert "Invalid arguments for tool 'some_tool'" in msg
        assert "missing required field" in msg
        assert "get_schema" in msg

    @pytest.mark.asyncio
    async def test_includes_signature_when_ctx_available(self):
        """When a context is available, the tool's signature is included."""

        async def my_tool(x: str, y: int = 3) -> str:
            """doc"""
            return x

        tool = FastMCPTool.from_function(fn=my_tool, name="my_tool")

        ctx = MagicMock()
        ctx.fastmcp = AsyncMock()
        ctx.fastmcp.get_tool = AsyncMock(return_value=tool)

        class P(PydanticBaseModel):
            x: str

        try:
            P.model_validate({"x": 123})
        except PydanticValidationError as exc:
            msg = await _format_validation_error(exc, "my_tool", ctx=ctx)

        assert "Expected: my_tool(" in msg
        assert "x: str" in msg
