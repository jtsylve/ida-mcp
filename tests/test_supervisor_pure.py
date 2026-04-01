# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Unit tests for supervisor / worker_provider pure utility functions.

These tests cover prefix_uri, extract_db_prefix, and capability-based
tool/resource filtering — all functions that can run without idalib loaded.
"""

from __future__ import annotations

import asyncio

import mcp.types as types
import pytest
from fastmcp.resources.template import ResourceTemplate as FastMCPResourceTemplate
from fastmcp.tools import Tool as FastMCPTool

from ida_mcp.exceptions import IDAError
from ida_mcp.worker_provider import (
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
    pool._cached_capabilities = None
    return worker


# Ensures _setup_pool always has at least one tool so capability filtering
# tests don't need to worry about empty-pool edge cases.
_SENTINEL_TOOL = _make_mcp_tool("_sentinel")


def _setup_pool(
    tools: list[types.Tool],
    resource_templates: list[FastMCPResourceTemplate] | None = None,
) -> WorkerPoolProvider:
    """Create a WorkerPoolProvider with pre-populated schemas (skipping bootstrap)."""
    pool = WorkerPoolProvider()
    all_tools = [_SENTINEL_TOOL, *tools]
    pool._base_tool_schemas = all_tools
    pool._bootstrapped = True

    # Build RoutingTool instances
    for t in all_tools:
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


class TestCapabilityFilteringTools:
    """Test that _list_tools filters by aggregate worker capabilities."""

    def _list_tools(self, pool: WorkerPoolProvider) -> list[FastMCPTool]:
        return asyncio.run(pool._list_tools())

    def test_decompiler_tools_hidden_when_no_capable_worker(self):
        pool = _setup_pool(
            [
                _make_mcp_tool("get_segments"),
                _make_mcp_tool("decompile_function", tags={"decompiler"}),
            ]
        )
        _add_worker(pool, "sparc", {"decompiler": False, "assembler": False})

        tools = self._list_tools(pool)
        tool_names = {t.name for t in tools}
        assert "get_segments" in tool_names
        assert "decompile_function" not in tool_names

    def test_decompiler_tools_visible_when_capable_worker_exists(self):
        pool = _setup_pool(
            [
                _make_mcp_tool("get_segments"),
                _make_mcp_tool("decompile_function", tags={"decompiler"}),
            ]
        )
        _add_worker(pool, "sparc", {"decompiler": False, "assembler": False})
        _add_worker(pool, "x86", {"decompiler": True, "assembler": True})

        tools = self._list_tools(pool)
        tool_names = {t.name for t in tools}
        assert "decompile_function" in tool_names

    def test_assembler_tools_hidden_when_no_capable_worker(self):
        pool = _setup_pool(
            [
                _make_mcp_tool("assemble_instruction", tags={"assembler"}),
            ]
        )
        _add_worker(pool, "arm", {"decompiler": True, "assembler": False})

        tools = self._list_tools(pool)
        tool_names = {t.name for t in tools}
        assert "assemble_instruction" not in tool_names

    def test_untagged_tools_always_visible(self):
        pool = _setup_pool([_make_mcp_tool("get_segments")])
        _add_worker(pool, "sparc", {"decompiler": False, "assembler": False})

        tools = self._list_tools(pool)
        worker_names = {t.name for t in tools}
        assert "get_segments" in worker_names

    def test_show_all_tools_disables_filtering(self):
        pool = _setup_pool(
            [
                _make_mcp_tool("decompile_function", tags={"decompiler"}),
            ]
        )
        _add_worker(pool, "sparc", {"decompiler": False})
        pool.filter_by_capability = False

        tools = self._list_tools(pool)
        tool_names = {t.name for t in tools}
        assert "decompile_function" in tool_names

    def test_show_all_tools_reenables_filtering(self):
        pool = _setup_pool(
            [
                _make_mcp_tool("decompile_function", tags={"decompiler"}),
            ]
        )
        _add_worker(pool, "sparc", {"decompiler": False})
        pool.filter_by_capability = False

        # Re-enable filtering
        pool.filter_by_capability = True
        tools = self._list_tools(pool)
        tool_names = {t.name for t in tools}
        assert "decompile_function" not in tool_names

    def test_no_workers_hides_all_capability_tools(self):
        pool = _setup_pool(
            [
                _make_mcp_tool("get_segments"),
                _make_mcp_tool("decompile_function", tags={"decompiler"}),
            ]
        )

        tools = self._list_tools(pool)
        worker_names = {t.name for t in tools}
        assert "get_segments" in worker_names
        assert "decompile_function" not in worker_names


# ---------------------------------------------------------------------------
# Capability filtering — resource templates
# ---------------------------------------------------------------------------


class TestCapabilityFilteringResources:
    """Test that _list_resource_templates filters by aggregate capabilities."""

    def _list_templates(self, pool: WorkerPoolProvider) -> list[FastMCPResourceTemplate]:
        return asyncio.run(pool._list_resource_templates())

    def test_decompiler_resource_hidden_when_no_capable_worker(self):
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

        templates = self._list_templates(pool)
        names = {t.name for t in templates}
        assert "function_detail" in names
        assert "function_vars" not in names

    def test_decompiler_resource_visible_when_capable_worker_exists(self):
        pool = _setup_pool(
            tools=[],
            resource_templates=[
                _make_resource_template(
                    "ida://{database}/functions/{addr}/vars",
                    "function_vars",
                    tags={"decompiler"},
                ),
            ],
        )
        _add_worker(pool, "x86", {"decompiler": True, "assembler": True})

        templates = self._list_templates(pool)
        names = {t.name for t in templates}
        assert "function_vars" in names

    def test_show_all_disables_resource_filtering(self):
        pool = _setup_pool(
            tools=[],
            resource_templates=[
                _make_resource_template(
                    "ida://{database}/functions/{addr}/vars",
                    "function_vars",
                    tags={"decompiler"},
                ),
            ],
        )
        _add_worker(pool, "sparc", {"decompiler": False})
        pool.filter_by_capability = False

        templates = self._list_templates(pool)
        names = {t.name for t in templates}
        assert "function_vars" in names


# ---------------------------------------------------------------------------
# Capability cache invalidation
# ---------------------------------------------------------------------------


class TestCapabilityCacheInvalidation:
    """Test that the aggregate capabilities cache is invalidated correctly."""

    def test_cache_populated_on_first_access(self):
        pool = _setup_pool([])
        _add_worker(pool, "x86", {"decompiler": True})
        assert pool._cached_capabilities is None

        caps = pool._aggregate_capabilities()
        assert caps == {"decompiler"}
        assert pool._cached_capabilities is not None

    def test_cache_reused_on_second_access(self):
        pool = _setup_pool([])
        _add_worker(pool, "x86", {"decompiler": True})

        caps1 = pool._aggregate_capabilities()
        caps2 = pool._aggregate_capabilities()
        assert caps1 is caps2  # same object

    def test_cache_invalidated_on_mark_worker_dead(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "x86", {"decompiler": True})
        pool._aggregate_capabilities()
        assert pool._cached_capabilities is not None

        asyncio.run(pool.mark_worker_dead(worker))
        assert pool._cached_capabilities is None

    def test_cache_invalidated_on_terminate_worker(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "x86", {"decompiler": True})
        pool._aggregate_capabilities()
        assert pool._cached_capabilities is not None

        asyncio.run(pool.terminate_worker(worker.file_path, save=False))
        assert pool._cached_capabilities is None


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


# ---------------------------------------------------------------------------
# close_for_session
# ---------------------------------------------------------------------------


class TestCloseForSession:
    """Test WorkerPoolProvider.close_for_session."""

    def test_terminate_when_last_session(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("s1")

        result = asyncio.run(pool.close_for_session(worker, "s1"))
        assert result["status"] == "closed"
        assert "db1" not in pool._id_to_path

    def test_detach_when_other_sessions_remain(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("s1")
        worker.attach("s2")

        result = asyncio.run(pool.close_for_session(worker, "s1"))
        assert result["status"] == "detached"
        assert result["remaining_sessions"] == 1
        assert not worker.is_attached("s1")
        assert worker.is_attached("s2")
        # Worker still in pool
        assert "db1" in pool._id_to_path

    def test_terminate_when_force(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("s1")
        worker.attach("s2")

        result = asyncio.run(pool.close_for_session(worker, "s1", force=True))
        assert result["status"] == "closed"
        assert "db1" not in pool._id_to_path

    def test_terminate_when_session_none(self):
        """None session falls back to legacy terminate behavior."""
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("s1")

        result = asyncio.run(pool.close_for_session(worker, None))
        assert result["status"] == "closed"

    def test_unattached_session_raises(self):
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("s1")

        with pytest.raises(IDAError, match="NotAttached"):
            asyncio.run(pool.close_for_session(worker, "s2"))

    def test_unattached_session_with_force_terminates(self):
        """force=True always terminates, even if the caller isn't attached."""
        pool = _setup_pool([])
        worker = _add_worker(pool, "db1", {})
        worker.attach("s1")

        result = asyncio.run(pool.close_for_session(worker, "s2", force=True))
        assert result["status"] == "closed"
        assert "db1" not in pool._id_to_path


# ---------------------------------------------------------------------------
# detach_all
# ---------------------------------------------------------------------------


class TestDetachAll:
    """Test WorkerPoolProvider.detach_all."""

    def test_terminates_workers_with_no_remaining_sessions(self):
        pool = _setup_pool([])
        w1 = _add_worker(pool, "db1", {})
        w1.attach("s1")
        w2 = _add_worker(pool, "db2", {})
        w2.attach("s1")

        asyncio.run(pool.detach_all("s1"))
        # Both workers should be removed (no sessions left)
        assert "db1" not in pool._id_to_path
        assert "db2" not in pool._id_to_path

    def test_keeps_workers_with_remaining_sessions(self):
        pool = _setup_pool([])
        w1 = _add_worker(pool, "db1", {})
        w1.attach("s1")
        w1.attach("s2")
        w2 = _add_worker(pool, "db2", {})
        w2.attach("s1")

        asyncio.run(pool.detach_all("s1"))
        # db1 still has s2, so should remain
        assert "db1" in pool._id_to_path
        assert w1.session_count == 1
        # db2 had only s1, so should be terminated
        assert "db2" not in pool._id_to_path

    def test_none_session_delegates_to_shutdown_all(self):
        pool = _setup_pool([])
        _add_worker(pool, "db1", {})
        _add_worker(pool, "db2", {})

        asyncio.run(pool.detach_all(None))
        assert len(pool._alive_workers()) == 0

    def test_skips_inactive_workers(self):
        pool = _setup_pool([])
        w1 = _add_worker(pool, "db1", {})
        w1.attach("s1")
        w2 = _add_worker(pool, "db2", {})
        w2.attach("s1")
        w2.state = WorkerState.DEAD

        asyncio.run(pool.detach_all("s1"))
        # db1 terminated, db2 skipped (already dead)
        assert "db1" not in pool._id_to_path

    def test_skips_unattached_workers(self):
        pool = _setup_pool([])
        w1 = _add_worker(pool, "db1", {})
        w1.attach("s1")
        w2 = _add_worker(pool, "db2", {})
        w2.attach("s2")

        asyncio.run(pool.detach_all("s1"))
        # db1 terminated (s1 was sole session)
        assert "db1" not in pool._id_to_path
        # db2 untouched (s1 was never attached)
        assert "db2" in pool._id_to_path
        assert w2.session_count == 1
