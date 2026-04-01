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
from fastmcp.resources.template import ResourceTemplate as FastMCPResourceTemplate
from fastmcp.tools import Tool as FastMCPTool

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


def testprefix_uri_basic():
    assert prefix_uri("ida://idb/metadata", "mybin") == "ida://mybin/idb/metadata"


def testprefix_uri_nested_path():
    assert prefix_uri("ida://functions/0x401000", "db1") == "ida://db1/functions/0x401000"


def testprefix_uri_non_ida_scheme():
    assert prefix_uri("https://example.com", "mybin") == "https://example.com"


def testprefix_uri_template_placeholder():
    assert prefix_uri("ida://types/{name}", "{database}") == "ida://{database}/types/{name}"


# ---------------------------------------------------------------------------
# extract_db_prefix
# ---------------------------------------------------------------------------


def testextract_db_prefix_basic():
    db, worker_uri = extract_db_prefix("ida://mybin/idb/metadata")
    assert db == "mybin"
    assert worker_uri == "ida://idb/metadata"


def testextract_db_prefix_nested():
    db, worker_uri = extract_db_prefix("ida://db1/functions/0x401000")
    assert db == "db1"
    assert worker_uri == "ida://functions/0x401000"


def testextract_db_prefix_non_ida_scheme():
    db, uri = extract_db_prefix("https://example.com/path")
    assert db is None
    assert uri == "https://example.com/path"


def testextract_db_prefix_no_path_segment():
    """URI like ``ida://databases`` has no slash after the first segment."""
    db, uri = extract_db_prefix("ida://databases")
    assert db is None
    assert uri == "ida://databases"


def testextract_db_prefix_empty_segment():
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


def testexpand_uri_template_path_params():
    """Simple {key} path parameters are expanded."""
    result = expand_uri_template("ida://functions/{addr}", {"addr": "0x1000"})
    assert result == "ida://functions/0x1000"


def testexpand_uri_template_query_params():
    """RFC 6570 {?key1,key2} query parameters are expanded."""
    result = expand_uri_template("ida://functions{?offset,limit}", {"offset": 0, "limit": 100})
    assert result == "ida://functions?offset=0&limit=100"


def testexpand_uri_template_query_params_partial():
    """Only provided query params appear in the result."""
    result = expand_uri_template("ida://functions{?offset,limit}", {"limit": 50})
    assert result == "ida://functions?limit=50"


def testexpand_uri_template_query_params_empty():
    """No query params provided → no query string appended."""
    result = expand_uri_template("ida://functions{?offset,limit}", {})
    assert result == "ida://functions"


def testexpand_uri_template_mixed():
    """Path and query parameters together."""
    result = expand_uri_template(
        "ida://idb/segments/search/{pattern}{?offset,limit}",
        {"pattern": "text", "offset": 0, "limit": 10},
    )
    assert result == "ida://idb/segments/search/text?offset=0&limit=10"


def testexpand_uri_template_no_params():
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
