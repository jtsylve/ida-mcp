# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Unit tests for supervisor.py pure utility functions.

These tests cover _prefix_uri, _extract_db_prefix, and capability-based
tool/resource filtering — all functions that can run without idalib loaded.
"""

from __future__ import annotations

import asyncio

from fastmcp.resources.template import ResourceTemplate as FastMCPResourceTemplate
from fastmcp.tools import Tool as FastMCPTool

from ida_mcp.supervisor import ProxyMCP, Worker, WorkerState, _extract_db_prefix, _prefix_uri

# ---------------------------------------------------------------------------
# _prefix_uri
# ---------------------------------------------------------------------------


def test_prefix_uri_basic():
    assert _prefix_uri("ida://idb/metadata", "mybin") == "ida://mybin/idb/metadata"


def test_prefix_uri_nested_path():
    assert _prefix_uri("ida://functions/0x401000", "db1") == "ida://db1/functions/0x401000"


def test_prefix_uri_non_ida_scheme():
    assert _prefix_uri("https://example.com", "mybin") == "https://example.com"


def test_prefix_uri_template_placeholder():
    assert _prefix_uri("ida://types/{name}", "{database}") == "ida://{database}/types/{name}"


# ---------------------------------------------------------------------------
# _extract_db_prefix
# ---------------------------------------------------------------------------


def test_extract_db_prefix_basic():
    db, worker_uri = _extract_db_prefix("ida://mybin/idb/metadata")
    assert db == "mybin"
    assert worker_uri == "ida://idb/metadata"


def test_extract_db_prefix_nested():
    db, worker_uri = _extract_db_prefix("ida://db1/functions/0x401000")
    assert db == "db1"
    assert worker_uri == "ida://functions/0x401000"


def test_extract_db_prefix_non_ida_scheme():
    db, uri = _extract_db_prefix("https://example.com/path")
    assert db is None
    assert uri == "https://example.com/path"


def test_extract_db_prefix_no_path_segment():
    """URI like ``ida://databases`` has no slash after the first segment."""
    db, uri = _extract_db_prefix("ida://databases")
    assert db is None
    assert uri == "ida://databases"


def test_extract_db_prefix_empty_segment():
    """URI like ``ida:///path`` has an empty segment before the slash."""
    db, uri = _extract_db_prefix("ida:///path")
    assert db is None
    assert uri == "ida:///path"


def test_extract_roundtrip():
    """_prefix_uri and _extract_db_prefix are inverses for ida:// URIs."""
    original = "ida://idb/segments"
    db_id = "testdb"
    prefixed = _prefix_uri(original, db_id)
    extracted_db, extracted_uri = _extract_db_prefix(prefixed)
    assert extracted_db == db_id
    assert extracted_uri == original


# ---------------------------------------------------------------------------
# Capability-based filtering helpers
# ---------------------------------------------------------------------------


def _make_tool(name: str, tags: set[str] | None = None) -> FastMCPTool:
    """Create a minimal FastMCPTool for testing."""
    return FastMCPTool(
        name=name,
        description=f"{name} tool",
        parameters={"type": "object", "properties": {}},
        tags=tags or set(),
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
    proxy: ProxyMCP,
    db_id: str,
    capabilities: dict[str, bool],
) -> Worker:
    """Add a mock worker with the given capabilities to a ProxyMCP instance."""
    canonical = f"/tmp/{db_id}"
    worker = Worker(database_id=db_id, file_path=canonical)
    worker.state = WorkerState.IDLE
    worker.metadata = {"capabilities": capabilities}
    proxy._workers[canonical] = worker
    proxy._id_to_path[db_id] = canonical
    proxy._cached_capabilities = None
    return worker


_SENTINEL_TOOL = _make_tool("_sentinel")


def _setup_proxy(
    tools: list[FastMCPTool],
    resource_templates: list[FastMCPResourceTemplate] | None = None,
) -> ProxyMCP:
    """Create a ProxyMCP with pre-populated tool schemas (skipping bootstrap).

    A sentinel tool is always included so the schemas list is truthy,
    preventing ``_bootstrap_worker_schemas`` from spawning a real worker.
    """
    proxy = ProxyMCP()
    all_tools = [_SENTINEL_TOOL, *tools]
    proxy._worker_tool_schemas = all_tools
    # Build augmented tools (adds database param) — skip management tools
    mgmt_names = ProxyMCP._MANAGEMENT_TOOLS
    proxy._augmented_worker_tools = [
        ProxyMCP._augment_schema(t) for t in all_tools if t.name not in mgmt_names
    ]
    proxy._worker_resource_templates = resource_templates or []
    return proxy


# ---------------------------------------------------------------------------
# Capability filtering — tools
# ---------------------------------------------------------------------------


class TestCapabilityFilteringTools:
    """Test that list_tools filters by aggregate worker capabilities."""

    def _list_tools(self, proxy: ProxyMCP) -> list[FastMCPTool]:
        return asyncio.run(proxy.list_tools())

    def test_decompiler_tools_hidden_when_no_capable_worker(self):
        proxy = _setup_proxy(
            [
                _make_tool("get_segments"),
                _make_tool("decompile_function", tags={"decompiler"}),
            ]
        )
        _add_worker(proxy, "sparc", {"decompiler": False, "assembler": False})

        tools = self._list_tools(proxy)
        tool_names = {t.name for t in tools}
        assert "get_segments" in tool_names
        assert "decompile_function" not in tool_names

    def test_decompiler_tools_visible_when_capable_worker_exists(self):
        proxy = _setup_proxy(
            [
                _make_tool("get_segments"),
                _make_tool("decompile_function", tags={"decompiler"}),
            ]
        )
        _add_worker(proxy, "sparc", {"decompiler": False, "assembler": False})
        _add_worker(proxy, "x86", {"decompiler": True, "assembler": True})

        tools = self._list_tools(proxy)
        tool_names = {t.name for t in tools}
        assert "decompile_function" in tool_names

    def test_assembler_tools_hidden_when_no_capable_worker(self):
        proxy = _setup_proxy(
            [
                _make_tool("assemble_instruction", tags={"assembler"}),
            ]
        )
        _add_worker(proxy, "arm", {"decompiler": True, "assembler": False})

        tools = self._list_tools(proxy)
        tool_names = {t.name for t in tools}
        assert "assemble_instruction" not in tool_names

    def test_untagged_tools_always_visible(self):
        proxy = _setup_proxy([_make_tool("get_segments")])
        _add_worker(proxy, "sparc", {"decompiler": False, "assembler": False})

        tools = self._list_tools(proxy)
        worker_names = {t.name for t in tools} - ProxyMCP._MANAGEMENT_TOOLS
        assert "get_segments" in worker_names

    def test_show_all_tools_disables_filtering(self):
        proxy = _setup_proxy(
            [
                _make_tool("decompile_function", tags={"decompiler"}),
            ]
        )
        _add_worker(proxy, "sparc", {"decompiler": False})
        proxy._filter_by_capability = False

        tools = self._list_tools(proxy)
        tool_names = {t.name for t in tools}
        assert "decompile_function" in tool_names

    def test_show_all_tools_reenables_filtering(self):
        proxy = _setup_proxy(
            [
                _make_tool("decompile_function", tags={"decompiler"}),
            ]
        )
        _add_worker(proxy, "sparc", {"decompiler": False})
        proxy._filter_by_capability = False

        # Re-enable filtering
        proxy._filter_by_capability = True
        tools = self._list_tools(proxy)
        tool_names = {t.name for t in tools}
        assert "decompile_function" not in tool_names

    def test_no_workers_hides_all_capability_tools(self):
        proxy = _setup_proxy(
            [
                _make_tool("get_segments"),
                _make_tool("decompile_function", tags={"decompiler"}),
            ]
        )

        tools = self._list_tools(proxy)
        worker_names = {t.name for t in tools} - ProxyMCP._MANAGEMENT_TOOLS
        assert "get_segments" in worker_names
        assert "decompile_function" not in worker_names


# ---------------------------------------------------------------------------
# Capability filtering — resource templates
# ---------------------------------------------------------------------------


class TestCapabilityFilteringResources:
    """Test that list_resource_templates filters by aggregate capabilities."""

    def _list_templates(self, proxy: ProxyMCP) -> list[FastMCPResourceTemplate]:
        return asyncio.run(proxy.list_resource_templates())

    def test_decompiler_resource_hidden_when_no_capable_worker(self):
        proxy = _setup_proxy(
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
        _add_worker(proxy, "sparc", {"decompiler": False})

        templates = self._list_templates(proxy)
        names = {t.name for t in templates}
        assert "function_detail" in names
        assert "function_vars" not in names

    def test_decompiler_resource_visible_when_capable_worker_exists(self):
        proxy = _setup_proxy(
            tools=[],
            resource_templates=[
                _make_resource_template(
                    "ida://{database}/functions/{addr}/vars",
                    "function_vars",
                    tags={"decompiler"},
                ),
            ],
        )
        _add_worker(proxy, "x86", {"decompiler": True, "assembler": True})

        templates = self._list_templates(proxy)
        names = {t.name for t in templates}
        assert "function_vars" in names

    def test_show_all_disables_resource_filtering(self):
        proxy = _setup_proxy(
            tools=[],
            resource_templates=[
                _make_resource_template(
                    "ida://{database}/functions/{addr}/vars",
                    "function_vars",
                    tags={"decompiler"},
                ),
            ],
        )
        _add_worker(proxy, "sparc", {"decompiler": False})
        proxy._filter_by_capability = False

        templates = self._list_templates(proxy)
        names = {t.name for t in templates}
        assert "function_vars" in names


# ---------------------------------------------------------------------------
# Capability cache invalidation
# ---------------------------------------------------------------------------


class TestCapabilityCacheInvalidation:
    """Test that the aggregate capabilities cache is invalidated correctly."""

    def test_cache_populated_on_first_access(self):
        proxy = _setup_proxy([])
        _add_worker(proxy, "x86", {"decompiler": True})
        assert proxy._cached_capabilities is None

        caps = proxy._aggregate_capabilities()
        assert caps == {"decompiler"}
        assert proxy._cached_capabilities is not None

    def test_cache_reused_on_second_access(self):
        proxy = _setup_proxy([])
        _add_worker(proxy, "x86", {"decompiler": True})

        caps1 = proxy._aggregate_capabilities()
        caps2 = proxy._aggregate_capabilities()
        assert caps1 is caps2  # same object

    def test_cache_invalidated_on_mark_worker_dead(self):
        proxy = _setup_proxy([])
        worker = _add_worker(proxy, "x86", {"decompiler": True})
        proxy._aggregate_capabilities()
        assert proxy._cached_capabilities is not None

        asyncio.run(proxy._mark_worker_dead(worker))
        assert proxy._cached_capabilities is None
