# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Hybrid tool transform for the IDA supervisor.

Pins common analysis tools alongside ``search_tools``, ``execute``, and
``batch`` meta-tools.  Common tools are directly callable with full schemas
visible.  Additional tools are discoverable via ``search_tools`` and callable
either directly by name or through ``execute`` blocks for chaining, looping,
and parallel queries, or ``batch`` for sequential multi-tool execution.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from collections.abc import Sequence
from typing import Annotated, Any, Literal

from fastmcp.server.context import Context
from fastmcp.server.transforms import GetToolNext
from fastmcp.server.transforms.catalog import CatalogTransform
from fastmcp.server.transforms.search.base import (
    serialize_tools_for_output_json,
    serialize_tools_for_output_markdown,
)
from fastmcp.tools.base import ToolResult
from fastmcp.tools.tool import Tool
from fastmcp.utilities.versions import VersionSpec
from pydantic import BaseModel, Field

from ida_mcp.exceptions import IDAError
from ida_mcp.sandbox import RestrictedPythonSandbox

# Management tools are registered directly on the supervisor and must remain
# visible in the tool listing — they handle database lifecycle, not analysis.
# worker_provider.py derives _MANAGEMENT_TOOLS from this set (minus
# list_databases and list_targets, which are supervisor-only).
MANAGEMENT_TOOLS = frozenset(
    {
        "open_database",
        "close_database",
        "list_databases",
        "wait_for_analysis",
        "save_database",
        "list_targets",
    }
)

META_TOOLS = frozenset({"search_tools", "get_schema", "execute", "batch"})

ToolDetailLevel = Literal["brief", "detailed", "full"]
"""Detail level for tool description output.

- ``"brief"``: tool names and one-line descriptions
- ``"detailed"``: compact markdown with parameter names, types, and required markers
- ``"full"``: complete JSON schema
"""


def _render_tools_at_detail(tools: Sequence[Tool], detail: ToolDetailLevel) -> str:
    """Render tools at the requested detail level."""
    if not tools:
        return "No tools matched."
    if detail == "full":
        return json.dumps(serialize_tools_for_output_json(tools), indent=2)
    if detail == "detailed":
        return serialize_tools_for_output_markdown(tools)
    lines: list[str] = []
    for t in tools:
        first_line = (t.description or "").split("\n")[0]
        desc = f": {first_line}" if first_line else ""
        lines.append(f"- {t.name}{desc}")
    return "\n".join(lines)


def _env_flag(name: str, *, default: bool = False) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return default


# Tools that are always directly visible.
PINNED_TOOLS = frozenset(
    {
        *MANAGEMENT_TOOLS,
        *META_TOOLS,
        # Exploration
        "get_database_info",
        "list_functions",
        "get_strings",
        "decompile_function",
        "disassemble_function",
        "list_names",
        "find_code_by_string",
        "get_xrefs_to",
        "get_xrefs_from",
        # Mutation
        "rename_function",
        "set_comment",
        "set_decompiler_comment",
        # Structs
        "list_structures",
        "get_structure",
        "create_structure",
        "add_struct_member",
        "retype_struct_member",
        # Types
        "list_local_types",
        "parse_type_declaration",
        "apply_type_at_address",
        "get_type_info",
        "set_type",
    }
)

# Blocked inside execute/batch to prevent escaping tool boundaries.
_BLOCKED_TOOLS = MANAGEMENT_TOOLS | META_TOOLS


class BatchOperation(BaseModel):
    """A single operation in a batch request."""

    tool: str = Field(description="Tool name to call.")
    params: dict[str, Any] = Field(default_factory=dict, description="Tool parameters.")


class BatchItemResult(BaseModel):
    """Result of one operation in a batch."""

    index: int = Field(description="0-based position in the input list.")
    tool: str = Field(description="Tool that was called.")
    result: Any = Field(default=None, description="Tool result on success, null on error.")
    error: str | None = Field(default=None, description="Error message if this item failed.")


class BatchResult(BaseModel):
    """Result of a batch execution."""

    results: list[BatchItemResult] = Field(description="Per-operation results.")
    succeeded: int = Field(description="Number of successful operations.")
    failed: int = Field(description="Number of failed operations.")
    cancelled: bool = Field(
        default=False,
        description="Whether batch stopped before completing all operations (stop_on_error or client cancellation).",
    )


_EXECUTE_DESCRIPTION_PREAMBLE = """\
Execute Python code that chains multiple IDA tool calls in one block.
Use `await call_tool(name, params)` to invoke tools.
Use `return` to produce output.

The `database` parameter is auto-injected into every `call_tool` \
invocation — do not include it in params. It is also available as \
the `database` variable in your code. To target a different database \
for a specific call (cross-database analysis), pass `database` \
explicitly in that call's params to override the default.

**STOP — do NOT wrap a single tool call in execute:**
```
# BAD — pointless overhead, just call decompile_function directly:
r = await call_tool("decompile_function", {"address": "0x1234"})
return r
```

**execute is for multi-step pipelines:**
```
# GOOD — chaining tool A output into tool B:
decomp = await call_tool("decompile_function", {"address": "0x1234"})
addrs = re.findall(r'sub_([0-9A-Fa-f]+)', decomp["pseudocode"])
xrefs = [
    await call_tool("get_xrefs_to", {"address": f"0x{a}"})
    for a in addrs
]
return {"decomp": decomp, "xrefs": xrefs}
```

## Choosing the right call pattern

Need ONE tool with no post-processing?
  → Call the tool directly. Never wrap it in execute.

Multiple independent calls (same or different tools)?
  → Check if the tool has a **batch parameter** first (e.g. get_strings
    has `filters=[...]` for multi-pattern single-pass search).<<BATCH_HINT>>
  → Use get_schema to look up parameter details for any tool before calling.
  → Only fall back to execute if you need conditional logic or filtering.

Conditional logic, filtering, or chaining tool A output into B?
  → Use execute. This is what it's for.

Cross-database parallel queries?
  → Use execute with asyncio.gather and explicit `database` params.
  Note: calls to the same database are serialized by the worker —
  asyncio.gather only helps for cross-database work.

**Important:**
- Only IDA analysis tools are callable via `call_tool` inside execute. \
Management tools (open_database, close_database, save_database, \
list_databases, wait_for_analysis, list_targets) and meta-tools \
(<<META_TOOL_LIST>>) must be called directly — they are \
not available inside execute.
- `database` is auto-injected into every `call_tool` invocation. \
To target a different database for one call, pass `database` \
explicitly in that call's params.
- Addresses are strings: hex ("0x401000"), bare hex ("4010a0"), \
decimal, or symbol names ("main").
- `filter_pattern` parameters are **Python regex** — escape special \
characters (use `re.escape("C++")`, not `"C++"` literally).
- `asyncio`, `collections`, `functools`, `itertools`, `json`, \
`math`, `operator`, `re`, `struct`, and `typing` are importable. \
No filesystem or network I/O.
- **Paginated results** include `items`, `total`, `offset`, `limit`, \
`has_more` — always check `has_more` and paginate if needed. \
All results include a `database` field.
- **Tool schemas:** call `get_schema(tools=[...])` before execute to look \
up parameter names, types, and return field names for any tool.
- **Return only what you need.** Filter large results before returning — \
extract specific fields from pseudocode, return summary dicts instead of \
raw tool outputs. Large returns waste context in the calling conversation.\
"""


_PROCESSING_PATTERN = re.compile(
    r"\bfor\b|\bwhile\b|\bif\b|\bgather\b|\bcreate_task\b|\bre\.\b"
    r"|\bjson\.\b|\bmath\.\b"
    r"|\bint\(|\blen\(|\bstr\(|\bsorted\(|\bfilter\(|\bmap\("
    r"|\bzip\(|\benumerate\(|\bany\(|\ball\(|\bsum\(|\bmin\(|\bmax\("
    r"|\[[^\]]*\bfor\b"  # list comprehensions
)


def _has_processing_logic(code: str) -> bool:
    """Return True if code contains loops, conditionals, or data processing.

    Intentionally a loose heuristic — false negatives are acceptable since
    this only drives an advisory hint on single-call execute blocks.
    """
    return bool(_PROCESSING_PATTERN.search(code))


def unwrap_auto_wrapped(data: dict[str, Any]) -> dict[str, Any]:
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


def _unwrap_tool_result(result: ToolResult) -> dict[str, Any] | str:
    """Extract the payload from an MCP ``ToolResult``.

    FastMCP wraps Union return types in ``{"result": ...}`` to satisfy the
    outputSchema.  We peel that wrapper so execute code sees the inner dict
    directly (e.g. ``{"items": [...], "total": ...}`` instead of
    ``{"result": {"items": [...], ...}}``).
    """
    if result.structured_content is not None:
        sc = result.structured_content
        if isinstance(sc, dict):
            return unwrap_auto_wrapped(sc)
        return sc
    return "\n".join(
        content.text if hasattr(content, "text") else str(content) for content in result.content
    )


class IDAToolTransform(CatalogTransform):
    """Hybrid transform: pins common tools, adds search, execute, and batch.

    Common analysis tools remain directly callable with full schemas visible.
    Additional tools are discoverable via ``search_tools`` and callable either
    directly by name, through ``execute`` blocks for chaining and parallel
    queries, or ``batch`` for sequential multi-tool execution.
    """

    def __init__(
        self,
        *,
        pinned: frozenset[str] = PINNED_TOOLS,
        max_search_results: int = 10_000,
        enable_execute: bool | None = None,
        enable_batch: bool | None = None,
    ):
        # enable_execute/enable_batch: None means "consult IDA_MCP_DISABLE_* env var"
        # (both default to enabled); an explicit bool overrides the env var.
        super().__init__()
        self._enable_execute = (
            not _env_flag("IDA_MCP_DISABLE_EXECUTE") if enable_execute is None else enable_execute
        )
        self._enable_batch = (
            not _env_flag("IDA_MCP_DISABLE_BATCH") if enable_batch is None else enable_batch
        )
        self._pinned = pinned
        self._max_search_results = max_search_results
        self._cached_search_tool: Tool | None = None
        self._cached_schema_tool: Tool | None = None
        self._cached_execute_tool: Tool | None = None
        self._cached_batch_tool: Tool | None = None

    # ------------------------------------------------------------------
    # CatalogTransform interface
    # ------------------------------------------------------------------

    async def transform_tools(self, tools: Sequence[Tool]) -> Sequence[Tool]:
        visible = [t for t in tools if t.name in self._pinned]
        out: list[Tool] = [*visible, self._get_search_tool(), self._get_schema_tool()]
        if self._enable_execute:
            out.append(self._get_execute_tool())
        if self._enable_batch:
            out.append(self._get_batch_tool())
        return out

    async def get_tool(
        self,
        name: str,
        call_next: GetToolNext,
        *,
        version: VersionSpec | None = None,
    ) -> Tool | None:
        if name == "search_tools":
            return self._get_search_tool()
        if name == "get_schema":
            return self._get_schema_tool()
        if name == "execute":
            return self._get_execute_tool() if self._enable_execute else None
        if name == "batch":
            return self._get_batch_tool() if self._enable_batch else None
        # Fall through — any real tool is callable by name, even hidden ones.
        return await call_next(name, version=version)

    # ------------------------------------------------------------------
    # search_tools — regex discovery of hidden tools
    # ------------------------------------------------------------------

    def _get_search_tool(self) -> Tool:
        if self._cached_search_tool is None:
            self._cached_search_tool = self._make_search_tool()
        return self._cached_search_tool

    def _make_search_tool(self) -> Tool:
        transform = self

        async def search_tools(
            pattern: Annotated[
                str,
                Field(
                    description=(
                        "Regex pattern to match against tool names, descriptions, and tags"
                    )
                ),
            ],
            detail: Annotated[
                ToolDetailLevel,
                Field(
                    description=(
                        "'brief' (default) for names and one-line descriptions, "
                        "'detailed' for parameter schemas as markdown, "
                        "'full' for complete JSON schemas"
                    )
                ),
            ] = "brief",
            ctx: Context | None = None,
        ) -> str:
            """Search hidden tools by regex pattern.

            Searches tools that are hidden from the default listing (pinned
            tools are always visible and excluded from results).  Use ``.*``
            to list all hidden tools.

            Returns tool names and one-line summaries by default.  Pass
            ``detail="detailed"`` to get parameter schemas inline, or follow
            up with ``get_schema(tools=[...])`` to drill into specific tools.
            """
            catalog = await transform.get_tool_catalog(ctx)
            hidden = [t for t in catalog if t.name not in transform._pinned]

            try:
                compiled = re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                raise IDAError(f"Invalid regex pattern: {exc}") from exc

            matched: list[Tool] = []
            truncated = False
            for tool in hidden:
                text = f"{tool.name} {tool.description or ''}"
                if tool.tags:
                    text += " " + " ".join(tool.tags)
                if compiled.search(text):
                    matched.append(tool)
                    if len(matched) >= transform._max_search_results:
                        truncated = True
                        break

            result = _render_tools_at_detail(matched, detail)
            if truncated:
                result += (
                    f"\n\n(Results capped at {transform._max_search_results}."
                    " Refine your pattern to see more.)"
                )
            return result

        return Tool.from_function(fn=search_tools, name="search_tools")

    # ------------------------------------------------------------------
    # get_schema — parameter schemas for tools by name
    # ------------------------------------------------------------------

    def _get_schema_tool(self) -> Tool:
        if self._cached_schema_tool is None:
            self._cached_schema_tool = self._make_schema_tool()
        return self._cached_schema_tool

    def _make_schema_tool(self) -> Tool:
        transform = self

        async def get_schema(
            tools: Annotated[
                list[str],
                Field(description="Tool names to get schemas for."),
            ],
            detail: Annotated[
                ToolDetailLevel,
                Field(
                    description=(
                        "'brief' for names and descriptions, "
                        "'detailed' for parameter schemas as markdown (default), "
                        "'full' for complete JSON schemas"
                    )
                ),
            ] = "detailed",
            ctx: Context | None = None,
        ) -> str:
            """Get parameter schemas for specific tools by name.

            Use after search_tools to see parameter types and return shapes
            before calling a tool.  Works for both pinned and hidden tools.
            Pass ``detail="full"`` to get the complete JSON schema for tools
            with deeply nested parameters.
            """
            catalog = await transform.get_tool_catalog(ctx)
            # get_tool_catalog bypasses transform_tools, so meta-tools are
            # not included.  Merge them in manually so callers can look up
            # search_tools, get_schema, execute, and batch by name.
            meta: list[Tool] = [
                transform._get_search_tool(),
                transform._get_schema_tool(),
            ]
            if transform._enable_execute:
                meta.append(transform._get_execute_tool())
            if transform._enable_batch:
                meta.append(transform._get_batch_tool())
            catalog_by_name = {t.name: t for t in [*catalog, *meta]}
            matched = [catalog_by_name[n] for n in tools if n in catalog_by_name]
            not_found = [n for n in tools if n not in catalog_by_name]

            parts: list[str] = []
            if matched:
                parts.append(_render_tools_at_detail(matched, detail))
            if not_found:
                parts.append(f"Tools not found: {', '.join(not_found)}")
            return "\n\n".join(parts) if parts else "(no tool names provided)"

        return Tool.from_function(fn=get_schema, name="get_schema")

    # ------------------------------------------------------------------
    # execute — sandboxed Python with call_tool for batching
    # ------------------------------------------------------------------

    def _get_execute_tool(self) -> Tool:
        if self._cached_execute_tool is None:
            self._cached_execute_tool = self._make_execute_tool()
        return self._cached_execute_tool

    def _make_execute_tool(self) -> Tool:
        sandbox = RestrictedPythonSandbox()

        async def execute(
            code: Annotated[
                str,
                Field(
                    description=(
                        "Python async code to execute tool calls via call_tool(name, arguments)"
                    )
                ),
            ],
            database: Annotated[
                str,
                Field(
                    description=(
                        "Database to target (stem ID from open_database). "
                        "Available as `database` variable in code and "
                        "auto-injected into call_tool params. Individual "
                        "calls can override by passing `database` explicitly."
                    ),
                ),
            ],
            ctx: Context | None = None,
        ) -> Any:
            """Execute tool calls using Python code."""
            if ctx is None:
                raise IDAError("execute requires an MCP context")

            call_count = 0

            async def call_tool(tool_name: str, params: dict[str, Any]) -> Any:
                nonlocal call_count
                if tool_name in _BLOCKED_TOOLS:
                    raise IDAError(
                        f"'{tool_name}' cannot be called via execute. "
                        "Management tools and meta-tools must be called directly.",
                        error_type="InvalidOperation",
                    )
                if "database" not in params:
                    params = {**params, "database": database}
                call_count += 1
                result = await ctx.fastmcp.call_tool(tool_name, params)
                return _unwrap_tool_result(result)

            try:
                result = await sandbox.run(
                    code,
                    inputs={"database": database},
                    external_functions={"call_tool": call_tool},
                )
            except SyntaxError as exc:
                raise IDAError(str(exc), error_type="SyntaxError") from exc
            except IDAError:
                raise
            except Exception as exc:
                raise IDAError(str(exc)) from exc

            if call_count == 1 and not _has_processing_logic(code):
                hint = (
                    "Hint: this execute block contained a single call_tool with "
                    "no processing. Use the direct tool instead for better efficiency."
                )
                if isinstance(result, dict):
                    result = {**result, "_hint": hint}
                elif isinstance(result, str):
                    result = result + "\n\n" + hint

            return result

        if self._enable_batch:
            batch_hint = (
                "\n  → Otherwise, use the **batch** meta-tool for sequential "
                "multi-tool\n    execution with per-item error collection and "
                "progress reporting."
            )
            meta_tool_list = "search_tools, get_schema, execute, batch"
        else:
            batch_hint = ""
            meta_tool_list = "search_tools, get_schema, execute"
        description = _EXECUTE_DESCRIPTION_PREAMBLE.replace("<<BATCH_HINT>>", batch_hint).replace(
            "<<META_TOOL_LIST>>", meta_tool_list
        )

        return Tool.from_function(
            fn=execute,
            name="execute",
            description=description,
        )

    # ------------------------------------------------------------------
    # batch — sequential multi-tool execution with error collection
    # ------------------------------------------------------------------

    def _get_batch_tool(self) -> Tool:
        if self._cached_batch_tool is None:
            self._cached_batch_tool = self._make_batch_tool()
        return self._cached_batch_tool

    def _make_batch_tool(self) -> Tool:
        async def batch(
            operations: Annotated[
                list[BatchOperation],
                Field(
                    description="List of tool calls to execute sequentially (max 50).",
                    max_length=50,
                ),
            ],
            database: Annotated[
                str,
                Field(
                    description=(
                        "Database to target (stem ID from open_database). "
                        "Auto-injected into each operation's params. "
                        "Individual operations can override by including "
                        "`database` in their params."
                    ),
                ),
            ],
            stop_on_error: Annotated[
                bool,
                Field(description="Stop on first error instead of continuing."),
            ] = False,
            ctx: Context | None = None,
        ) -> BatchResult:
            """Execute multiple tool calls in a single request.

            Runs operations sequentially, collecting results and errors per item.
            Use for applying the same operation to many targets (rename 20
            functions, set comments at 30 addresses) or mixing different
            operations without per-call round-trip overhead.

            The database parameter is automatically injected into each
            operation — you do not need to include it in individual params.
            To target a different database for a specific operation
            (cross-database analysis), include ``database`` in that
            operation's params to override the default.

            For multi-step pipelines where one tool's output feeds another,
            use execute instead.
            """
            if ctx is None:
                raise IDAError("batch requires an MCP context")

            results: list[BatchItemResult] = []
            succeeded = failed = 0
            cancelled = False

            try:
                for i, op in enumerate(operations):
                    try:
                        if op.tool in _BLOCKED_TOOLS:
                            raise IDAError(
                                f"'{op.tool}' cannot be called via batch. "
                                "Management tools and meta-tools must be called directly.",
                                error_type="InvalidOperation",
                            )
                        params = op.params
                        if "database" not in params:
                            params = {**params, "database": database}
                        tool_result = await ctx.fastmcp.call_tool(op.tool, params)
                        payload = _unwrap_tool_result(tool_result)
                        results.append(BatchItemResult(index=i, tool=op.tool, result=payload))
                        succeeded += 1
                    except Exception as exc:
                        results.append(BatchItemResult(index=i, tool=op.tool, error=str(exc)))
                        failed += 1

                    await ctx.report_progress(i + 1, len(operations))

                    if stop_on_error and failed:
                        cancelled = True
                        break
            except asyncio.CancelledError:
                cancelled = True

            return BatchResult(
                results=results,
                succeeded=succeeded,
                failed=failed,
                cancelled=cancelled,
            )

        return Tool.from_function(fn=batch, name="batch")
