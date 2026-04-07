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
import re
from collections.abc import Sequence
from typing import Annotated, Any

from fastmcp.experimental.transforms.code_mode import MontySandboxProvider
from fastmcp.server.context import Context
from fastmcp.server.transforms import GetToolNext
from fastmcp.server.transforms.catalog import CatalogTransform
from fastmcp.tools.base import ToolResult
from fastmcp.tools.tool import Tool
from fastmcp.utilities.versions import VersionSpec
from pydantic import BaseModel, Field
from pydantic_monty import MontyRuntimeError

from ida_mcp.exceptions import IDAError

# Management tools are registered directly on the supervisor and must remain
# visible in the tool listing — they handle database lifecycle, not analysis.
# worker_provider.py derives _MANAGEMENT_TOOLS from this set (minus
# list_databases, which is supervisor-only, not proxied to workers).
MANAGEMENT_TOOLS = frozenset(
    {
        "open_database",
        "close_database",
        "list_databases",
        "wait_for_analysis",
        "save_database",
    }
)

META_TOOLS = frozenset({"search_tools", "execute", "batch"})

# Tools that are always directly visible alongside the meta-tools.
PINNED_TOOLS = frozenset(
    {
        *MANAGEMENT_TOOLS,
        "get_database_info",
        # Exploration
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
        "create_structure",
        "apply_type_at_address",
    }
)

# Blocked inside execute/batch to prevent escaping tool boundaries.
_BLOCKED_TOOLS = MANAGEMENT_TOOLS | META_TOOLS


class ToolInfo(BaseModel):
    """Summary of a discovered tool returned by ``search_tools``."""

    name: str = Field(description="Tool name.")
    description: str = Field(description="Tool description.")
    tags: list[str] = Field(default_factory=list, description="Tool tags.")


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


_EXECUTE_DESCRIPTION = """\
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
xrefs = await asyncio.gather(*[
    call_tool("get_xrefs_to", {"address": f"0x{a}"})
    for a in addrs
])
return {"decomp": decomp, "xrefs": xrefs}
```

## Choosing the right call pattern

Need ONE tool with no post-processing?
  → Call the tool directly. Never wrap it in execute.

Need the SAME tool on multiple targets?
  → Check if the tool has a **batch parameter** first (e.g. get_strings
    has `filters=[...]` for multi-pattern single-pass search).
  → Otherwise, use the **batch** meta-tool for sequential multi-tool
    execution with per-item error collection and progress reporting.
  → Only fall back to execute loops if you need inter-step processing logic.

Need to chain: tool A's output feeds tool B's input?
  → Use execute. This is what it's for.

Need multiple INDEPENDENT queries in parallel?
  → Use execute with asyncio.gather.

**Important:**
- Only IDA analysis tools are callable via `call_tool` inside execute. \
Management tools (open_database, close_database, list_databases, \
wait_for_analysis, save_database) and meta-tools (search_tools, execute, \
batch) must be called directly — they are not available inside execute.
- `database` is auto-injected into every `call_tool` invocation. \
To target a different database for one call, pass `database` \
explicitly in that call's params.
- Addresses are strings: hex ("0x401000"), bare hex ("4010a0"), \
decimal, or symbol names ("main").
- **Address parsing:** IDA tools return addresses as hex strings \
like "0x9AFC". To convert in execute: `int(addr, 16)` or \
`int(addr, 0)`. Both work.
- `filter_pattern` parameters are **Python regex** — escape special \
characters (use `re.escape("C++")`, not `"C++"` literally).
- `asyncio`, `json`, `re`, and `math` are importable. \
No filesystem or network I/O.

## Execute patterns

- **Chain outputs:** decompile a function, extract callees, resolve them:
  ```
  import re, asyncio
  decomp = await call_tool("decompile_function", {"address": "main"})
  addrs = re.findall(r'sub_([0-9A-Fa-f]+)', decomp["pseudocode"])
  xrefs = await asyncio.gather(*[
      call_tool("get_xrefs_to", {"address": f"0x{a}"})
      for a in addrs
  ])
  return {"decomp": decomp, "callee_xrefs": xrefs}
  ```
- **Filter and enrich:** find strings, then resolve which functions use them:
  ```
  strings = await call_tool("get_strings", {"filter_pattern": "password|secret"})
  results = []
  for s in strings["items"]:
      refs = await call_tool("get_xrefs_to", {"address": s["address"]})
      for ref in refs["items"]:
          results.append({"string": s["value"], "caller": ref["from_name"]})
  return results
  ```

**Return only what you need.** Filter large results before returning — \
extract specific lines from pseudocode, return summary dicts, not raw \
tool outputs. Large returns waste context in the calling conversation.

**Common tool signatures and return shapes:**

`database` is auto-injected — omit it from call_tool params. \
All results include a `database` field. Paginated results include \
`items`, `total`, `offset`, `limit`, `has_more` — always check \
`has_more` and paginate if needed.

```
list_functions(offset=0, limit=100, filter_pattern="", \
filter_type="", filters=[])
  → single: {items: [{name, start, end, size}], total, offset, limit, has_more}
  → batch:  {groups: [{pattern, filter_type, matches, total_scanned}], cancelled}
  filter_type values: "library", "noreturn", "thunk", "user"

decompile_function(address=, name=)
  → {address, name, pseudocode}

disassemble_function(address)
  → {address, name, instruction_count, instructions: [{address, disasm}]}

get_strings(filter_pattern="", filters=[], min_length=4, \
offset=0, limit=100)
  → single: {items: [{address, value, length, type}], total, has_more}
  → batch:  {groups: [{pattern, matches, total_scanned}], cancelled}

get_xrefs_to(address, offset=0, limit=100)
  → {address, items: [{from, from_name, type, is_code}], \
total, has_more}

find_code_by_string(pattern, min_length=4, offset=0, \
limit=20)
  → {results: [{string_address, string_value, function_address, \
function_name}], total_strings_scanned, unique_functions}
  Note: field is "results", not "items".

get_database_info()
  → {file_path, processor, bitness, file_type, min_address, \
max_address, entry_point, function_count, segment_count, ...}

list_names(filter_pattern="", filters=[], offset=0, limit=100)
  → single: {items: [{address, name}], total, has_more}
  → batch:  {groups: [{pattern, matches, total_scanned}], cancelled}

rename_function(address, new_name)
  → {old_name, new_name, address}

set_comment(address, comment, repeatable=false)
  → {address, old_comment, comment, repeatable}

set_decompiler_comment(address, comment)
  → {address, comment}
```

**Resources** (read via MCP resource protocol, not call_tool):
- `ida://<database>/idb/imports` — full import table
- `ida://<database>/idb/exports` — full export table
- `ida://<database>/idb/entrypoints` — entry points
- `ida://<database>/statistics` — function/segment/string counts
Each also has a `/search/{pattern}` variant for regex filtering.\
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


def _unwrap_tool_result(result: ToolResult) -> dict[str, Any] | str:
    """Extract the payload from an MCP ``ToolResult``."""
    if result.structured_content is not None:
        return result.structured_content
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
        execute_description: str = _EXECUTE_DESCRIPTION,
    ):
        super().__init__()
        self._pinned = pinned
        self._max_search_results = max_search_results
        self._execute_description = execute_description
        self._cached_search_tool: Tool | None = None
        self._cached_execute_tool: Tool | None = None
        self._cached_batch_tool: Tool | None = None

    # ------------------------------------------------------------------
    # CatalogTransform interface
    # ------------------------------------------------------------------

    async def transform_tools(self, tools: Sequence[Tool]) -> Sequence[Tool]:
        visible = [t for t in tools if t.name in self._pinned]
        return [
            *visible,
            self._get_search_tool(),
            self._get_execute_tool(),
            self._get_batch_tool(),
        ]

    async def get_tool(
        self,
        name: str,
        call_next: GetToolNext,
        *,
        version: VersionSpec | None = None,
    ) -> Tool | None:
        if name == "search_tools":
            return self._get_search_tool()
        if name == "execute":
            return self._get_execute_tool()
        if name == "batch":
            return self._get_batch_tool()
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
            ctx: Context | None = None,
        ) -> list[ToolInfo]:
            """Search for non-pinned tools by regex pattern.

            Searches only tools that are hidden from the default listing.
            Pinned tools (visible in the tool listing) are excluded.
            Returns matching tool names and descriptions.  Use ``.*`` to
            list all hidden tools.
            """
            catalog = await transform.get_tool_catalog(ctx)
            hidden = [t for t in catalog if t.name not in transform._pinned]

            try:
                compiled = re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                raise IDAError(f"Invalid regex pattern: {exc}") from exc

            results: list[ToolInfo] = []
            for tool in hidden:
                text = f"{tool.name} {tool.description or ''}"
                if tool.tags:
                    text += " " + " ".join(tool.tags)
                if compiled.search(text):
                    results.append(
                        ToolInfo(
                            name=tool.name,
                            description=tool.description or "",
                            tags=sorted(tool.tags) if tool.tags else [],
                        )
                    )
                    if len(results) >= transform._max_search_results:
                        break
            return results

        return Tool.from_function(fn=search_tools, name="search_tools")

    # ------------------------------------------------------------------
    # execute — sandboxed Python with call_tool for batching
    # ------------------------------------------------------------------

    def _get_execute_tool(self) -> Tool:
        if self._cached_execute_tool is None:
            self._cached_execute_tool = self._make_execute_tool()
        return self._cached_execute_tool

    def _make_execute_tool(self) -> Tool:
        sandbox = MontySandboxProvider()

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
            except MontyRuntimeError as exc:
                # Re-raise as IDAError so MCP clients see isError=True.
                inner = exc.exception()
                raise IDAError(str(inner) if inner is not None else str(exc)) from exc

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

        return Tool.from_function(
            fn=execute,
            name="execute",
            description=self._execute_description,
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
