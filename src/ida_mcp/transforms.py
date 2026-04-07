# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Hybrid tool transform for the IDA supervisor.

Pins common analysis tools alongside ``search_tools`` and ``execute``
meta-tools.  Common tools are directly callable with full schemas visible.
Additional tools are discoverable via ``search_tools`` and callable either
directly by name or through ``execute`` blocks for batching, looping, and
parallel queries.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Annotated, Any

from fastmcp.experimental.transforms.code_mode import MontySandboxProvider
from fastmcp.server.context import Context
from fastmcp.server.transforms.catalog import CatalogTransform
from fastmcp.tools.tool import Tool
from pydantic import BaseModel, Field
from pydantic_monty import MontyRuntimeError

from ida_mcp.exceptions import IDAError

# Management tools are registered directly on the supervisor and must remain
# visible in the tool listing — they handle database lifecycle, not analysis.
# Keep in sync with _MANAGEMENT_TOOLS in worker_provider.py (that set omits
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

# Blocked inside execute to prevent sandbox code from escaping tool boundaries.
_BLOCKED_IN_EXECUTE = MANAGEMENT_TOOLS | frozenset({"search_tools", "execute"})


class ToolInfo(BaseModel):
    """Summary of a discovered tool returned by ``search_tools``."""

    name: str = Field(description="Tool name.")
    description: str = Field(description="Tool description.")


_EXECUTE_DESCRIPTION = """\
Execute Python code that chains multiple IDA tool calls in one block.
Use `await call_tool(name, params)` to invoke tools.
Use `return` to produce output.

**STOP — do NOT wrap a single tool call in execute:**
```
# BAD — pointless overhead, just call decompile_function directly:
r = await call_tool("decompile_function", {"database": db, "address": "0x1234"})
return r
```

**execute is for multi-step pipelines:**
```
# GOOD — chaining tool A output into tool B:
decomp = await call_tool("decompile_function", {"database": db, "address": "0x1234"})
addrs = re.findall(r'sub_([0-9A-Fa-f]+)', decomp["pseudocode"])
xrefs = await asyncio.gather(*[
    call_tool("get_xrefs_to", {"database": db, "address": f"0x{a}"})
    for a in addrs
])
return {"decomp": decomp, "xrefs": xrefs}
```

## Choosing the right call pattern

Need ONE tool with no post-processing?
  → Call the tool directly. Never wrap it in execute.

Need the SAME tool on multiple targets?
  → **Use the tool's batch parameter** (addresses=[...], filters=[...]).
  → Only fall back to execute loops if no batch parameter exists.

Need to chain: tool A's output feeds tool B's input?
  → Use execute. This is what it's for.

Need multiple INDEPENDENT queries in parallel?
  → Use execute with asyncio.gather.

## Batch parameters (always preferred over loops)

- **decompile_function:** pass `addresses=[...]` (up to 50) instead \
of decompiling one at a time. THIS IS ALWAYS PREFERRED over looping \
in execute or making multiple direct calls.
- **get_xrefs_to:** pass `addresses=[...]` (up to 50) with \
`direction='to'/'from'/'both'`. Replaces separate get_xrefs_to and \
get_xrefs_from calls for batch lookups.
- **get_strings:** pass `filters=[...]` (up to 10 patterns in one pass).

**Important:**
- Only IDA analysis tools are callable via `call_tool` inside execute. \
Management tools (open_database, close_database, list_databases, \
wait_for_analysis, save_database) and meta-tools (search_tools, execute) \
must be called directly — they are not available inside execute.
- Every analysis tool requires `database` (the ID from open_database).
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

- **Parallel calls:** use `asyncio.gather` for independent queries:
  ```
  import asyncio
  info, funcs, strings = await asyncio.gather(
      call_tool("get_database_info", {"database": db}),
      call_tool("list_functions", {"database": db}),
      call_tool("get_strings", {"database": db}),
  )
  ```
- **Loops:** iterate patterns or addresses in a single block:
  ```
  results = {}
  for pat in ["encrypt", "decrypt", "aes", "sha"]:
      r = await call_tool("get_strings", {"database": db, "filter_pattern": pat})
      results[pat] = r["items"]
  ```

**Return only what you need.** Filter large results before returning — \
extract specific lines from pseudocode, return summary dicts, not raw \
tool outputs. Large returns waste context in the calling conversation.

**Common tool signatures and return shapes:**

All results include a `database` field. Paginated results include \
`items`, `total`, `offset`, `limit`, `has_more` — always check \
`has_more` and paginate if needed.

```
list_functions(database, offset=0, limit=100, filter_pattern="", \
filter_type="")
  → {items: [{name, start, end, size}], total, offset, limit, has_more}
  filter_type values: "library", "noreturn", "thunk", "user"

decompile_function(database, address=, name=, addresses=[])
  → single: {address, name, pseudocode}
  → batch:  {functions: [{address, name, pseudocode}], errors: [...]}

disassemble_function(database, address)
  → {address, name, instruction_count, instructions: [str]}

get_strings(database, filter_pattern="", filters=[], min_length=4, \
offset=0, limit=100)
  → single: {items: [{address, value, length, type}], total, has_more}
  → batch:  {groups: [{pattern, items, total}], ...}

get_xrefs_to(database, address=, addresses=[], direction="to", \
offset=0, limit=100)
  → single: {address, items: [{from, from_name, type, is_code}], \
total, has_more}
  → batch:  {results: [{address, direction, xrefs: [{ref_address, \
ref_name, type, is_code}], has_more}], errors: [{address, error}], \
cancelled}

find_code_by_string(database, pattern, min_length=4, offset=0, \
limit=100)
  → {results: [{string_address, string_value, function_address, \
function_name}], total_strings_scanned, unique_functions}
  Note: field is "results", not "items".

get_database_info(database)
  → {file_path, processor, bitness, file_type, min_address, \
max_address, entry_point, function_count, segment_count, ...}

list_names(database, filter_pattern="", offset=0, limit=100)
  → {items: [{address, name, is_public, is_weak}], total, has_more}

rename_function(database, address, new_name)
  → {old_name, new_name, address}

set_comment(database, address, comment, is_repeatable=false)
  → {address, comment}

set_decompiler_comment(database, address, comment)
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
    """Return True if code contains loops, conditionals, or data processing."""
    return bool(_PROCESSING_PATTERN.search(code))


def _unwrap_tool_result(result: Any) -> dict[str, Any] | str:
    """Extract the payload from an MCP ``ToolResult``."""
    if result.structured_content is not None:
        return result.structured_content
    return "\n".join(
        content.text if hasattr(content, "text") else str(content) for content in result.content
    )


class IDAToolTransform(CatalogTransform):
    """Hybrid transform: pins common tools, adds search and execute.

    Common analysis tools remain directly callable with full schemas visible.
    Additional tools are discoverable via ``search_tools`` and callable either
    directly by name or through ``execute`` blocks for batching.
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

    # ------------------------------------------------------------------
    # CatalogTransform interface
    # ------------------------------------------------------------------

    async def transform_tools(self, tools: Sequence[Tool]) -> Sequence[Tool]:
        visible = [t for t in tools if t.name in self._pinned]
        return [*visible, self._get_search_tool(), self._get_execute_tool()]

    async def get_tool(
        self,
        name: str,
        call_next: Any,
        *,
        version: Any = None,
    ) -> Tool | None:
        if name == "search_tools":
            return self._get_search_tool()
        if name == "execute":
            return self._get_execute_tool()
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
                    results.append(ToolInfo(name=tool.name, description=tool.description or ""))
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
            ctx: Context | None = None,
        ) -> Any:
            """Execute tool calls using Python code."""
            call_count = 0

            async def call_tool(tool_name: str, params: dict[str, Any]) -> Any:
                nonlocal call_count
                if tool_name in _BLOCKED_IN_EXECUTE:
                    raise IDAError(
                        f"'{tool_name}' cannot be called via execute. "
                        "Management tools and meta-tools must be called directly.",
                        error_type="InvalidOperation",
                    )
                call_count += 1
                result = await ctx.fastmcp.call_tool(tool_name, params)
                return _unwrap_tool_result(result)

            try:
                result = await sandbox.run(
                    code,
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
                    result["_hint"] = hint
                elif isinstance(result, str):
                    result = result + "\n\n" + hint

            return result

        return Tool.from_function(
            fn=execute,
            name="execute",
            description=self._execute_description,
        )
