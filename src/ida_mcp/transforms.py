# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Hybrid tool transform for the IDA supervisor.

Pins common analysis tools alongside ``search_tools``, ``get_schema``,
``execute``, ``batch``, and ``call`` meta-tools.  Common tools are directly
callable with full schemas visible.  Additional tools are discoverable via
``search_tools`` and callable via ``call`` (single), ``batch`` (multiple),
or ``execute`` (chaining/looping).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import types
import typing
from collections.abc import Sequence
from typing import Annotated, Any, Literal

from fastmcp.exceptions import ValidationError as FastMCPValidationError
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
from pydantic import ValidationError as PydanticValidationError

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

META_TOOLS = frozenset({"search_tools", "get_schema", "execute", "batch", "call"})

ToolDetailLevel = Literal["brief", "detailed", "full"]
"""Detail level for tool description output.

- ``"brief"``: one-line Python-style signature per tool plus its first
  description line (e.g. ``rename_function(address: str, new_name: str) -> RenameResult``)
- ``"detailed"``: compact markdown with full parameter descriptions and
  required markers
- ``"full"``: complete JSON schema
"""


async def run_with_heartbeat(
    task: asyncio.Task[Any],
    ctx: Context | None,
    *,
    interval: float = 5.0,
) -> None:
    """Drive *task* to completion while sending periodic progress notifications.

    Every *interval* seconds a ``report_progress`` notification is sent so that
    MCP clients with per-request timeouts keep the connection alive during long-
    running operations.  Errors from ``report_progress`` are silently swallowed
    — they must never abort the underlying work.  Call ``task.result()`` after
    this returns to retrieve the value or re-raise any exception from the task.
    """
    elapsed = 0.0
    while not task.done():
        done, _ = await asyncio.wait({task}, timeout=interval)
        if not done:
            elapsed += interval
            if ctx is not None:
                with contextlib.suppress(Exception):
                    await ctx.report_progress(elapsed, None)


_JSON_TO_PY_TYPE = {
    "string": "str",
    "integer": "int",
    "number": "float",
    "boolean": "bool",
    "null": "None",
    "object": "dict",
}


def _join_union(labels: Sequence[str]) -> str:
    """Join rendered union branches, collapsing a ``None`` branch into ``X | None``.

    Shared by JSON-schema and Python-annotation renderers so both emit the
    same nullable shape.
    """
    deduped = list(dict.fromkeys(labels))
    non_none = [b for b in deduped if b != "None"]
    if len(non_none) == len(deduped):
        return " | ".join(deduped) if deduped else "any"
    if not non_none:
        return "None"
    return f"{' | '.join(non_none)} | None"


def _type_label(schema: Any) -> str:
    """Compact type label for a JSON schema fragment.

    ``$ref``-aware so Pydantic model parameters render as
    ``FunctionFilter`` rather than ``object``.
    """
    if not isinstance(schema, dict):
        return "any"
    if "$ref" in schema:
        # "#/$defs/FunctionFilter" → "FunctionFilter"
        return schema["$ref"].rsplit("/", 1)[-1]
    t = schema.get("type")
    if t == "array":
        return f"list[{_type_label(schema.get('items'))}]"
    if isinstance(t, str) and t:
        return _JSON_TO_PY_TYPE.get(t, t)
    if isinstance(t, list) and t:
        # JSON Schema list-of-types form: ``{"type": ["string", "null"]}``.
        # Pydantic prefers ``anyOf``, but third-party schemas (or hand-written
        # ones) may emit this shape.  Route through ``_join_union`` so the
        # ``null`` branch collapses to ``| None`` consistently.
        return _join_union([_JSON_TO_PY_TYPE.get(b, b) if isinstance(b, str) else "any" for b in t])
    for key in ("anyOf", "oneOf"):
        branches = schema.get(key)
        if branches:
            return _join_union([_type_label(b) for b in branches])
    all_of = schema.get("allOf")
    if all_of:
        # Pydantic v2 sometimes wraps a ``$ref`` in a single-element ``allOf``
        # (e.g. when attaching a description to a referenced model).  Unwrap
        # so nested models still render by name instead of as ``object``.
        if len(all_of) == 1 and isinstance(all_of[0], dict):
            return _type_label(all_of[0])
        return _join_union([_type_label(b) for b in all_of])
    return "object" if "properties" in schema else "any"


def _render_type_annotation(tp: Any) -> str:
    """Render a Python type annotation using ``typing`` introspection.

    Walks the type structurally via ``typing.get_origin`` / ``get_args`` so
    nested generics, unions (``A | B`` and ``Union[A, B]``), ``Optional``,
    and ``Literal`` all render with class names only — no module prefixes,
    no regex on ``repr``.
    """
    if tp is None or tp is type(None):
        return "None"
    origin = typing.get_origin(tp)
    args = typing.get_args(tp)
    if origin is typing.Union or origin is types.UnionType:
        return _join_union([_render_type_annotation(a) for a in args])
    if origin is typing.Literal:
        return f"Literal[{', '.join(repr(a) for a in args)}]"
    if origin is not None:
        origin_name = getattr(origin, "__name__", None) or str(origin).removeprefix("typing.")
        if args:
            return f"{origin_name}[{', '.join(_render_type_annotation(a) for a in args)}]"
        return origin_name
    if isinstance(tp, type):
        return tp.__name__
    # Forward refs, ``typing.Any``, and other non-class objects: prefer a
    # bare ``__name__`` if the object has one, otherwise strip the ``typing.``
    # module prefix from the repr.  Also strip any other ``foo.bar.`` prefix
    # so fully-qualified class paths collapse to the leaf name.
    name = getattr(tp, "__name__", None)
    if name:
        return name
    rendered = str(tp).removeprefix("typing.")
    return rendered.rsplit(".", 1)[-1] if "." in rendered and "[" not in rendered else rendered


def _format_return_type(tool: Tool) -> str:
    """Render a tool's return type, preferring the Python annotation."""
    rt = getattr(tool, "return_type", None)
    if rt is not None and rt is not type(None):
        return _render_type_annotation(rt)
    if tool.output_schema is not None:
        # Peel FastMCP's ``{"result": ...}`` wrapper for Union/non-object returns.
        schema = tool.output_schema
        if schema.get("x-fastmcp-wrap-result"):
            inner = schema.get("properties", {}).get("result")
            if inner is not None:
                return _type_label(inner)
        return _type_label(schema)
    return "None"


_DEFAULT_STRING_MAX = 32


def _format_default(value: Any) -> str:
    """Render a JSON-schema default value compactly for a signature line.

    Strings round-trip through ``json.dumps`` so embedded quotes/escapes
    stay valid; strings longer than ``_DEFAULT_STRING_MAX`` are truncated
    with an ellipsis inside the quotes (e.g. ``"some long val…"``) so the
    shape of the default stays visible instead of collapsing to ``"..."``.
    """
    if value is None:
        return "None"
    # ``bool`` must be checked before ``int`` because ``isinstance(True, int)``
    # is ``True`` — reordering these branches would silently render booleans
    # as ``1`` / ``0``.
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, str):
        if len(value) > _DEFAULT_STRING_MAX:
            truncated = value[: _DEFAULT_STRING_MAX - 1] + "…"
            return json.dumps(truncated, ensure_ascii=False)
        return json.dumps(value)
    if isinstance(value, (int, float)):
        return json.dumps(value)
    if isinstance(value, list) and not value:
        return "[]"
    if isinstance(value, dict) and not value:
        return "{}"
    return "..."


def _signature_line(tool: Tool) -> str:
    """Build a compact Python-style signature string for a tool."""
    params_schema = tool.parameters if isinstance(tool.parameters, dict) else {}
    props = params_schema.get("properties") or {}
    required = set(params_schema.get("required") or [])
    parts: list[str] = []
    for name, field in props.items():
        type_label = _type_label(field) if isinstance(field, dict) else "any"
        if name in required:
            parts.append(f"{name}: {type_label}")
        elif isinstance(field, dict) and "default" in field:
            parts.append(f"{name}: {type_label} = {_format_default(field['default'])}")
        else:
            # Optional with no declared default — render as `= ...` to avoid
            # falsely advertising a concrete default value.
            parts.append(f"{name}: {type_label} = ...")
    return f"{tool.name}({', '.join(parts)}) -> {_format_return_type(tool)}"


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
        sig = _signature_line(t)
        first_line = (t.description or "").split("\n")[0].strip()
        if first_line:
            lines.append(f"- `{sig}` — {first_line}")
        else:
            lines.append(f"- `{sig}`")
    return "\n".join(lines)


def env_flag(name: str, *, default: bool = False) -> bool:
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

# Tools blocked inside execute/batch.
# This is a manually-maintained subset of MANAGEMENT_TOOLS plus META_TOOLS —
# keep in sync if MANAGEMENT_TOOLS changes.
# - Lifecycle tools (open_database, close_database) create session-scoped side
#   effects that don't compose well inside a call chain.
# - wait_for_analysis and list_targets have no practical use inside execute.
# - Meta-tools (execute, batch, search_tools, get_schema, call) are blocked to
#   prevent nesting/recursion.
# save_database and list_databases are intentionally allowed: the former is
# useful at the end of a mutation-heavy block; the latter enables multi-
# database iteration without hardcoding IDs in the execute block.
_BLOCKED_TOOLS = frozenset(
    {
        "open_database",
        "close_database",
        "wait_for_analysis",
        "list_targets",
        *META_TOOLS,
    }
)


def _check_blocked(tool_name: str, caller: str) -> None:
    """Raise ``InvalidOperation`` if *tool_name* is in the blocked set.

    Shared by ``invoke`` (execute), ``batch``, and ``call`` so the error
    message and check are defined once.
    """
    if tool_name in _BLOCKED_TOOLS:
        raise IDAError(
            f"'{tool_name}' cannot be called via {caller}. "
            "Lifecycle tools and meta-tools must be called directly.",
            error_type="InvalidOperation",
        )


async def _safe_call_tool(
    ctx: Context,
    tool_name: str,
    params: dict[str, Any],
) -> dict[str, Any] | str:
    """Call a tool via ``ctx.fastmcp.call_tool`` with validation-error wrapping.

    Catches Pydantic and FastMCP validation errors and re-raises them as
    :class:`IDAError` with a descriptive message including the tool's
    expected signature.  Used by ``invoke`` (execute), ``batch``, and
    ``call`` to share the error-handling path.
    """
    try:
        result = await ctx.fastmcp.call_tool(tool_name, params)
    except (PydanticValidationError, FastMCPValidationError) as exc:
        raise IDAError(
            await _format_validation_error(exc, tool_name, ctx),
            error_type="InvalidArguments",
        ) from exc
    return _unwrap_tool_result(result)


async def _format_validation_error(
    exc: PydanticValidationError | FastMCPValidationError,
    tool_name: str,
    ctx: Context | None,
) -> str:
    """Format a validation error with the tool's expected signature.

    Produces a message that tells the caller exactly which parameters were
    wrong and what the tool expects.
    """
    parts = [f"Invalid arguments for tool '{tool_name}':"]

    if isinstance(exc, PydanticValidationError):
        for err in exc.errors():
            loc = ".".join(str(part) for part in err["loc"]) if err.get("loc") else ""
            msg = err.get("msg", str(err))
            if loc:
                parts.append(f"  - {loc}: {msg}")
            else:
                parts.append(f"  - {msg}")
    else:
        parts.append(f"  {exc}")

    # Try to look up the tool's signature for context.
    if ctx is not None:
        try:
            tool = await ctx.fastmcp.get_tool(tool_name)
            if tool is not None:
                parts.append("")
                parts.append(f"Expected: {_signature_line(tool)}")
        except Exception:
            pass

    parts.append("")
    parts.append(f'Use get_schema(tools=["{tool_name}"]) for full parameter details.')
    return "\n".join(parts)


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
Run Python code that chains IDA tool calls. Use `await invoke(name, params)` \
to call tools; use `return` to produce output.

`database` is auto-injected into every `invoke` — omit it from params. \
Override per-call with explicit `database` for cross-database work.

## When NOT to use execute

- **Single tool call** → use the **call** meta-tool (or the direct tool if pinned).
<<BATCH_LINE>>\
- Check if a tool has a built-in batch parameter first (e.g. \
get_strings `filters=[...]`).

## When to use execute

**Multi-step pipelines** — chaining one tool's output into another:
```
decomp = await invoke("decompile_function", {"address": "0x1234"})
addrs = re.findall(r'sub_([0-9A-Fa-f]+)', decomp["pseudocode"])
xrefs = [await invoke("get_xrefs_to", {"address": f"0x{a}"}) for a in addrs]
return {"decomp": decomp, "xrefs": xrefs}
```

**Cross-database parallel queries** — use asyncio.gather with explicit \
`database` params. Same-database calls are serialized by the worker.

## Reference

- **Blocked tools:** open_database, close_database, \
wait_for_analysis, list_targets, and meta-tools (<<META_TOOL_LIST>>) \
must be called directly. save_database and list_databases are allowed.
- **Addresses** are strings: "0x401000", "4010a0", or symbol names.
- **filter_pattern** is Python regex — use `re.escape()` for literals.
- **Available imports:** asyncio, collections, functools, itertools, \
json, math, operator, re, struct, typing. No FS/network I/O.
- **Paginated results** have `items`, `total`, `offset`, `limit`, \
`has_more` — always check `has_more`.
<<SCHEMA_HINT>>\
- **Return only what you need** — filter before returning to save context.\
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
    """Hybrid transform: pins common tools, adds search, schema, execute, and batch.

    Common analysis tools remain directly callable with full schemas visible.
    Additional tools are discoverable via ``search_tools`` and callable either
    via ``call`` (single), ``batch`` (multiple), or ``execute`` (chaining).
    """

    def __init__(
        self,
        *,
        pinned: frozenset[str] = PINNED_TOOLS,
        max_search_results: int = 10_000,
        enable_execute: bool | None = None,
        enable_batch: bool | None = None,
        enable_tool_search: bool | None = None,
    ):
        # enable_execute/enable_batch/enable_tool_search: None means "consult
        # IDA_MCP_DISABLE_* env var" (all default to enabled); an explicit bool
        # overrides the env var.
        super().__init__()
        self._enable_execute = (
            not env_flag("IDA_MCP_DISABLE_EXECUTE") if enable_execute is None else enable_execute
        )
        self._enable_batch = (
            not env_flag("IDA_MCP_DISABLE_BATCH") if enable_batch is None else enable_batch
        )
        self._enable_tool_search = (
            not env_flag("IDA_MCP_DISABLE_TOOL_SEARCH")
            if enable_tool_search is None
            else enable_tool_search
        )
        self._pinned = pinned
        self._max_search_results = max_search_results
        self._cached_search_tool: Tool | None = None
        self._cached_schema_tool: Tool | None = None
        self._cached_execute_tool: Tool | None = None
        self._cached_batch_tool: Tool | None = None
        self._cached_call_tool: Tool | None = None

    # ------------------------------------------------------------------
    # CatalogTransform interface
    # ------------------------------------------------------------------

    async def transform_tools(self, tools: Sequence[Tool]) -> Sequence[Tool]:
        if self._enable_tool_search:
            visible = [t for t in tools if t.name in self._pinned]
            out: list[Tool] = [*visible, self._get_search_tool(), self._get_schema_tool()]
        else:
            out = list(tools)
        if self._enable_execute:
            out.append(self._get_execute_tool())
        if self._enable_batch:
            out.append(self._get_batch_tool())
        out.append(self._get_call_tool())
        return out

    async def get_tool(
        self,
        name: str,
        call_next: GetToolNext,
        *,
        version: VersionSpec | None = None,
    ) -> Tool | None:
        if name == "search_tools":
            return self._get_search_tool() if self._enable_tool_search else None
        if name == "get_schema":
            return self._get_schema_tool() if self._enable_tool_search else None
        if name == "execute":
            return self._get_execute_tool() if self._enable_execute else None
        if name == "batch":
            return self._get_batch_tool() if self._enable_batch else None
        if name == "call":
            return self._get_call_tool()
        # Fall through — server resolves hidden tools by name (used by
        # call/batch/execute; many MCP clients refuse to call tools not
        # in their tools/list cache, so the meta-tools provide the bridge).
        return await call_next(name, version=version)

    # ------------------------------------------------------------------
    # search_tools — regex discovery of hidden tools
    # ------------------------------------------------------------------

    def _get_search_tool(self) -> Tool:
        if self._cached_search_tool is None:
            self._cached_search_tool = self._make_search_tool()
        return self._cached_search_tool

    def _make_search_tool(self) -> Tool:
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
                        "'brief' (default) for a one-line signature + summary per tool, "
                        "'detailed' for parameter schemas as markdown, "
                        "'full' for complete JSON schemas"
                    )
                ),
            ] = "brief",
            ctx: Context | None = None,
        ) -> str:
            """Search hidden tools by regex (pinned tools excluded; use ``.*`` for all).

            Returns one-line signatures by default. Use ``detail="detailed"``
            for parameter schemas, or follow up with ``get_schema(tools=[...])``.

            Hidden tools must be called via **call**, **batch**, or **execute**
            — direct calls will fail because they are not in the client tool list.
            """
            catalog = await self.get_tool_catalog(ctx)
            hidden = [t for t in catalog if t.name not in self._pinned]

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
                    if len(matched) >= self._max_search_results:
                        truncated = True
                        break

            result = _render_tools_at_detail(matched, detail)
            if truncated:
                result += (
                    f"\n\n(Results capped at {self._max_search_results}."
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
        async def get_schema(
            tools: Annotated[
                list[str],
                Field(description="Tool names to get schemas for."),
            ],
            detail: Annotated[
                ToolDetailLevel,
                Field(
                    description=(
                        "'brief' for a one-line signature + summary per tool, "
                        "'detailed' for parameter schemas as markdown (default), "
                        "'full' for complete JSON schemas"
                    )
                ),
            ] = "detailed",
            ctx: Context | None = None,
        ) -> str:
            """Get parameter schemas for specific tools by name (pinned and hidden).

            Use after search_tools or before execute/batch to check parameter
            types and return shapes. Pass ``detail="full"`` for complete JSON schemas.

            Hidden tools must be called via **call**, **batch**, or **execute**
            — direct calls will fail because they are not in the client tool list.
            """
            catalog = await self.get_tool_catalog(ctx)
            # get_tool_catalog bypasses transform_tools, so meta-tools are
            # not included.  Merge them in manually so callers can look up
            # search_tools, get_schema, execute, and batch by name.
            meta: list[Tool] = [
                self._get_search_tool(),
                self._get_schema_tool(),
            ]
            if self._enable_execute:
                meta.append(self._get_execute_tool())
            if self._enable_batch:
                meta.append(self._get_batch_tool())
            meta.append(self._get_call_tool())
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
    # execute — sandboxed Python with invoke for chaining
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
                        "Python async code to execute tool calls via invoke(name, arguments)"
                    )
                ),
            ],
            database: Annotated[
                str,
                Field(
                    description=(
                        "Database to target (stem ID from open_database). "
                        "Available as `database` variable in code and "
                        "auto-injected into invoke params. Individual "
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

            async def invoke(tool_name: str, params: dict[str, Any]) -> Any:
                nonlocal call_count
                _check_blocked(tool_name, "execute")
                if "database" not in params:
                    params = {**params, "database": database}
                call_count += 1
                return await _safe_call_tool(ctx, tool_name, params)

            sandbox_task = asyncio.create_task(
                sandbox.run(
                    code,
                    inputs={"database": database},
                    external_functions={"invoke": invoke},
                )
            )
            await run_with_heartbeat(sandbox_task, ctx)

            try:
                result = sandbox_task.result()
            except SyntaxError as exc:
                raise IDAError(str(exc), error_type="SyntaxError") from exc
            except IDAError:
                raise
            except Exception as exc:
                raise IDAError(str(exc)) from exc

            if call_count == 1 and not _has_processing_logic(code):
                hint = (
                    "Hint: this execute block contained a single invoke with "
                    "no processing. Use the **call** meta-tool instead for "
                    "single tool calls (or the direct tool if it is pinned)."
                )
                if isinstance(result, dict):
                    result = {**result, "_hint": hint}
                elif isinstance(result, str):
                    result = result + "\n\n" + hint

            return result

        if self._enable_batch:
            batch_line = (
                "- **N independent calls** → use `batch` "
                "(lower overhead, per-item errors).\n"
                "  → Otherwise, use the **batch** meta-tool for sequential "
                "multi-tool\n    execution with per-item error collection and "
                "progress reporting.\n"
            )
        else:
            batch_line = ""
        meta_parts = []
        if self._enable_tool_search:
            meta_parts += ["search_tools", "get_schema"]
        meta_parts.append("execute")
        if self._enable_batch:
            meta_parts.append("batch")
        meta_parts.append("call")
        meta_tool_list = ", ".join(meta_parts)
        schema_hint = (
            "- Use `get_schema(tools=[...])` to look up parameter names and types.\n"
            if self._enable_tool_search
            else ""
        )
        description = (
            _EXECUTE_DESCRIPTION_PREAMBLE.replace("<<BATCH_LINE>>", batch_line)
            .replace("<<META_TOOL_LIST>>", meta_tool_list)
            .replace("<<SCHEMA_HINT>>", schema_hint)
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
            ] = True,
            ctx: Context | None = None,
        ) -> BatchResult:
            """Run 2+ independent tool calls in a single request with per-item error collection.

            Preferred over `execute` for independent calls (no sandbox overhead).
            Examples: decompile/disassemble N functions, rename N symbols, set N
            comments, fetch N xrefs.

            Use `execute` only when chaining one tool's output into another.

            `database` is auto-injected into each operation — omit from params.
            Override per-operation with explicit `database` for cross-DB work.
            """
            if ctx is None:
                raise IDAError("batch requires an MCP context")

            results: list[BatchItemResult] = []
            succeeded = failed = 0
            cancelled = False

            try:
                for i, op in enumerate(operations):
                    try:
                        _check_blocked(op.tool, "batch")
                        params = op.params
                        if "database" not in params:
                            params = {**params, "database": database}
                        payload = await _safe_call_tool(ctx, op.tool, params)
                        results.append(BatchItemResult(index=i, tool=op.tool, result=payload))
                        succeeded += 1
                    except Exception as exc:
                        results.append(BatchItemResult(index=i, tool=op.tool, error=str(exc)))
                        failed += 1

                    if i + 1 < len(operations):
                        await ctx.report_progress(i + 1, len(operations))

                    if stop_on_error and failed:
                        cancelled = True
                        break
            except asyncio.CancelledError:
                cancelled = True

            batch_result = BatchResult(
                results=results,
                succeeded=succeeded,
                failed=failed,
                cancelled=cancelled,
            )

            # Raise when any operation failed so the MCP response has
            # isError=True — otherwise the client sees a "successful" call
            # with errors buried in the results array.
            if failed > 0:
                raise IDAError(
                    batch_result.model_dump_json(),
                    error_type="BatchFailed",
                )

            return batch_result

        return Tool.from_function(fn=batch, name="batch")

    # ------------------------------------------------------------------
    # call — lightweight proxy for calling any tool by name
    # ------------------------------------------------------------------

    def _get_call_tool(self) -> Tool:
        if self._cached_call_tool is None:
            self._cached_call_tool = self._make_call_tool()
        return self._cached_call_tool

    def _make_call_tool(self) -> Tool:
        async def call(
            tool: Annotated[
                str,
                Field(description="Tool name to call."),
            ],
            arguments: Annotated[
                dict[str, Any],
                Field(default_factory=dict, description="Arguments to pass to the tool."),
            ],
            database: Annotated[
                str,
                Field(
                    description=(
                        "Database to target (stem ID from open_database). "
                        "Auto-injected into arguments unless already present."
                    ),
                ),
            ] = "",
            ctx: Context | None = None,
        ) -> dict[str, Any] | str:
            """Call any tool by name, including hidden tools not in the client tool list.

            Use for single hidden-tool calls. For multiple calls, prefer **batch**.
            """
            if ctx is None:
                raise IDAError("call requires an MCP context")
            _check_blocked(tool, "call")
            params = dict(arguments)
            if database and "database" not in params:
                params["database"] = database
            return await _safe_call_tool(ctx, tool, params)

        return Tool.from_function(fn=call, name="call")
