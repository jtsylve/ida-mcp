# Architecture

This document describes the architecture and design decisions behind the IDA MCP Server.

## Overview

The IDA MCP Server is a headless IDA Pro server that communicates over the Model Context Protocol (MCP) using stdio transport. It uses [idalib](https://docs.hex-rays.com/release-notes/9_0#idalib-ida-as-a-library) — IDA Pro running as a library — to expose IDA's analysis capabilities as structured tool calls that LLMs can invoke.

```
LLM Client  <──stdio──>  ProxyMCP (supervisor.py)
                              |
                              +──stdio──>  Worker 1 (server.py + tools/*.py + idalib)
                              +──stdio──>  Worker 2 (server.py + tools/*.py + idalib)
```

For single-database usage, there is one worker. Multiple workers are spawned when `open_database` is called multiple times (the default keeps previously opened databases open).

## Design Decisions

### Why idalib over IDA GUI scripting?

idalib runs IDA Pro as a library within a normal Python process — no GUI, no IDAPython console. This is a good fit for headless automation:

- No X11/display dependencies
- Process lifecycle is controlled by the server, not the IDA GUI
- Direct function calls instead of script injection

The trade-off is that idalib is **single-threaded**: all IDA API calls must happen on the same thread that imported `idapro`. Each worker process handles a single database; the supervisor routes requests to the correct worker via stdio pipes.

### Why FastMCP?

[FastMCP](https://gofastmcp.com) provides a decorator-based API for defining MCP tools. Each tool is a plain Python function with type annotations — FastMCP handles JSON schema generation, argument validation, and transport.

The server uses stdio transport (not SSE/HTTP) because:
- MCP clients like Claude Desktop expect stdio
- No port management or auth needed
- Process lifecycle is tied to the client session

### Main-thread execution (`IDAServer`)

idalib is thread-affine: the `idapro` import and all subsequent IDA API calls must happen on the main OS thread. FastMCP v3 dispatches sync tool functions via `anyio.to_thread.run_sync`, which runs them on arbitrary pool threads. The `IDAServer` subclass in `server.py` solves this by wrapping every sync tool and resource function registered via `@mcp.tool()` or `@mcp.resource()` into an `async def` that calls the original function directly on the event-loop thread (which is the main thread). FastMCP sees an async function and skips its own threadpool. Blocking the event loop is acceptable because each worker handles one database and the supervisor serializes requests per worker.

### Import ordering constraint

idalib requires that `import idapro` happen before any `ida_*` module is imported. The package `__init__.py` provides a lazy `bootstrap()` function that handles this:

```python
# src/ida_mcp/server.py (worker entry point)
import ida_mcp
ida_mcp.bootstrap()  # Initialize idalib before any ida_* imports
```

`bootstrap()` first tries a normal `import idapro`. If that fails, it locates the idalib wheel from the local IDA installation and adds it to `sys.path`. The supervisor process never calls `bootstrap()`, avoiding the idalib license cost.

After `bootstrap()` runs, `ida_*` imports can be top-level in all other modules — they're guaranteed to run after `idapro` has initialized the IDA kernel.

### Session singleton

The `Session` class in `session.py` manages the idalib database connection within each worker process:

```python
session = Session()  # module-level singleton (one per worker process)
```

Key behaviors:
- Each worker process handles one database (idalib is single-threaded with global state)
- Opening a new database auto-closes the previous one (with save)
- `session.require_open` is a decorator that raises `IDAError` if no database is open. Since `IDAError` subclasses fastmcp's `ToolError`, fastmcp automatically returns `isError=True` with the message as text content
- The decorator also clears IDA's cancellation flag before each call and catches `Cancelled` exceptions, re-raising them as `IDAError`
- An `atexit` hook calls `session.close(save=True)` on process exit. Signal handlers: `SIGTERM` raises `SystemExit` (triggers atexit save); `SIGINT` sets IDA's cancellation flag on first press, escalates to shutdown on second; `SIGUSR1` sets the cancellation flag without escalation (used by the supervisor for cooperative cancellation)

### Multi-database supervisor

The `ProxyMCP` class in `supervisor.py` subclasses `FastMCP` and manages multiple worker subprocesses. Each worker is managed via a `fastmcp.Client` with `StdioTransport` — the Client handles the subprocess connection lifecycle (session task, initialization, cleanup) while the supervisor handles routing, schema augmentation, and worker state management. The supervisor overrides `list_tools()`, `call_tool()`, `list_resources()`, `list_resource_templates()`, and `read_resource()`:

- `list_tools()` injects a required `database` property into every worker tool's JSON schema
- `call_tool()` extracts the `database` argument, resolves the target worker, and delegates to `_proxy_to_worker()`
- `_proxy_to_worker()` centralizes the dispatch-with-error-handling pattern: acquires the per-worker semaphore, sends the call via `client.call_tool_mcp()`, and translates transport/protocol errors into structured `CallToolResult` responses
- `list_resources()` returns supervisor-owned resources only; worker resources are exposed as templates via `list_resource_templates()` (with a `{database}` prefix in the URI)
- `read_resource()` routes reads to the supervisor or the appropriate worker via `client.read_resource_mcp()`; the database prefix is stripped before forwarding
- Prompts are registered directly on the supervisor (they don't require database state)

All tools require the `database` parameter (the stem ID returned by `open_database`) except `open_database`, `list_databases`, and `show_all_tools`.

#### Per-worker concurrency

Because idalib is single-threaded, requests to the same worker must be serialized. Each `Worker` has a per-worker semaphore, acquired via its `dispatch()` async context manager, which also tracks busy/activity state. Requests to *different* workers run fully in parallel. The `Worker.state` property derives the effective state (BUSY/IDLE) from the `_busy_since` timestamp rather than requiring manual state transitions.

Configuration environment variables:
- `IDA_MCP_MAX_WORKERS` — maximum simultaneous databases (1-8, unlimited when unset)
- `IDA_MCP_IDLE_TIMEOUT` — seconds before an idle database is auto-closed (default 1800, 0 to disable)
- `IDA_MCP_ALLOW_SCRIPTS` — enables the `run_script` tool for arbitrary IDAPython execution (set to `1`, `true`, or `yes`)

### Error handling convention

Tools return Pydantic model instances on success (FastMCP serializes these automatically). On failure, they raise `IDAError` (a subclass of fastmcp's `ToolError`). FastMCP catches `ToolError` and returns `isError=True` with the error text as content — tools never return error dicts directly.

`IDAError.__str__` returns a JSON object with `error`, `error_type`, and optional detail fields (e.g. `available_variables`, `valid_types`). This keeps the MCP error text machine-parseable while preserving a structured error taxonomy. Common error types include:

- `NoDatabase` — no database is open
- `InvalidAddress` — could not parse/resolve address
- `NotFound` — function, type, or symbol not found
- `DecompilationFailed` — Hex-Rays decompilation error
- `InvalidArgument` — bad parameter value
- `Cancelled` — operation cancelled via cooperative cancellation

Individual tools define additional error types specific to their domain (e.g. `ParseError`, `DecodeFailed`, `SetCommentFailed`).

Mutation tools return the previous state of modified items (e.g. `old_comment`, `old_type`, `old_bytes`, `old_flags`) alongside the new values, enabling undo tracking and change verification by the LLM.

### Address resolution

Addresses are the most common parameter type. The `parse_address` function in `helpers.py` accepts multiple formats to minimize friction for LLM callers:

- `"0x401000"` — hex with prefix
- `"4010a0"` — bare hex (must contain a-f; all-digit strings are decimal)
- `"4198400"` — decimal
- `"main"` — symbol name (resolved via IDA's name database)

Higher-level helpers build on this:
- `resolve_address(addr)` → `int` (raises `IDAError` on failure)
- `resolve_function(addr)` → `func_t` (raises `IDAError`)
- `decompile_at(addr)` → `(cfunc, func_t)` (raises `IDAError`)
- `decode_insn_at(ea)` → `insn_t` (raises `IDAError`)
- `resolve_segment(addr)` → `segment_t` (raises `IDAError`)
- `resolve_struct(name)` → `int` (raises `IDAError`)
- `resolve_enum(name)` → `int` (raises `IDAError`)

Each raises `IDAError` on failure, so tool implementations avoid manual error-checking.

### Pagination

List-returning tools use `paginate(items, offset, limit)`, `paginate_iter(items, offset, limit)`, or `async_paginate_iter(items, offset, limit)` from `helpers.py`. `paginate_iter` works on generators without materializing the full list. `async_paginate_iter` adds progress reporting via `ctx.report_progress()`. Tools that build lists eagerly (e.g. `get_imports`, `get_segments`, `get_enum_members`) use `paginate` instead. All three produce the same response shape:

```python
{
    "items": [...],
    "total": 1500,
    "offset": 0,
    "limit": 100,
    "has_more": True
}
```

The default limit is 100 for most tools. A few tools default to 50 (batch decompilation/disassembly export, segment listing). There is no hard cap — callers can request larger pages when needed.

## Module Organization

### Core modules

| Module | Role |
|--------|------|
| `supervisor.py` | Main entry point (`ida-mcp`) — spawns workers via `fastmcp.Client` + `StdioTransport`, proxies tool/resource calls, registers prompts directly, manages multi-database routing |
| `server.py` | Worker entry point (`ida-mcp-worker`) — creates `IDAServer` (a `FastMCP` subclass), registers tools/resources, runs stdio transport |
| `session.py` | Database session singleton (per worker), `require_open` decorator |
| `exceptions.py` | `IDAError(ToolError)` — structured error type; `DEFAULT_TOOL_TIMEOUT` / `SLOW_TOOL_TIMEOUTS` — centralized timeout constants shared by workers and supervisor |
| `helpers.py` | Address parsing, formatting, pagination, resolution helpers, string decoding, MCP annotation presets, meta presets, `Annotated` parameter type aliases |
| `models.py` | Shared Pydantic models used across multiple tool modules (e.g. `PaginatedResult`, `FunctionSummary`, `RenameResult`); tool-specific models live in their respective tool modules. FastMCP derives and emits the JSON schema from return type annotations in tool definitions |
| `resources.py` | MCP resources — read-only, cacheable context endpoints organized in four tiers |
| `prompts/` | MCP prompt templates for guided analysis workflows (analysis, security, workflow) |
| `__init__.py` | Lazy `bootstrap()` function to initialize idapro |

### Tool modules (`tools/`)

Each tool module follows the same pattern:

```python
from ida_mcp.helpers import ANNO_READ_ONLY, Address, Limit, Offset

def register(mcp: FastMCP):
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"domain"})
    @session.require_open
    def my_tool(address: Address, offset: Offset = 0, limit: Limit = 100) -> MyToolResult:
        """Tool description for LLM consumption.

        Args:
            address: Address of the thing.
        """
        # Implementation using ida_* APIs
        return MyToolResult(result="...")
```

Key conventions:
- All `ida_*` imports are top-level (safe because `server.py` calls `bootstrap()` before importing tool modules)
- `@session.require_open` is applied to all tools that need a database (everything except `open_database`, `close_database`, and `convert_number`)
- Every tool has MCP annotations (`ANNO_READ_ONLY`, `ANNO_MUTATE`, `ANNO_MUTATE_NON_IDEMPOTENT`, or `ANNO_DESTRUCTIVE`) and `tags=` for categorical grouping. Tools may also have `meta=` presets (`META_DECOMPILER`, `META_BATCH`, `META_READS_FILES`, `META_WRITES_FILES`) for static metadata
- Use `Annotated` type aliases (`Address`, `Offset`, `Limit`, `FilterPattern`, `OperandIndex`, `HexBytes`) for parameter types — they embed descriptions and validation constraints (e.g. `ge=0`, `ge=1`) directly into the JSON schema
- For slow tools, add an entry to `SLOW_TOOL_TIMEOUTS` in `exceptions.py` and pass `timeout=tool_timeout("name")` to `@mcp.tool()`
- Tool docstrings are sent to the LLM as tool descriptions — they should be clear and concise
- Tools that accept addresses use `resolve_address` or `resolve_function` from helpers

### Tool module grouping

The tool modules are organized by IDA domain. Some modules contain both read and write operations; the grouping reflects the primary purpose of each module.

**Query-oriented tools** (primarily read operations):
- `functions.py` — function listing, info, disassembly, decompilation, renaming, deletion
- `xrefs.py` — cross-reference queries, call graphs
- `search.py` — string/byte/text/immediate search, function pattern search
- `data.py` — raw byte reading, segment listing
- `imports_exports.py` — imports, exports, entry points
- `cfg.py` — basic blocks, CFG edges
- `operands.py` — instruction decoding, operand value resolution
- `frames.py` — stack frames, local variables
- `ctree.py` — Hex-Rays AST exploration
- `processor.py` — architecture info, instruction classification, instruction set listing
- `switches.py` — switch/jump table analysis
- `regfinder.py` — register value tracking
- `nalt.py` — address metadata: source line numbers, analysis flags, library item marking
- `analysis.py` — auto-analysis control, analysis problems, fixups, exception handlers, segment registers
- `export.py` — batch decompilation/disassembly export, output file generation, executable rebuilding

**Mutation-oriented tools** (primarily write operations):
- `database.py` — database lifecycle, metadata, flags, file region mapping
- `chunks.py` — function chunk (tail) listing and management
- `patching.py` — byte patching, function/code creation, undefine
- `assemble.py` — instruction assembly
- `comments.py` — comment management
- `names.py` — address renaming
- `types.py`, `typeinf.py` — type application and local type management
- `function_type.py` — function prototypes and calling conventions
- `structs.py` — structure CRUD
- `enums.py` — enum CRUD
- `decompiler.py` — pseudocode variable renaming/retyping, microcode, decompiler comments
- `operand_repr.py` — operand display changes
- `segments.py`, `rebase.py` — segment manipulation
- `xref_manip.py` — cross-reference manipulation
- `entry_manip.py` — entry point addition, renaming, and forwarders
- `makedata.py` — data type definition
- `load_data.py` — loading bytes into database
- `func_flags.py` — function flag and hidden range management
- `regvars.py` — register variable add/delete/rename/comment
- `srclang.py` — source declaration parsing (C, C++, Objective-C, Swift, Go) via compiler parsers

**Utility tools**:
- `utility.py` — number conversion, IDC evaluation, script execution
- `bookmarks.py` — bookmark management
- `colors.py` — address/function coloring
- `undo.py` — undo/redo
- `snapshots.py` — database snapshot take/list/restore
- `dirtree.py` — IDA directory tree management
- `signatures.py`, `sig_gen.py` — FLIRT signatures, type libraries, IDS modules
- `demangle.py` — C++ name demangling

## Resources

MCP resources provide read-only, cacheable context about the open database without consuming tool calls. They are defined in `resources.py` and organized in four tiers:

- **Tier 1 — Core Context:** database metadata, paths, processor, segments, entry points, imports, exports
- **Tier 2 — Structural Reference:** local types, structs, enums, FLIRT signatures, type libraries
- **Tier 3 — Browsable Collections:** strings, functions, names, bookmarks, statistics
- **Tier 4 — Per-Entity:** parameterized resources for individual functions (`ida://functions/{addr}`), stack frames, exceptions, variables, and cross-references

The supervisor also owns one resource (`ida://databases`) that lists all open databases with worker state.

### Resource proxying

The supervisor proxies resource reads to the appropriate worker. It bootstraps worker resource schemas alongside tool schemas in `_bootstrap_worker_schemas()`, and routes `read_resource` calls by checking whether the URI matches a supervisor-owned resource or should be forwarded to a worker.

## Prompts

MCP prompts provide guided analysis workflow templates. They are defined in `prompts/` with modules for different domains:

- `analysis.py` — binary triage (`survey_binary`), function analysis (`analyze_function`), before/after diff (`diff_before_after`), function classification (`classify_functions`)
- `security.py` — cryptographic constant scanning (`find_crypto_constants`)
- `workflow.py` — string-based rename suggestions (`auto_rename_strings`), ABI type application (`apply_abi`), annotation export script generation (`export_idc_script`)

Prompts are registered only on the supervisor (directly in `supervisor.py`). Workers do not register or handle prompts.

## Adding a New Tool

1. Create `src/ida_mcp/tools/newtool.py` with a `register(mcp: FastMCP)` function
2. Define tool functions inside `register()` using `@mcp.tool()` and `@session.require_open`
3. Add `annotations=` (`ANNO_READ_ONLY`, `ANNO_MUTATE`, `ANNO_MUTATE_NON_IDEMPOTENT`, or `ANNO_DESTRUCTIVE`) and `tags=` to `@mcp.tool()`
4. Use `Annotated` type aliases for parameters: `Address`, `Offset`, `Limit`, `FilterPattern`, `OperandIndex`, `HexBytes`
5. For slow tools, add an entry to `SLOW_TOOL_TIMEOUTS` in `exceptions.py` and pass `timeout=tool_timeout("tool_name")` to `@mcp.tool()`
6. Import and call `newtool.register(mcp)` in `server.py`
7. Use helpers from `helpers.py` — `resolve_address`, `resolve_function`, `paginate`, etc.
8. Return Pydantic model instances on success; raise `IDAError` on failure (do not return error dicts)
9. Add any new `ida_*` imports to the `known-third-party` list in `pyproject.toml` under `[tool.ruff.lint.isort]`

## IDA 9 API Notes

- `ida_ida.get_inf_structure()` is **removed** — use free functions: `ida_ida.inf_get_min_ea()`, `ida_ida.inf_get_max_ea()`, `ida_ida.inf_get_start_ea()`, `ida_ida.inf_get_app_bitness()`, `ida_ida.inf_is_64bit()`, etc.
- IDAPython `.so` modules use stable ABI (no cpython version tag) — works with Python 3.12+
- `idapro.open_database(path, run_auto_analysis)` returns 0 on success
- The target binary must be in a writable directory (IDA creates `.i64` alongside it)
- idalib is single-threaded — all calls must be on the thread that imported `idapro`
