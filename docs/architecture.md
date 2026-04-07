# Architecture

## Overview

The IDA MCP Server is a headless IDA Pro server that communicates over the Model Context Protocol (MCP) using stdio transport. It uses [idalib](https://docs.hex-rays.com/release-notes/9_0#idalib-ida-as-a-library) — IDA Pro running as a library — to expose IDA's analysis capabilities as structured tool calls that LLMs can invoke.

```
LLM Client  <──stdio──>  ProxyMCP (supervisor.py)
                              │
                              ├── management tools (open/close/save/list_databases)
                              ├── ida://databases resource
                              ├── prompts/
                              │
                              └── WorkerPoolProvider (worker_provider.py)
                                    │
                                    ├── RoutingTool instances (tool proxying)
                                    ├── RoutingTemplate instances (resource proxying)
                                    │
                                    ├──stdio──>  Worker 1 (server.py + tools/*.py + idalib)
                                    └──stdio──>  Worker 2 (server.py + tools/*.py + idalib)
```

For single-database usage, there is one worker. Multiple workers are spawned when `open_database` is called multiple times (the default keeps previously opened databases open).

## Design Decisions

### Why idalib over IDA GUI scripting?

idalib runs IDA Pro as a library within a normal Python process — no GUI, no IDAPython console. This suits headless automation well:

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

idalib is thread-affine: the `idapro` import and all subsequent IDA API calls must happen on the main OS thread. The MCP event loop runs on a daemon background thread, while the main thread runs a `MainThreadExecutor` work queue. The `IDAServer` subclass in `server.py` wraps every sync tool and resource function registered via `@mcp.tool()` or `@mcp.resource()` into an `async def` that dispatches the call to the main thread via `call_ida` (backed by `MainThreadExecutor`). FastMCP sees an async function and skips its own threadpool. This ensures all IDA API calls execute on the main thread while keeping the MCP server responsive. Async tool functions run on the event-loop thread and must use `call_ida` for individual IDA API calls.

Functions in `helpers.py` that contain IDA API calls are marked with `@ida_dispatch`. This decorator tags the function with a `_ida_dispatch` attribute (it does not alter execution) and signals that the function must be invoked via `call_ida` from async code. A pre-commit lint script (`scripts/lint_ida_threading.py`) enforces this: it checks that `@ida_dispatch`-marked functions are not called directly from async functions without going through `call_ida`.

### Import ordering constraint

idalib requires that `import idapro` happen before any `ida_*` module is imported. The package `__init__.py` provides a lazy `bootstrap()` function that handles this:

```python
# src/ida_mcp/server.py (worker entry point)
import ida_mcp
ida_mcp.bootstrap()  # Initialize idalib before any ida_* imports
```

`bootstrap()` first tries a normal `import idapro`. If that fails, it locates the `idapro` wheel from the local IDA installation and adds it to `sys.path`. The supervisor process never calls `bootstrap()`, avoiding the idalib license cost.

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
- The worker's `main()` function calls `session.close(save=True)` in its `finally` block on shutdown
- Signal handlers:
  - `SIGTERM` — raises `SystemExit` (triggers shutdown cleanup and save)
  - `SIGINT` — first press sets IDA's cancellation flag; second press escalates to shutdown
  - `SIGUSR1` — sets the cancellation flag without escalation (used by the supervisor for cooperative cancellation)

### Multi-database supervisor and provider architecture

The supervisor uses FastMCP's native Provider system to expose worker tools and resources through the standard provider chain, rather than overriding `list_tools()`, `call_tool()`, etc.

**`ProxyMCP`** (`supervisor.py`) subclasses `FastMCP`. It creates a `WorkerPoolProvider` and calls `self.add_provider(worker_pool)`. Management tools (`open_database`, `close_database`, `save_database`, `list_databases`, `wait_for_analysis`) and the `ida://databases` resource are registered directly on the `FastMCP` server via its internal `_local_provider`. Prompts are also registered directly (they don't require database state). An `IDAToolTransform` (a `CatalogTransform` subclass defined in `transforms.py`) is applied at the server level. It pins a set of common analysis tools (e.g. `list_functions`, `decompile_function`, `get_strings`) alongside three meta-tools: `search_tools` (regex discovery of all other tools), `execute` (sandboxed Python that chains `await call_tool` invocations for multi-step pipelines and parallel queries), and `batch` (sequential multi-tool execution with per-item error collection). Tools not in the pinned set are hidden from the tool listing but remain callable by name. Management tools delegate to `WorkerPoolProvider` methods for worker lifecycle and are session-aware: `close_database` delegates to `close_for_session()` which atomically detaches and conditionally terminates under `_lock`; `save_database` checks attachment before proceeding. A `_session_id()` helper uses `try_get_context()` (from `context.py`) to extract the session ID without exposing a `ctx` parameter in the tool schema.

**`WorkerPoolProvider`** (`worker_provider.py`) implements FastMCP's `Provider` interface. It manages worker subprocesses (each via a `fastmcp.Client` with `StdioTransport`) and exposes their tools and resources through the provider chain:

- `_list_tools()` / `_get_tool()` return `RoutingTool` instances — `Tool` subclasses constructed from bootstrapped MCP tool schemas. Each `RoutingTool` has the `database` parameter injected into its JSON schema at construction and preserves `output_schema` for structured output passthrough.
- `_list_resource_templates()` / `_get_resource_template()` return `RoutingTemplate` instances — `ResourceTemplate` subclasses that override `_read()` to extract `database` from params, resolve the worker, reconstruct the backend URI, and proxy the read via `client.read_resource_mcp()`. All worker resources (both fixed resources and templates) are exposed as templates with a `{database}` prefix in the URI.
- `RoutingTool.run()` pops `database` from arguments, resolves the target worker, implicitly attaches the current session (if a `Context` is available), and delegates to `proxy_to_worker()` (which tracks active calls via `worker.dispatch()` and calls `worker.client.call_tool_mcp()`). The result is enriched with `database` and returned as a `ToolResult`, or raised as a `ToolError`. Error handling (worker crashes, timeouts) is contained within `proxy_to_worker()`.
- `lifespan()` shuts down all workers on exit.
- `check_attached(worker, session_id)` raises `IDAError` if the session is not attached to the worker (pass-through when session ID is `None` or the worker has no tracked sessions for backward compatibility).
- `close_for_session(worker, session_id, save, force)` atomically checks attachment, detaches, and conditionally terminates under `_lock` — prevents races where a concurrent `attach()` from `RoutingTool.run()` could sneak in between detach and terminate.
- `detach_all(session_id, save=True)` detaches a session from all workers under `_lock`, terminating any whose session set becomes empty; falls back to `shutdown_all()` when session ID is `None`.
- `build_database_list(include_state, caller_session_id)` returns all open databases with metadata; when `caller_session_id` is provided, each entry includes an `attached` flag and `session_count`.

Tool/resource schemas are bootstrapped lazily from a temporary worker on first access. `RoutingTool` and `RoutingTemplate` both set `task_config = TaskConfig(mode="optional")`.

All tools except management tools (`open_database`, `close_database`, `save_database`, `list_databases`, `wait_for_analysis`) require the `database` parameter (the stem ID returned by `open_database`).

#### Background analysis

When `open_database(run_auto_analysis=True)` is called, `spawn_worker()` opens the database without analysis, then starts a background `asyncio.Task` (via `Worker.start_analysis()`) that dispatches `wait_for_analysis` through the normal proxy path. The response includes `"analyzing": true` so the client knows analysis is in progress. While background analysis is running, all tools are blocked except `wait_for_analysis` — the IDA thread is occupied by `auto_wait()`. `wait_for_analysis` blocks until analysis finishes. After analysis completes, worker metadata (function count, etc.) is refreshed via `get_database_info`, and MCP log and resource-list-changed notifications are sent if an `mcp_session` is available. Clients should call `wait_for_analysis` on the database to block until completion rather than polling `list_databases`. Background analysis tasks are cancelled during worker shutdown.

#### Per-worker concurrency

Because idalib is single-threaded, requests to the same worker are serialized by the worker's single-threaded MCP transport. The `dispatch()` async context manager tracks active call count and activity timestamps. Requests to *different* workers run fully in parallel. The `Worker.state` property derives the effective state (BUSY/IDLE) from the `_active_calls` counter rather than requiring manual state transitions. Crashed workers are detected on-demand when tool calls or resource reads encounter connection errors (`ClosedResourceError`, `EndOfStream`, `BrokenPipeError`, `McpError` with connection-closed code) — `proxy_to_worker()` and `RoutingTemplate._read()` call `mark_worker_dead()` to clean up.

#### Session tracking

Workers track which MCP sessions are using them via `attach(session_id)` / `detach(session_id)` / `is_attached(session_id)` / `session_count`. Sessions are attached implicitly when a tool or resource is accessed (via `attach_current_session()`, called from `RoutingTool.run()` and `RoutingTemplate._read()`) and explicitly on `open_database`. `close_database` delegates to `close_for_session()` which atomically checks attachment, detaches, and conditionally terminates under `_lock`. When other sessions are still using the database, it returns a `detached` status instead of terminating. `save_database` and `close_database` check attachment before proceeding (unless `force=True`). When an MCP session disconnects, a cleanup callback registered on the session's exit stack automatically detaches the session from all workers (via `detach_all`), terminating any workers that have no remaining sessions.

Configuration environment variables:
- `IDA_MCP_MAX_WORKERS` — maximum simultaneous databases (1-8, unlimited when unset)
- `IDA_MCP_ALLOW_SCRIPTS` — enables the `run_script` tool for arbitrary IDAPython execution (set to `1`, `true`, or `yes`)
- `IDA_MCP_LOG_LEVEL` — logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`); defaults to `WARNING`, output goes to stderr

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

Addresses are the most common parameter type. The `parse_address` function in `helpers.py` accepts multiple formats to minimize friction for LLM callers. Resolution order:

1. `"0x401000"` — hex with `0x` prefix (unambiguous, tried first)
2. `"4198400"` — decimal (all-digit strings are always decimal)
3. `"main"` — symbol name (resolved via IDA's name database)
4. `"4010a0"` — bare hex fallback (tried last, only if the string contains a-f)

Symbol names are checked before bare hex so that names like `add`, `dead`, or `cafe` resolve to the named symbol rather than being parsed as hexadecimal. Use the `0x` prefix for explicit hex (e.g. `0xADD` instead of `add`).

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

The default limit is 100 for most tools. Some tools use smaller defaults: 50 for batch decompilation/disassembly export and segment listing, 20 for `find_code_by_string`. There is no hard cap — callers can request larger pages when needed.

## Module Organization

### Core modules

| Module | Role |
|--------|------|
| `supervisor.py` | Main entry point (`ida-mcp`) — creates `ProxyMCP(FastMCP)` with `WorkerPoolProvider`, registers management tools and prompts directly |
| `worker_provider.py` | `WorkerPoolProvider(Provider)` — manages worker subprocesses, exposes tools via `RoutingTool(Tool)` and resources via `RoutingTemplate(ResourceTemplate)` through the native provider chain |
| `server.py` | Worker entry point (`ida-mcp-worker`) — creates `IDAServer` (a `FastMCP` subclass), auto-discovers and registers all tool modules from `tools/`, runs stdio transport |
| `session.py` | Database session singleton (per worker), `require_open` decorator |
| `context.py` | `try_get_context()` — idalib-safe FastMCP context accessor, used by both supervisor and workers |
| `exceptions.py` | `IDAError(ToolError)` — structured error type |
| `helpers.py` | Address parsing, formatting, pagination, resolution helpers, string decoding, MCP annotation presets, meta presets, `Annotated` parameter type aliases, `call_ida` main-thread dispatch, `@ida_dispatch` marker |
| `models.py` | Shared Pydantic models used across multiple tool modules (e.g. `PaginatedResult`, `FunctionSummary`, `RenameResult`); tool-specific models live in their respective tool modules. FastMCP derives and emits the JSON schema from return type annotations in tool definitions |
| `transforms.py` | `IDAToolTransform(CatalogTransform)` — pins common tools, adds `search_tools`, `execute`, and `batch` meta-tools, hides the rest from listing while keeping them callable by name |
| `resources.py` | MCP resources — read-only, cacheable context endpoints (static binary data + aggregate statistics) |
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
- All `ida_*` imports are top-level (safe because `server.py` calls `bootstrap()` before importing tool modules). Tool modules are auto-discovered via `pkgutil.iter_modules` — any `tools/*.py` with a `register(mcp)` function is loaded automatically
- `@session.require_open` is applied to all worker tools that need a database (everything except `convert_number`). Management tools (`open_database`, `close_database`, etc.) live on the supervisor, not in worker tool modules
- Every tool has MCP annotations (`ANNO_READ_ONLY`, `ANNO_MUTATE`, `ANNO_MUTATE_NON_IDEMPOTENT`, or `ANNO_DESTRUCTIVE`) and `tags=` for categorical grouping. Tools may also have `meta=` presets (`META_DECOMPILER`, `META_BATCH`, `META_READS_FILES`, `META_WRITES_FILES`) for static metadata
- Use `Annotated` type aliases (`Address`, `Offset`, `Limit`, `FilterPattern`, `OperandIndex`, `HexBytes`) for parameter types — they embed descriptions and validation constraints (e.g. `ge=0`, `ge=1`) directly into the JSON schema
- Tool docstrings are sent to the LLM as tool descriptions — they should be clear and concise
- Tools that accept addresses use `resolve_address` or `resolve_function` from helpers

### Tool module grouping

The tool modules are organized by IDA domain. Some modules contain both read and write operations; the grouping reflects the primary purpose of each module.

**Query-oriented tools** (primarily read operations):
- `functions.py` — function listing, info, disassembly, decompilation, renaming, deletion, bounds
- `xrefs.py` — cross-reference queries, call graphs
- `search.py` — string extraction, byte/text/immediate search, string-to-code reference lookup
- `data.py` — raw byte reading, segment listing, pointer table reading
- `imports_exports.py` — imports, exports, entry points, import name/ordinal modification
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
- `decompiler.py` — pseudocode variable listing/renaming/retyping, microcode, decompiler comments
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

MCP resources provide read-only context about the open database. They are defined in `resources.py` and reserved for genuinely static or aggregate data that benefits from caching:

- **Static binary data** — imports, exports, entry points (baked into the binary, stable), each with a regex search variant
- **Aggregate snapshot** — statistics (function/segment/entry point/string/name counts, code coverage)

The supervisor also owns one resource (`ida://databases`) that lists all open databases with worker state.

### Resource proxying

Worker resources are exposed through `RoutingTemplate` instances in the `WorkerPoolProvider`. Each `RoutingTemplate` stores the original worker URI template as `_backend_uri_template` and presents a prefixed version with `{database}` to clients (e.g. `ida://functions/{addr}` becomes `ida://{database}/functions/{addr}`). At read time, `_read()` pops `database` from the params to resolve the worker, then reconstructs the backend URI from the stored template with the remaining params. The supervisor's own `ida://databases` resource is registered directly on the `FastMCP` server and is served by the internal `_local_provider` — the provider chain handles routing automatically.

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
5. Tool modules are auto-discovered — any `tools/*.py` with a `register()` function is loaded automatically
6. Use helpers from `helpers.py` — `resolve_address`, `resolve_function`, `paginate`, etc.
7. Return Pydantic model instances on success; raise `IDAError` on failure (do not return error dicts)
8. Add any new `ida_*` imports to the `known-third-party` list in `pyproject.toml` under `[tool.ruff.lint.isort]`

## IDA 9 API Notes

- `ida_ida.get_inf_structure()` is **removed** — use free functions: `ida_ida.inf_get_min_ea()`, `ida_ida.inf_get_max_ea()`, `ida_ida.inf_get_start_ea()`, `ida_ida.inf_get_app_bitness()`, `ida_ida.inf_is_64bit()`, etc.
- IDAPython `.so` modules use stable ABI (no cpython version tag) — works with Python 3.12+
- `idapro.open_database(path, run_auto_analysis)` returns 0 on success
- The target binary must be in a writable directory (IDA creates `.i64` alongside it)
- idalib is single-threaded — all calls must be on the thread that imported `idapro`
