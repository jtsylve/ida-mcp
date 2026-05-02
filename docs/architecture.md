# Architecture

## Overview

The IDA MCP Server is a headless IDA Pro server that communicates over the Model Context Protocol (MCP). It uses [idalib](https://docs.hex-rays.com/release-notes/9_0#idalib-ida-as-a-library) — IDA Pro running as a library — to expose IDA's analysis capabilities as structured tool calls that LLMs can invoke.

The project is a monorepo with three packages:
- **`re-mcp-core`** (`packages/re-mcp-core/src/re_mcp/`) — generic MCP supervisor infrastructure (transport, worker management, tool transforms, sandboxed execution)
- **`ida-mcp`** (`packages/ida-mcp/src/ida_mcp/`) — IDA-specific backend (idalib bootstrap, tools, resources, prompts)
- **`ghidra-mcp`** (`packages/ghidra-mcp/src/ghidra_mcp/`) — Ghidra-specific backend (pyhidra bootstrap, tools, resources, prompts)

The server supports three transport modes:

```
# Default: stdio proxy → persistent HTTP daemon (workers survive reconnects)
LLM Client  <──stdio──>  Proxy (re_mcp.proxy)  <──HTTP──>  Daemon (re_mcp.daemon)
                                                                │
                                                            ProxyMCP (re_mcp.supervisor)
                                                                │
                                                                └── WorkerPoolProvider
                                                                      ├──stdio──>  Worker 1
                                                                      └──stdio──>  Worker 2

# Direct stdio: single-session, workers die on disconnect
LLM Client  <──stdio──>  ProxyMCP (re_mcp.supervisor)
                              └── WorkerPoolProvider
                                    ├──stdio──>  Worker 1
                                    └──stdio──>  Worker 2
```

The **default mode** (`ida-mcp` or `ida-mcp proxy`) runs a stdio-to-HTTP proxy that auto-spawns a persistent background daemon. The daemon runs `ProxyMCP` (from `re_mcp.supervisor`) over streamable HTTP with bearer token authentication, so worker processes and database state survive client reconnections. The proxy bridges stdio MCP messages bidirectionally to the daemon.

The **serve mode** (`ida-mcp serve`) runs the daemon directly (used by the proxy's auto-spawn, or for manual daemon management).

The **stdio mode** (`ida-mcp stdio`) runs the supervisor directly over stdio — workers die when the client disconnects. This is the simplest mode, suitable for single-session usage.

The **stop command** (`ida-mcp stop`) gracefully shuts down a running daemon.

For single-database usage, there is one worker. Multiple workers are spawned when `open_database` is called multiple times (the default keeps previously opened databases open).

## Design Decisions

### Why idalib over the IDA GUI and plugins?

idalib runs IDA Pro as a library within a normal Python process — no GUI, no IDAPython console. Benefits for headless automation:

- No X11/display dependencies
- Process lifecycle is controlled by the server, not the IDA GUI
- Direct function calls instead of script injection

The trade-off is that idalib is **single-threaded**: all IDA API calls must happen on the same thread that imported `idapro`. Each worker process handles a single database; the supervisor routes requests to the correct worker via stdio pipes.

### Why FastMCP?

[FastMCP](https://gofastmcp.com) provides a decorator-based API for defining MCP tools. Each tool is a plain Python function with type annotations — FastMCP handles JSON schema generation, argument validation, and transport.

The direct stdio mode uses stdio transport because:
- stdio is the most widely supported transport across MCP clients (Claude Desktop, Cursor, etc.)
- No port management or auth needed
- Process lifecycle is tied to the client session

### Persistent daemon architecture

The default transport mode runs a persistent HTTP daemon behind a stdio proxy. This solves a key problem with direct stdio: when the MCP client disconnects (e.g. the user closes their editor), the supervisor and all worker processes die, losing database state and analysis progress.

The daemon (`re_mcp.daemon`) runs `ProxyMCP` over FastMCP's streamable HTTP transport with bearer token authentication. It writes a state file containing the host, bound port, bearer token, PID, and version. The state file location is platform-specific: `~/Library/Application Support/ida-mcp/daemon.json` on macOS, `$XDG_STATE_HOME/ida-mcp/daemon.json` (defaulting to `~/.local/state/ida-mcp/daemon.json`) on Linux, and `%LOCALAPPDATA%\ida-mcp\daemon.json` on Windows. The state file is created atomically with restricted permissions (0o600) and cleaned up on shutdown.

The proxy (`re_mcp.proxy`) is the default entry point. It checks for an existing daemon via the state file and process liveness, spawns one if needed (with a file lock to prevent races between concurrent clients), and bridges stdio MCP messages to the daemon's HTTP endpoint using `mcp.client.streamable_http`. The daemon process is fully detached (new session on Unix, `CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP` on Windows) so it survives the proxy's exit.

When auto-spawned by the proxy, the daemon enables idle auto-shutdown (default 300 seconds, configurable via `IDA_MCP_IDLE_TIMEOUT`). An `_idle_monitor` coroutine runs alongside the uvicorn server, polling every 10 seconds. When uvicorn has no active connections, the provider has no registered MCP sessions, no worker calls are in flight, and no proxy keepalive is active — all for the idle timeout duration — the monitor sets `server.should_exit = True` to trigger a graceful shutdown. The provider's lifespan then terminates all workers via `shutdown_all()`, and the daemon's `finally` block removes the state file. The idle timer resets whenever activity resumes. Daemons started manually via `ida-mcp serve` do not enable idle shutdown by default (`--idle-timeout=0`); pass `--idle-timeout=N` to opt in.

Security: the bearer token is a 256-bit random hex string generated per daemon lifetime. Only the spawning proxy and the daemon know the token. The daemon binds to `127.0.0.1` by default; binding to non-loopback addresses emits a warning.

### Main-thread execution (`IDAServer`)

idalib is thread-affine: the `idapro` import and all subsequent IDA API calls must happen on the main OS thread. The MCP event loop runs on a background thread (a Python `daemon=True` thread, unrelated to the persistent HTTP daemon), while the main thread runs a `MainThreadExecutor` work queue.

The `IDAServer` subclass in `ida_mcp.server` wraps every sync tool and resource function registered via `@mcp.tool()` or `@mcp.resource()` into an `async def` that dispatches the call to the main thread via `call_ida` (backed by `MainThreadExecutor`). FastMCP sees an async function and skips its own threadpool, so all IDA API calls land on the main thread while the MCP server remains responsive. Async tool functions run on the event-loop thread and must use `call_ida` for individual IDA API calls.

Functions in `ida_mcp.helpers` that contain IDA API calls are marked with `@ida_dispatch`. This decorator tags the function with a `_ida_dispatch` attribute (it does not alter execution) and signals that the function must be invoked via `call_ida` from async code. A pre-commit lint script (`scripts/lint_ida_threading.py`) enforces this: it checks that `@ida_dispatch`-marked functions are not called directly from async functions without going through `call_ida`.

### Import ordering constraint

idalib requires that `import idapro` happen before any `ida_*` module is imported. The `ida_mcp.__init__` module provides a lazy `bootstrap()` function that handles this:

```python
# packages/ida-mcp/src/ida_mcp/server.py (worker entry point)
import ida_mcp
ida_mcp.bootstrap()  # Initialize idalib before any ida_* imports
```

`bootstrap()` first tries a normal `import idapro`. If that fails, it locates the `idapro` wheel from the local IDA installation and adds it to `sys.path`. The supervisor process never calls `bootstrap()`, avoiding the idalib license cost.

After `bootstrap()` runs, `ida_*` imports can be top-level in all other modules — they're guaranteed to run after `idapro` has initialized the IDA kernel.

### Session singleton

The `Session` class in `ida_mcp.session` manages the idalib database connection within each worker process:

```python
session = Session()  # module-level singleton (one per worker process)
```

Key behaviors:
- Each worker process handles one database (idalib is single-threaded with global state)
- Calling `Session.open()` on a worker that already has a database open auto-closes the previous one with save (the supervisor spawns a fresh worker per database, so this path is only hit in standalone worker use)
- `session.require_open` is a decorator that raises `IDAError` if no database is open. Since `IDAError` subclasses `BackendError` (which subclasses FastMCP's `ToolError`), FastMCP automatically returns `isError=True` with the message as text content
- The decorator also clears IDA's cancellation flag before each call and catches `Cancelled` exceptions, re-raising them as `IDAError`
- The worker's `main()` function calls `session.close(save=True)` in its `finally` block on shutdown
- Signal handlers:
  - `SIGTERM` — raises `SystemExit` (triggers shutdown cleanup and save)
  - `SIGINT` — first press sets IDA's cancellation flag; second press escalates to shutdown
  - `SIGUSR1` — sets the cancellation flag without escalation (used by the supervisor for cooperative cancellation)

### Multi-database supervisor and provider architecture

The supervisor uses FastMCP's native Provider system to expose worker tools and resources through the standard provider chain, rather than overriding `list_tools()`, `call_tool()`, etc.

**`ProxyMCP`** (`re_mcp.supervisor`) subclasses `FastMCP`. It creates a `WorkerPoolProvider` and calls `self.add_provider(worker_pool)`. Generic management tools (`close_database`, `save_database`, `list_databases`, `wait_for_analysis`, `list_targets`) are registered by the supervisor; backend-specific management tools (e.g. IDA's `open_database` with `processor`/`fat_arch` parameters) are registered by the backend via `register_management_tools()`. Prompts and the `ida://databases` resource are also registered directly on the supervisor — they do not require database state and are served by FastMCP's internal local provider.

A `ToolTransform` (a `CatalogTransform` subclass defined in `re_mcp.transforms`) is applied at the server level. It pins a set of common analysis tools (e.g. `list_functions`, `decompile_function`, `get_strings`) alongside five meta-tools:

- `search_tools` — regex discovery over all non-pinned tools.
- `get_schema` — parameter schemas and return shapes for tools by name.
- `execute` — sandboxed Python that chains `await invoke` calls for multi-step pipelines and parallel queries.
- `batch` — sequential multi-tool execution with per-item error collection and progress reporting.
- `call` — lightweight proxy for calling any tool by name, including hidden tools not in the client tool list.

Tools not in the pinned set are hidden from the tool listing but callable via `call`, `batch`, or `execute`.

Management tools delegate to `WorkerPoolProvider` methods for worker lifecycle and are session-aware: `close_database` delegates to `close_for_session()`, which atomically detaches and conditionally terminates under `_lock`; `save_database` checks attachment before proceeding. `try_get_session_id()` (from `re_mcp.context`) extracts the session ID without exposing a `ctx` parameter in the tool schema. The exception is `save_database`, which accepts a `ctx` parameter for heartbeat progress notifications during long saves (FastMCP strips it from the JSON schema).

**`WorkerPoolProvider`** (`re_mcp.worker_provider`) implements FastMCP's `Provider` interface. It manages worker subprocesses (each via a `fastmcp.Client` with `StdioTransport`) and exposes their tools and resources through the provider chain:

- `_list_tools()` / `_get_tool()` return `RoutingTool` instances — `Tool` subclasses constructed from bootstrapped MCP tool schemas. Each `RoutingTool` has the `database` parameter injected into its JSON schema at construction and preserves `output_schema` for structured output passthrough.
- `_list_resource_templates()` / `_get_resource_template()` return `RoutingTemplate` instances — `ResourceTemplate` subclasses that override `_read()` to extract `database` from params, resolve the worker, reconstruct the backend URI, and proxy the read via `client.read_resource_mcp()`. All worker resources (both fixed resources and templates) are exposed as templates with a `{database}` prefix in the URI.
- `RoutingTool.run()` pops `database` from arguments, resolves the target worker, implicitly attaches the current session (if a `Context` is available), and delegates to `proxy_to_worker()` (which tracks active calls via `worker.dispatch()` and calls `worker.client.call_tool_mcp()`). The result is enriched with `database` and returned as a `ToolResult`, or raised as a `ToolError`. Error handling (worker crashes, timeouts) is contained within `proxy_to_worker()`.
- `lifespan()` shuts down all workers on exit.
- `check_attached(worker, session_id)` raises `BackendError` if the session is not attached to the worker (pass-through when session ID is `None` or the worker has no tracked sessions for backward compatibility).
- `close_for_session(worker, session_id, save, force)` atomically checks attachment, detaches, and conditionally terminates under `_lock` — prevents races where a concurrent `attach()` from `RoutingTool.run()` could sneak in between detach and terminate.
- `detach_all(session_id, terminate=True)` detaches a session from all workers under `_lock`. When `terminate=True` (default), workers whose session set becomes empty are shut down; `terminate=False` detaches for bookkeeping only (used by the disconnect callback). Falls back to `shutdown_all()` when session ID is `None`.
- `build_database_list(include_state, caller_session_id)` returns all open databases with metadata and a `session_count` per entry; when `caller_session_id` is provided, each entry also includes an `attached` flag.

Tool/resource schemas are bootstrapped lazily from a temporary worker on first access. `RoutingTool` and `RoutingTemplate` both set `task_config = TaskConfig(mode="optional")`.

All tools except management tools (`open_database`, `close_database`, `save_database`, `list_databases`, `wait_for_analysis`, `list_targets`) require the `database` parameter (the stem ID returned by `open_database` or `list_databases`).

#### Background analysis

`spawn_worker()` returns immediately. The worker subprocess, database open, and optional auto-analysis all run in a background `asyncio.Task` (`_background_spawn`). The initial response includes `"opening": true`, and callers must call `wait_for_analysis` to block until the database is ready for tool calls.

When `run_auto_analysis=True`, `_background_spawn` chains into a second task (via `Worker.start_analysis()`) that dispatches `wait_for_analysis` through the normal proxy path once the open completes. While that task runs, `list_databases` reports `"analyzing": true` for the worker.

While background analysis is running, every worker tool except `wait_for_analysis` is rejected by `RoutingTool.run()` — the IDA thread is occupied by `auto_wait()`. `wait_for_analysis` awaits the background task directly rather than making a redundant proxy call.

After analysis completes, worker metadata (function count, etc.) is refreshed via `get_database_info`, and MCP log and resource-list-changed notifications are sent if an `mcp_session` is available. Clients should call `wait_for_analysis` on the database to block until completion rather than polling `list_databases`. Background spawn and analysis tasks are cancelled during worker shutdown.

#### Fat Mach-O binaries

Mach-O universal ("fat") binaries contain multiple architecture slices. Before spawning a worker, `open_database` calls `check_fat_binary` (in `ida_mcp.exceptions`), which parses the on-disk `FAT_MAGIC` / `FAT_MAGIC_64` header via `detect_fat_slices` and refuses to proceed without an explicit `fat_arch` parameter — headless idalib would otherwise silently pick a default slice. The resulting `IDAError` uses `error_type="AmbiguousFatBinary"` and includes an `available` detail listing the slice names (`x86_64`, `arm64`, `arm64e`, ...).

`check_fat_binary` returns the slice's 1-based position in the on-disk fat header, which `build_ida_args` emits as `-T"Fat Mach-O file, <index>"` — the only documented way to pick a slice in headless mode. Because the fat-slice selector already uses `-T`, `loader` cannot be combined with `fat_arch`.

Per-slice sidecars are stored at `<binary>.<arch>.i64` (via an `-o<stem>` override in `Session.open`) so multiple architectures of the same universal binary coexist on disk. The check short-circuits on existing `.i64`/`.idb` databases (and on matching per-slice sidecars unless `force_new=True`), since stored analysis already pins a slice. To analyze multiple slices from the same file concurrently, open once per slice with distinct `database_id` values.

#### Per-worker concurrency

Because idalib is single-threaded, requests to the same worker are serialized by the worker's single-threaded MCP transport. The `dispatch()` async context manager tracks active call count and activity timestamps. Requests to *different* workers run fully in parallel. The `Worker.state` property derives the effective state (BUSY/IDLE) from the `_active_calls` counter rather than requiring manual state transitions.

Crashed workers are detected on-demand when tool calls or resource reads encounter connection errors (`ClosedResourceError`, `EndOfStream`, `BrokenPipeError`/`OSError`, `McpError` with connection-closed code) — `proxy_to_worker()` and `RoutingTemplate._read()` call `mark_worker_dead()` to clean up.

#### Session tracking

Workers track which MCP sessions are using them via `attach(session_id)` / `detach(session_id)` / `is_attached(session_id)` / `session_count`. Sessions are attached implicitly when a tool or resource is accessed (via `attach_current_session()`, called from `RoutingTool.run()` and `RoutingTemplate._read()`) and explicitly on `open_database`.

`close_database` delegates to `close_for_session()`, which atomically checks attachment, detaches, and conditionally terminates under `_lock`. When other sessions are still using the database, it returns a `detached` status instead of terminating. `save_database` and `close_database` check attachment before proceeding (unless `force=True`).

When an MCP session disconnects, a cleanup callback registered on the session's exit stack automatically detaches the session from all workers (via `detach_all(terminate=False)`). Workers are **not** terminated on disconnect — in Claude Code's multi-agent architecture all agents share one MCP session, so a session cycle would otherwise kill databases still in active use. Termination happens only via an explicit `close_database` call, `open_database(keep_open=False)`, or supervisor shutdown.

#### Configuration environment variables

- `IDA_MCP_MAX_WORKERS` — maximum simultaneous databases (clamped to 1-8 when set; unlimited when unset)
- `IDA_MCP_ALLOW_SCRIPTS` — enables the `run_script` tool for arbitrary IDAPython execution (set to `1`, `true`, or `yes`)
- `IDA_MCP_LOG_LEVEL` — logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`); defaults to `WARNING`, output goes to stderr
- `IDADIR` — path to the IDA Pro installation directory (auto-detected when unset)
- `IDA_MCP_LOG_DIR` — directory that receives per-run log files. When set, each component tees Python logging to `<dir>/<run_id>-<label>.log` (labels: `daemon`, `proxy`, `supervisor` for direct stdio mode), each worker to `<dir>/<run_id>-worker-<db>.log`, and each worker's raw stderr is captured to `<dir>/<run_id>-worker-<db>.stderr` (catches pre-logging output and C-level crashes from idalib). `<run_id>` is a timestamp generated once per supervisor start. When unset, logs go only to stderr (inherited by workers).
- `IDA_MCP_IDLE_TIMEOUT` — idle auto-shutdown timeout in seconds for auto-spawned daemons (default `300`). Set to `0` to disable. When the daemon has no active HTTP connections, no MCP sessions, no in-flight worker calls, and no proxy keepalive for this duration, it shuts down gracefully. Only affects daemons spawned by the proxy; `ida-mcp serve` defaults to `0` (use `--idle-timeout=N` to override)
- `IDA_MCP_DISABLE_EXECUTE` — hides the `execute` meta-tool (sandboxed Python code mode) when set to `1`, `true`, `yes`, or `on`
- `IDA_MCP_DISABLE_BATCH` — hides the `batch` meta-tool when set to `1`, `true`, `yes`, or `on`
- `IDA_MCP_DISABLE_TOOL_SEARCH` — disables server-side progressive tool disclosure when set to `1`, `true`, `yes`, or `on`. All tools become directly visible and callable; `search_tools` and `get_schema` meta-tools are removed. Useful with clients that provide their own tool deferral (e.g. Claude Code).

### Error handling convention

Tools return Pydantic model instances on success (FastMCP serializes these automatically). On failure, they raise `IDAError` (a subclass of `BackendError`, which subclasses FastMCP's `ToolError`). FastMCP catches `ToolError` and returns `isError=True` with the error text as content — tools never return error dicts directly.

`IDAError.__str__` (inherited from `BackendError`) returns a JSON object with `error`, `error_type`, and optional detail fields (e.g. `available_variables`, `valid_types`). This keeps the MCP error text machine-parseable while preserving a structured error taxonomy. Common error types include:

- `NoDatabase` — no database is open
- `InvalidAddress` — could not parse/resolve address
- `NotFound` — function, type, or symbol not found
- `DecompilationFailed` — Hex-Rays decompilation error
- `InvalidArgument` — bad parameter value
- `Cancelled` — operation cancelled via cooperative cancellation
- `AmbiguousProcessor` — raw binary opened with a bitness-ambiguous processor module (e.g. bare `arm`); fix by passing a variant like `arm:ARMv7-M`
- `AmbiguousFatBinary` — Mach-O universal binary opened without `fat_arch`; the error's `available` detail lists the slices
- `UnknownFatArch` — `fat_arch` value not present in the fat binary; the error's `available` detail lists the valid slices
- `DuplicateFatSlice` — fat binary contains two slices that resolve to the same lipo-style architecture name; run `lipo -thin` to extract the intended slice and reopen the thin file

Individual tools define additional error types specific to their domain (e.g. `ParseError`, `DecodeFailed`, `SetCommentFailed`).

Mutation tools return the previous state of modified items (e.g. `old_comment`, `old_type`, `old_bytes`, `old_flags`) alongside the new values, enabling undo tracking and change verification by the LLM.

### Address resolution

Addresses are the most common parameter type. The `parse_address` function in `ida_mcp.helpers` accepts multiple formats to minimize friction for LLM callers. Resolution order:

1. `"0x401000"` — hex with `0x` prefix (unambiguous, tried first)
2. `"4198400"` — decimal (all-digit strings are always decimal)
3. `"main"` — symbol name (resolved via IDA's name database)
4. `"4010a0"` — bare hex fallback (last resort; reached only when the string is not pure digits and is not a known symbol)

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

List-returning tools use `paginate(items, offset, limit)`, `paginate_iter(items, offset, limit)`, or `async_paginate_iter(items, offset, limit)` from `ida_mcp.helpers`. `paginate_iter` consumes a generator one item at a time rather than building a full list; after collecting the requested page it reads ahead up to `_COUNT_AHEAD` items beyond the page end to compute `has_more` and an approximate `total` — if the iterator has more items beyond that budget, `total` reflects items seen so far and `has_more` is `True`. `async_paginate_iter` dispatches the entire iteration to the main thread via `call_ida`, so lazy iterators that make IDA API calls execute safely. Tools that build lists eagerly (e.g. `get_imports`, `get_segments`, `get_enum_members`) use `paginate` instead. All three produce the same response shape:

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

### `re-mcp-core` modules (`packages/re-mcp-core/src/re_mcp/`)

| Module | Role |
|--------|------|
| `supervisor.py` | Main entry point (`re-mcp` / `ida-mcp`) — creates `ProxyMCP(FastMCP)` with `WorkerPoolProvider`, registers generic management tools. CLI dispatches to daemon, proxy, direct stdio, or stop mode |
| `daemon.py` | Persistent streamable HTTP daemon — runs `ProxyMCP` with bearer token auth and state file for proxy discovery. Workers survive client reconnections |
| `proxy.py` | Stdio-to-HTTP bridge — auto-spawns the daemon if needed, then forwards MCP messages bidirectionally between stdio and the daemon's HTTP endpoint |
| `worker_provider.py` | `WorkerPoolProvider(Provider)` — manages worker subprocesses, exposes tools via `RoutingTool(Tool)` and resources via `RoutingTemplate(ResourceTemplate)` through the native provider chain |
| `backend.py` | `Backend` protocol and `BackendInfo` dataclass — each backend (IDA, Ghidra, ...) implements this and registers via `re_mcp.backends` entry points |
| `context.py` | `try_get_context()`, `try_get_session_id()`, and `notify_resources_changed()` — FastMCP context helpers with no backend dependencies, used by supervisor modules |
| `exceptions.py` | `BackendError(ToolError)` — base structured error type for all backends |
| `helpers.py` | Backend-agnostic utilities — address parsing/formatting, pagination (`paginate`, `paginate_iter`, `async_paginate_iter`), `dispatch_to_main` main-thread dispatch, MCP annotation presets, `Annotated` parameter type aliases (`Address`, `Offset`, `Limit`, `FilterPattern`, `HexBytes`), filter compilation |
| `models.py` | Shared Pydantic models (e.g. `PaginatedResult`) used across backends |
| `sandbox.py` | `RestrictedPythonSandbox` — AST-restricted Python execution for the `execute` meta-tool |
| `transforms.py` | `ToolTransform(CatalogTransform)` — pins common tools, adds `search_tools`, `get_schema`, `execute`, `batch`, and `call` meta-tools, hides the rest from listing (callable via `call`/`batch`/`execute`) |
| `_process.py` | Platform-aware process utilities (`pid_alive`, `pid_exit_code`, `IS_WINDOWS`) — stdlib only, no backend dependencies |
| `__init__.py` | `configure_logging()`, `ensure_run_id()`, `resolve_log_file()`, `get_version()` — shared infrastructure utilities |

### `ida-mcp` modules (`packages/ida-mcp/src/ida_mcp/`)

| Module | Role |
|--------|------|
| `backend.py` | `IDABackend` — implements the `Backend` protocol; registers `open_database`, prompts, IDA-specific LLM instructions, and target listing |
| `server.py` | Worker entry point (`ida-mcp-worker`) — creates `IDAServer` (a `FastMCP` subclass), auto-discovers and registers all tool modules from `tools/`, runs stdio transport |
| `session.py` | Database session singleton (per worker), `require_open` decorator |
| `exceptions.py` | `IDAError(BackendError)` — IDA-specific structured error type, plus idalib-safe validation utilities (`build_ida_args`, `check_processor_ambiguity`, `check_fat_binary`, `detect_fat_slices`, `slice_sidecar_stem`, `AMBIGUOUS_PROCESSORS`, `PRIMARY_IDB_EXTENSIONS`) |
| `helpers.py` | Address parsing, formatting, pagination, resolution helpers, string decoding, MCP annotation presets, meta presets, `Annotated` parameter type aliases, `call_ida` main-thread dispatch, `@ida_dispatch` marker |
| `models.py` | Shared Pydantic models used by multiple tool modules (e.g. `FunctionSummary`, `RenameResult`). Tool-specific models live in their respective tool modules; FastMCP derives the JSON output schema from each tool's return type annotation |
| `transforms.py` | IDA-specific tool visibility constants — `PINNED_TOOLS` and `MANAGEMENT_TOOLS` frozensets |
| `resources.py` | MCP resources — read-only, cacheable context endpoints (static binary data + aggregate statistics) |
| `prompts/` | MCP prompt templates for guided analysis workflows (analysis, security, workflow) |
| `__init__.py` | Lazy `bootstrap()` to initialize idapro, plus `find_ida_dir()` for IDA installation discovery |
| `_cli.py` | Convenience CLI entry point — `ida-mcp` is equivalent to `re-mcp --backend ida` |

### Tool modules (`packages/ida-mcp/src/ida_mcp/tools/`)

Each tool module follows the same pattern:

```python
from fastmcp import FastMCP

from ida_mcp.helpers import ANNO_READ_ONLY, Address, Limit, Offset
from ida_mcp.session import session

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
- All `ida_*` imports are top-level (safe because `ida_mcp.server` calls `bootstrap()` before importing tool modules). Tool modules are auto-discovered via `pkgutil.iter_modules` — any `tools/*.py` with a `register(mcp)` function is loaded automatically
- `@session.require_open` is applied to all worker tools that need a database. The exceptions are `convert_number` (no database needed) and the worker-side `open_database` / `close_database` (lifecycle tools that manage the session themselves). The supervisor (`re_mcp.supervisor`) exposes its own session-aware versions of `close_database`, `save_database`, `wait_for_analysis`, and `list_databases`, while the IDA backend (`ida_mcp.backend`) registers `open_database`. Of these, only `save_database` is proxied to the worker implementation; the others are handled entirely by the supervisor or backend. `list_databases` and `list_targets` are supervisor-only and have no worker equivalent
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
- `load_data.py` — loading bytes and additional binary files into database
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

MCP resources provide read-only context about the open database. They are defined in `ida_mcp.resources` and reserved for genuinely static or aggregate data that benefits from caching:

- **Static binary data** — imports, exports, entry points (baked into the binary, stable), each with a regex search variant
- **Aggregate snapshot** — statistics (function/segment/entry point/string/name counts, code coverage)

The supervisor also owns one resource (`ida://databases`) that lists all open databases with worker state.

### Resource proxying

Worker resources are exposed through `RoutingTemplate` instances in `WorkerPoolProvider`. Each `RoutingTemplate` stores the original worker URI template as `_backend_uri_template` and presents a prefixed version with `{database}` to clients (e.g. `ida://idb/imports{?offset,limit}` becomes `ida://{database}/idb/imports{?offset,limit}`). At read time, `_read()` pops `database` from the params to resolve the worker, then reconstructs the backend URI from the stored template with the remaining params. The supervisor's own `ida://databases` resource is registered directly on the `FastMCP` server and served by FastMCP's internal local provider — the provider chain handles routing automatically.

## Prompts

MCP prompts provide guided analysis workflow templates. They are defined in `ida_mcp.prompts` with modules for different domains:

- `analysis.py` — binary triage (`survey_binary`), function analysis (`analyze_function`), before/after diff (`diff_before_after`), function classification (`classify_functions`)
- `security.py` — cryptographic constant scanning (`find_crypto_constants`)
- `workflow.py` — string-based rename suggestions (`auto_rename_strings`), ABI type application (`apply_abi`), annotation export script generation (`export_idc_script`)

Prompts are registered on the supervisor by the backend (via `IDABackend.register_prompts()`). Workers do not register or handle prompts.

## Adding a New Tool

1. Create `packages/ida-mcp/src/ida_mcp/tools/newtool.py` with a `register(mcp: FastMCP)` function
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
