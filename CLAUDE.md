# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Headless IDA Pro 9+ MCP server using idalib. Python + FastMCP, stdio transport. Requires a licensed IDA Pro 9+ installation.

## Commands

```bash
uv sync                          # Install dependencies
uv run ida-mcp                   # Run the MCP server (stdio)
uv run ruff check src/           # Lint
uv run ruff format src/          # Format
uv run ruff check --fix src/     # Lint with auto-fix
```

Pre-commit hooks run reuse lint, ruff lint (with `--fix --exit-non-zero-on-fix`), ruff format, and pytest on commit.

## Architecture

**Entry point:** `src/ida_mcp/supervisor.py` — the `ida-mcp` script entry point. Creates `ProxyMCP` (a `FastMCP` subclass) that adds a `WorkerPoolProvider` via `self.add_provider()` and registers management tools (`open_database`, `close_database`, `save_database`, `list_databases`, `show_all_tools`) plus the `ida://databases` resource directly on itself. Prompt templates are also registered directly (not proxied to workers). The management tools delegate to `WorkerPoolProvider` methods for worker lifecycle. Supports multiple simultaneous databases (the default; `open_database` keeps previously opened databases open unless `keep_open=False` is passed). All worker tools require a `database` parameter (the stem ID returned by `open_database`/`list_databases`); worker resource URIs always include the database ID (`ida://{database}/…`).

**`worker_provider.py`** — `WorkerPoolProvider(Provider)` implements FastMCP's Provider interface to manage worker subprocesses and expose their tools/resources through the native provider chain. Key classes:
- `WorkerPoolProvider` — owns the worker pool (`_workers`, `_id_to_path`, `_lock`), worker lifecycle (`spawn_worker`, `terminate_worker`, `mark_worker_dead`, `shutdown_all`), reaper (idle/stuck detection), and capability aggregation. Implements `_list_tools()`, `_get_tool()`, `_list_resource_templates()`, `_get_resource_template()` to return `RoutingTool`/`RoutingTemplate` instances filtered by aggregate capabilities. Tool/resource schemas are bootstrapped from a temporary worker on first access. The `lifespan()` method manages the reaper task.
- `RoutingTool(Tool)` — a `Tool` subclass constructed from the bootstrapped MCP tool schema. Injects a required `database` parameter into its JSON schema at construction. Preserves `output_schema` from the worker for structured output passthrough. Sets `task_config = TaskConfig(mode="forbidden")`. `run()` pops `database` from arguments, resolves the target worker via the provider, acquires the per-worker semaphore via `worker.dispatch()`, calls `worker.client.call_tool_mcp()`, enriches the result with `database`, and returns a `ToolResult` or raises `ToolError`.
- `RoutingTemplate(ResourceTemplate)` — overrides `_read()` to extract `database` from params, resolve the worker, reconstruct the backend URI from the stored `_backend_uri_template`, and proxy the read via `client.read_resource_mcp()`. Sets `task_config = TaskConfig(mode="forbidden")`.
- `Worker` dataclass — per-worker state including `Client`, `AsyncExitStack`, PID, metadata, and an `asyncio.Semaphore(1)` for serialization (idalib is single-threaded). The `dispatch()` context manager acquires the semaphore, tracks busy state, and sends `SIGUSR1` on cancellation.

Each worker is managed via a `fastmcp.Client` with `StdioTransport` — the Client handles the subprocess connection lifecycle. Supports cooperative cancellation: when a handler's `CancelScope` is cancelled, the `dispatch()` context manager sends `SIGUSR1` to the worker, setting IDA's cancellation flag so batch loops can break early. The reaper uses per-tool timeouts (plus a safety margin) instead of a fixed 5-minute threshold.

**Worker:** `src/ida_mcp/server.py` — creates an `IDAServer("IDA Pro")` instance (a `FastMCP` subclass that wraps sync tool and resource functions into async functions so they run on the main thread where idalib was initialized), imports and registers all tool modules and resources, runs with stdio transport via `main()`. The `ida-mcp-worker` script entry point calls `server:main`. Each worker handles one database.

**`__init__.py`** — `import idapro` must happen before any `ida_*` module is imported. The package `__init__.py` provides a lazy `bootstrap()` function that handles this: it first tries a normal import, and if that fails, auto-detects the IDA Pro installation (via `IDADIR`, `~/.idapro/ida-config.json`, or platform defaults), adds the idalib wheel to `sys.path`, and imports from there. `server.py` calls `bootstrap()` at module scope before any `ida_*` imports. The supervisor never calls `bootstrap()`, avoiding idalib license cost.

**`session.py`** — Singleton `Session` managing the idalib database within each worker process. Key pattern: `session.require_open` is a decorator that raises `IDAError` if no database is open. Used on nearly every tool. The decorator also clears IDA's cancellation flag before each call and catches `Cancelled` exceptions, re-raising as `IDAError`. `Session.open()` and `Session.close()` raise `IDAError` on failure. An `atexit` hook calls `session.close(save=True)` on process exit. Signal handlers: `SIGTERM` raises `SystemExit` (triggers atexit save); `SIGINT` sets IDA's cancellation flag on first press, escalates to shutdown on second; `SIGUSR1` sets the cancellation flag without escalation (used by the supervisor for cooperative cancellation).

**`exceptions.py`** — Error types and shared timeout constants (importable without idalib):
- `IDAError(ToolError)` — defined here; re-exported by `helpers.py` for convenience. Raised on failure by all tools; fastmcp catches it and returns `isError=True`. `__str__` returns a JSON object with `error`, `error_type`, and optional detail kwargs (e.g. `available_variables`, `valid_types`). Error taxonomy includes `InvalidAddress`, `NotFound`, `DecompilationFailed`, etc.
- `DEFAULT_TOOL_TIMEOUT` (120s) / `SLOW_TOOL_TIMEOUTS` — centralized timeout constants used by both worker `@mcp.tool(timeout=...)` and supervisor transport/reaper timeouts.

**`helpers.py`** — Shared utilities used across all tool modules:
- `tool_timeout(name)` — returns the timeout for a tool from the centralized constants
- `ANNO_READ_ONLY` / `ANNO_MUTATE` / `ANNO_MUTATE_NON_IDEMPOTENT` / `ANNO_DESTRUCTIVE` — MCP annotation presets (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) passed to `@mcp.tool(annotations=...)`
- `META_DECOMPILER` / `META_BATCH` / `META_READS_FILES` / `META_WRITES_FILES` — MCP meta presets (static metadata) passed to `@mcp.tool(meta=...)` to tag tools that require the decompiler, perform batch operations, or access the filesystem
- `Address`, `Offset`, `Limit`, `FilterPattern`, `OperandIndex`, `HexBytes` — `Annotated` type aliases with Pydantic `Field` metadata (descriptions and constraints like `ge=0`, `ge=1`). Use these as parameter types in tool signatures instead of bare `str`/`int` to get automatic schema descriptions and validation.
- `parse_address` / `resolve_address` — accepts hex strings, bare hex, decimal, or symbol names; raises `IDAError`
- `resolve_function` — resolve address to `func_t`; raises `IDAError`
- `decompile_at` — returns `(cfunc, func_t)`; raises `IDAError`
- `decode_insn_at` — decode instruction at address; raises `IDAError`
- `resolve_segment` — resolve address to `segment_t`; raises `IDAError`
- `resolve_struct` / `resolve_enum` — struct/enum name to type ID; raises `IDAError`
- `compile_filter` — compile optional regex filter; returns `Pattern | None`; raises `IDAError`
- `parse_permissions` — parse "RWX" string to flags; raises `IDAError`
- `validate_operand_num` — raises `IDAError` if negative
- `parse_type` — parse C type string to `tinfo_t`; raises `IDAError`
- `paginate` / `paginate_iter` / `async_paginate_iter` — standard offset/limit pagination (no hard cap); `paginate_iter` works on generators without materializing the full list; `async_paginate_iter` adds progress reporting via `ctx.report_progress()`
- `Cancelled` — exception raised by `check_cancelled()` when IDA's cancellation flag is set
- `check_cancelled` — call between loop iterations; raises `Cancelled` if the flag is set
- `is_cancelled` — non-raising variant; returns `bool` for loops that just `break`
- `format_address`, `is_bad_addr`, `clean_disasm_line`, `get_func_name`, `xref_type_name`
- `segment_bitness`, `format_permissions`, `safe_type_size`
- `try_get_context` — return the current FastMCP `Context` or `None` outside a request; safe to call anywhere
- `decode_string` — decode a string from the database with encoding detection (UTF-8/16/32)
- `get_old_item_info` — read current item type and size at an address (used by patching/makedata tools)

**`models.py`** — Shared Pydantic models used across multiple tool modules (e.g. `PaginatedResult`, `FunctionSummary`, `RenameResult`). Tool-specific models live in their respective tool modules. FastMCP derives the JSON schema from return type annotations and includes it in tool definitions so MCP clients can discover response shapes.

**`resources.py`** — MCP resources providing read-only, cacheable context endpoints organized in four tiers: core context (metadata, segments, imports/exports), structural reference (types, structs, enums), browsable collections (strings, functions, names, bookmarks, statistics), and per-entity parameterized resources (`ida://functions/{addr}`, xrefs, stack frames, etc.).

**`prompts/`** — MCP prompt templates for guided analysis workflows. Modules: `analysis.py` (binary triage, function analysis, diff, classification), `security.py` (crypto constant scanning), `workflow.py` (string-based renaming, ABI application, annotation export).

**`tools/`** — modules each exporting a `register(mcp: FastMCP)` function that defines `@mcp.tool()` decorated functions inside it. Every tool has MCP annotations (`ANNO_READ_ONLY`, `ANNO_MUTATE`, `ANNO_MUTATE_NON_IDEMPOTENT`, or `ANNO_DESTRUCTIVE`), tags for categorical grouping, and uses `Annotated` type aliases for parameter metadata. Tools return Pydantic model instances on success; errors raise `IDAError` (caught by fastmcp → `isError=True`). Mutation tools return old values alongside new values for change tracking.

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

## IDA 9 API

- `ida_ida.get_inf_structure()` is **removed** — use free functions: `ida_ida.inf_get_min_ea()`, `ida_ida.inf_get_max_ea()`, `ida_ida.inf_get_start_ea()`, `ida_ida.inf_get_app_bitness()`, `ida_ida.inf_is_64bit()`, etc.
- idalib is single-threaded: all IDA calls must happen on the same thread that imported `idapro`
- `idapro.open_database(path, run_auto_analysis)` returns 0 on success. `run_auto_analysis` defaults to `False` — pass `True` only for first-time analysis of a new binary (no existing `.i64`). The binary must be in a writable directory (IDA creates `.i64` alongside it).

## Lint / Style

- ruff configured in `pyproject.toml` — line-length 100, target py312
- isort knows all `ida_*` modules as third-party (configured in `[tool.ruff.lint.isort]`)
- Do not credit Claude in commit messages
