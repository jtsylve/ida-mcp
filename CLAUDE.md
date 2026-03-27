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

**Entry point:** `src/ida_mcp/supervisor.py` — the `ida-mcp` script entry point. Creates `ProxyMCP` (a `FastMCP` subclass) that spawns worker subprocesses and proxies MCP tool calls and resource reads to the appropriate worker. Supports multiple simultaneous databases via `keep_open=True` on `open_database`. Owns the `ida://databases` resource and registers prompt templates directly (prompts are not proxied to workers). Supports cooperative cancellation: when an MCP `notifications/cancelled` fires (or the handler's `CancelScope` is cancelled), the supervisor sends `SIGUSR1` to the worker, setting IDA's cancellation flag so batch loops can break early. The reaper uses per-tool timeouts (plus a safety margin) instead of a fixed 5-minute threshold.

**Worker:** `src/ida_mcp/server.py` — creates `FastMCP("IDA Pro")` instance, imports and registers all tool modules and resources, runs with stdio transport via `main()`. The `ida-mcp-worker` script entry point calls `server:main`. Each worker handles one database.

**`__init__.py`** — `import idapro` must happen before any `ida_*` module is imported. The package `__init__.py` provides a lazy `bootstrap()` function that handles this: it first tries a normal import, and if that fails, auto-detects the IDA Pro installation (via `IDADIR`, `~/.idapro/ida-config.json`, or platform defaults), adds the idalib wheel to `sys.path`, and imports from there. `server.py` calls `bootstrap()` at module scope before any `ida_*` imports. The supervisor never calls `bootstrap()`, avoiding idalib license cost.

**`session.py`** — Singleton `Session` managing the idalib database within each worker process. Key pattern: `session.require_open` is a decorator that returns an error dict instead of raising if no database is open. Used on nearly every tool. The decorator also clears IDA's cancellation flag before each call and catches `Cancelled` exceptions, returning a structured error. An `atexit` hook calls `session.close(save=True)` on process exit. Signal handlers: `SIGTERM` raises `SystemExit` (triggers atexit save); `SIGINT` sets IDA's cancellation flag on first press, escalates to shutdown on second; `SIGUSR1` sets the cancellation flag without escalation (used by the supervisor for cooperative cancellation).

**`helpers.py`** — Shared utilities used across all tool modules:
- `parse_address` / `resolve_address` — accepts hex strings, bare hex, decimal, or symbol names
- `resolve_function` — returns `(func_t, error_dict)` tuple (error is `None` on success)
- `decompile_at` — returns `(cfunc, func_t, error_dict)` tuple (error is `None` on success)
- `decode_insn_at` — decode instruction at address, returns `(insn_t, error_dict)` tuple
- `resolve_segment` — resolve address and get segment, returns `(segment_t, error_dict)` tuple
- `resolve_struct` / `resolve_enum` — struct/enum name resolution; both return `(tid, error_dict)` where `tid` is the type ID (`None`/`0` on error)
- `compile_filter` — compile optional regex filter returning `(pattern, error_dict)` tuple
- `paginate` / `paginate_iter` — standard offset/limit pagination (no hard cap); `paginate_iter` works on generators without materializing the full list
- `Cancelled` — exception raised by `check_cancelled()` when IDA's cancellation flag is set
- `check_cancelled` — call between loop iterations; raises `Cancelled` if the flag is set
- `is_cancelled` — non-raising variant; returns `bool` for loops that just `break`
- `format_address`, `is_bad_addr`, `clean_disasm_line`, `get_func_name`, `xref_type_name`
- `segment_bitness`, `format_permissions` / `parse_permissions`, `validate_operand_num`
- `parse_type`, `safe_type_size`
- `decode_string` — decode a string from the database with encoding detection (UTF-8/16/32)
- `get_old_item_info` — read current item type and size at an address (used by patching/makedata tools)

**`resources.py`** — MCP resources providing read-only, cacheable context endpoints organized in four tiers: core context (metadata, segments, imports/exports), structural reference (types, structs, enums), browsable collections (strings, functions, names, bookmarks, statistics), and per-entity parameterized resources (`ida://functions/{addr}`, xrefs, stack frames, etc.).

**`prompts/`** — MCP prompt templates for guided analysis workflows. Modules: `analysis.py` (binary triage, function analysis, diff, classification), `security.py` (crypto constant scanning), `workflow.py` (string-based renaming, ABI application, annotation export).

**`tools/`** — modules each exporting a `register(mcp: FastMCP)` function that defines `@mcp.tool()` decorated functions inside it. Tools return dicts; errors use `{"error": ..., "error_type": ...}` convention. Mutation tools return old values alongside new values for change tracking.

## Adding a New Tool

1. Create `src/ida_mcp/tools/newtool.py` with a `register(mcp: FastMCP)` function
2. Define tool functions inside `register()` using `@mcp.tool()` and `@session.require_open`
3. Import and call `newtool.register(mcp)` in `server.py`
4. Use helpers from `helpers.py` — `resolve_address`, `resolve_function`, `paginate`, etc.
5. Return dicts for both success and error cases
6. Add any new `ida_*` imports to the `known-third-party` list in `pyproject.toml` under `[tool.ruff.lint.isort]`

## IDA 9 API

- `ida_ida.get_inf_structure()` is **removed** — use free functions: `ida_ida.inf_get_min_ea()`, `ida_ida.inf_get_max_ea()`, `ida_ida.inf_get_start_ea()`, `ida_ida.inf_get_app_bitness()`, `ida_ida.inf_is_64bit()`, etc.
- idalib is single-threaded: all IDA calls must happen on the same thread that imported `idapro`
- `idapro.open_database(path, run_auto_analysis)` returns 0 on success. `run_auto_analysis` defaults to `False` — pass `True` only for first-time analysis of a new binary (no existing `.i64`). The binary must be in a writable directory (IDA creates `.i64` alongside it).

## Lint / Style

- ruff configured in `pyproject.toml` — line-length 100, target py312
- isort knows all `ida_*` modules as third-party (configured in `[tool.ruff.lint.isort]`)
- Do not credit Claude in commit messages
