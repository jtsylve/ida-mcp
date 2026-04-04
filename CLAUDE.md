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

Pre-commit hooks run reuse lint, ruff lint (with `--fix --exit-non-zero-on-fix`), ruff format, idalib threading lint (`scripts/lint_ida_threading.py`), and pytest on commit.

## Architecture

See `docs/architecture.md` for full details. Key points for editing:

- **Supervisor** (`supervisor.py`): entry point, `ProxyMCP(FastMCP)` + `WorkerPoolProvider`. Registers management tools directly; worker tools/resources go through the provider chain. Management tools use `_session_id()` (via `try_get_context()` from `context.py`) — no `ctx` parameter in tool schemas.
- **Worker provider** (`worker_provider.py`): `WorkerPoolProvider(Provider)`, `RoutingTool(Tool)`, `RoutingTemplate(ResourceTemplate)`, `Worker` dataclass. Session-scoped ownership under `_lock` — `close_for_session()` and `detach_all()` are atomic. `ensure_session_cleanup()` registers a disconnect callback on the MCP session's exit stack.
- **Worker** (`server.py`): `IDAServer(FastMCP)`, one per database, stdio transport. `ida-mcp-worker` entry point.
- **idalib-safe modules** (importable without `bootstrap()`): `context.py`, `exceptions.py`, `models.py`, `prompts/`. The supervisor imports `context.py`, `exceptions.py` (via `worker_provider.py`), `prompts/`, and `worker_provider.py`.
- **idalib-required modules**: `helpers.py`, `session.py`, `tools/`, `resources.py`. Top-level `ida_*` imports — only loaded in worker processes.
- `@session.require_open` (no parens) — decorator on nearly every tool
- All tools return Pydantic models on success; raise `IDAError` on failure
- `helpers.py` re-exports from `context.py` and `exceptions.py` for convenience

## Adding a New Tool

1. Create `src/ida_mcp/tools/newtool.py` with a `register(mcp: FastMCP)` function
2. Define tool functions inside `register()` using `@mcp.tool()` and `@session.require_open`
3. Add `annotations=` (`ANNO_READ_ONLY`, `ANNO_MUTATE`, `ANNO_MUTATE_NON_IDEMPOTENT`, or `ANNO_DESTRUCTIVE`) and `tags=` to `@mcp.tool()`
4. Use `Annotated` type aliases for parameters: `Address`, `Offset`, `Limit`, `FilterPattern`, `OperandIndex`, `HexBytes`
5. Tool modules are auto-discovered — any `tools/*.py` with a `register()` function is loaded automatically
6. Use helpers from `helpers.py` — `resolve_address`, `resolve_function`, `paginate`, etc.
7. Return Pydantic model instances on success; raise `IDAError` on failure (do not return error dicts)
8. Add any new `ida_*` imports to the `known-third-party` list in `pyproject.toml` under `[tool.ruff.lint.isort]`

## IDA 9 API

- `ida_ida.get_inf_structure()` is **removed** — use free functions: `ida_ida.inf_get_min_ea()`, `ida_ida.inf_get_max_ea()`, `ida_ida.inf_get_start_ea()`, `ida_ida.inf_get_app_bitness()`, `ida_ida.inf_is_64bit()`, etc.
- idalib is single-threaded: all IDA calls must happen on the same thread that imported `idapro`
- `idapro.open_database(path, run_auto_analysis)` returns 0 on success. `run_auto_analysis` defaults to `False` — pass `True` only for first-time analysis of a new binary (no existing `.i64`). The binary must be in a writable directory (IDA creates `.i64` alongside it).

## Lint / Style

- ruff configured in `pyproject.toml` — line-length 100, target py312
- isort knows all `ida_*` modules as third-party (configured in `[tool.ruff.lint.isort]`)
- Do not credit Claude in commit messages
