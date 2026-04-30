# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Headless IDA Pro 9+ MCP server using idalib. Python + FastMCP, stdio and streamable HTTP transports. Requires a licensed IDA Pro 9+ installation.

## Commands

```bash
uv sync                              # Install dependencies
uv run ida-mcp                       # Run the MCP server (stdio proxy to persistent daemon)
uv run ruff check packages/          # Lint
uv run ruff format packages/         # Format
uv run ruff check --fix packages/    # Lint with auto-fix
```

Pre-commit hooks run REUSE compliance checks, ruff lint (with `--fix --exit-non-zero-on-fix`), ruff format, idalib threading lint (`scripts/lint_ida_threading.py`), and pytest on commit.

## Architecture

See `docs/architecture.md` for full details. The project is a monorepo with two packages:

- **`re-mcp-core`** (`packages/re-mcp-core/src/re_mcp/`): generic MCP supervisor infrastructure — `supervisor.py`, `daemon.py`, `proxy.py`, `worker_provider.py`, `backend.py`, `context.py`, `exceptions.py`, `models.py`, `sandbox.py`, `transforms.py`, `_process.py`
- **`ida-mcp`** (`packages/ida-mcp/src/ida_mcp/`): IDA-specific backend — `backend.py`, `server.py`, `session.py`, `helpers.py`, `exceptions.py`, `models.py`, `transforms.py`, `_cli.py`, `tools/`, `resources.py`, `prompts/`

Key points for editing:

- **Supervisor** (`re_mcp.supervisor`): entry point, `ProxyMCP(FastMCP)` + `WorkerPoolProvider`. Registers generic management tools (`close_database`, `save_database`, `list_databases`, `wait_for_analysis`, `list_targets`); the IDA backend registers `open_database` via `backend.py`. Management tools use `_session_id()` (via `try_get_context()` from `re_mcp.context`). Most omit `ctx` from their signature; `save_database` is the exception (it accepts `ctx` for heartbeat progress notifications, but FastMCP strips it from the JSON schema).
- **IDA backend** (`ida_mcp.backend`): `IDABackend` implements the `Backend` protocol — registers `open_database`, prompts, IDA-specific instructions, and target listing.
- **Worker provider** (`re_mcp.worker_provider`): `WorkerPoolProvider(Provider)`, `RoutingTool(Tool)`, `RoutingTemplate(ResourceTemplate)`, `Worker` dataclass. Session-scoped ownership under `_lock` — `close_for_session()` and `detach_all()` are atomic. `ensure_session_cleanup()` registers a disconnect callback on the MCP session's exit stack.
- **Worker** (`ida_mcp.server`): `IDAServer(FastMCP)`, one per database, stdio transport. `ida-mcp-worker` entry point.
- **idalib-safe modules** (importable without `bootstrap()`): all `re_mcp` modules, plus `ida_mcp.exceptions`, `ida_mcp.models`, `ida_mcp.transforms`, `ida_mcp.prompts/`. The supervisor never imports idalib-required modules.
- **idalib-required modules**: `ida_mcp.helpers`, `ida_mcp.session`, `ida_mcp.tools/`, `ida_mcp.resources`. Top-level `ida_*` imports — only loaded in worker processes.
- `@session.require_open` (no parens) — decorator on nearly every tool
- All tools return Pydantic models on success; raise `IDAError` on failure
- `helpers.py` re-exports `IDAError` from `exceptions.py` for convenience

## Adding a New Tool

1. Create `packages/ida-mcp/src/ida_mcp/tools/newtool.py` with a `register(mcp: FastMCP)` function
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
