# Architecture

This document describes the architecture and design decisions behind the IDA MCP Server.

## Overview

The IDA MCP Server is a headless IDA Pro 9.3 server that communicates over the Model Context Protocol (MCP) using stdio transport. It uses [idalib](https://docs.hex-rays.com/release-notes/9_0#idalib-ida-as-a-library) — IDA Pro running as a library — to expose IDA's full analysis capabilities as structured tool calls that LLMs can invoke.

```
LLM Client  <──stdio──>  FastMCP  ──>  Tool Modules  ──>  idalib (IDA Pro)
                          server.py     tools/*.py         idapro + ida_*
```

## Design Decisions

### Why idalib over IDA GUI scripting?

idalib runs IDA Pro as a library within a normal Python process — no GUI, no IDAPython console. This makes it ideal for headless automation:

- No X11/display dependencies
- Process lifecycle is controlled by the server, not the IDA GUI
- Direct function calls instead of script injection
- Single process, no IPC overhead

The trade-off is that idalib is **single-threaded**: all IDA API calls must happen on the same thread that imported `idapro`. The MCP stdio transport naturally serializes requests, so this is not a limitation in practice.

### Why FastMCP?

[FastMCP](https://github.com/modelcontextprotocol/python-sdk) provides a minimal decorator-based API for defining MCP tools. Each tool is a plain Python function with type annotations — FastMCP handles JSON schema generation, argument validation, and transport.

The server uses stdio transport (not SSE/HTTP) because:
- MCP clients like Claude Desktop expect stdio
- No port management or auth needed
- Process lifecycle is tied to the client session

### Import ordering constraint

idalib requires that `import idapro` be the **first import** before any `ida_*` module. The package `__init__.py` enforces this:

```python
# src/ida_mcp/__init__.py
import idapro  # MUST be first import, initializes idalib
```

This means `ida_*` imports can be top-level in all other modules — they're guaranteed to run after `idapro` has initialized the IDA kernel.

`server.py` also imports `ida_mcp` explicitly as a safety measure since it's the entry point:

```python
import ida_mcp  # noqa: F401 — triggers idapro import
```

### Session singleton

The `Session` class in `session.py` manages the single idalib database connection:

```python
session = Session()  # module-level singleton
```

Key behaviors:
- Only one database can be open at a time (idalib limitation)
- Opening a new database auto-closes the previous one (with save)
- `session.require_open` is a decorator that returns an error dict instead of raising — this keeps the MCP protocol clean since tool errors should be data, not exceptions
- An `atexit` hook and a `SIGTERM` handler both call `session.close(save=True)`, ensuring the database is saved on any normal or signal-driven process exit

### Error handling convention

All tools return dicts. Errors follow a consistent shape:

```python
{"error": "Human-readable message", "error_type": "ErrorCategory"}
```

Common error types:
- `NoDatabase` — no database is open
- `InvalidAddress` — could not parse/resolve address
- `NotFound` — function, type, or symbol not found
- `DecompilationFailed` — Hex-Rays decompilation error
- `InvalidArgument` — bad parameter value

This convention means the MCP client always gets structured data and can present errors naturally without catching exceptions across the protocol boundary.

### Address resolution

Addresses are the most common parameter type. The `parse_address` function in `helpers.py` accepts multiple formats to minimize friction for LLM callers:

- `"0x401000"` — hex with prefix
- `"4010a0"` — bare hex (must contain a-f; all-digit strings are decimal)
- `"4198400"` — decimal
- `"main"` — symbol name (resolved via IDA's name database)

Higher-level helpers build on this:
- `resolve_address(addr)` → `(ea, error_dict | None)`
- `resolve_function(addr)` → `(func_t, error_dict | None)`
- `decompile_at(addr)` → `(cfunc, func_t, error_dict | None)`
- `decode_insn_at(ea)` → `(insn_t, error_dict | None)`
- `resolve_segment(addr)` → `(segment_t, error_dict | None)`
- `resolve_struct(name)` → `(tid, error_dict | None)`
- `resolve_enum(name)` → `(tid, error_dict | None)`

Each returns a tuple where the second (or third) element is `None` on success and an error dict on failure. This pattern eliminates try/except boilerplate in tool implementations.

### Pagination

List-returning tools use `paginate(items, offset, limit)` from `helpers.py`:

```python
{
    "items": [...],
    "total": 1500,
    "offset": 0,
    "limit": 100,
    "has_more": true
}
```

Maximum limit is capped at 500 to prevent overwhelming responses.

## Module Organization

### Core modules

| Module | Role |
|--------|------|
| `server.py` | Entry point — creates FastMCP, registers all tools, runs stdio transport |
| `session.py` | Database session singleton, `require_open` decorator |
| `helpers.py` | Address parsing, formatting, pagination, resolution helpers |
| `__init__.py` | Guarantees `idapro` is imported first |

### Tool modules (`tools/`)

Each tool module follows the same pattern:

```python
def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def my_tool(param: str) -> dict:
        """Tool description for LLM consumption.

        Args:
            param: Description of param.
        """
        # Implementation using ida_* APIs
        return {"result": "..."}
```

Key conventions:
- All `ida_*` imports are top-level (safe because `__init__.py` runs first)
- `@session.require_open` is applied to all tools that need a database (everything except `open_database` and `close_database`)
- Tool docstrings are sent to the LLM as tool descriptions — they should be clear and concise
- Tools that accept addresses use `resolve_address` or `resolve_function` from helpers

### Tool module grouping

The tool modules are organized by IDA domain:

**Query tools** (read-only analysis):
- `functions.py` — function listing, info, disassembly, decompilation
- `chunks.py` — function chunk (tail) listing and management
- `xrefs.py` — cross-reference queries, call graphs
- `search.py` — string/byte/text/immediate search, function pattern search
- `data.py` — raw byte reading, segment listing
- `imports_exports.py` — imports, exports, entry points
- `cfg.py` — basic blocks, CFG edges
- `operands.py` — instruction decoding
- `frames.py` — stack frames, local variables
- `ctree.py` — Hex-Rays AST exploration
- `processor.py` — architecture info, instruction classification, instruction set listing
- `switches.py` — switch/jump table analysis
- `regfinder.py` — register value tracking
- `nalt.py` — address metadata: source line numbers, analysis flags, library item status
- `analysis.py` — analysis problems, fixups, exception handlers
- `export.py` — batch decompilation/disassembly export, output file generation

**Mutation tools** (modify the database):
- `database.py` — open/close database
- `patching.py` — byte patching, function/code creation
- `assemble.py` — instruction assembly
- `comments.py` — comment management
- `names.py` — address renaming
- `types.py`, `typeinf.py` — type application and local type management
- `function_type.py` — function prototypes and calling conventions
- `structs.py` — structure CRUD
- `enums.py` — enum CRUD
- `decompiler.py` — variable renaming/retyping in pseudocode
- `operand_repr.py` — operand display changes
- `segments.py`, `rebase.py` — segment manipulation
- `xref_manip.py` — cross-reference manipulation
- `entry_manip.py` — entry point addition/deletion
- `makedata.py` — data type definition
- `load_data.py` — loading bytes into database
- `func_flags.py` — function flag and hidden range management
- `regvars.py` — register variable add/delete/rename/retype
- `srclang.py` — C/C++ source parsing via compiler parser (clang), type import

**Utility tools**:
- `utility.py` — number conversion, IDC evaluation, script execution
- `bookmarks.py` — bookmark management
- `colors.py` — address/function coloring
- `undo.py` — undo/redo
- `dirtree.py` — IDA directory tree management
- `signatures.py`, `sig_gen.py` — FLIRT signatures and type libraries
- `demangle.py` — C++ name demangling

## Adding New Tools

1. Create `src/ida_mcp/tools/newtool.py`
2. Follow the `register(mcp)` pattern with `@mcp.tool()` and `@session.require_open`
3. Use `resolve_address` / `resolve_function` / `paginate` from `helpers.py`
4. Return dicts with the standard error convention
5. Import and call `newtool.register(mcp)` in `server.py`
6. Add any new `ida_*` imports to the `known-third-party` list in `pyproject.toml` under `[tool.ruff.lint.isort]`

## IDA 9.3 API Notes

- `ida_ida.get_inf_structure()` is **removed** — use free functions: `inf_get_min_ea()`, `inf_get_max_ea()`, `inf_get_start_ea()`, `inf_get_app_bitness()`, `inf_is_64bit()`, etc.
- IDAPython `.so` modules use stable ABI (no cpython version tag) — works with Python 3.12+
- `idapro.open_database(path, run_auto_analysis)` returns 0 on success
- The target binary must be in a writable directory (IDA creates `.i64` alongside it)
- idalib is single-threaded — all calls must be on the thread that imported `idapro`
