# IDA MCP Server

A headless [IDA Pro](https://hex-rays.com/ida-pro/) MCP server built on [idalib](https://docs.hex-rays.com/release-notes/9_0#idalib-ida-as-a-library). Exposes IDA Pro's binary analysis capabilities over the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP), letting LLMs drive IDA Pro for reverse engineering tasks. Supports multiple simultaneous databases through a supervisor/worker architecture.

> **Note:** This is a standalone server, not an IDA plugin. It uses [idalib](https://docs.hex-rays.com/release-notes/9_0#idalib-ida-as-a-library) (IDA as a library) to run IDA's analysis engine headlessly — no IDA GUI needs to be running. You just need IDA Pro 9+ installed on the same machine.

## Requirements

- IDA Pro 9+ with a valid license (including Hex-Rays decompiler for decompilation tools)
- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager (recommended) or pip
- macOS, Windows, or Linux

## Installation

```bash
uv tool install ida-mcp
```

Or with pip:

```bash
pip install ida-mcp
```

The `idapro` package is loaded at runtime directly from your local IDA Pro installation — no extra setup steps or environment variables are needed if IDA is installed in a standard location.

### From source

```bash
git clone https://github.com/jtsylve/ida-mcp && cd ida-mcp
uv sync
```

Or with pip:

```bash
git clone https://github.com/jtsylve/ida-mcp && cd ida-mcp
pip install -e .
```

### Finding IDA Pro

At startup, the server looks for your IDA Pro installation in the following order:

1. **`IDADIR` environment variable** — checked first; set this if IDA is in a non-standard location.
2. **IDA's own config file** — `Paths.ida-install-dir` in `~/.idapro/ida-config.json` (macOS/Linux) or `%APPDATA%\Hex-Rays\IDA Pro\ida-config.json` (Windows). If the `IDAUSR` environment variable is set, it is used as the config directory instead. This is the same config file IDA itself uses.
3. **Platform-specific default paths:**

| Platform | Default search paths |
|----------|---------------------|
| macOS    | `/Applications/IDA Professional *.app/Contents/MacOS` |
| Windows  | `C:\Program Files\IDA Professional 9.3`, `C:\Program Files\IDA Pro 9.3`, and their `Program Files (x86)` equivalents |
| Linux    | `/opt/ida-pro-9.3`, `/opt/idapro-9.3`, `/opt/ida-9.3`, `~/ida-pro-9.3`, `~/idapro-9.3` |

If the server can't find IDA, you'll get a clear error message telling you to set `IDADIR`.

## Usage

### Stdio transport (default)

```bash
uvx ida-mcp
```

Or if installed with pip:

```bash
ida-mcp
```

### Running without installing

You can run the server without installing it first:

```bash
# uv
IDADIR=/path/to/ida uvx ida-mcp

# pipx (set IDADIR if IDA isn't in a standard location)
IDADIR=/path/to/ida pipx run ida-mcp
```

```powershell
# uv
$env:IDADIR = "C:\Program Files\IDA Professional 9.3"
uvx ida-mcp

# pipx (set IDADIR if IDA isn't in a standard location)
$env:IDADIR = "C:\Program Files\IDA Professional 9.3"
pipx run ida-mcp
```

### MCP client configuration

Add to your MCP client config (e.g. Claude Desktop `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "ida": {
      "command": "uvx",
      "args": ["ida-mcp"]
    }
  }
}
```

If you don't use uv, use `ida-mcp` directly (assuming it's installed and on your `PATH`):

```json
{
  "mcpServers": {
    "ida": {
      "command": "ida-mcp"
    }
  }
}
```

If `ida-mcp` isn't on your `PATH` (e.g. installed into a pyenv or virtualenv), use the full path to the executable:

```json
{
  "mcpServers": {
    "ida": {
      "command": "/home/user/.pyenv/versions/<version>/bin/ida-mcp"
    }
  }
}
```

On macOS, the path would typically be `/Users/<you>/.pyenv/versions/<version>/bin/ida-mcp`.

If IDA is not in a default location, add `IDADIR` via the `env` key (works with any command):

```json
{
  "mcpServers": {
    "ida": {
      "command": "uvx",
      "args": ["ida-mcp"],
      "env": {
        "IDADIR": "/path/to/ida"
      }
    }
  }
}
```

### Basic workflow

1. **Open a binary** — call `open_database` with the path to a binary or an existing `.i64`/`.idb` database, then `wait_for_analysis` to block until it is ready
2. **Analyze** — use the available tools (list functions, decompile, search strings, read bytes, etc.)
3. **Close** — call `close_database` when done (auto-saves by default)

Raw binaries must be in a writable directory since IDA creates a `.i64` database file alongside them. When opening an existing database, the original binary does not need to be present.

### Multi-database mode

Multiple databases can be open at the same time. By default, `open_database` keeps previously opened databases open. Pass `keep_open=False` to save and close databases owned by the current session before opening the new one. All tools except management tools (`open_database`, `close_database`, `save_database`, `list_databases`, `wait_for_analysis`) require the `database` parameter (the stem ID returned by `open_database` or `list_databases`).

```
open_database("first.bin")                              # spawns worker (returns immediately)
wait_for_analysis(database="first")                     # blocks until ready
open_database("second.bin")                             # spawns second worker
wait_for_analysis(database="second")                    # blocks until ready
decompile_function(address="main", database="first")    # targets first
close_database(database="second")                       # closes second
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IDADIR` | *(auto-detected)* | Path to IDA Pro installation directory |
| `IDA_MCP_MAX_WORKERS` | *(no limit)* | Maximum simultaneous databases (1-8, unset for unlimited) |
| `IDA_MCP_ALLOW_SCRIPTS` | *(unset)* | Set to `1`, `true`, or `yes` to enable the `run_script` tool for arbitrary IDAPython execution |
| `IDA_MCP_LOG_LEVEL` | `WARNING` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) — output goes to stderr |

## Tools

To keep token usage manageable, only a set of common analysis tools are directly visible to clients. Two meta-tools handle the rest:

- **`search_tools`** — regex search over tool names, descriptions, and tags (searches non-pinned tools; pinned tools are already visible)
- **`execute`** — sandboxed Python that chains multiple `await call_tool` invocations in a single round trip (supports `asyncio.gather` for parallel queries, loops, and result processing)

Tools not in the pinned set are hidden from the listing but remain callable by name. Management tools (`open_database`, `close_database`, `save_database`, `list_databases`, `wait_for_analysis`) are always visible.

The full tool catalog covers all major areas of IDA Pro's functionality:

- **Database** — open/close/save/list databases, file region mapping, metadata
- **Functions** — list, query, decompile, disassemble, rename, prototypes, chunks, stack frames
- **Decompiler** — pseudocode variable renaming/retyping, decompiler comments, microcode
- **Ctree** — Hex-Rays AST exploration and pattern matching
- **Cross-References** — xref queries, call graphs, xref creation/deletion
- **Imports & Exports** — imported functions, exported symbols, entry points
- **Search** — string extraction, byte patterns, text in disassembly, immediate values, string-to-code references, string list rebuilding
- **Types & Structures** — local types, structs, enums, type parsing and application, source declarations
- **Instructions & Operands** — decode instructions, resolve operand values, change operand display format
- **Control Flow** — basic blocks, CFG edges, switch/jump tables
- **Data** — raw byte reading, hex dumps, segment listing, pointer tables
- **Patching** — byte patching, instruction assembly, function/code creation, data loading
- **Data Definition** — define bytes, words, dwords, qwords, floats, doubles, strings, and arrays
- **Segments** — create, modify, and rebase segments
- **Names & Comments** — rename addresses, manage comments (get, set, and append)
- **Demangling** — C++ symbol name demangling
- **Analysis** — auto-analysis, fixups, exception handlers, segment registers
- **Address Metadata** — source line numbers, analysis flags, library item marking
- **Register Tracking** — register and stack pointer value tracking
- **Register Variables** — register-to-name mappings within functions
- **Signatures** — FLIRT signatures, type libraries, IDS modules
- **Export** — batch decompilation/disassembly, output file generation, executable rebuilding
- **Snapshots** — take, list, and restore database snapshots
- **Processor** — architecture info, register names, instruction classification
- **Bookmarks** — marked-position management
- **Colors** — address/function coloring
- **Undo** — undo/redo operations
- **Directory Tree** — IDA folder organization
- **Utility** — number conversion, IDC evaluation, scripting

All tools include MCP [annotations](https://modelcontextprotocol.io/docs/concepts/tools#annotations) (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) so clients can distinguish safe reads from mutations and prompt for confirmation on destructive operations. Mutation tools return old values alongside new values for change tracking.

See [docs/tools.md](docs/tools.md) for the complete tools reference.

## Resources

The server exposes [MCP resources](https://modelcontextprotocol.io/docs/concepts/resources) — read-only, cacheable context endpoints that provide structured data without consuming tool calls:

- **Static binary data** — imports, exports, entry points (with regex search variants)
- **Aggregate snapshot** — statistics (function/segment/entry point/string/name counts, code coverage)
- **Supervisor** — `ida://databases` lists all open databases with worker state

## Prompts

The server provides [MCP prompts](https://modelcontextprotocol.io/docs/concepts/prompts) — guided workflow templates that instruct the LLM to use tools in a structured sequence:

- **`survey_binary`** — binary triage producing an executive summary
- **`analyze_function`** — full single-function analysis with decompilation, data flow, and behavior summary
- **`diff_before_after`** — preview the effect of renaming/retyping on decompiler output
- **`classify_functions`** — categorize functions by behavioral pattern
- **`find_crypto_constants`** — scan for known cryptographic constants
- **`auto_rename_strings`** — suggest function renames based on string references
- **`apply_abi`** — apply known ABI type information to identified functions
- **`export_idc_script`** — generate an IDAPython script that reproduces user annotations

## Architecture

See [docs/architecture.md](docs/architecture.md) for detailed architecture documentation.

## Development

```bash
# With uv (recommended)
uv sync                          # Install dependencies
uv run ruff check src/           # Lint
uv run ruff format src/          # Format
uv run ruff check --fix src/     # Lint with auto-fix

# With pip
pip install -e .                 # Install in editable mode
pip install pre-commit pytest pytest-asyncio ruff  # Install dev tools (see [dependency-groups] in pyproject.toml for pinned versions)
ruff check src/                  # Lint
ruff format src/                 # Format
ruff check --fix src/            # Lint with auto-fix
```

Pre-commit hooks run REUSE compliance checks, ruff lint (with auto-fix), ruff formatting, idalib threading lint, and pytest on every commit.

## License

This project is licensed under the [MIT License](LICENSES/MIT.txt).

© 2026 Joe T. Sylve, Ph.D.

This project is [REUSE compliant](https://reuse.software/).

---

*IDA Pro and Hex-Rays are trademarks of Hex-Rays SA. ida-mcp is an independent project and is not affiliated with or endorsed by Hex-Rays.*
