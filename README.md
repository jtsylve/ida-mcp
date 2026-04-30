# IDA MCP Server

A headless [IDA Pro](https://hex-rays.com/ida-pro/) MCP server built on [idalib](https://docs.hex-rays.com/release-notes/9_0#idalib-ida-as-a-library). Exposes IDA Pro's binary analysis capabilities over the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP), letting LLMs drive IDA Pro for reverse engineering tasks. Supports multiple simultaneous databases through a supervisor/worker architecture.

This is a standalone server, not an IDA plugin. It uses [idalib](https://docs.hex-rays.com/release-notes/9_0#idalib-ida-as-a-library) (IDA as a library) to run IDA's analysis engine without a GUI — no IDA GUI needs to be running. IDA Pro 9+ must be installed on the same machine.

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
pip install -e packages/re-mcp-core -e packages/ida-mcp
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

### Running the server

```bash
uvx ida-mcp
```

Or if installed with pip:

```bash
ida-mcp
```

The server uses a persistent HTTP daemon behind the scenes. The default mode runs a stdio proxy that auto-spawns this daemon, handling port allocation and authentication transparently. Workers and database state persist across client reconnections. The daemon shuts down automatically after 5 minutes of inactivity (configurable via `IDA_MCP_IDLE_TIMEOUT`).

| Command | Description |
|---------|-------------|
| `ida-mcp` (or `ida-mcp proxy`) | Stdio proxy that auto-spawns a persistent HTTP daemon (default) |
| `ida-mcp serve` | Start the HTTP daemon directly (for manual daemon management) |
| `ida-mcp stop` | Gracefully shut down a running daemon |
| `ida-mcp stdio` | Direct stdio mode — single-session, workers die on disconnect |

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

This runs the stdio proxy, which auto-spawns the persistent HTTP daemon in the background. The proxy handles port allocation and authentication automatically — no manual daemon management required.

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

If IDA is not in a default location, add `IDADIR` via the `env` key:

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

**Connecting to a running daemon directly:**

If you started the daemon manually with `ida-mcp serve`, the connection details (host, port, bearer token) are in the state file. Clients that support streamable HTTP can connect directly.

State file locations:
- **macOS:** `~/Library/Application Support/ida-mcp/daemon.json`
- **Linux:** `$XDG_STATE_HOME/ida-mcp/daemon.json` (defaults to `~/.local/state/ida-mcp/daemon.json`)
- **Windows:** `%LOCALAPPDATA%\ida-mcp\daemon.json`

```json
{
  "mcpServers": {
    "ida": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:<port>/mcp",
      "headers": {
        "Authorization": "Bearer <token>"
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

Multiple databases can be open at the same time. By default, `open_database` keeps previously opened databases open. Pass `keep_open=False` to save and close databases owned by the current session before opening the new one. All tools except management tools (`open_database`, `close_database`, `save_database`, `list_databases`, `wait_for_analysis`, `list_targets`) require the `database` parameter (the stem ID returned by `open_database` or `list_databases`).

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
| `IDA_MCP_MAX_WORKERS` | *(unlimited)* | Maximum simultaneous databases (clamped to 1-8 when set) |
| `IDA_MCP_ALLOW_SCRIPTS` | *(unset)* | Set to `1`, `true`, or `yes` to enable the `run_script` tool for arbitrary IDAPython execution |
| `IDA_MCP_LOG_LEVEL` | `WARNING` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) — output goes to stderr |
| `IDA_MCP_LOG_DIR` | *(unset)* | Directory for per-run log files. Each component logs to `<dir>/<run_id>-<label>.log` (labels: `daemon`, `proxy`, `supervisor` for direct stdio mode), each worker to `<dir>/<run_id>-worker-<db>.log`, and each worker's raw stderr to `<dir>/<run_id>-worker-<db>.stderr` (catches pre-logging output and C-level crashes). When unset, logs go only to stderr. |
| `IDA_MCP_IDLE_TIMEOUT` | `300` | Idle auto-shutdown timeout in seconds for auto-spawned daemons. Set to `0` to disable. `ida-mcp serve` defaults to `0` (use `--idle-timeout=N` to override). |
| `IDA_MCP_DISABLE_EXECUTE` | *(unset)* | Set to `1`, `true`, `yes`, or `on` to hide the `execute` meta-tool (sandboxed Python code mode) |
| `IDA_MCP_DISABLE_BATCH` | *(unset)* | Set to `1`, `true`, `yes`, or `on` to hide the `batch` meta-tool |
| `IDA_MCP_DISABLE_TOOL_SEARCH` | *(unset)* | Set to `1`, `true`, `yes`, or `on` to disable server-side progressive tool disclosure — all tools become directly visible and callable, and the `search_tools` and `get_schema` meta-tools are removed. Useful with clients that provide their own tool deferral (e.g. Claude Code). |

## Tools

To keep token usage manageable, only common analysis tools and management tools are directly visible to clients. The rest are discoverable and callable through meta-tools:

- **`search_tools`** — regex search over non-pinned tool names, descriptions, and tags (pinned tools are already visible).
- **`get_schema`** — parameter schemas and return shapes for tools by name.
- **`call`** — lightweight proxy for calling any tool by name, including hidden tools not in the client tool list.
- **`execute`** — sandboxed Python that chains multiple `await invoke(name, params)` calls in a single round trip. Supports `asyncio.gather` for parallel queries, loops, and conditional logic between calls.
- **`batch`** — sequential multi-tool execution with per-item error collection and progress reporting (up to 50 operations per call).

Management tools (`open_database`, `close_database`, `save_database`, `list_databases`, `wait_for_analysis`, `list_targets`) are always visible. Most must be called directly — `save_database` and `list_databases` are the exceptions, also callable through `call`, `execute`, and `batch` for use in multi-step workflows.

The full tool catalog spans these areas:

- **Database** — open/close/save/list databases, file region mapping, metadata
- **Functions** — list, query, decompile, disassemble, rename, prototypes, chunks, stack frames
- **Decompiler** — pseudocode variable renaming/retyping, decompiler comments, microcode
- **Ctree** — Hex-Rays AST exploration and pattern matching
- **Cross-References** — xref queries, call graphs, xref creation/deletion
- **Imports & Exports** — imported functions, exported symbols, entry point listing and manipulation
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

The server exposes [MCP resources](https://modelcontextprotocol.io/docs/concepts/resources) — read-only, cacheable endpoints for structured database context:

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
uv sync                              # Install dependencies
uv run ruff check packages/          # Lint
uv run ruff format packages/         # Format
uv run ruff check --fix packages/    # Lint with auto-fix

# With pip
pip install -e packages/re-mcp-core -e packages/ida-mcp  # Install in editable mode
pip install pre-commit pytest pytest-asyncio ruff jsonschema  # dev tools; see [dependency-groups] in pyproject.toml for version constraints
ruff check packages/             # Lint
ruff format packages/            # Format
ruff check --fix packages/       # Lint with auto-fix
```

Pre-commit hooks run REUSE compliance checks, ruff lint (with `--fix --exit-non-zero-on-fix`), ruff format, idalib threading lint, and pytest on every commit.

## License

This project is dual-licensed under the [MIT License](LICENSES/MIT.txt) and [Apache License 2.0](LICENSES/Apache-2.0.txt).

© 2026 Joe T. Sylve, Ph.D.

This project is [REUSE compliant](https://reuse.software/).

---

*IDA Pro and Hex-Rays are trademarks of Hex-Rays SA. ida-mcp is an independent project and is not affiliated with or endorsed by Hex-Rays.*
