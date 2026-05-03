# RE-MCP

A multi-backend reverse-engineering [MCP](https://modelcontextprotocol.io/) server. Exposes binary analysis capabilities from [IDA Pro](https://hex-rays.com/ida-pro/) and [Ghidra](https://ghidra-sre.org/) over the Model Context Protocol, letting LLMs drive reverse-engineering tools directly. Supports multiple simultaneous databases through a supervisor/worker architecture.

Both backends are standalone servers, not plugins. They use headless APIs ([idalib](https://docs.hex-rays.com/release-notes/9_0#idalib-ida-as-a-library) for IDA, [pyhidra](https://github.com/dod-cyber-crime-center/pyhidra) for Ghidra) to run analysis engines without a GUI.

## Backends

| Backend | Package | Requirements |
|---------|---------|--------------|
| **IDA Pro** | [`re-mcp-ida`](packages/re-mcp-ida/) | IDA Pro 9+ with valid license |
| **Ghidra** | [`re-mcp-ghidra`](packages/re-mcp-ghidra/) | Ghidra 11+, JDK 21+ |

Both backends share a common tool interface — core analysis tools use the same names, parameters, and response shapes — so LLM workflows are portable across backends. Each backend also has tools for platform-specific features (e.g. IDA: file region mapping, executable rebuilding, IDC evaluation, IDAPython scripting; Ghidra: Function ID analysis, data type archives).

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager (recommended) or pip
- macOS, Windows, or Linux
- At least one supported backend installed on the same machine

## Installation

### IDA backend

```bash
uv tool install re-mcp-ida
```

### Ghidra backend

```bash
uv tool install re-mcp-ghidra
```

### Both backends

```bash
pip install re-mcp
```

With pip, individual backends can also be installed separately:

```bash
pip install re-mcp-ida    # IDA only
pip install re-mcp-ghidra # Ghidra only
```

### From source

```bash
git clone https://github.com/jtsylve/ida-mcp && cd ida-mcp
uv sync
```

Or with pip:

```bash
git clone https://github.com/jtsylve/ida-mcp && cd ida-mcp
pip install -e packages/re-mcp-core -e packages/re-mcp-ida -e packages/re-mcp-ghidra
```

### Finding IDA Pro

The IDA backend looks for your IDA Pro installation in the following order:

1. **`IDADIR` environment variable** — checked first; set this if IDA is in a non-standard location.
2. **IDA's own config file** — `Paths.ida-install-dir` in `~/.idapro/ida-config.json` (macOS/Linux) or `%APPDATA%\Hex-Rays\IDA Pro\ida-config.json` (Windows). If the `IDAUSR` environment variable is set, it is used as the config directory instead.
3. **Platform-specific default paths:**

| Platform | Default search paths |
|----------|---------------------|
| macOS    | `/Applications/IDA Professional *.app/Contents/MacOS` |
| Windows  | `C:\Program Files\IDA Professional 9.3`, `C:\Program Files\IDA Pro 9.3`, and `Program Files (x86)` equivalents |
| Linux    | `/opt/ida-pro-9.3`, `/opt/idapro-9.3`, `/opt/ida-9.3`, `~/ida-pro-9.3`, `~/idapro-9.3` |

The `idapro` package is loaded at runtime directly from your local IDA Pro installation — no extra setup steps or environment variables are needed if IDA is installed in a standard location.

### Finding Ghidra

The Ghidra backend looks for your Ghidra installation in the following order:

1. **`GHIDRA_INSTALL_DIR` environment variable** — checked first; set this if Ghidra is in a non-standard location.
2. **Config file** — `ghidra-install-dir` in `~/.ghidra/ghidra-config.json`.
3. **Platform-specific default paths:**

| Platform | Default search paths |
|----------|---------------------|
| macOS    | `/Applications/ghidra_*`, `~/ghidra_*` |
| Windows  | `C:\ghidra_*`, `~/ghidra_*` |
| Linux    | `/opt/ghidra_*`, `/usr/local/ghidra_*`, `~/ghidra_*` |

## Usage

### Running the server

Each backend has its own CLI:

```bash
# IDA Pro backend
uvx re-mcp-ida

# Ghidra backend
uvx re-mcp-ghidra
```

Or if installed with pip:

```bash
re-mcp-ida
re-mcp-ghidra
```

Both CLIs support the same subcommands:

| Command | Description |
|---------|-------------|
| `<backend>` (or `<backend> proxy`) | Stdio proxy that auto-spawns a persistent HTTP daemon (default) |
| `<backend> serve` | Start the HTTP daemon directly (for manual daemon management) |
| `<backend> stop` | Gracefully shut down a running daemon |
| `<backend> stdio` | Direct stdio mode — single-session, workers die on disconnect |

The server uses a persistent HTTP daemon behind the scenes. The default mode runs a stdio proxy that auto-spawns this daemon, handling port allocation and authentication transparently. Workers and database state persist across client reconnections. The daemon shuts down automatically after 5 minutes of inactivity (configurable via `<PREFIX>IDLE_TIMEOUT`).

### Running without installing

```bash
# IDA (uv)
IDADIR=/path/to/ida uvx re-mcp-ida

# Ghidra (uv)
GHIDRA_INSTALL_DIR=/path/to/ghidra uvx re-mcp-ghidra

# pipx
IDADIR=/path/to/ida pipx run re-mcp-ida
GHIDRA_INSTALL_DIR=/path/to/ghidra pipx run re-mcp-ghidra
```

```powershell
# IDA (uv)
$env:IDADIR = "C:\Program Files\IDA Professional 9.3"
uvx re-mcp-ida

# Ghidra (uv)
$env:GHIDRA_INSTALL_DIR = "C:\ghidra_11.4.3_PUBLIC"
uvx re-mcp-ghidra
```

### MCP client configuration

Add to your MCP client config (e.g. Claude Desktop `claude_desktop_config.json`):

**IDA backend:**

```json
{
  "mcpServers": {
    "ida": {
      "command": "uvx",
      "args": ["re-mcp-ida"]
    }
  }
}
```

**Ghidra backend:**

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "uvx",
      "args": ["re-mcp-ghidra"]
    }
  }
}
```

**Both backends simultaneously:**

```json
{
  "mcpServers": {
    "ida": {
      "command": "uvx",
      "args": ["re-mcp-ida"]
    },
    "ghidra": {
      "command": "uvx",
      "args": ["re-mcp-ghidra"]
    }
  }
}
```

If you don't use uv, use the backend command directly (assuming it's on your `PATH`):

```json
{
  "mcpServers": {
    "ida": {
      "command": "re-mcp-ida"
    }
  }
}
```

If the command isn't on your `PATH`, use the full path to the executable:

```json
{
  "mcpServers": {
    "ida": {
      "command": "/home/user/.pyenv/versions/<version>/bin/re-mcp-ida"
    }
  }
}
```

If the backend (IDA or Ghidra) isn't in a default location, add the install directory via the `env` key:

```json
{
  "mcpServers": {
    "ida": {
      "command": "uvx",
      "args": ["re-mcp-ida"],
      "env": {
        "IDADIR": "/path/to/ida"
      }
    },
    "ghidra": {
      "command": "uvx",
      "args": ["re-mcp-ghidra"],
      "env": {
        "GHIDRA_INSTALL_DIR": "/path/to/ghidra"
      }
    }
  }
}
```

**Connecting to a running daemon directly:**

If you started the daemon manually with `<backend> serve`, the connection details (host, port, bearer token) are in the state file. Clients that support streamable HTTP can connect directly.

State file locations:
- **macOS:** `~/Library/Application Support/<backend>/daemon.json`
- **Linux:** `$XDG_STATE_HOME/<backend>/daemon.json` (defaults to `~/.local/state/<backend>/daemon.json`)
- **Windows:** `%LOCALAPPDATA%\<backend>\daemon.json`

Where `<backend>` is `re-mcp-ida` or `re-mcp-ghidra`.

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

1. **Open a binary** — call `open_database` with the path to a binary (or existing database file), then `wait_for_analysis` to block until it is ready
2. **Analyze** — use the available tools (list functions, decompile, search strings, read bytes, etc.)
3. **Close** — call `close_database` when done (auto-saves by default)

Raw binaries must be in a writable directory since both backends create database files alongside them. When opening an existing database, the original binary does not need to be present.

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

Each backend uses its own environment variable prefix (`IDA_MCP_` or `GHIDRA_MCP_`). The table below uses `<PREFIX>` as a placeholder.

**Backend installation:**

| Variable | Backend | Default | Description |
|----------|---------|---------|-------------|
| `IDADIR` | IDA | *(auto-detected)* | Path to IDA Pro installation directory |
| `GHIDRA_INSTALL_DIR` | Ghidra | *(auto-detected)* | Path to Ghidra installation directory |

**Shared settings** (replace `<PREFIX>` with `IDA_MCP_` or `GHIDRA_MCP_`):

| Variable | Default | Description |
|----------|---------|-------------|
| `<PREFIX>MAX_WORKERS` | *(unlimited)* | Maximum simultaneous databases (clamped to 1-8 when set) |
| `<PREFIX>LOG_LEVEL` | `WARNING` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) — output goes to stderr |
| `<PREFIX>LOG_DIR` | *(unset)* | Directory for per-run log files. Each component logs to `<dir>/<run_id>-<label>.log`, each worker to `<dir>/<run_id>-worker-<db>.log`, and each worker's raw stderr to `<dir>/<run_id>-worker-<db>.stderr`. When unset, logs go only to stderr. |
| `<PREFIX>IDLE_TIMEOUT` | `300` | Idle auto-shutdown timeout in seconds for auto-spawned daemons. Set to `0` to disable. `<backend> serve` defaults to `0` (use `--idle-timeout=N` to override). |
| `<PREFIX>DISABLE_EXECUTE` | *(unset)* | Set to `1`, `true`, `yes`, or `on` to hide the `execute` meta-tool (sandboxed Python code mode) |
| `<PREFIX>DISABLE_BATCH` | *(unset)* | Set to `1`, `true`, `yes`, or `on` to hide the `batch` meta-tool |
| `<PREFIX>DISABLE_TOOL_SEARCH` | *(unset)* | Set to `1`, `true`, `yes`, or `on` to disable server-side progressive tool disclosure — all tools become directly visible and callable, and the `search_tools` and `get_schema` meta-tools are removed. Useful with clients that provide their own tool deferral (e.g. Claude Code). |

**IDA-only settings:**

| Variable | Default | Description |
|----------|---------|-------------|
| `IDA_MCP_ALLOW_SCRIPTS` | *(unset)* | Set to `1`, `true`, or `yes` to enable the `run_script` tool for arbitrary IDAPython execution |

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
- **Ctree** — AST exploration and pattern matching
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
- **Signatures** — FLIRT signatures/type libraries (IDA), Function ID/data type archives (Ghidra)
- **Export** — batch decompilation/disassembly, output file generation
- **Snapshots** — take, list, and restore database snapshots
- **Processor** — architecture info, register names, instruction classification
- **Bookmarks** — marked-position management
- **Colors** — address/function coloring
- **Undo** — undo/redo operations
- **Directory Tree** — folder organization
- **Utility** — number conversion, expression evaluation, scripting

All tools include MCP [annotations](https://modelcontextprotocol.io/docs/concepts/tools#annotations) (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) so clients can distinguish safe reads from mutations and prompt for confirmation on destructive operations. Mutation tools return old values alongside new values for change tracking.

See [docs/tools.md](docs/tools.md) for the complete tools reference.

## Resources

The server exposes [MCP resources](https://modelcontextprotocol.io/docs/concepts/resources) — read-only, cacheable endpoints for structured database context:

- **Static binary data** — imports, exports, entry points (with regex search variants)
- **Aggregate snapshot** — statistics (function/segment/entry point/string/name counts, code coverage)
- **Supervisor** — `<scheme>://databases` lists all open databases with worker state

The URI scheme is `ida://` for the IDA backend and `ghidra://` for the Ghidra backend.

## Prompts

The server provides [MCP prompts](https://modelcontextprotocol.io/docs/concepts/prompts) — guided workflow templates that instruct the LLM to use tools in a structured sequence. Prompts are currently available for the IDA backend only.

- **`survey_binary`** — binary triage producing an executive summary
- **`analyze_function`** — full single-function analysis with decompilation, data flow, and behavior summary
- **`diff_before_after`** — preview the effect of renaming/retyping on decompiler output
- **`classify_functions`** — categorize functions by behavioral pattern
- **`find_crypto_constants`** — scan for known cryptographic constants
- **`auto_rename_strings`** — suggest function renames based on string references
- **`apply_abi`** — apply known ABI type information to identified functions
- **`export_idc_script`** — generate a script that reproduces user annotations

## Architecture

The project is a monorepo with three packages:

- [`re-mcp-core`](packages/re-mcp-core/) — shared supervisor infrastructure, transport, and common utilities
- [`re-mcp-ida`](packages/re-mcp-ida/) — IDA Pro backend
- [`re-mcp-ghidra`](packages/re-mcp-ghidra/) — Ghidra backend

See [docs/architecture.md](docs/architecture.md) for detailed architecture documentation.

## Development

```bash
# With uv (recommended)
uv sync                              # Install dependencies
uv run ruff check packages/          # Lint
uv run ruff format packages/         # Format
uv run ruff check --fix packages/    # Lint with auto-fix

# With pip
pip install -e packages/re-mcp-core -e packages/re-mcp-ida -e packages/re-mcp-ghidra
pip install pre-commit pytest pytest-asyncio ruff jsonschema
ruff check packages/
ruff format packages/
ruff check --fix packages/
```

Pre-commit hooks run REUSE compliance checks, ruff lint (with `--fix --exit-non-zero-on-fix`), ruff format, idalib threading lint, and pytest on every commit.

## License

This project is dual-licensed under the [MIT License](LICENSES/MIT.txt) and [Apache License 2.0](LICENSES/Apache-2.0.txt).

© 2026 Joe T. Sylve, Ph.D.

This project is [REUSE compliant](https://reuse.software/).

---

*IDA Pro and Hex-Rays are trademarks of Hex-Rays SA. Ghidra is developed by the NSA. RE-MCP is an independent project and is not affiliated with or endorsed by Hex-Rays or the NSA.*
