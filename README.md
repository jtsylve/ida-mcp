# IDA MCP Server

A headless [IDA Pro](https://hex-rays.com/ida-pro/) 9.3 MCP server built on [idalib](https://docs.hex-rays.com/release-notes/9_0#idalib-ida-as-a-library). Exposes IDA Pro's binary analysis capabilities over the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP), letting LLMs drive IDA Pro for reverse engineering tasks. Supports multiple simultaneous databases via a supervisor/worker architecture.

## Requirements

- IDA Pro 9.3 with a valid license (including Hex-Rays decompiler for decompilation tools)
- Python 3.13+
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

### Finding IDA Pro

At startup the server looks for your IDA Pro installation in the following order:

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

### Running without installing

You can run the server without installing it first:

```bash
# macOS/Linux
IDADIR=/path/to/ida uvx ida-mcp

# Windows (PowerShell)
$env:IDADIR = "C:\Program Files\IDA Professional 9.3"
uvx ida-mcp
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

### Basic workflow

1. **Open a binary** — call `open_database` with the path to a binary file
2. **Analyze** — use the available tools (list functions, decompile, search strings, read bytes, etc.)
3. **Close** — call `close_database` when done (auto-saves by default)

The binary must be in a writable directory since IDA creates a `.i64` database file alongside it.

### Multi-database mode

Multiple databases can be open at the same time. Pass `keep_open=True` to `open_database` to keep previously opened databases open. When multiple databases are open, pass the `database` parameter to any tool to specify the target. Omit it when only one database is open.

```
open_database("first.bin")                              # opens first
open_database("second.bin", keep_open=True)             # opens second, keeps first
list_databases()                                        # shows both
decompile_function(address="main", database="first")    # targets first
close_database(database="second")                       # closes second
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IDADIR` | *(auto-detected)* | Path to IDA Pro installation directory |
| `IDA_MCP_MAX_WORKERS` | `1` | Maximum simultaneous databases (1-8) |
| `IDA_MCP_IDLE_TIMEOUT` | `1800` | Seconds before an idle database is auto-closed (0 to disable) |
| `IDA_MCP_ALLOW_SCRIPTS` | *(unset)* | Set to `1`, `true`, or `yes` to enable the `run_script` tool for arbitrary IDAPython execution |

## Tools

The server provides tools covering all major areas of IDA Pro's functionality:

- **Database** — open/close/save/list databases, file region mapping, metadata
- **Functions** — list, query, decompile, disassemble, rename, manage chunks and types
- **Decompiler** — pseudocode variable renaming/retyping, microcode, ctree AST exploration and pattern matching
- **Cross-References** — xref queries, call graphs, xref creation/deletion
- **Search** — strings, byte patterns, text in disassembly, immediate values, function name regex
- **Types & Structures** — local types, structs, enums, type parsing and application
- **Instructions & Operands** — decode instructions, resolve operand values, change operand display format
- **Control Flow** — basic blocks, CFG edges, switch/jump tables
- **Patching** — byte patching, instruction assembly, function/code creation
- **Segments** — create, modify, rebase segments
- **Names & Comments** — rename addresses, manage comments, C++ demangling
- **Analysis** — auto-analysis, fixups, exception handlers, register tracking
- **Signatures** — FLIRT signatures, type libraries, IDS modules
- **Export** — batch decompilation/disassembly, output file generation
- **Utility** — number conversion, IDC evaluation, bookmarks, colors, undo/redo

See [docs/tools.md](docs/tools.md) for the complete tools reference.

## Architecture

See [docs/architecture.md](docs/architecture.md) for detailed architecture documentation.

## Development

```bash
uv sync                          # Install dependencies
uv run ruff check src/           # Lint
uv run ruff format src/          # Format
uv run ruff check --fix src/     # Lint with auto-fix
```

Pre-commit hooks run REUSE compliance checks, ruff lint (with auto-fix), ruff formatting, and pytest on every commit.

## License

This project is licensed under the [MIT License](LICENSES/MIT.txt).

© 2026 Joe T. Sylve, Ph.D.

This project is [REUSE compliant](https://reuse.software/).
