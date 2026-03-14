# IDA MCP Server

A headless [IDA Pro](https://hex-rays.com/ida-pro/) 9.3 MCP server built on [idalib](https://docs.hex-rays.com/release-notes/9_0#idalib-ida-as-a-library). Exposes a comprehensive set of binary analysis tools over the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP), letting LLMs drive IDA Pro for reverse engineering tasks.

## Requirements

- IDA Pro 9.3 with a valid license (including Hex-Rays decompiler for decompilation tools)
- Python 3.13+
- [uv](https://docs.astral.sh/uv/) package manager
- macOS, Windows, or Linux

## Installation

```bash
git clone https://github.com/jtsylve/ida-mcp && cd ida-mcp
uv sync
```

That's it. The `idapro` package is loaded at runtime directly from your local IDA Pro installation — no extra setup steps or environment variables are needed if IDA is installed in a standard location.

### Finding IDA Pro

At startup the server looks for your IDA Pro installation in the following order:

1. **`IDADIR` environment variable** — checked first; set this if IDA is in a non-standard location.
2. **IDA's own config file** — `ida-install-dir` in `~/.idapro/ida-config.json` (macOS/Linux) or `%APPDATA%\Hex-Rays\IDA Pro\ida-config.json` (Windows). This is the same file IDA itself uses.
3. **Platform-specific default paths:**

| Platform | Default search paths |
|----------|---------------------|
| macOS    | `/Applications/IDA Professional *.app/Contents/MacOS` |
| Windows  | `C:\Program Files\IDA Professional 9.3`, `C:\Program Files\IDA Pro 9.3` |
| Linux    | `/opt/ida-pro-9.3`, `/opt/idapro-9.3`, `~/ida-pro-9.3` |

If the server can't find IDA, you'll get a clear error message telling you to set `IDADIR`.

## Usage

### Stdio transport (default)

```bash
uv run ida-mcp
```

### Running directly from GitHub

You can run the server without cloning the repo:

```bash
# macOS/Linux
IDADIR=/path/to/ida uvx --from git+https://github.com/jtsylve/ida-mcp ida-mcp

# Windows (PowerShell)
$env:IDADIR = "C:\Program Files\IDA Professional 9.3"
uvx --from git+https://github.com/jtsylve/ida-mcp ida-mcp
```

### MCP client configuration

Add to your MCP client config (e.g. Claude Desktop `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "ida": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/jtsylve/ida-mcp", "ida-mcp"]
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
      "args": ["--from", "git+https://github.com/jtsylve/ida-mcp", "ida-mcp"],
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

## Tools

The server provides a comprehensive set of tools covering all major areas of IDA Pro's functionality:

- **Database** — open/close/save databases, file region mapping, metadata
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
