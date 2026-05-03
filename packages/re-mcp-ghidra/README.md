# re-mcp-ghidra

Ghidra backend for [RE-MCP](https://github.com/jtsylve/ida-mcp) — a headless [Ghidra](https://ghidra-sre.org/) MCP server using [pyhidra](https://github.com/dod-cyber-crime-center/pyhidra). Exposes Ghidra's analysis capabilities over the [Model Context Protocol](https://modelcontextprotocol.io/), letting LLMs drive reverse engineering directly.

This is a standalone server, not a Ghidra plugin. It uses pyhidra to run Ghidra's analysis engine without a GUI.

## Requirements

- Python 3.12+
- Ghidra 11+
- JDK 21+
- macOS, Windows, or Linux

## Installation

```bash
uv tool install re-mcp-ghidra
```

Or with pip:

```bash
pip install re-mcp-ghidra
```

## Finding Ghidra

The server looks for your Ghidra installation in the following order:

1. **`GHIDRA_INSTALL_DIR` environment variable** — set this if Ghidra is in a non-standard location.
2. **Config file** — `ghidra-install-dir` in `~/.ghidra/ghidra-config.json`.
3. **Platform-specific default paths** (e.g. `/Applications/ghidra_*` on macOS).

See the [main documentation](https://github.com/jtsylve/ida-mcp#finding-ghidra) for the full list of default search paths per platform.

## Usage

```bash
# Run the server (direct stdio mode)
re-mcp-ghidra

# Or with uvx (no install needed)
uvx re-mcp-ghidra
```

### MCP client configuration

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

### CLI subcommands

| Command | Description |
|---------|-------------|
| `re-mcp-ghidra` (or `re-mcp-ghidra stdio`) | Direct stdio mode — single-session, workers die on disconnect (default) |
| `re-mcp-ghidra proxy` | Stdio proxy that auto-spawns a persistent HTTP daemon |
| `re-mcp-ghidra serve` | Start the HTTP daemon directly |
| `re-mcp-ghidra stop` | Gracefully shut down a running daemon |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GHIDRA_INSTALL_DIR` | *(auto-detected)* | Path to Ghidra installation directory |
| `GHIDRA_MCP_MAX_WORKERS` | *(unlimited)* | Maximum simultaneous databases (1-8) |
| `GHIDRA_MCP_LOG_LEVEL` | `WARNING` | Logging level |
| `GHIDRA_MCP_LOG_DIR` | *(unset)* | Directory for per-run log files |
| `GHIDRA_MCP_IDLE_TIMEOUT` | `300` | Auto-shutdown timeout in seconds (0 to disable) |

## Features

- Full decompilation and disassembly
- Function, type, and structure management
- Cross-reference and call graph analysis
- String and byte pattern search
- Binary patching and instruction assembly
- Function ID and data type archive support
- Multi-database support with concurrent analysis
- MCP resources for structured read-only access

See the [main documentation](https://github.com/jtsylve/ida-mcp) for the full tool catalog, multi-database workflows, and detailed usage.

## License

Dual-licensed under [MIT](https://github.com/jtsylve/ida-mcp/blob/main/LICENSES/MIT.txt) and [Apache-2.0](https://github.com/jtsylve/ida-mcp/blob/main/LICENSES/Apache-2.0.txt).
