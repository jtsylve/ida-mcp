# ghidra-mcp

Ghidra backend for [RE-MCP](../../README.md) — a headless [Ghidra](https://ghidra-sre.org/) MCP server using [pyhidra](https://github.com/dod-cyber-crime-center/pyhidra). Exposes Ghidra's analysis capabilities over the [Model Context Protocol](https://modelcontextprotocol.io/), letting LLMs drive reverse engineering directly.

This is a standalone server, not a Ghidra plugin. It uses pyhidra to run Ghidra's analysis engine without a GUI.

> **Status: Alpha** — functional but less mature than the IDA backend.

## Requirements

- Python 3.12+
- Ghidra 11+
- JDK 21+
- macOS, Windows, or Linux

## Installation

```bash
uv tool install ghidra-mcp
```

Or with pip:

```bash
pip install ghidra-mcp
```

## Finding Ghidra

The server looks for your Ghidra installation in the following order:

1. **`GHIDRA_INSTALL_DIR` environment variable** — set this if Ghidra is in a non-standard location.
2. **Config file** — `ghidra-install-dir` in `~/.ghidra/ghidra-config.json`.
3. **Platform-specific default paths** (e.g. `/Applications/ghidra_*` on macOS).

## Usage

```bash
# Run the server (stdio proxy with auto-spawned persistent daemon)
ghidra-mcp

# Or with uvx (no install needed)
uvx ghidra-mcp
```

### MCP client configuration

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "uvx",
      "args": ["ghidra-mcp"]
    }
  }
}
```

### CLI subcommands

| Command | Description |
|---------|-------------|
| `ghidra-mcp` (or `ghidra-mcp proxy`) | Stdio proxy that auto-spawns a persistent HTTP daemon (default) |
| `ghidra-mcp serve` | Start the HTTP daemon directly |
| `ghidra-mcp stop` | Gracefully shut down a running daemon |
| `ghidra-mcp stdio` | Direct stdio mode — single-session, workers die on disconnect |

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
- Function ID and data type archive support
- Multi-database support with concurrent analysis
- MCP resources for structured read-only access

See the [main README](../../README.md) for the full tool catalog and detailed documentation.

## License

Dual-licensed under [MIT](../../LICENSES/MIT.txt) and [Apache-2.0](../../LICENSES/Apache-2.0.txt).
