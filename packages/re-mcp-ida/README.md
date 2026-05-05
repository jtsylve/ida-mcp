# re-mcp-ida

IDA Pro backend for [RE-MCP](https://github.com/jtsylve/ida-mcp) — a headless [IDA Pro](https://hex-rays.com/ida-pro/) MCP server using [idalib](https://docs.hex-rays.com/release-notes/9_0#idalib-ida-as-a-library). Exposes IDA's full analysis capabilities over the [Model Context Protocol](https://modelcontextprotocol.io/), letting LLMs drive reverse engineering directly.

This is a standalone server, not an IDA plugin. It uses idalib to run IDA's analysis engine without a GUI.

## Requirements

- Python 3.12+
- IDA Pro 9+ with a valid license
- macOS, Windows, or Linux

## Installation

```bash
uv tool install re-mcp-ida
```

Or with pip:

```bash
pip install re-mcp-ida
```

## Finding IDA Pro

The server looks for your IDA Pro installation in the following order:

1. **`IDADIR` environment variable** — set this if IDA is in a non-standard location.
2. **IDA's config file** — `Paths.ida-install-dir` in `~/.idapro/ida-config.json` (macOS/Linux) or `%APPDATA%\Hex-Rays\IDA Pro\ida-config.json` (Windows).
3. **Platform-specific default paths** (e.g. `/Applications/IDA Professional *.app/Contents/MacOS` on macOS).

See the [main documentation](https://github.com/jtsylve/ida-mcp#finding-ida-pro) for the full list of default search paths per platform.

## Usage

```bash
# Run the server (direct stdio mode)
re-mcp-ida

# Or with uvx (no install needed)
uvx re-mcp-ida
```

### MCP client configuration

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

### CLI subcommands

| Command | Description |
|---------|-------------|
| `re-mcp-ida` (or `re-mcp-ida stdio`) | Direct stdio mode — single-session, workers die on disconnect (default) |
| `re-mcp-ida proxy` | Stdio proxy that auto-spawns a persistent HTTP daemon |
| `re-mcp-ida serve` | Start the HTTP daemon directly |
| `re-mcp-ida stop` | Gracefully shut down a running daemon |
| `re-mcp-ida backends` | List installed backends |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IDADIR` | *(auto-detected)* | Path to IDA Pro installation directory |
| `IDA_MCP_MAX_WORKERS` | *(unlimited)* | Maximum simultaneous databases (1-8) |
| `IDA_MCP_LOG_LEVEL` | `WARNING` | Logging level |
| `IDA_MCP_LOG_DIR` | *(unset)* | Directory for per-run log files |
| `IDA_MCP_IDLE_TIMEOUT` | `300` | Auto-shutdown timeout in seconds (0 to disable) |
| `IDA_MCP_ALLOW_SCRIPTS` | *(unset)* | Set to `1`, `true`, or `yes` to enable `run_script` for arbitrary IDAPython |

## Features

- Full decompilation and disassembly
- Function, type, and structure management
- Cross-reference and call graph analysis
- String and byte pattern search
- Binary patching and instruction assembly
- FLIRT signature and type library support
- MCP prompts for guided workflows (binary triage, function analysis, crypto detection, etc.)
- Multi-database support with concurrent analysis
- MCP resources for structured read-only access

See the [main documentation](https://github.com/jtsylve/ida-mcp) for the full tool catalog, multi-database workflows, and detailed usage.

## License

Dual-licensed under [MIT](https://github.com/jtsylve/ida-mcp/blob/main/LICENSES/MIT.txt) and [Apache-2.0](https://github.com/jtsylve/ida-mcp/blob/main/LICENSES/Apache-2.0.txt).
