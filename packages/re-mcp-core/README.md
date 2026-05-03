# re-mcp-core

Shared infrastructure for reverse-engineering MCP backends. This package provides the supervisor/worker architecture, transport layer, and common utilities that backend packages (`ida-mcp`, `ghidra-mcp`) build on.

This package is not intended to be used directly — install a backend package instead. See the [main documentation](https://github.com/jtsylve/ida-mcp) for user-facing documentation.

## What's included

- **Supervisor** — `ProxyMCP(FastMCP)` entry point with worker pool management and management tool registration (`close_database`, `save_database`, `list_databases`, `wait_for_analysis`, `list_targets`)
- **Worker provider** — session-scoped worker ownership, routing tools and resource templates that dispatch to the correct worker process
- **Daemon / proxy** — persistent HTTP daemon with auto-spawning stdio proxy, bearer-token auth, idle timeout
- **Backend protocol** — interface that backends implement to register `open_database`, prompts, and backend-specific instructions
- **Sandboxed execution** — `execute` meta-tool running RestrictedPython with `invoke()` for chaining tool calls
- **Helpers** — address resolution, pagination, type aliases (`Address`, `Offset`, `Limit`, `FilterPattern`, `HexBytes`), tool annotations, and Pydantic model transforms

## Requirements

- Python 3.12+

## License

Dual-licensed under [MIT](https://github.com/jtsylve/ida-mcp/blob/main/LICENSES/MIT.txt) and [Apache-2.0](https://github.com/jtsylve/ida-mcp/blob/main/LICENSES/Apache-2.0.txt).
