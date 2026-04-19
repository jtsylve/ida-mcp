# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Streamable HTTP daemon for the IDA MCP server.

Runs the supervisor as a persistent HTTP daemon so that worker processes
survive MCP client (stdio) reconnections.  The daemon writes a state file
containing the bound port and bearer token so that the stdio proxy
(``proxy.py``) can connect automatically.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import secrets
import socket
import sys
import tempfile
from pathlib import Path

import fastmcp
import uvicorn
from fastmcp.server.auth.auth import AccessToken, AuthProvider

from ida_mcp import get_version

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Bearer token auth
# ---------------------------------------------------------------------------


class BearerTokenAuth(AuthProvider):
    """Static bearer token verifier for local daemon authentication."""

    def __init__(self, expected_token: str):
        super().__init__()
        self._expected_token = expected_token

    async def verify_token(self, token: str) -> AccessToken | None:
        if secrets.compare_digest(token, self._expected_token):
            return AccessToken(token=token, client_id="local", scopes=[])
        return None


# ---------------------------------------------------------------------------
# State file management
# ---------------------------------------------------------------------------


def _state_dir() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "ida-mcp"
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA", str(Path.home()))
        return Path(base) / "ida-mcp"
    base = os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state"))
    return Path(base) / "ida-mcp"


def _state_file() -> Path:
    return _state_dir() / "daemon.json"


def write_state(*, pid: int, host: str, port: int, token: str, version: str) -> None:
    """Atomically write the daemon state file with restricted permissions."""
    path = _state_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps({"pid": pid, "host": host, "port": port, "token": token, "version": version})
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        os.write(fd, data.encode())
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
    except BaseException:
        os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    else:
        os.close(fd)
        os.replace(tmp, path)
    log.info("Wrote daemon state to %s (port=%d)", path, port)


def read_state() -> dict | None:
    """Read and validate the daemon state file.  Returns None if unusable."""
    path = _state_file()
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    for key in ("pid", "host", "port", "token", "version"):
        if key not in data:
            return None
    return data


def remove_state() -> None:
    """Remove the daemon state file, ignoring missing files."""
    with contextlib.suppress(FileNotFoundError):
        _state_file().unlink()


def daemon_alive(state: dict) -> bool:
    """Check whether the daemon process recorded in *state* is still alive."""
    pid = state.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Serve command
# ---------------------------------------------------------------------------


def _is_loopback(host: str) -> bool:
    """Return True if *host* resolves to a loopback address."""
    import ipaddress  # noqa: PLC0415

    try:
        info = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        return all(ipaddress.ip_address(addr[4][0]).is_loopback for addr in info)
    except (socket.gaierror, ValueError):
        return False


def serve(*, host: str = "127.0.0.1", port: int = 0) -> None:
    """Start the streamable HTTP daemon (blocking)."""
    from ida_mcp import configure_logging  # noqa: PLC0415
    from ida_mcp.supervisor import ProxyMCP  # noqa: PLC0415

    configure_logging(label="daemon")

    if not _is_loopback(host):
        log.warning(
            "Binding to non-loopback address %s — the daemon will be accessible from the network",
            host,
        )

    token = secrets.token_hex(32)
    auth = BearerTokenAuth(token)
    # lifespan=None skips the stdio-mode signal handlers (uvicorn manages
    # its own signal handling for graceful shutdown).
    proxy = ProxyMCP(auth=auth, lifespan=None)
    app = proxy.http_app(transport="streamable-http")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(socket.SOMAXCONN)
    # uvicorn passes the socket to asyncio's loop.create_server() which requires non-blocking mode
    sock.setblocking(False)
    actual_port = sock.getsockname()[1]

    state_written = False
    try:
        write_state(
            pid=os.getpid(), host=host, port=actual_port, token=token, version=get_version()
        )
        state_written = True
        log.info(
            "Daemon listening on http://%s:%d%s",
            host,
            actual_port,
            fastmcp.settings.streamable_http_path,
        )

        config = uvicorn.Config(app, lifespan="on", log_level="warning")
        server = uvicorn.Server(config)

        # Uvicorn's capture_signals() re-raises caught signals after shutdown,
        # which would trigger the default handler (SIGTERM → exit 143) before
        # our finally block runs.  Install handlers that convert signals to
        # SystemExit so cleanup code executes.  These are overridden by
        # uvicorn during serve() and restored + re-raised on exit.
        import signal  # noqa: PLC0415

        def _exit_on_signal(signum: int, _frame: object) -> None:
            log.info("Received %s, shutting down daemon", signal.Signals(signum).name)
            sys.exit(0)

        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, _exit_on_signal)

        asyncio.run(server.serve(sockets=[sock]))
    except SystemExit as exc:
        if exc.code:
            raise
    finally:
        if state_written:
            remove_state()
        sock.close()
