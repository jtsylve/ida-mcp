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
import time
from pathlib import Path
from typing import TYPE_CHECKING

import fastmcp
import uvicorn
from fastmcp.server.auth.auth import AccessToken, AuthProvider

from ida_mcp import get_version

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send

    from ida_mcp.worker_provider import WorkerPoolProvider

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


_IDLE_POLL_INTERVAL = 10
KEEPALIVE_INTERVAL = 30
_PROXY_KEEPALIVE_TIMEOUT = KEEPALIVE_INTERVAL * 3


# ---------------------------------------------------------------------------
# Proxy keepalive tracking
# ---------------------------------------------------------------------------


class ProxyTracker:
    """Tracks proxy keepalive pings for the idle monitor.

    Tracks a single proxy — if multiple proxies connect, the most recent
    ping wins.  This is fine for the current single-proxy design.

    Not thread-safe; relies on asyncio's single-threaded event loop
    (both the ASGI health middleware and the idle monitor run on the
    same loop).
    """

    def __init__(self):
        self._last_seen: float = 0

    def ping(self) -> None:
        self._last_seen = time.monotonic()

    @property
    def has_active_proxy(self) -> bool:
        if self._last_seen == 0:
            return False
        return (time.monotonic() - self._last_seen) < _PROXY_KEEPALIVE_TIMEOUT

    @property
    def proxy_was_seen(self) -> bool:
        """True if a proxy has ever sent a keepalive ping."""
        return self._last_seen > 0


def _wrap_with_health(app: ASGIApp, tracker: ProxyTracker, expected_token: str) -> ASGIApp:
    """ASGI middleware that handles ``GET /health`` keepalive pings.

    Requires the same bearer token as the rest of the API.
    """

    async def wrapped(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"] == "/health" and scope["method"] == "GET":
            headers = dict(scope.get("headers", []))
            auth_value = (headers.get(b"authorization") or b"").decode()
            if not auth_value.startswith("Bearer ") or not secrets.compare_digest(
                auth_value.removeprefix("Bearer "), expected_token
            ):
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [(b"content-length", b"0")],
                    }
                )
                await send({"type": "http.response.body", "body": b""})
                return
            tracker.ping()
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        (b"content-type", b"text/plain"),
                        (b"content-length", b"2"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b"ok"})
            return
        await app(scope, receive, send)

    return wrapped


async def _idle_monitor(
    server: uvicorn.Server,
    pool: WorkerPoolProvider,
    idle_limit: int,
    proxy_tracker: ProxyTracker | None = None,
) -> None:
    """Set ``server.should_exit`` after *idle_limit* seconds with no connections."""
    idle_since: float | None = None
    while not server.should_exit:
        await asyncio.sleep(_IDLE_POLL_INTERVAL)
        has_connections = bool(server.server_state.connections)
        has_sessions = await pool.active_session_count() > 0
        has_active_work = await pool.has_active_work()
        has_proxy = proxy_tracker is not None and proxy_tracker.has_active_proxy

        # When a proxy dies abruptly, its MCP sessions can become orphaned:
        # the SSE transport closes but the in-memory read stream stays open,
        # so the MCP session never unwinds and _registered_sessions keeps
        # the stale entry.  Discount sessions (and connections that may be
        # lingering from those sessions) when the proxy is confirmed dead.
        if not has_proxy and proxy_tracker is not None and proxy_tracker.proxy_was_seen:
            has_sessions = False
            has_connections = False

        if has_connections or has_sessions or has_active_work or has_proxy:
            if idle_since is not None:
                log.info("Connection activity resumed; idle shutdown cancelled")
            idle_since = None
            continue
        now = time.monotonic()
        if idle_since is None:
            idle_since = now
            log.info("No active connections; idle timer started (%ds)", idle_limit)
            continue
        elapsed = now - idle_since
        if elapsed >= idle_limit:
            log.info("Idle for %.0fs (limit %ds); initiating auto-shutdown", elapsed, idle_limit)
            server.should_exit = True
            return


async def _serve_with_idle_monitor(
    server: uvicorn.Server,
    sockets: list[socket.socket],
    pool: WorkerPoolProvider,
    idle_timeout: int,
    proxy_tracker: ProxyTracker | None = None,
) -> None:
    """Run the uvicorn server with a concurrent idle-shutdown monitor."""
    monitor = asyncio.create_task(_idle_monitor(server, pool, idle_timeout, proxy_tracker))
    try:
        await server.serve(sockets=sockets)
    finally:
        monitor.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await monitor


def serve(*, host: str = "127.0.0.1", port: int = 0, idle_timeout: int = 0) -> None:
    """Start the streamable HTTP daemon (blocking).

    When *idle_timeout* is positive the daemon auto-shuts-down after that
    many seconds with no active HTTP connections or MCP sessions.
    """
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
    tracker = ProxyTracker()
    app = _wrap_with_health(app, tracker, token)

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

        if idle_timeout > 0:
            log.info("Idle auto-shutdown enabled (timeout=%ds)", idle_timeout)
            asyncio.run(
                _serve_with_idle_monitor(server, [sock], proxy.worker_pool, idle_timeout, tracker)
            )
        else:
            asyncio.run(server.serve(sockets=[sock]))
    except SystemExit as exc:
        if exc.code:
            raise
    finally:
        if state_written:
            remove_state()
        sock.close()
