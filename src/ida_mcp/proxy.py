# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Stdio-to-HTTP proxy for the IDA MCP daemon.

Bridges a stdio MCP connection (from Claude Code or any MCP client) to a
persistent streamable HTTP daemon.  Auto-spawns the daemon if it is not
already running.

This module is the default entry point for ``ida-mcp`` (no arguments).
"""

from __future__ import annotations

import contextlib
import logging
import os
import subprocess
import sys
import time

import anyio
import fastmcp
import httpx
from mcp.client.streamable_http import streamable_http_client
from mcp.server.stdio import stdio_server

from ida_mcp import get_version, resolve_log_file
from ida_mcp.daemon import KEEPALIVE_INTERVAL, _state_dir, daemon_alive, read_state, remove_state

log = logging.getLogger(__name__)

_DAEMON_STARTUP_TIMEOUT = 15.0
_DAEMON_POLL_INTERVAL = 0.1
_DEFAULT_IDLE_TIMEOUT = 300

# IDA analysis on large binaries can take minutes; the read timeout must
# accommodate long-running tool calls (decompile, wait_for_analysis, etc.).
_HTTP_CONNECT_TIMEOUT = 30.0
_HTTP_READ_TIMEOUT = 300.0


# ---------------------------------------------------------------------------
# Daemon management
# ---------------------------------------------------------------------------


def _lock_path() -> str:
    """Return the path of the daemon spawn lock file."""
    return str(_state_dir() / "daemon.lock")


@contextlib.contextmanager
def _spawn_lock():
    """Exclusive lock to prevent concurrent daemon spawns."""
    path = _lock_path()
    _state_dir().mkdir(parents=True, exist_ok=True)
    fp = open(path, "w")  # noqa: SIM115
    try:
        if sys.platform == "win32":
            import msvcrt  # noqa: PLC0415

            msvcrt.locking(fp.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                with contextlib.suppress(OSError):
                    msvcrt.locking(fp.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl  # noqa: PLC0415

            fcntl.flock(fp, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fp, fcntl.LOCK_UN)
    finally:
        fp.close()


def _version_ok(state: dict) -> bool:
    """Return True if the daemon's version matches the current package."""
    current = get_version()
    daemon_ver = state.get("version")
    if not daemon_ver or daemon_ver == "unknown" or current == "unknown":
        return True
    return current == daemon_ver


def _wait_for_exit(pid: int, timeout: float) -> bool:
    """Poll until *pid* exits or *timeout* elapses.  Returns True if exited."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            return True
        time.sleep(0.1)
    return False


def _stop_daemon(state: dict) -> None:
    """Send SIGTERM to the daemon, escalating to SIGKILL if needed."""
    import signal  # noqa: PLC0415

    pid = state["pid"]
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return
    if _wait_for_exit(pid, 5.0):
        return
    # On Windows os.kill(SIGTERM) already calls TerminateProcess (immediate),
    # so reaching here means the process is truly stuck — nothing more to try.
    if sys.platform == "win32":
        log.error("Daemon pid=%d did not exit after TerminateProcess", pid)
        return
    log.warning("Daemon pid=%d did not exit after SIGTERM, sending SIGKILL", pid)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        return
    if not _wait_for_exit(pid, 2.0):
        log.error("Daemon pid=%d did not exit after SIGKILL", pid)


def _ensure_daemon() -> dict:
    """Return a valid daemon state, spawning a new daemon if needed."""
    state = read_state()
    if state is not None and daemon_alive(state) and _version_ok(state):
        log.debug("Reusing existing daemon (pid=%d, port=%d)", state["pid"], state["port"])
        return state

    with _spawn_lock():
        state = read_state()
        if state is not None and daemon_alive(state) and _version_ok(state):
            log.debug("Reusing existing daemon (pid=%d, port=%d)", state["pid"], state["port"])
            return state

        if state is not None and daemon_alive(state):
            log.info(
                "Daemon version mismatch (running=%s, current=%s), restarting",
                state.get("version"),
                get_version(),
            )
            _stop_daemon(state)
            remove_state()
        elif state is not None:
            log.info("Stale daemon state (pid=%d), spawning new daemon", state["pid"])
            remove_state()

        return _spawn_daemon()


def _spawn_daemon() -> dict:
    """Start a daemon subprocess and wait for its state file to appear."""
    idle_timeout_str = os.environ.get("IDA_MCP_IDLE_TIMEOUT", str(_DEFAULT_IDLE_TIMEOUT))
    try:
        idle_timeout = int(idle_timeout_str)
    except ValueError:
        log.error("IDA_MCP_IDLE_TIMEOUT must be an integer, got %r", idle_timeout_str)
        sys.exit(1)
    if idle_timeout < 0:
        log.error("IDA_MCP_IDLE_TIMEOUT must be >= 0, got %d", idle_timeout)
        sys.exit(1)
    cmd = [sys.executable, "-m", "ida_mcp.supervisor", "serve", "--idle-timeout", str(idle_timeout)]
    log.info("Spawning daemon: %s", " ".join(cmd))

    stderr_dest: int = subprocess.DEVNULL
    stderr_path = resolve_log_file("daemon-spawn", suffix=".stderr")
    stderr_file = None
    if stderr_path:
        stderr_file = open(stderr_path, "w")  # noqa: SIM115
        stderr_dest = stderr_file.fileno()

    kwargs: dict = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": stderr_dest,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen(cmd, **kwargs)
    except Exception:
        if stderr_file:
            stderr_file.close()
        raise

    # The child process owns the fd now; close the parent's file object so
    # it doesn't leak for the lifetime of the proxy process.
    if stderr_file:
        stderr_file.close()

    deadline = time.monotonic() + _DAEMON_STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        time.sleep(_DAEMON_POLL_INTERVAL)
        rc = proc.poll()
        if rc is not None:
            msg = f"Daemon process exited immediately with code {rc}"
            if stderr_path:
                msg += f"; see {stderr_path}"
            raise RuntimeError(msg)
        state = read_state()
        if state is not None and daemon_alive(state):
            log.info("Daemon started (pid=%d, port=%d)", state["pid"], state["port"])
            return state

    msg = f"Daemon failed to start within {_DAEMON_STARTUP_TIMEOUT:.0f} seconds"
    if stderr_path:
        msg += f"; see {stderr_path}"
    raise RuntimeError(msg)


# ---------------------------------------------------------------------------
# Message bridge
# ---------------------------------------------------------------------------


async def _forward(
    reader: anyio.abc.ObjectReceiveStream,
    writer: anyio.abc.ObjectSendStream,
    label: str,
) -> None:
    """Forward messages from *reader* to *writer*, aborting on transport errors."""
    try:
        async for item in reader:
            if isinstance(item, Exception):
                log.error("Transport error (%s): %s", label, item)
                raise item
            await writer.send(item)
        log.debug("Stream ended cleanly (%s)", label)
    except (anyio.ClosedResourceError, anyio.EndOfStream) as exc:
        log.debug("Stream closed (%s): %s", label, type(exc).__name__)
    except Exception:
        log.exception("Unexpected error forwarding (%s)", label)
        raise
    finally:
        await writer.aclose()


async def _keepalive(http_client: httpx.AsyncClient, base_url: str) -> None:
    """Send periodic keepalive pings to prevent daemon idle shutdown."""
    url = f"{base_url}/health"
    while True:
        try:
            resp = await http_client.get(url)
            if resp.status_code != 200:
                log.debug("Keepalive ping returned %d", resp.status_code)
        except httpx.HTTPError:
            log.debug("Keepalive ping failed", exc_info=True)
        await anyio.sleep(KEEPALIVE_INTERVAL)


async def _bridge(state: dict) -> None:
    """Bridge stdio ↔ HTTP, forwarding SessionMessage objects bidirectionally."""
    host = state.get("host", "127.0.0.1")
    base_url = f"http://{host}:{state['port']}"
    url = f"{base_url}{fastmcp.settings.streamable_http_path}"
    headers = {"Authorization": f"Bearer {state['token']}"}

    http_client = httpx.AsyncClient(
        headers=headers,
        timeout=httpx.Timeout(_HTTP_CONNECT_TIMEOUT, read=_HTTP_READ_TIMEOUT),
    )
    async with (
        http_client,
        stdio_server() as (stdio_read, stdio_write),
        streamable_http_client(url, http_client=http_client) as (
            http_read,
            http_write,
            _,
        ),
        anyio.create_task_group() as tg,
    ):
        tg.start_soon(_keepalive, http_client, base_url)
        try:
            # Inner group scopes the forwarding tasks; when either direction
            # closes, the inner group exits and the finally cancels the
            # outer group's keepalive task.
            async with anyio.create_task_group() as forward_tg:
                forward_tg.start_soon(_forward, stdio_read, http_write, "stdio->http")
                forward_tg.start_soon(_forward, http_read, stdio_write, "http->stdio")
        finally:
            tg.cancel_scope.cancel()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def stop() -> bool:
    """Stop the running daemon.  Returns True if a daemon was stopped."""
    state = read_state()
    if state is None or not daemon_alive(state):
        if state is not None:
            remove_state()
        return False
    _stop_daemon(state)
    remove_state()
    return True


def main() -> None:
    """Proxy entry point: ensure daemon is running, then bridge stdio to it."""
    from ida_mcp import configure_logging  # noqa: PLC0415

    configure_logging(label="proxy")

    state = _ensure_daemon()
    anyio.run(_bridge, state)
