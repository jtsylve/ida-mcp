# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Tests for daemon idle auto-shutdown: ProxyTracker, health middleware, idle monitor."""

from __future__ import annotations

import asyncio
import contextlib
import sys
import time
from dataclasses import dataclass, field
from unittest.mock import AsyncMock, patch

import pytest

from ida_mcp.daemon import (
    _PROXY_KEEPALIVE_TIMEOUT,
    KEEPALIVE_INTERVAL,
    ProxyTracker,
    _idle_monitor,
    _wrap_with_health,
)
from ida_mcp.proxy import _spawn_daemon
from ida_mcp.supervisor import main
from ida_mcp.worker_provider import Worker, WorkerPoolProvider, WorkerState

# ---------------------------------------------------------------------------
# ProxyTracker
# ---------------------------------------------------------------------------


class TestProxyTracker:
    def test_initial_state(self):
        t = ProxyTracker()
        assert t.has_active_proxy is False
        assert t.proxy_was_seen is False

    def test_ping_activates(self):
        t = ProxyTracker()
        t.ping()
        assert t.has_active_proxy is True
        assert t.proxy_was_seen is True

    def test_expires_after_timeout(self, monkeypatch):
        t = ProxyTracker()
        t.ping()
        real_monotonic = time.monotonic
        offset = _PROXY_KEEPALIVE_TIMEOUT + 1
        monkeypatch.setattr("time.monotonic", lambda: real_monotonic() + offset)
        assert t.has_active_proxy is False
        assert t.proxy_was_seen is True

    def test_ping_refreshes(self, monkeypatch):
        t = ProxyTracker()
        t.ping()
        real_monotonic = time.monotonic
        half = _PROXY_KEEPALIVE_TIMEOUT / 2
        monkeypatch.setattr("time.monotonic", lambda: real_monotonic() + half)
        t.ping()
        monkeypatch.setattr("time.monotonic", lambda: real_monotonic() + half + half)
        assert t.has_active_proxy is True

    def test_keepalive_timeout_is_3x_interval(self):
        assert _PROXY_KEEPALIVE_TIMEOUT == KEEPALIVE_INTERVAL * 3


# ---------------------------------------------------------------------------
# Health middleware (_wrap_with_health)
# ---------------------------------------------------------------------------


class TestWrapWithHealth:
    @pytest.fixture()
    def tracker(self):
        return ProxyTracker()

    @pytest.fixture()
    def token(self):
        return "test-token-abc"

    @pytest.fixture()
    def inner_app(self):
        calls = []

        async def app(scope, receive, send):
            calls.append(scope)

        app.calls = calls
        return app

    @pytest.fixture()
    def wrapped(self, inner_app, tracker, token):
        return _wrap_with_health(inner_app, tracker, token)

    @staticmethod
    def _make_scope(path="/health", method="GET", headers=None):
        scope = {"type": "http", "path": path, "method": method}
        if headers is not None:
            scope["headers"] = headers
        return scope

    @pytest.mark.asyncio
    async def test_valid_token_returns_200(self, wrapped, tracker, token):
        sent = []
        scope = self._make_scope(headers=[(b"authorization", f"Bearer {token}".encode())])
        await wrapped(scope, AsyncMock(), lambda msg: sent.append(msg) or asyncio.sleep(0))
        assert sent[0]["status"] == 200
        assert sent[1]["body"] == b"ok"
        assert tracker.has_active_proxy is True

    @pytest.mark.asyncio
    async def test_missing_token_returns_401(self, wrapped, tracker):
        sent = []
        scope = self._make_scope(headers=[])
        await wrapped(scope, AsyncMock(), lambda msg: sent.append(msg) or asyncio.sleep(0))
        assert sent[0]["status"] == 401
        assert tracker.has_active_proxy is False

    @pytest.mark.asyncio
    async def test_wrong_token_returns_401(self, wrapped, tracker):
        sent = []
        scope = self._make_scope(headers=[(b"authorization", b"Bearer wrong-token")])
        await wrapped(scope, AsyncMock(), lambda msg: sent.append(msg) or asyncio.sleep(0))
        assert sent[0]["status"] == 401

    @pytest.mark.asyncio
    async def test_non_health_path_passes_through(self, wrapped, inner_app, token):
        scope = self._make_scope(
            path="/mcp", headers=[(b"authorization", f"Bearer {token}".encode())]
        )
        await wrapped(scope, AsyncMock(), AsyncMock())
        assert len(inner_app.calls) == 1
        assert inner_app.calls[0]["path"] == "/mcp"

    @pytest.mark.asyncio
    async def test_non_get_method_passes_through(self, wrapped, inner_app, token):
        scope = self._make_scope(
            method="POST", headers=[(b"authorization", f"Bearer {token}".encode())]
        )
        await wrapped(scope, AsyncMock(), AsyncMock())
        assert len(inner_app.calls) == 1

    @pytest.mark.asyncio
    async def test_non_http_scope_passes_through(self, wrapped, inner_app):
        scope = {"type": "lifespan"}
        await wrapped(scope, AsyncMock(), AsyncMock())
        assert len(inner_app.calls) == 1


# ---------------------------------------------------------------------------
# Idle monitor
# ---------------------------------------------------------------------------


@dataclass
class FakeServerState:
    connections: set = field(default_factory=set)


@dataclass
class FakeServer:
    should_exit: bool = False
    server_state: FakeServerState = field(default_factory=FakeServerState)


class FakePool:
    """Minimal stand-in for WorkerPoolProvider with controllable return values."""

    def __init__(self, sessions: int = 0, active_work: bool = False):
        self._sessions = sessions
        self._active_work = active_work

    async def active_session_count(self) -> int:
        return self._sessions

    async def has_active_work(self) -> bool:
        return self._active_work


class TestIdleMonitor:
    @pytest.mark.asyncio
    async def test_shuts_down_after_idle_limit(self, monkeypatch):
        """Idle monitor sets should_exit after the idle limit elapses."""
        monkeypatch.setattr("ida_mcp.daemon._IDLE_POLL_INTERVAL", 0)
        server = FakeServer()
        pool = FakePool()

        call_count = 0

        def fake_monotonic():
            nonlocal call_count
            call_count += 1
            return 0.0 if call_count <= 2 else 100.0

        monkeypatch.setattr("time.monotonic", fake_monotonic)

        await _idle_monitor(server, pool, idle_limit=5)
        assert server.should_exit is True

    @pytest.mark.asyncio
    async def test_connections_reset_idle_timer(self, monkeypatch):
        """Active connections prevent shutdown and reset the idle timer."""
        monkeypatch.setattr("ida_mcp.daemon._IDLE_POLL_INTERVAL", 0)
        server = FakeServer()
        pool = FakePool()

        iteration = 0
        base = 0.0

        def fake_monotonic():
            return base

        monkeypatch.setattr("time.monotonic", fake_monotonic)

        original_sleep = asyncio.sleep

        async def tick_sleep(_):
            nonlocal iteration, base
            await original_sleep(0)
            iteration += 1
            base += 1.0
            if iteration == 2:
                server.server_state.connections.add("conn1")
            elif iteration == 3:
                server.server_state.connections.clear()
            elif iteration >= 5:
                server.should_exit = True

        monkeypatch.setattr("asyncio.sleep", tick_sleep)

        await _idle_monitor(server, pool, idle_limit=5)
        assert iteration >= 5

    @pytest.mark.asyncio
    async def test_sessions_prevent_shutdown(self, monkeypatch):
        """Active MCP sessions prevent idle shutdown."""
        monkeypatch.setattr("ida_mcp.daemon._IDLE_POLL_INTERVAL", 0)
        server = FakeServer()
        pool = FakePool(sessions=1)

        iteration = 0
        original_sleep = asyncio.sleep

        async def tick_sleep(_):
            nonlocal iteration
            await original_sleep(0)
            iteration += 1
            if iteration >= 3:
                server.should_exit = True

        monkeypatch.setattr("asyncio.sleep", tick_sleep)

        await _idle_monitor(server, pool, idle_limit=1)
        assert iteration >= 3

    @pytest.mark.asyncio
    async def test_active_work_prevents_shutdown(self, monkeypatch):
        """In-flight worker calls prevent idle shutdown."""
        monkeypatch.setattr("ida_mcp.daemon._IDLE_POLL_INTERVAL", 0)
        server = FakeServer()
        pool = FakePool(active_work=True)

        iteration = 0
        original_sleep = asyncio.sleep

        async def tick_sleep(_):
            nonlocal iteration
            await original_sleep(0)
            iteration += 1
            if iteration >= 3:
                server.should_exit = True

        monkeypatch.setattr("asyncio.sleep", tick_sleep)

        await _idle_monitor(server, pool, idle_limit=1)
        assert iteration >= 3

    @pytest.mark.asyncio
    async def test_proxy_keepalive_prevents_shutdown(self, monkeypatch):
        """Active proxy keepalive prevents idle shutdown."""
        monkeypatch.setattr("ida_mcp.daemon._IDLE_POLL_INTERVAL", 0)
        server = FakeServer()
        pool = FakePool()
        tracker = ProxyTracker()
        tracker.ping()

        iteration = 0
        original_sleep = asyncio.sleep

        async def tick_sleep(_):
            nonlocal iteration
            await original_sleep(0)
            iteration += 1
            if iteration >= 3:
                server.should_exit = True

        monkeypatch.setattr("asyncio.sleep", tick_sleep)

        await _idle_monitor(server, pool, idle_limit=1, proxy_tracker=tracker)
        assert iteration >= 3

    @pytest.mark.asyncio
    async def test_dead_proxy_discounts_orphaned_sessions(self, monkeypatch):
        """When the proxy is confirmed dead, stale sessions are discounted."""
        monkeypatch.setattr("ida_mcp.daemon._IDLE_POLL_INTERVAL", 0)
        server = FakeServer()
        pool = FakePool(sessions=2)

        tracker = ProxyTracker()
        tracker._last_seen = 1.0

        base_time = time.monotonic() + _PROXY_KEEPALIVE_TIMEOUT + 100
        call_count = 0

        def fake_monotonic():
            nonlocal call_count
            call_count += 1
            return base_time if call_count <= 3 else base_time + 10

        monkeypatch.setattr("time.monotonic", fake_monotonic)

        await _idle_monitor(server, pool, idle_limit=5, proxy_tracker=tracker)
        assert server.should_exit is True

    @pytest.mark.asyncio
    async def test_no_proxy_tracker_ignores_proxy_logic(self, monkeypatch):
        """Without a proxy tracker, idle shutdown proceeds normally."""
        monkeypatch.setattr("ida_mcp.daemon._IDLE_POLL_INTERVAL", 0)
        server = FakeServer()
        pool = FakePool()

        call_count = 0

        def fake_monotonic():
            nonlocal call_count
            call_count += 1
            return 0.0 if call_count <= 2 else 100.0

        monkeypatch.setattr("time.monotonic", fake_monotonic)

        await _idle_monitor(server, pool, idle_limit=5, proxy_tracker=None)
        assert server.should_exit is True

    @pytest.mark.asyncio
    async def test_exits_immediately_if_already_exiting(self, monkeypatch):
        """If server.should_exit is already True, the monitor returns immediately."""
        monkeypatch.setattr("ida_mcp.daemon._IDLE_POLL_INTERVAL", 0)
        server = FakeServer()
        server.should_exit = True
        pool = FakePool()

        await _idle_monitor(server, pool, idle_limit=999)
        assert server.should_exit is True


# ---------------------------------------------------------------------------
# WorkerPoolProvider.active_session_count / has_active_work
# ---------------------------------------------------------------------------


class TestWorkerPoolProviderIdleMethods:
    @pytest.mark.asyncio
    async def test_active_session_count_empty(self):
        pool = WorkerPoolProvider()
        assert await pool.active_session_count() == 0

    @pytest.mark.asyncio
    async def test_active_session_count_with_sessions(self):
        pool = WorkerPoolProvider()
        pool._registered_sessions.update(["s1", "s2", "s3"])
        assert await pool.active_session_count() == 3

    @pytest.mark.asyncio
    async def test_has_active_work_empty(self):
        pool = WorkerPoolProvider()
        assert await pool.has_active_work() is False

    @pytest.mark.asyncio
    async def test_has_active_work_with_busy_worker(self):
        pool = WorkerPoolProvider()
        w = Worker(database_id="test", file_path="/tmp/test.i64")
        w.state = WorkerState.IDLE
        w._active_calls = 1
        pool._workers["/tmp/test.i64"] = w
        assert await pool.has_active_work() is True

    @pytest.mark.asyncio
    async def test_has_active_work_with_opening_worker(self):
        pool = WorkerPoolProvider()
        w = Worker(database_id="test", file_path="/tmp/test.i64")
        pool._workers["/tmp/test.i64"] = w
        assert await pool.has_active_work() is True

    @pytest.mark.asyncio
    async def test_has_active_work_with_analyzing_worker(self):
        pool = WorkerPoolProvider()
        w = Worker(database_id="test", file_path="/tmp/test.i64")
        w.state = WorkerState.IDLE
        w._ready_event.set()
        w._analysis_task = asyncio.ensure_future(asyncio.sleep(999))
        pool._workers["/tmp/test.i64"] = w
        try:
            assert await pool.has_active_work() is True
        finally:
            w._analysis_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await w._analysis_task


# ---------------------------------------------------------------------------
# Idle timeout validation
# ---------------------------------------------------------------------------


class TestIdleTimeoutValidation:
    def test_argparse_rejects_negative(self):
        with (
            pytest.raises(SystemExit),
            patch.object(sys, "argv", ["ida-mcp", "serve", "--idle-timeout", "-1"]),
        ):
            main()

    def test_proxy_rejects_negative_env(self, monkeypatch):
        monkeypatch.setenv("IDA_MCP_IDLE_TIMEOUT", "-5")
        with pytest.raises(SystemExit):
            _spawn_daemon()
