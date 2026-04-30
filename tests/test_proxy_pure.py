# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit tests for proxy.py pure utility functions.

These tests cover daemon management logic (ensure, spawn, lock) without
actually spawning daemon processes — all subprocess and state file access
is mocked.
"""

from __future__ import annotations

import signal
import subprocess
import threading
import time
from unittest.mock import MagicMock, patch

import pytest
from ida_mcp.backend import IDABackend
from re_mcp.proxy import (
    _ensure_daemon,
    _lock_path,
    _spawn_daemon,
    _spawn_lock,
    _stop_daemon,
    _version_ok,
    _wait_for_exit,
    stop,
)

# ---------------------------------------------------------------------------
# Lock path
# ---------------------------------------------------------------------------


class TestLockPath:
    def test_returns_string(self):
        path = _lock_path()
        assert isinstance(path, str)
        assert path.endswith("daemon.lock")


# ---------------------------------------------------------------------------
# Spawn lock
# ---------------------------------------------------------------------------


class TestSpawnLock:
    def test_lock_is_exclusive(self, tmp_path, monkeypatch):
        lock_file = str(tmp_path / "daemon.lock")
        monkeypatch.setattr("re_mcp.proxy._lock_path", lambda *a, **kw: lock_file)
        monkeypatch.setattr("re_mcp.proxy._state_dir", lambda *a, **kw: tmp_path)

        order = []

        def worker(name: str):
            with _spawn_lock():
                order.append(f"{name}-start")
                time.sleep(0.05)
                order.append(f"{name}-end")

        t1 = threading.Thread(target=worker, args=("a",))
        t2 = threading.Thread(target=worker, args=("b",))
        t1.start()
        time.sleep(0.01)
        t2.start()
        t1.join()
        t2.join()

        assert order[0] == "a-start"
        assert order[1] == "a-end"
        assert order[2] == "b-start"
        assert order[3] == "b-end"


# ---------------------------------------------------------------------------
# _ensure_daemon
# ---------------------------------------------------------------------------


class TestVersionOk:
    def test_matching_versions(self):
        state = {"version": "2.0.0"}
        with patch("re_mcp.proxy.get_version", return_value="2.0.0"):
            assert _version_ok(state) is True

    def test_mismatched_versions(self):
        state = {"version": "1.0.0"}
        with patch("re_mcp.proxy.get_version", return_value="2.0.0"):
            assert _version_ok(state) is False

    def test_current_unknown_passes(self):
        state = {"version": "1.0.0"}
        with patch("re_mcp.proxy.get_version", return_value="unknown"):
            assert _version_ok(state) is True

    def test_daemon_unknown_passes(self):
        state = {"version": "unknown"}
        with patch("re_mcp.proxy.get_version", return_value="2.0.0"):
            assert _version_ok(state) is True

    def test_missing_version_key(self):
        with patch("re_mcp.proxy.get_version", return_value="2.0.0"):
            assert _version_ok({}) is True


class TestWaitForExit:
    def test_already_exited(self):
        with patch("re_mcp.proxy.pid_alive", return_value=False):
            assert _wait_for_exit(1234, 1.0) is True

    def test_timeout(self, monkeypatch):
        monkeypatch.setattr("re_mcp.proxy.time.sleep", lambda _: None)
        times = iter([0.0, 0.5, 1.5])
        monkeypatch.setattr("re_mcp.proxy.time.monotonic", lambda: next(times))
        with patch("re_mcp.proxy.pid_alive", return_value=True):
            assert _wait_for_exit(1234, 1.0) is False


class TestStopDaemon:
    def test_sends_sigterm(self):
        with patch("os.kill") as mock_kill:
            mock_kill.side_effect = [None, OSError]
            _stop_daemon({"pid": 1234})
        mock_kill.assert_any_call(1234, signal.SIGTERM)

    def test_already_dead(self):
        with patch("os.kill", side_effect=OSError):
            _stop_daemon({"pid": 1234})

    def test_escalates_to_sigkill(self, monkeypatch):
        monkeypatch.setattr("re_mcp.proxy.IS_WINDOWS", False)
        kill_calls = []

        def fake_kill(pid, sig):
            kill_calls.append((pid, sig))
            if sig == signal.SIGKILL:
                raise OSError

        with (
            patch("os.kill", side_effect=fake_kill),
            patch("re_mcp.proxy._wait_for_exit", side_effect=[False, True]),
        ):
            _stop_daemon({"pid": 1234})
        assert (1234, signal.SIGTERM) in kill_calls
        assert (1234, signal.SIGKILL) in kill_calls

    def test_no_sigkill_on_windows(self, monkeypatch):
        monkeypatch.setattr("re_mcp.proxy.IS_WINDOWS", True)
        kill_calls = []

        def fake_kill(pid, sig):
            kill_calls.append((pid, sig))

        with (
            patch("os.kill", side_effect=fake_kill),
            patch("re_mcp.proxy._wait_for_exit", return_value=False),
        ):
            _stop_daemon({"pid": 1234})
        assert (1234, signal.SIGTERM) in kill_calls
        sigs = [sig for _, sig in kill_calls]
        assert signal.SIGKILL not in sigs


class TestEnsureDaemon:
    def test_reuses_existing_daemon(self):
        state = {"pid": 1, "host": "127.0.0.1", "port": 8080, "token": "t", "version": "v"}
        with (
            patch("re_mcp.proxy.read_state", return_value=state),
            patch("re_mcp.proxy.daemon_alive", return_value=True),
            patch("re_mcp.proxy._version_ok", return_value=True),
        ):
            result = _ensure_daemon(IDABackend)
        assert result is state

    def test_spawns_when_no_state(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "re_mcp.proxy._lock_path", lambda *a, **kw: str(tmp_path / "daemon.lock")
        )
        monkeypatch.setattr("re_mcp.proxy._state_dir", lambda *a, **kw: tmp_path)
        new_state = {"pid": 2, "host": "127.0.0.1", "port": 9090, "token": "new", "version": "v"}
        with (
            patch("re_mcp.proxy.read_state", return_value=None),
            patch("re_mcp.proxy._spawn_daemon", return_value=new_state) as mock_spawn,
        ):
            result = _ensure_daemon(IDABackend)
        assert result is new_state
        mock_spawn.assert_called_once()

    def test_spawns_when_stale(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "re_mcp.proxy._lock_path", lambda *a, **kw: str(tmp_path / "daemon.lock")
        )
        monkeypatch.setattr("re_mcp.proxy._state_dir", lambda *a, **kw: tmp_path)
        stale = {"pid": 99999, "host": "127.0.0.1", "port": 8080, "token": "old", "version": "v"}
        new_state = {"pid": 2, "host": "127.0.0.1", "port": 9090, "token": "new", "version": "v"}
        call_count = 0

        def read_state_side_effect(*a, **kw):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return stale
            return None

        with (
            patch("re_mcp.proxy.read_state", side_effect=read_state_side_effect),
            patch("re_mcp.proxy.daemon_alive", return_value=False),
            patch("re_mcp.proxy._version_ok", return_value=True),
            patch("re_mcp.proxy.remove_state") as mock_remove,
            patch("re_mcp.proxy._spawn_daemon", return_value=new_state),
        ):
            result = _ensure_daemon(IDABackend)
        assert result is new_state
        mock_remove.assert_called_once()

    def test_double_check_under_lock(self, tmp_path, monkeypatch):
        """If another process spawned the daemon while we waited for the lock,
        the second read_state inside the lock should find it."""
        monkeypatch.setattr(
            "re_mcp.proxy._lock_path", lambda *a, **kw: str(tmp_path / "daemon.lock")
        )
        monkeypatch.setattr("re_mcp.proxy._state_dir", lambda *a, **kw: tmp_path)
        state = {"pid": 1, "host": "127.0.0.1", "port": 8080, "token": "t", "version": "v"}
        call_count = 0

        def read_state_side_effect(*a, **kw):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return None
            return state

        with (
            patch("re_mcp.proxy.read_state", side_effect=read_state_side_effect),
            patch("re_mcp.proxy.daemon_alive", return_value=True),
            patch("re_mcp.proxy._version_ok", return_value=True),
            patch("re_mcp.proxy._spawn_daemon") as mock_spawn,
        ):
            result = _ensure_daemon(IDABackend)
        assert result is state
        mock_spawn.assert_not_called()

    def test_version_mismatch_restarts_daemon(self, tmp_path, monkeypatch):
        """A running daemon with a different version should be stopped and replaced."""
        monkeypatch.setattr(
            "re_mcp.proxy._lock_path", lambda *a, **kw: str(tmp_path / "daemon.lock")
        )
        monkeypatch.setattr("re_mcp.proxy._state_dir", lambda *a, **kw: tmp_path)
        old_state = {
            "pid": 100,
            "host": "127.0.0.1",
            "port": 8080,
            "token": "old",
            "version": "1.0.0",
        }
        new_state = {
            "pid": 200,
            "host": "127.0.0.1",
            "port": 9090,
            "token": "new",
            "version": "2.0.0",
        }

        with (
            patch("re_mcp.proxy.read_state", return_value=old_state),
            patch("re_mcp.proxy.daemon_alive", return_value=True),
            patch("re_mcp.proxy._version_ok", return_value=False),
            patch("re_mcp.proxy._stop_daemon") as mock_stop,
            patch("re_mcp.proxy.remove_state") as mock_remove,
            patch("re_mcp.proxy._spawn_daemon", return_value=new_state) as mock_spawn,
        ):
            result = _ensure_daemon(IDABackend)
        assert result is new_state
        mock_stop.assert_called_once_with(old_state)
        mock_remove.assert_called_once()
        mock_spawn.assert_called_once()


# ---------------------------------------------------------------------------
# _spawn_daemon
# ---------------------------------------------------------------------------


class TestSpawnDaemon:
    def test_immediate_exit_raises(self, monkeypatch):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1

        with (
            patch("re_mcp.proxy.resolve_log_file", return_value=None),
            patch("subprocess.Popen", return_value=mock_proc),
            patch("re_mcp.proxy.read_state", return_value=None),
            pytest.raises(RuntimeError, match="exited immediately with code 1"),
        ):
            _spawn_daemon(IDABackend)

    def test_success(self, monkeypatch):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        state = {"pid": 42, "host": "127.0.0.1", "port": 5555, "token": "tok", "version": "v"}
        call_count = 0

        def read_state_side_effect(*a, **kw):
            nonlocal call_count
            call_count += 1
            return state if call_count >= 2 else None

        with (
            patch("re_mcp.proxy.resolve_log_file", return_value=None),
            patch("subprocess.Popen", return_value=mock_proc),
            patch("re_mcp.proxy.read_state", side_effect=read_state_side_effect),
            patch("re_mcp.proxy.daemon_alive", return_value=True),
            patch("time.sleep"),
        ):
            result = _spawn_daemon(IDABackend)
        assert result is state

    def test_timeout_raises(self, monkeypatch):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        monkeypatch.setattr("re_mcp.proxy._DAEMON_STARTUP_TIMEOUT", 0.01)

        with (
            patch("re_mcp.proxy.resolve_log_file", return_value=None),
            patch("subprocess.Popen", return_value=mock_proc),
            patch("re_mcp.proxy.read_state", return_value=None),
            pytest.raises(RuntimeError, match="failed to start"),
        ):
            _spawn_daemon(IDABackend)

    def test_stderr_captured_to_log_file(self, tmp_path, monkeypatch):
        stderr_path = str(tmp_path / "daemon-spawn.stderr")
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1

        with (
            patch("re_mcp.proxy.resolve_log_file", return_value=stderr_path),
            patch("subprocess.Popen", return_value=mock_proc),
            patch("re_mcp.proxy.read_state", return_value=None),
            pytest.raises(RuntimeError, match=stderr_path),
        ):
            _spawn_daemon(IDABackend)

    def test_windows_shim_exits_but_daemon_starts(self, monkeypatch):
        """On Windows the launcher/shim may exit immediately while the real
        daemon writes the state file as a grandchild."""
        monkeypatch.setattr("re_mcp.proxy.IS_WINDOWS", True)
        monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
        monkeypatch.setattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200, raising=False)
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 0
        state = {"pid": 42, "host": "127.0.0.1", "port": 5555, "token": "tok", "version": "v"}
        call_count = 0

        def read_state_side_effect(*a, **kw):
            nonlocal call_count
            call_count += 1
            return state if call_count >= 3 else None

        with (
            patch("re_mcp.proxy.resolve_log_file", return_value=None),
            patch("subprocess.Popen", return_value=mock_proc),
            patch("re_mcp.proxy.read_state", side_effect=read_state_side_effect),
            patch("re_mcp.proxy.daemon_alive", return_value=True),
            patch("time.sleep"),
        ):
            result = _spawn_daemon(IDABackend)
        assert result is state

    def test_windows_shim_timeout_includes_exit_code(self, monkeypatch):
        """When the shim exits on Windows but the daemon never starts, the
        timeout error includes the launcher's exit code."""
        monkeypatch.setattr("re_mcp.proxy.IS_WINDOWS", True)
        monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
        monkeypatch.setattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200, raising=False)
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 7

        call_count = 0

        def fake_monotonic():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return 0.0
            return 1e9

        with (
            patch("re_mcp.proxy.resolve_log_file", return_value=None),
            patch("subprocess.Popen", return_value=mock_proc),
            patch("re_mcp.proxy.read_state", return_value=None),
            patch("re_mcp.proxy.daemon_alive", return_value=False),
            patch("time.sleep"),
            patch("time.monotonic", side_effect=fake_monotonic),
            pytest.raises(RuntimeError, match=r"launcher exited with code 7"),
        ):
            _spawn_daemon(IDABackend)


# ---------------------------------------------------------------------------
# stop
# ---------------------------------------------------------------------------


class TestStop:
    def test_no_state_returns_false(self):
        with patch("re_mcp.proxy.read_state", return_value=None):
            assert stop(IDABackend) is False

    def test_stale_state_cleans_up(self):
        state = {"pid": 999999999, "host": "127.0.0.1", "port": 8080, "token": "t", "version": "v"}
        with (
            patch("re_mcp.proxy.read_state", return_value=state),
            patch("re_mcp.proxy.daemon_alive", return_value=False),
            patch("re_mcp.proxy.remove_state") as mock_remove,
        ):
            assert stop(IDABackend) is False
        mock_remove.assert_called_once()

    def test_running_daemon_stopped(self):
        state = {"pid": 123, "host": "127.0.0.1", "port": 8080, "token": "t", "version": "v"}
        with (
            patch("re_mcp.proxy.read_state", return_value=state),
            patch("re_mcp.proxy.daemon_alive", return_value=True),
            patch("re_mcp.proxy._stop_daemon") as mock_stop,
            patch("re_mcp.proxy.remove_state") as mock_remove,
        ):
            assert stop(IDABackend) is True
        mock_stop.assert_called_once_with(state)
        mock_remove.assert_called_once()
