# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit tests for daemon.py pure utility functions.

These tests cover state file management, bearer token auth, daemon liveness
checks, and the loopback detection helper — all functions that can run
without idalib or a running daemon.
"""

from __future__ import annotations

import json
import os
import stat

import pytest
from re_mcp.daemon import (
    BearerTokenAuth,
    _is_loopback,
    _state_dir,
    daemon_alive,
    read_state,
    remove_state,
    write_state,
)

# ---------------------------------------------------------------------------
# State file management
# ---------------------------------------------------------------------------


class TestWriteState:
    def test_creates_state_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr("re_mcp.daemon._state_file", lambda *a, **kw: tmp_path / "daemon.json")
        write_state(pid=1234, host="127.0.0.1", port=8080, token="abc123", version="1.0.0")
        data = json.loads((tmp_path / "daemon.json").read_text())
        assert data == {
            "pid": 1234,
            "host": "127.0.0.1",
            "port": 8080,
            "token": "abc123",
            "version": "1.0.0",
        }

    def test_restricted_permissions(self, tmp_path, monkeypatch):
        monkeypatch.setattr("re_mcp.daemon._state_file", lambda *a, **kw: tmp_path / "daemon.json")
        write_state(pid=1, host="127.0.0.1", port=1, token="t", version="v")
        mode = stat.S_IMODE(os.stat(tmp_path / "daemon.json").st_mode)
        assert mode == 0o600

    def test_overwrites_existing(self, tmp_path, monkeypatch):
        monkeypatch.setattr("re_mcp.daemon._state_file", lambda *a, **kw: tmp_path / "daemon.json")
        write_state(pid=1, host="127.0.0.1", port=1, token="old", version="1")
        write_state(pid=2, host="127.0.0.1", port=2, token="new", version="2")
        data = json.loads((tmp_path / "daemon.json").read_text())
        assert data["token"] == "new"
        assert data["pid"] == 2

    def test_creates_parent_directories(self, tmp_path, monkeypatch):
        nested = tmp_path / "a" / "b" / "daemon.json"
        monkeypatch.setattr("re_mcp.daemon._state_file", lambda *a, **kw: nested)
        write_state(pid=1, host="127.0.0.1", port=1, token="t", version="v")
        assert nested.exists()


class TestReadState:
    def test_valid_state(self, tmp_path, monkeypatch):
        state_file = tmp_path / "daemon.json"
        state_file.write_text(
            json.dumps({"pid": 1, "host": "127.0.0.1", "port": 2, "token": "t", "version": "v"})
        )
        monkeypatch.setattr("re_mcp.daemon._state_file", lambda *a, **kw: state_file)
        result = read_state()
        assert result == {"pid": 1, "host": "127.0.0.1", "port": 2, "token": "t", "version": "v"}

    def test_missing_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "re_mcp.daemon._state_file", lambda *a, **kw: tmp_path / "nonexistent.json"
        )
        assert read_state() is None

    def test_invalid_json(self, tmp_path, monkeypatch):
        state_file = tmp_path / "daemon.json"
        state_file.write_text("not json{{{")
        monkeypatch.setattr("re_mcp.daemon._state_file", lambda *a, **kw: state_file)
        assert read_state() is None

    def test_missing_keys(self, tmp_path, monkeypatch):
        state_file = tmp_path / "daemon.json"
        state_file.write_text(json.dumps({"pid": 1, "port": 2}))
        monkeypatch.setattr("re_mcp.daemon._state_file", lambda *a, **kw: state_file)
        assert read_state() is None

    def test_not_a_dict(self, tmp_path, monkeypatch):
        state_file = tmp_path / "daemon.json"
        state_file.write_text(json.dumps([1, 2, 3]))
        monkeypatch.setattr("re_mcp.daemon._state_file", lambda *a, **kw: state_file)
        assert read_state() is None


class TestRemoveState:
    def test_removes_existing(self, tmp_path, monkeypatch):
        state_file = tmp_path / "daemon.json"
        state_file.write_text("{}")
        monkeypatch.setattr("re_mcp.daemon._state_file", lambda *a, **kw: state_file)
        remove_state()
        assert not state_file.exists()

    def test_missing_file_no_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "re_mcp.daemon._state_file", lambda *a, **kw: tmp_path / "nonexistent.json"
        )
        remove_state()


# ---------------------------------------------------------------------------
# Daemon liveness
# ---------------------------------------------------------------------------


class TestDaemonAlive:
    def test_current_process(self):
        assert daemon_alive({"pid": os.getpid()}) is True

    def test_dead_process(self):
        assert daemon_alive({"pid": 999999999}) is False

    def test_invalid_pid(self):
        assert daemon_alive({"pid": -1}) is False
        assert daemon_alive({"pid": 0}) is False

    def test_non_int_pid(self):
        assert daemon_alive({"pid": "abc"}) is False

    def test_missing_pid(self):
        assert daemon_alive({}) is False

    def test_delegates_to_pid_alive(self, monkeypatch):
        monkeypatch.setattr("re_mcp.daemon.pid_alive", lambda pid: pid == 42)
        assert daemon_alive({"pid": 42}) is True
        assert daemon_alive({"pid": 99}) is False


# ---------------------------------------------------------------------------
# Bearer token auth
# ---------------------------------------------------------------------------


class TestBearerTokenAuth:
    @pytest.mark.asyncio
    async def test_valid_token(self):
        auth = BearerTokenAuth("secret-token-123")
        result = await auth.verify_token("secret-token-123")
        assert result is not None
        assert result.token == "secret-token-123"
        assert result.client_id == "local"

    @pytest.mark.asyncio
    async def test_invalid_token(self):
        auth = BearerTokenAuth("secret-token-123")
        result = await auth.verify_token("wrong-token")
        assert result is None

    @pytest.mark.asyncio
    async def test_empty_token(self):
        auth = BearerTokenAuth("secret-token-123")
        result = await auth.verify_token("")
        assert result is None

    @pytest.mark.asyncio
    async def test_timing_safe(self):
        auth = BearerTokenAuth("a" * 64)
        assert await auth.verify_token("b" * 64) is None


# ---------------------------------------------------------------------------
# Loopback detection
# ---------------------------------------------------------------------------


class TestIsLoopback:
    def test_localhost_ipv4(self):
        assert _is_loopback("127.0.0.1") is True

    def test_localhost_name(self):
        assert _is_loopback("localhost") is True

    def test_all_interfaces(self):
        assert _is_loopback("0.0.0.0") is False

    def test_external_address(self):
        assert _is_loopback("192.168.1.1") is False

    def test_invalid_host(self):
        assert _is_loopback("not.a.real.host.invalid") is False


# ---------------------------------------------------------------------------
# State directory
# ---------------------------------------------------------------------------


class TestStateDir:
    def test_darwin(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "darwin")
        monkeypatch.setattr("pathlib.Path.home", lambda: __import__("pathlib").Path("/Users/test"))
        assert str(_state_dir("re-mcp-ida")) == "/Users/test/Library/Application Support/re-mcp-ida"

    def test_linux_default(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.delenv("XDG_STATE_HOME", raising=False)
        monkeypatch.setattr("pathlib.Path.home", lambda: __import__("pathlib").Path("/home/test"))
        assert str(_state_dir("re-mcp-ida")) == "/home/test/.local/state/re-mcp-ida"

    def test_linux_xdg(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setenv("XDG_STATE_HOME", "/custom/state")
        assert str(_state_dir("re-mcp-ida")) == "/custom/state/re-mcp-ida"

    def test_windows(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        monkeypatch.setenv("LOCALAPPDATA", "C:\\Users\\test\\AppData\\Local")
        result = _state_dir("re-mcp-ida")
        assert result.parts[-1] == "re-mcp-ida"
        assert "AppData" in str(result)
