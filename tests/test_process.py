# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Unit tests for _process.py platform-aware process utilities."""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ida_mcp._process import pid_alive, pid_exit_code

# ---------------------------------------------------------------------------
# Unix path (default on non-Windows)
# ---------------------------------------------------------------------------


class TestPidAliveUnix:
    def test_current_process(self):
        assert pid_alive(os.getpid()) is True

    def test_dead_process(self):
        assert pid_alive(999_999_999) is False


class TestPidExitCodeUnix:
    def test_returns_none_on_unix(self):
        assert pid_exit_code(os.getpid()) is None


# ---------------------------------------------------------------------------
# Windows path — mocked ctypes
# ---------------------------------------------------------------------------


def _make_kernel32(*, open_returns=1, exit_code=259, get_exit_ok=True):
    kernel32 = MagicMock()
    kernel32.OpenProcess.return_value = open_returns

    def fake_get_exit_code(_handle, p_exit_code):
        p_exit_code.value = exit_code
        return int(get_exit_ok)

    kernel32.GetExitCodeProcess.side_effect = fake_get_exit_code
    kernel32.CloseHandle.return_value = 1
    return kernel32


def _patch_ctypes(monkeypatch, kernel32):
    """Install a fake ctypes module that delegates to *kernel32*."""
    fake_ctypes = MagicMock()
    fake_ctypes.windll = SimpleNamespace(kernel32=kernel32)
    fake_ctypes.c_ulong = type(MagicMock(value=0))
    fake_ctypes.byref = lambda x: x
    monkeypatch.setitem(__import__("sys").modules, "ctypes", fake_ctypes)


class TestPidAliveWindows:
    """Exercise the Windows branch by patching ``IS_WINDOWS`` and ``ctypes``."""

    @pytest.fixture(autouse=True)
    def _enable_windows_path(self, monkeypatch):
        monkeypatch.setattr("ida_mcp._process.IS_WINDOWS", True)

    def test_alive_process(self, monkeypatch):
        kernel32 = _make_kernel32(open_returns=1, exit_code=259)
        _patch_ctypes(monkeypatch, kernel32)

        assert pid_alive(1234) is True
        kernel32.OpenProcess.assert_called_once_with(0x1000, False, 1234)
        kernel32.CloseHandle.assert_called_once()

    def test_dead_process_open_fails(self, monkeypatch):
        kernel32 = _make_kernel32(open_returns=0)
        _patch_ctypes(monkeypatch, kernel32)

        assert pid_alive(1234) is False

    def test_exited_process(self, monkeypatch):
        kernel32 = _make_kernel32(open_returns=1, exit_code=0)
        _patch_ctypes(monkeypatch, kernel32)

        assert pid_alive(1234) is False

    def test_get_exit_code_fails(self, monkeypatch):
        kernel32 = _make_kernel32(open_returns=1, get_exit_ok=False)
        _patch_ctypes(monkeypatch, kernel32)

        assert pid_alive(1234) is False
        kernel32.CloseHandle.assert_called_once()


class TestPidExitCodeWindows:
    """Exercise pid_exit_code Windows branch."""

    @pytest.fixture(autouse=True)
    def _enable_windows_path(self, monkeypatch):
        monkeypatch.setattr("ida_mcp._process.IS_WINDOWS", True)

    def test_returns_exit_code(self, monkeypatch):
        kernel32 = _make_kernel32(open_returns=1, exit_code=42)
        _patch_ctypes(monkeypatch, kernel32)

        assert pid_exit_code(1234) == 42
        kernel32.CloseHandle.assert_called_once()

    def test_returns_none_when_open_fails(self, monkeypatch):
        kernel32 = _make_kernel32(open_returns=0)
        _patch_ctypes(monkeypatch, kernel32)

        assert pid_exit_code(1234) is None

    def test_returns_none_when_still_active(self, monkeypatch):
        kernel32 = _make_kernel32(open_returns=1, exit_code=259)
        _patch_ctypes(monkeypatch, kernel32)

        assert pid_exit_code(1234) is None
        kernel32.CloseHandle.assert_called_once()

    def test_returns_none_when_get_exit_code_fails(self, monkeypatch):
        kernel32 = _make_kernel32(open_returns=1, get_exit_ok=False)
        _patch_ctypes(monkeypatch, kernel32)

        assert pid_exit_code(1234) is None
        kernel32.CloseHandle.assert_called_once()
