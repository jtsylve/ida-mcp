# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Platform-aware process utilities (stdlib only, no backend dependencies)."""

from __future__ import annotations

import os
import sys

__all__ = ["IS_WINDOWS", "pid_alive", "pid_exit_code"]

IS_WINDOWS = sys.platform == "win32"

# Win32 constants
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
# GetExitCodeProcess returns 259 both for still-running processes and for
# processes that genuinely exited with code 259.  There is no way to
# disambiguate via this API alone.  In practice exit code 259 is rare.
_STILL_ACTIVE = 259


def pid_alive(pid: int) -> bool:
    """Return ``True`` if the process *pid* appears to be running.

    On Windows, uses ``OpenProcess`` + ``GetExitCodeProcess`` via ctypes
    because ``os.kill(pid, 0)`` is unreliable — ``signal.CTRL_C_EVENT``
    is defined as 0, so CPython dispatches to ``GenerateConsoleCtrlEvent``
    rather than performing a pure liveness probe.

    On Unix, ``os.kill(pid, 0)`` is the standard zero-signal probe.
    """
    if IS_WINDOWS:
        import ctypes  # noqa: PLC0415

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong()
            if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return exit_code.value == _STILL_ACTIVE
            return False
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def pid_exit_code(pid: int) -> int | None:
    """Return the exit code of a dead process, or ``None`` if unavailable.

    On Windows, re-opens the process handle and queries the exit code.
    Returns ``None`` if the handle cannot be opened (e.g. already fully
    cleaned up) or if the process is still running.

    On Unix, the exit code is obtained via ``os.waitpid`` at the call
    site, so this function always returns ``None``.
    """
    if not IS_WINDOWS:
        return None
    import ctypes  # noqa: PLC0415

    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        exit_code = ctypes.c_ulong()
        if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            if exit_code.value == _STILL_ACTIVE:
                return None
            return exit_code.value
        return None
    finally:
        kernel32.CloseHandle(handle)
