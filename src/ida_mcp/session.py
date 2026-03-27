# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Database session manager for idalib.

Tracks whether a database is currently open and provides guards
for tools that require an open database.
"""

from __future__ import annotations

import atexit
import functools
import logging
import os
import signal

import ida_auto
import ida_idaapi
import ida_kernwin
import idapro

from ida_mcp.helpers import Cancelled

log = logging.getLogger(__name__)


class Session:
    """Singleton managing the single idalib database session."""

    def __init__(self):
        self._current_path: str | None = None

    def is_open(self) -> bool:
        return self._current_path is not None

    @property
    def current_path(self) -> str | None:
        return self._current_path

    def open(self, file_path: str, run_auto_analysis: bool = False) -> dict:
        """Open a binary for analysis. Auto-closes any previously open database.

        Returns a status dict on success, or an error dict on failure.
        """
        path = os.path.abspath(os.path.expanduser(file_path))
        if not os.path.isfile(path):
            return {"error": f"File not found: {path}", "error_type": "FileNotFoundError"}

        if self.is_open():
            result = self.close(save=True)
            if "error" in result:
                return result

        result = idapro.open_database(path, run_auto_analysis)
        if result != 0:
            return {
                "error": f"Failed to open database: error code {result}",
                "error_type": "RuntimeError",
            }

        self._current_path = path
        log.info("Opened database: %s", path)
        return {"status": "ok", "path": path}

    def close(self, save: bool = True) -> dict:
        """Close the current database."""
        if not self.is_open():
            return {"status": "no_database_open"}

        path = self._current_path
        try:
            # Disable auto-analysis and drain all queues so that
            # close_database does not hang waiting for pending work.
            ida_auto.enable_auto(False)
            for name in dir(ida_auto):
                if name.startswith("AU_") and name != "AU_NONE":
                    ida_auto.auto_unmark(0, ida_idaapi.BADADDR, getattr(ida_auto, name))
            idapro.close_database(save)
        except Exception:
            log.exception("Error closing database %s", path)
            return {"error": f"Error closing database {path}", "error_type": "CloseFailed"}
        finally:
            self._current_path = None
        log.info("Closed database: %s (saved=%s)", path, save)
        return {"status": "closed", "path": path, "saved": save}

    def require_open(self, fn):
        """Decorator that returns an error dict if no database is open."""

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if not self.is_open():
                return {
                    "error": "No database is open. Use open_database first.",
                    "error_type": "NoDatabase",
                }
            # Clear any stale cancellation flag from a previous operation
            # so it doesn't bleed into this tool call.
            ida_kernwin.clr_cancelled()
            try:
                return fn(*args, **kwargs)
            except Cancelled:
                return {"error": "Operation cancelled", "error_type": "Cancelled"}

        return wrapper


# Module-level singleton
session = Session()


def _save_on_exit():
    """Save the open database on any process exit (normal or signal)."""
    if session.is_open():
        log.info("Saving database on exit: %s", session.current_path)
        session.close(save=True)


def _terminate_handler(signum, frame):
    """SIGTERM — shut down immediately (triggers atexit save)."""
    raise SystemExit(0)


def _cancel_handler(signum, frame):
    """SIGINT — cooperative cancellation from terminal / standalone client.

    First signal sets IDA's cancellation flag so batch loops checking
    ``user_cancelled()`` can break early.  A second SIGINT while the flag
    is already set escalates to a full shutdown (for humans pressing Ctrl-C
    twice).
    """
    if ida_kernwin.user_cancelled():
        # Already cancelled once — escalate to shutdown.
        raise SystemExit(0)
    ida_kernwin.set_cancelled()


def _soft_cancel_handler(signum, frame):
    """SIGUSR1 — cooperative cancellation from the supervisor.

    Always sets the flag without escalating, since the supervisor may
    send repeated signals.
    """
    ida_kernwin.set_cancelled()


atexit.register(_save_on_exit)
# SIGTERM — hard shutdown (process managers, Claude Code exit).
if hasattr(signal, "SIGTERM"):
    signal.signal(signal.SIGTERM, _terminate_handler)
# SIGINT — cooperative cancel in standalone mode (Claude Code interrupt,
# or Ctrl-C from terminal).  Second SIGINT escalates to shutdown.
signal.signal(signal.SIGINT, _cancel_handler)
# SIGUSR1 — cooperative cancel from supervisor (idempotent, no escalation).
if hasattr(signal, "SIGUSR1"):
    signal.signal(signal.SIGUSR1, _soft_cancel_handler)
