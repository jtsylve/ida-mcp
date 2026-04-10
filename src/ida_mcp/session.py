# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Database session manager for idalib.

Tracks whether a database is currently open and provides guards
for tools that require an open database.
"""

from __future__ import annotations

import functools
import inspect
import logging
import os
import signal

import ida_auto
import ida_hexrays
import ida_idaapi
import ida_idp
import ida_kernwin
import idapro

from ida_mcp.exceptions import PRIMARY_IDB_EXTENSIONS
from ida_mcp.helpers import Cancelled, IDAError

log = logging.getLogger(__name__)

# IDA error codes → human-readable messages.
_ERROR_CODES: dict[int, str] = {
    1: "File not found or cannot be read",
    2: "Invalid file format or unsupported loader",
    3: "Insufficient memory or license error",
    4: (
        "Stale or incompatible existing database (.i64/.idb)."
        " Delete the existing database files and retry, or use force_new=True."
    ),
}

# File extensions created by IDA alongside the input binary.
_IDB_EXTENSIONS: tuple[str, ...] = (".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til")


class Session:
    """Singleton managing the single idalib database session."""

    def __init__(self):
        self._current_path: str | None = None
        self.capabilities: dict[str, bool] = {}

    def is_open(self) -> bool:
        return self._current_path is not None

    @property
    def current_path(self) -> str | None:
        return self._current_path

    def open(
        self,
        file_path: str,
        run_auto_analysis: bool = False,
        force_new: bool = False,
        options: str | None = None,
    ) -> dict:
        """Open a binary for analysis. Auto-closes any previously open database.

        Returns a status dict on success.  Raises :class:`IDAError` on failure.

        *file_path* can be a raw binary **or** an existing IDA database
        (``.i64`` / ``.idb``).  When a database path is given, IDA opens it
        directly — the original binary does not need to be present.

        When *force_new* is ``True``, any existing IDA database files
        alongside the binary (``.i64``, ``.idb``, etc.) are deleted before
        opening, forcing a fresh analysis from the raw binary.

        *options* is an optional string of additional IDA command-line
        arguments (e.g. ``-parm`` to select the ARM processor module,
        ``-TGeneric`` for a specific loader).
        """
        path = os.path.abspath(os.path.expanduser(file_path))

        # If the user passed an IDA database file, derive the binary path
        # (which is what idalib expects) and allow opening even when only the
        # database exists.
        _, ext = os.path.splitext(path)
        if ext.lower() in PRIMARY_IDB_EXTENSIONS:
            binary_path = os.path.splitext(path)[0]
            if not os.path.isfile(path):
                raise IDAError(f"Database not found: {path}", error_type="FileNotFoundError")
            # IDA expects the stem path; it finds the .i64 on its own.
            path = binary_path
        elif not os.path.isfile(path):
            raise IDAError(f"File not found: {path}", error_type="FileNotFoundError")

        if self.is_open():
            self.close(save=True)

        if force_new:
            # Use the full path as the base — IDA creates sidecar files by
            # appending extensions to the binary path (e.g. foo.exe → foo.exe.i64).
            # When the user passed a .i64/.idb, `path` was already set to
            # the stem (line above) so this still works for that case.
            base = path
            for ext in _IDB_EXTENSIONS:
                db_file = base + ext
                if os.path.isfile(db_file):
                    log.info("force_new: removing %s", db_file)
                    os.remove(db_file)

        log.debug(
            "Calling idapro.open_database(%s, run_auto_analysis=%s, args=%r)",
            path,
            run_auto_analysis,
            options,
        )
        result = idapro.open_database(path, run_auto_analysis, args=options)
        if result != 0:
            message = _ERROR_CODES.get(result, f"Unknown error (code {result})")
            log.error("idapro.open_database returned error code %d: %s", result, message)
            raise IDAError(f"Failed to open database: {message}", error_type="RuntimeError")

        self._current_path = path
        self.capabilities = self._probe_capabilities()
        log.info("Opened database: %s (capabilities: %s)", path, self.capabilities)
        return {"status": "ok", "path": path}

    def _probe_capabilities(self) -> dict[str, bool]:
        """Detect which optional features are available for the current database."""
        return {
            "decompiler": bool(ida_hexrays.init_hexrays_plugin()),
            # Only x86/x64 (metapc) has an assembler in IDA currently.
            "assembler": ida_idp.get_idp_name() == "metapc",
        }

    def close(self, save: bool = True) -> dict:
        """Close the current database.

        Raises :class:`IDAError` on failure.
        """
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
        except Exception as exc:
            log.exception("Error closing database %s", path)
            raise IDAError(f"Error closing database {path}", error_type="CloseFailed") from exc
        finally:
            self._current_path = None

        log.info("Closed database: %s (saved=%s)", path, save)
        return {"status": "closed", "path": path, "saved": save}

    def require_open(self, fn):
        """Decorator that raises :class:`IDAError` if no database is open."""

        def _check():
            if not self.is_open():
                raise IDAError(
                    "No database is open. Use open_database first.",
                    error_type="NoDatabase",
                )
            ida_kernwin.clr_cancelled()

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                from ida_mcp.helpers import call_ida  # noqa: PLC0415

                await call_ida(_check)
                try:
                    return await fn(*args, **kwargs)
                except Cancelled as exc:
                    raise IDAError("Operation cancelled", error_type="Cancelled") from exc

            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            _check()
            try:
                return fn(*args, **kwargs)
            except Cancelled as exc:
                raise IDAError("Operation cancelled", error_type="Cancelled") from exc

        return wrapper


# Module-level singleton
session = Session()


def _terminate_handler(signum, frame):
    """SIGTERM — shut down immediately (triggers lifespan cleanup)."""
    raise SystemExit(0)


def _cancel_handler(signum, frame):
    """SIGINT — cooperative cancellation.

    First signal sets IDA's cancellation flag so batch loops checking
    ``user_cancelled()`` can break early.  A second SIGINT while the flag
    is already set escalates to a full shutdown.
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


# SIGTERM — hard shutdown (triggers lifespan cleanup).
if hasattr(signal, "SIGTERM"):
    signal.signal(signal.SIGTERM, _terminate_handler)
# SIGINT — cooperative cancellation.  Second press escalates to shutdown.
signal.signal(signal.SIGINT, _cancel_handler)
# SIGUSR1 — cooperative cancel from supervisor (idempotent, no escalation).
if hasattr(signal, "SIGUSR1"):
    signal.signal(signal.SIGUSR1, _soft_cancel_handler)
