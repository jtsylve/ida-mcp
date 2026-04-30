# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""re-mcp core package — shared infrastructure for reverse-engineering MCP backends."""

from __future__ import annotations

import datetime as _dt
import logging
import os
import re
import sys

log = logging.getLogger(__name__)


def ensure_run_id(*, env_key: str = "RE_MCP_LOG_RUN") -> str:
    """Return a run ID shared across this supervisor and its workers.

    The supervisor generates the ID once and exports it via the environment
    so child worker processes inherit it and log to files with the same
    timestamp prefix.
    """
    for key in (env_key, "IDA_MCP_LOG_RUN"):
        run_id = os.environ.get(key)
        if run_id:
            os.environ.setdefault(env_key, run_id)
            return run_id
    run_id = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    os.environ[env_key] = run_id
    return run_id


_UNSAFE_LABEL_RE = re.compile(r"[^\w.-]+")


def _sanitize_label(label: str) -> str:
    """Strip filesystem-unsafe characters from a log-file label component."""
    return _UNSAFE_LABEL_RE.sub("_", label)


def resolve_log_file(
    label: str, *, suffix: str = ".log", env_key: str = "RE_MCP_LOG_DIR"
) -> str | None:
    """Build a log-file path inside the configured log directory.

    Returns ``<dir>/<run_id>-<sanitized_label><suffix>`` or ``None`` when
    the log directory environment variable is unset.
    """
    log_dir = os.environ.get(env_key) or os.environ.get("IDA_MCP_LOG_DIR")
    if not log_dir:
        return None
    path = os.path.expanduser(log_dir)
    os.makedirs(path, exist_ok=True)
    run_id = ensure_run_id()
    safe_label = _sanitize_label(label)
    filename = f"{run_id}-{safe_label}{suffix}" if safe_label else f"{run_id}{suffix}"
    return os.path.join(path, filename)


def configure_logging(*, label: str = "", env_prefix: str = "RE_MCP_") -> None:
    """Configure logging from environment variables.

    Reads ``{env_prefix}LOG_LEVEL`` (default WARNING) and optionally tees
    to a file under ``{env_prefix}LOG_DIR``.  Falls back to ``IDA_MCP_``
    prefixed variables for backward compatibility.
    """
    if not label:
        label = os.environ.get(f"{env_prefix}LABEL") or os.environ.get("IDA_MCP_LABEL", "")
    level_name = (
        os.environ.get(f"{env_prefix}LOG_LEVEL") or os.environ.get("IDA_MCP_LOG_LEVEL", "WARNING")
    ).upper()
    level = getattr(logging, level_name, None)
    if not isinstance(level, int):
        level = logging.WARNING
    name_part = f"%(name)s ({label})" if label else "%(name)s"
    fmt = f"%(asctime)s [%(levelname)s] {name_part}: %(message)s"
    logging.basicConfig(
        level=level,
        format=fmt,
        stream=sys.stderr,
    )
    log_file = resolve_log_file(label or "supervisor")
    if log_file:
        root = logging.getLogger()
        if not any(
            isinstance(h, logging.FileHandler)
            and getattr(h, "baseFilename", None) == os.path.abspath(log_file)
            for h in root.handlers
        ):
            handler = logging.FileHandler(log_file, mode="a")
            handler.setLevel(level)
            handler.setFormatter(logging.Formatter(fmt))
            root.addHandler(handler)


def get_version(package: str = "re-mcp-core") -> str:
    """Return the installed package version, or ``"unknown"`` if unavailable."""
    from importlib.metadata import version as pkg_version  # noqa: PLC0415

    try:
        return pkg_version(package)
    except Exception:
        return "unknown"
