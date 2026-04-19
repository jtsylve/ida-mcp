# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""ida-mcp package initialization.

Provides a lazy ``bootstrap()`` function that imports ``idapro`` and
initializes idalib.  Workers call ``bootstrap()`` at startup before any
``ida_*`` imports.  The supervisor process never calls it, avoiding the
idalib license cost.

If the ``idapro`` package is not already installed (e.g. when running via
``uv run --from git+…``), ``bootstrap()`` locates the wheel shipped with the
local IDA Pro installation and adds it to ``sys.path`` before importing.
"""

from __future__ import annotations

import datetime as _dt
import glob
import json
import logging
import os
import platform
import re
import sys

log = logging.getLogger(__name__)


def ensure_run_id() -> str:
    """Return a run ID shared across this supervisor and its workers.

    The supervisor generates the ID once and exports it via
    ``IDA_MCP_LOG_RUN`` so child worker processes inherit it and log to
    files with the same timestamp prefix — making it easy to group all
    files from one run together on disk.
    """
    run_id = os.environ.get("IDA_MCP_LOG_RUN")
    if not run_id:
        run_id = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        os.environ["IDA_MCP_LOG_RUN"] = run_id
    return run_id


_UNSAFE_LABEL_RE = re.compile(r"[^\w.-]+")


def _sanitize_label(label: str) -> str:
    """Strip filesystem-unsafe characters from a log-file label component."""
    return _UNSAFE_LABEL_RE.sub("_", label)


def resolve_log_file(label: str, *, suffix: str = ".log") -> str | None:
    """Build a log-file path inside ``$IDA_MCP_LOG_DIR``.

    Returns ``<dir>/<run_id>-<sanitized_label><suffix>`` (or
    ``<dir>/<run_id><suffix>`` if *label* is empty).  The directory is
    created if missing.  Returns ``None`` when ``IDA_MCP_LOG_DIR`` is
    unset.

    *label* is sanitized against ``[^\\w.-]`` so database-stem-derived
    labels cannot escape the configured directory.
    """
    log_dir = os.environ.get("IDA_MCP_LOG_DIR")
    if not log_dir:
        return None
    path = os.path.expanduser(log_dir)
    os.makedirs(path, exist_ok=True)
    run_id = ensure_run_id()
    safe_label = _sanitize_label(label)
    filename = f"{run_id}-{safe_label}{suffix}" if safe_label else f"{run_id}{suffix}"
    return os.path.join(path, filename)


def configure_logging(*, label: str = "") -> None:
    """Configure logging from the ``IDA_MCP_LOG_LEVEL`` environment variable.

    Writes to stderr so log output does not interfere with the stdio MCP
    transport on stdout.  Defaults to WARNING if the variable is unset.

    When ``IDA_MCP_LOG_DIR`` is set, log output is additionally tee'd to
    ``<dir>/<run_id>-<label>.log`` (append mode).  Under stdio transport
    the supervisor's stderr is captured by the MCP client and is not
    accessible for post-mortem analysis; the file tee preserves events
    (session lifecycle, spawn decisions, errors) on disk.

    *label* defaults to ``$IDA_MCP_LABEL`` (set by the supervisor when
    spawning workers) or ``"supervisor"``.  It is inserted into the log
    format (``%(name)s (label):``) and used as the filename label.
    """
    if not label:
        label = os.environ.get("IDA_MCP_LABEL", "")
    level_name = os.environ.get("IDA_MCP_LOG_LEVEL", "WARNING").upper()
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


def get_version() -> str:
    """Return the installed package version, or ``"unknown"`` if unavailable."""
    from importlib.metadata import version as pkg_version  # noqa: PLC0415

    try:
        return pkg_version("ida-mcp")
    except Exception:
        return "unknown"


def _find_idapro_wheel() -> str | None:
    """Locate the idapro wheel inside the local IDA Pro installation.

    Search order:
      1. ``IDADIR`` environment variable
      2. ``ida-install-dir`` from ``~/.idapro/ida-config.json``
         (or ``%APPDATA%/Hex-Rays/IDA Pro/ida-config.json`` on Windows)
      3. Platform-specific default installation paths
    """
    ida_dir = find_ida_dir()
    if ida_dir is None:
        return None
    matches = glob.glob(os.path.join(ida_dir, "idalib", "python", "idapro-*.whl"))
    return matches[0] if matches else None


def find_ida_dir() -> str | None:
    """Return the IDA Pro installation directory, or ``None`` if not found.

    Search order:
      1. ``IDADIR`` environment variable
      2. ``ida-install-dir`` from IDA's own config file
      3. Platform-specific default installation paths
    """
    # 1. Environment variable
    env = os.environ.get("IDADIR")
    if env and os.path.isdir(env):
        return env

    # 2. IDA's own config file (same logic as idapro.config)
    ida_dir = _read_ida_config()
    if ida_dir and os.path.isdir(ida_dir):
        return ida_dir

    # 3. Platform defaults
    for d in _platform_default_dirs():
        if os.path.isdir(d):
            return d

    return None


def _read_ida_config() -> str | None:
    """Read ida-install-dir from IDA's JSON config file."""
    idausr = os.environ.get("IDAUSR")
    if idausr:
        config_dir = idausr
    elif platform.system() == "Windows":
        appdata = os.environ.get("APPDATA", "")
        config_dir = os.path.join(appdata, "Hex-Rays", "IDA Pro")
    else:
        config_dir = os.path.join(os.path.expanduser("~"), ".idapro")

    config_path = os.path.join(config_dir, "ida-config.json")
    if not os.path.isfile(config_path):
        return None

    try:
        with open(config_path) as f:
            config = json.load(f)
        return config.get("Paths", {}).get("ida-install-dir") or None
    except (json.JSONDecodeError, OSError):
        return None


def _platform_default_dirs() -> list[str]:
    """Return candidate IDA install directories for the current platform."""
    plat = sys.platform
    if plat == "darwin":
        candidates = glob.glob("/Applications/IDA Professional *.app/Contents/MacOS")
        return sorted(candidates, reverse=True)  # newest version first
    if plat == "win32":
        return [
            r"C:\Program Files\IDA Professional 9.3",
            r"C:\Program Files\IDA Pro 9.3",
            r"C:\Program Files (x86)\IDA Professional 9.3",
            r"C:\Program Files (x86)\IDA Pro 9.3",
        ]
    # Linux
    home = os.path.expanduser("~")
    return [
        "/opt/ida-pro-9.3",
        "/opt/idapro-9.3",
        "/opt/ida-9.3",
        os.path.join(home, "ida-pro-9.3"),
        os.path.join(home, "idapro-9.3"),
    ]


# ---------------------------------------------------------------------------
# Lazy bootstrap: call bootstrap() before any ida_* imports
# ---------------------------------------------------------------------------

_bootstrapped = False


def bootstrap():
    """Ensure idapro is imported and idalib is initialized.

    Must be called before any ``ida_*`` module is imported.  Called once
    by ``server.main()`` at worker startup.  The supervisor never calls this.
    """
    global _bootstrapped  # noqa: PLW0603
    if _bootstrapped:
        return

    log.debug("Bootstrapping idalib...")
    try:
        import idapro  # noqa: PLC0415

        log.debug("idapro imported from existing installation")
    except ImportError:
        _wheel = _find_idapro_wheel()
        if _wheel is None:
            raise ImportError(
                "Could not find the idapro package or an IDA Pro installation.\n"
                "Either:\n"
                "  - Set the IDADIR environment variable to your IDA install directory, or\n"
                "  - Set ida-install-dir in ~/.idapro/ida-config.json\n"
                "See https://docs.hex-rays.com/release-notes/9_0#idalib-ida-as-a-library"
            ) from None
        log.debug("idapro not installed, loading wheel from %s", _wheel)
        sys.path.insert(0, _wheel)
        import idapro  # noqa: PLC0415, F401

    log.info("idalib bootstrapped successfully")
    _bootstrapped = True
