# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""ghidra-mcp package — Ghidra backend for re-mcp.

Provides a lazy ``bootstrap()`` function that imports ``pyhidra`` and
starts the Ghidra JVM.  Workers call ``bootstrap()`` at startup before
any Ghidra Java class imports.  The supervisor process never calls it.
"""

from __future__ import annotations

import glob
import json
import logging
import os
import sys

from re_mcp import (  # noqa: F401  — re-export for backward compatibility
    configure_logging,
    ensure_run_id,
    get_version,
    resolve_log_file,
)

log = logging.getLogger(__name__)


def find_ghidra_dir() -> str | None:
    """Return the Ghidra installation directory, or ``None`` if not found.

    Search order:
      1. ``GHIDRA_INSTALL_DIR`` environment variable
      2. ``ghidra-install-dir`` from ``~/.ghidra/ghidra-config.json``
      3. Platform-specific default installation paths
    """
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env and os.path.isdir(env):
        return env

    config_dir = _read_ghidra_config()
    if config_dir and os.path.isdir(config_dir):
        return config_dir

    for d in _platform_default_dirs():
        if os.path.isdir(d):
            return d

    return None


def _read_ghidra_config() -> str | None:
    """Read ghidra-install-dir from a config file."""
    home = os.path.expanduser("~")
    config_path = os.path.join(home, ".ghidra", "ghidra-config.json")
    if not os.path.isfile(config_path):
        return None
    try:
        with open(config_path) as f:
            config = json.load(f)
        return config.get("ghidra-install-dir") or None
    except (json.JSONDecodeError, OSError):
        return None


def _platform_default_dirs() -> list[str]:
    """Return candidate Ghidra install directories for the current platform."""
    plat = sys.platform
    home = os.path.expanduser("~")
    if plat == "darwin":
        candidates = glob.glob("/Applications/ghidra_*")
        candidates += glob.glob(os.path.join(home, "ghidra_*"))
        return sorted(candidates, reverse=True)
    if plat == "win32":
        candidates = glob.glob(r"C:\ghidra_*")
        candidates += glob.glob(os.path.join(home, "ghidra_*"))
        return sorted(candidates, reverse=True)
    candidates = glob.glob("/opt/ghidra_*")
    candidates += glob.glob("/usr/local/ghidra_*")
    candidates += glob.glob(os.path.join(home, "ghidra_*"))
    return sorted(candidates, reverse=True)


_bootstrapped = False


def bootstrap():
    """Ensure pyhidra is imported and the Ghidra JVM is started.

    Must be called before any Ghidra Java class is imported.  Called once
    by ``server.main()`` at worker startup.  The supervisor never calls this.
    """
    global _bootstrapped  # noqa: PLW0603
    if _bootstrapped:
        return

    log.debug("Bootstrapping pyhidra...")

    ghidra_dir = find_ghidra_dir()
    if ghidra_dir:
        os.environ.setdefault("GHIDRA_INSTALL_DIR", ghidra_dir)
        log.debug("Using Ghidra installation at %s", ghidra_dir)

    try:
        from pyhidra.launcher import HeadlessPyhidraLauncher  # noqa: PLC0415
    except ImportError:
        raise ImportError(
            "Could not find the pyhidra package.\n"
            "Install pyhidra and ensure Ghidra is installed:\n"
            "  pip install pyhidra\n"
            "Then either:\n"
            "  - Set the GHIDRA_INSTALL_DIR environment variable, or\n"
            "  - Place Ghidra in a standard location (/opt/ghidra_*, ~/ghidra_*)"
        ) from None

    launcher = HeadlessPyhidraLauncher()
    _NATIVE_ACCESS_ARG = "--enable-native-access=ALL-UNNAMED"
    if _NATIVE_ACCESS_ARG not in launcher.vm_args:
        launcher.vm_args.append(_NATIVE_ACCESS_ARG)
    launcher.start()
    log.info("pyhidra bootstrapped successfully")

    _bootstrapped = True
