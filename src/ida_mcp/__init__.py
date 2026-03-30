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

import glob
import json
import os
import platform
import sys


def _find_idapro_wheel() -> str | None:
    """Locate the idapro wheel inside the local IDA Pro installation.

    Search order:
      1. ``IDADIR`` environment variable
      2. ``ida-install-dir`` from ``~/.idapro/ida-config.json``
         (or ``%APPDATA%/Hex-Rays/IDA Pro/ida-config.json`` on Windows)
      3. Platform-specific default installation paths
    """
    ida_dir = _find_ida_dir()
    if ida_dir is None:
        return None
    matches = glob.glob(os.path.join(ida_dir, "idalib", "python", "idapro-*.whl"))
    return matches[0] if matches else None


def _find_ida_dir() -> str | None:
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

    try:
        import idapro  # noqa: PLC0415
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
        sys.path.insert(0, _wheel)
        import idapro  # noqa: PLC0415, F401

    _bootstrapped = True
