# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Convenience CLI that hardcodes the Ghidra backend.

``re-mcp-ghidra`` is equivalent to ``re-mcp --backend ghidra``.
"""

from __future__ import annotations

import os


def main() -> None:
    os.environ.setdefault("RE_MCP_BACKEND", "ghidra")
    from re_mcp.supervisor import main as supervisor_main  # noqa: PLC0415

    supervisor_main()


if __name__ == "__main__":
    main()
