# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Convenience CLI that hardcodes the IDA backend.

``re-mcp-ida`` is equivalent to ``re-mcp --backend ida``.
"""

from __future__ import annotations

import os
import sys


def main() -> None:
    if os.path.basename(sys.argv[0]) in ("ida-mcp", "ida-mcp.exe"):
        os.environ["_RE_MCP_DEPRECATED_CLI"] = "ida-mcp is deprecated, use re-mcp-ida instead"

    os.environ.setdefault("RE_MCP_BACKEND", "ida")
    from re_mcp.supervisor import main as supervisor_main  # noqa: PLC0415

    supervisor_main()


if __name__ == "__main__":
    main()
