# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""MCP prompt templates for guided analysis workflows.

Each module exports a ``register(mcp)`` function that registers prompts
on the given FastMCP instance using ``@mcp.prompt()``.
"""

from __future__ import annotations

from fastmcp import FastMCP

from ida_mcp.prompts import analysis, security, workflow


def register_all(mcp: FastMCP):
    """Register all prompt modules on *mcp*."""
    analysis.register(mcp)
    security.register(mcp)
    workflow.register(mcp)
