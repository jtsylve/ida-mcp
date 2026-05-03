# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Budget test for the authored surface of the brief tool listing.

The ``detail="brief"`` rendering in ``search_tools`` / ``get_schema`` is
what the agent sees when it surveys the full tool catalog.  Two inputs
feed that rendering: the mechanical Python-style signature (out of a tool
author's hands — scales with param count) and the first line of each
tool's docstring (authored prose).

This test guards the authored portion: the sum of all first-line
descriptions across every ``@mcp.tool``-decorated function stays under a
context budget.  We deliberately do NOT cap individual descriptions —
some tools genuinely need a long first line to disambiguate from
near-neighbors (e.g. ``save_database`` vs. a hypothetical
``flush_buffers``).  The aggregate budget lets authors spend length
where it earns them disambiguation and forces a conversation when the
catalog grows enough to threaten context.

Parsing is done via ``ast`` so this test runs without idalib — it never
imports any ``re_mcp_ida.tools.*`` module.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

TOOLS_DIR = (
    pathlib.Path(__file__).resolve().parent.parent
    / "packages"
    / "re-mcp-ida"
    / "src"
    / "re_mcp_ida"
    / "tools"
)

# Budget for the total first-line docstring characters across every tool.
# Current baseline (188 tools) sits near 10.7k chars; this leaves ~50%
# headroom for new tools and small wording growth before the test trips.
# When it does trip, the failure message lists the worst offenders so the
# author can decide whether to tighten existing lines or expand the budget
# alongside a deliberate review of the catalog size.
FIRST_LINE_TOTAL_BUDGET = 16000


def _iter_tool_docstrings() -> list[tuple[str, str, str]]:
    """Return ``(module, tool_name, first_line)`` for every @mcp.tool func.

    Detects any decorator of the form ``@mcp.tool(...)`` or ``@mcp.tool``
    — matches the ``register(mcp)`` convention documented in CLAUDE.md.
    """
    collected: list[tuple[str, str, str]] = []
    for path in sorted(TOOLS_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _is_mcp_tool_decorated(node):
                continue
            doc = ast.get_docstring(node) or ""
            first = doc.split("\n", 1)[0].strip()
            collected.append((path.stem, node.name, first))
    return collected


def _is_mcp_tool_decorated(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if (
            isinstance(target, ast.Attribute)
            and target.attr == "tool"
            and isinstance(target.value, ast.Name)
            and target.value.id == "mcp"
        ):
            return True
    return False


def test_every_tool_has_a_docstring():
    """A missing first line breaks the brief listing UX — fail loudly."""
    missing = [f"{module}.{name}" for module, name, first in _iter_tool_docstrings() if not first]
    assert not missing, f"tools missing a first-line docstring: {missing}"


def test_first_line_docstrings_fit_context_budget():
    """Sum of first-line docstrings across all tools stays under budget.

    No per-tool cap — authors can spend length where it earns
    disambiguation.  The budget is aggregate so catalog growth is what
    forces the conversation.
    """
    entries = _iter_tool_docstrings()
    assert entries, "no @mcp.tool-decorated functions found — parser regression?"

    total = sum(len(first) for _, _, first in entries)
    if total <= FIRST_LINE_TOTAL_BUDGET:
        return

    # Failure: surface the worst offenders so the author can see where to
    # trim (or decide the budget needs to move alongside a deliberate
    # review of catalog size).
    worst = sorted(entries, key=lambda e: len(e[2]), reverse=True)[:10]
    lines = [f"  {len(first):3d}  {module}.{name}: {first}" for module, name, first in worst]
    pytest.fail(
        f"Tool first-line docstrings total {total} chars across {len(entries)} tools, "
        f"exceeding the {FIRST_LINE_TOTAL_BUDGET}-char brief-listing budget.\n"
        f"Top offenders (trim these, or raise FIRST_LINE_TOTAL_BUDGET with review):\n"
        + "\n".join(lines)
    )
