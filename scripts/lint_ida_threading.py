#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Lint tool modules for direct IDA API calls in async function bodies.

IDA's idalib is single-threaded — all ida_* API calls must execute on the
main thread.  In our async tool functions (decorated with @session.require_open),
the body runs on the event loop thread.  IDA calls must be placed inside
a nested function/generator dispatched via call_ida() or async_paginate_iter(),
not at the top level of the async body.

This linter walks the AST of each tools/*.py file looking for:
  - async def functions decorated with @session.require_open
  - Direct ida_* attribute access (e.g. ida_funcs.get_func(...)) at the
    async function's own scope (not inside a nested def/lambda)
  - Bare calls to @ida_dispatch-decorated functions (e.g. resolve_address())
    at the async function's own scope

It also validates that @ida_dispatch-decorated functions are allowed to
contain direct ida_* calls (and flags ida_* calls in non-decorated, non-async
functions as IDA002).

Usage:
    python scripts/lint_ida_threading.py [paths...]
    python scripts/lint_ida_threading.py  # defaults to packages/ida-mcp/src/ida_mcp/tools/ + helpers
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

# Modules whose attribute access constitutes an IDA API call.
IDA_MODULES = {
    "ida_auto",
    "ida_bytes",
    "ida_dirtree",
    "ida_diskio",
    "ida_entry",
    "ida_enum",
    "ida_fixup",
    "ida_fpro",
    "ida_frame",
    "ida_funcs",
    "ida_gdl",
    "ida_hexrays",
    "ida_ida",
    "ida_idaapi",
    "ida_idp",
    "ida_kernwin",
    "ida_lines",
    "ida_loader",
    "ida_nalt",
    "ida_name",
    "ida_problems",
    "ida_range",
    "ida_regfinder",
    "ida_search",
    "ida_segment",
    "ida_srclang",
    "ida_strlist",
    "ida_struct",
    "ida_tryblks",
    "ida_typeinf",
    "ida_ua",
    "ida_undo",
    "ida_xref",
    "idc",
    "idautils",
}

# Path to helpers.py (source of @ida_dispatch functions).
_HELPERS_PATH = Path("packages/ida-mcp/src/ida_mcp/helpers.py")


def _collect_ida_dispatch_names(helpers_path: Path) -> set[str]:
    """Parse helpers.py and return names of @ida_dispatch-decorated functions."""
    if not helpers_path.exists():
        return set()
    source = helpers_path.read_text()
    try:
        tree = ast.parse(source, filename=str(helpers_path))
    except SyntaxError:
        return set()

    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and _has_decorator(node, "ida_dispatch"):
            names.add(node.name)
    return names


def _has_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> bool:
    """Check if a function has a decorator with the given name."""
    return any(isinstance(dec, ast.Name) and dec.id == name for dec in node.decorator_list)


def _has_require_open(decorators: list[ast.expr]) -> bool:
    """Check if a function is decorated with @session.require_open."""
    for dec in decorators:
        if (
            isinstance(dec, ast.Attribute)
            and dec.attr == "require_open"
            and isinstance(dec.value, ast.Name)
            and dec.value.id == "session"
        ):
            return True
    return False


def _is_ida_attr(node: ast.expr) -> bool:
    """Check if a node is an ida_*.something attribute access."""
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in IDA_MODULES
    )


# Functions that dispatch their arguments to the main thread.
_DISPATCH_FUNCTIONS = {"call_ida", "async_paginate_iter"}


class _IdaCallFinder(ast.NodeVisitor):
    """Find ida_* attribute accesses and bare @ida_dispatch calls at the top
    scope of an async function.

    Descends into control flow (if/for/while/with/try) but stops at
    nested function/class definitions — those run on the main thread
    when dispatched via call_ida().

    Also skips ida_* references that are:
    - Arguments to call_ida() / async_paginate_iter() (dispatched to main thread)
    - Inside generator expressions passed to those dispatchers
    """

    def __init__(self, filepath: str, func_name: str, ida_dispatch_names: set[str]):
        self.filepath = filepath
        self.func_name = func_name
        self.ida_dispatch_names = ida_dispatch_names
        self.violations: list[tuple[int, int, str, str]] = []  # (line, col, detail, code)
        # Nodes to skip (already verified as safe)
        self._safe_nodes: set[int] = set()

    # Stop descending into nested functions/classes/lambdas
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        pass  # don't recurse

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        pass  # don't recurse

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        pass  # don't recurse

    def visit_Lambda(self, node: ast.Lambda) -> None:
        pass  # don't recurse

    def visit_Await(self, node: ast.Await) -> None:
        # await call_ida(fn, ...) / await async_paginate_iter(iter, ...)
        # The first arg is the callable/iterator dispatched to the main thread —
        # its IDA references are safe.  Remaining args are evaluated on the
        # calling (event-loop) thread and must NOT contain IDA calls.
        if (
            isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id in _DISPATCH_FUNCTIONS
        ):
            self._visit_dispatch_call(node.value)
            return
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Non-awaited call_ida(...) — shouldn't happen in practice but handle it.
        if isinstance(node.func, ast.Name) and node.func.id in _DISPATCH_FUNCTIONS:
            self._visit_dispatch_call(node)
            return

        # Bare call to an @ida_dispatch function
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in self.ida_dispatch_names
            and id(node) not in self._safe_nodes
        ):
            self.violations.append(
                (
                    node.lineno,
                    node.col_offset,
                    node.func.id,
                    "IDA002",
                )
            )
            # Still visit args in case they contain other violations
            self._mark_subtree_safe(node)
            return

        self.generic_visit(node)

    def _visit_dispatch_call(self, call_node: ast.Call) -> None:
        """Process a call_ida / async_paginate_iter call.

        The first positional argument is the callable or iterator being
        dispatched to the main thread — mark it safe.  All remaining
        positional and keyword arguments are evaluated on the calling
        thread, so visit them normally to catch IDA calls.
        """
        # Mark the function name node itself safe (e.g. 'call_ida')
        self._safe_nodes.add(id(call_node.func))
        # First positional arg: the dispatched function/iterator — safe
        if call_node.args:
            self._mark_subtree_safe(call_node.args[0])
        # Remaining positional args: evaluated on calling thread — check them
        for arg in call_node.args[1:]:
            self.visit(arg)
        # Keyword args: evaluated on calling thread — check them
        for kw in call_node.keywords:
            self.visit(kw.value)

    def _mark_subtree_safe(self, node: ast.AST) -> None:
        """Mark a node and all its descendants as safe."""
        for child in ast.walk(node):
            self._safe_nodes.add(id(child))

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if id(node) not in self._safe_nodes and _is_ida_attr(node):
            self.violations.append(
                (
                    node.lineno,
                    node.col_offset,
                    f"{node.value.id}.{node.attr}",
                    "IDA001",
                )
            )
        self.generic_visit(node)


_MESSAGES = {
    "IDA001": "direct IDA call `{detail}` in async body of `{func}` — must be dispatched via call_ida()",
    "IDA002": "bare call to @ida_dispatch function `{detail}()` in async body of `{func}` — must be dispatched via call_ida()",
}


def lint_file(filepath: Path, ida_dispatch_names: set[str]) -> list[str]:
    """Lint a single file, returning a list of error messages."""
    source = filepath.read_text()
    try:
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError:
        return [f"{filepath}: SyntaxError, skipping"]

    errors = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        if not _has_require_open(node.decorator_list):
            continue

        # Collect local imports of @ida_dispatch names in this function
        local_dispatch_names = _collect_local_dispatch_imports(node, ida_dispatch_names)
        all_dispatch = ida_dispatch_names | local_dispatch_names

        finder = _IdaCallFinder(str(filepath), node.name, all_dispatch)
        for child in node.body:
            finder.visit(child)

        for lineno, col, detail, code in finder.violations:
            msg = _MESSAGES[code].format(detail=detail, func=node.name)
            errors.append(f"{filepath}:{lineno}:{col}: {code} {msg}")

    return errors


def _collect_local_dispatch_imports(
    node: ast.AsyncFunctionDef, ida_dispatch_names: set[str]
) -> set[str]:
    """Find @ida_dispatch names imported/aliased inside the function body."""
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.ImportFrom):
            for alias in child.names:
                real_name = alias.name
                if real_name in ida_dispatch_names:
                    names.add(alias.asname or real_name)
    return names


def main() -> int:
    # Collect @ida_dispatch function names from helpers.py
    ida_dispatch_names = _collect_ida_dispatch_names(_HELPERS_PATH)

    if len(sys.argv) > 1:
        paths = [Path(p) for p in sys.argv[1:]]
    else:
        paths = sorted(Path("packages/ida-mcp/src/ida_mcp/tools").glob("*.py"))

    all_errors = []
    for path in paths:
        if path.is_dir():
            for f in sorted(path.glob("**/*.py")):
                all_errors.extend(lint_file(f, ida_dispatch_names))
        else:
            all_errors.extend(lint_file(path, ida_dispatch_names))

    for err in all_errors:
        print(err)

    return 1 if all_errors else 0


if __name__ == "__main__":
    sys.exit(main())
