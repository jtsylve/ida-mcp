# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Sandboxed Python execution using RestrictedPython.

Uses RestrictedPython for AST-level code restriction with a custom policy
that allows async/await.  Used by the ``execute`` meta-tool in
``transforms.py``.
"""

from __future__ import annotations

import ast
import operator
from collections.abc import Callable
from typing import Any

from RestrictedPython import compile_restricted, safe_builtins
from RestrictedPython.Guards import guarded_unpack_sequence, safer_getattr
from RestrictedPython.transformer import RestrictingNodeTransformer

# ---------------------------------------------------------------------------
# Custom policy — allow async/await on top of standard restrictions
# ---------------------------------------------------------------------------

_WRAPPER_NAME = "sandboxmain"


class _AsyncRestrictingNodeTransformer(RestrictingNodeTransformer):
    """Extends RestrictedPython's default policy to permit async constructs.

    ``async def``, ``await``, ``async for``, and ``async with`` are blocked
    by the upstream transformer.  This subclass mirrors the handling of their
    synchronous equivalents so that ``await call_tool(...)`` and
    ``asyncio.gather(...)`` work inside execute blocks.
    """

    def visit_AsyncFunctionDef(self, node):
        self.check_name(node, node.name, allow_magic_methods=True)
        self.check_function_argument_names(node)
        with self.print_info.new_print_scope():
            node = self.node_contents_visit(node)
            self.inject_print_collector(node)
        return node

    def visit_Await(self, node):
        return self.node_contents_visit(node)

    def visit_AsyncFor(self, node):
        return self.guard_iter(node)

    def visit_AsyncWith(self, node):
        node = self.node_contents_visit(node)
        for item in reversed(node.items):
            if isinstance(item.optional_vars, ast.Tuple):
                tmp_target, unpack = self.gen_unpack_wrapper(node, item.optional_vars)
                item.optional_vars = tmp_target
                node.body.insert(0, unpack)
        return node


# ---------------------------------------------------------------------------
# Import whitelist
# ---------------------------------------------------------------------------

_ALLOWED_IMPORTS = frozenset(
    {
        "asyncio",
        "collections",
        "functools",
        "itertools",
        "json",
        "math",
        "operator",
        "re",
        "struct",
        "typing",
    }
)


def _safe_import(
    name: str,
    globals: dict | None = None,
    locals: dict | None = None,
    fromlist: tuple[str, ...] = (),
    level: int = 0,
) -> Any:
    if name.split(".", maxsplit=1)[0] not in _ALLOWED_IMPORTS:
        raise ImportError(f'Import of "{name}" is not allowed in the sandbox')
    return __import__(name, globals, locals, fromlist, level)


# ---------------------------------------------------------------------------
# Guard implementations
# ---------------------------------------------------------------------------

_INPLACE_OPS: dict[str, Callable[[Any, Any], Any]] = {
    "+=": operator.iadd,
    "-=": operator.isub,
    "*=": operator.imul,
    "/=": operator.itruediv,
    "//=": operator.ifloordiv,
    "%=": operator.imod,
    "**=": operator.ipow,
    "&=": operator.iand,
    "|=": operator.ior,
    "^=": operator.ixor,
    ">>=": operator.irshift,
    "<<=": operator.ilshift,
}


def _inplacevar(op: str, x: Any, y: Any) -> Any:
    fn = _INPLACE_OPS.get(op)
    if fn is None:
        raise ValueError(f"Unsupported in-place operation: {op}")
    return fn(x, y)


def _safe_hasattr(obj: Any, name: str) -> bool:
    """``hasattr`` that respects RestrictedPython's attribute guards."""
    try:
        safer_getattr(obj, name)
        return True
    except AttributeError:
        return False


# ---------------------------------------------------------------------------
# Builtins available inside the sandbox
# ---------------------------------------------------------------------------

_SANDBOX_BUILTINS: dict[str, Any] = {
    **safe_builtins,
    "__import__": _safe_import,
    # Container types (safe_builtins omits these)
    "list": list,
    "dict": dict,
    "set": set,
    "frozenset": frozenset,
    "bytearray": bytearray,
    "memoryview": memoryview,
    # Iteration helpers
    "map": map,
    "filter": filter,
    "enumerate": enumerate,
    "reversed": reversed,
    "iter": iter,
    "next": next,
    "zip": zip,
    # Aggregation
    "any": any,
    "all": all,
    "sum": sum,
    "min": min,
    "max": max,
    # Numeric
    "bin": bin,
    "hex": hex,
    "oct": oct,
    # Introspection — getattr/hasattr must go through safer_getattr to block
    # dunder access; raw builtins would bypass the _getattr_ AST guard.
    "type": type,
    "isinstance": isinstance,
    "hasattr": _safe_hasattr,
    "getattr": safer_getattr,
    # Formatting
    "format": format,
    "print": print,
    "super": super,
}


def _make_globals(
    *,
    inputs: dict[str, Any] | None = None,
    external_functions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the restricted globals dict for ``exec()``."""
    glb: dict[str, Any] = {
        "__builtins__": _SANDBOX_BUILTINS,
        "_getiter_": iter,
        "_getattr_": safer_getattr,
        "_getitem_": operator.getitem,
        "_iter_unpack_sequence_": guarded_unpack_sequence,
        "_unpack_sequence_": guarded_unpack_sequence,
        # _write_ wraps attribute/item stores.  The permissive lambda is the
        # standard RestrictedPython pattern — dunder writes are already blocked
        # at compile time by the AST transformer, so a runtime guard adds no
        # security benefit and would break attribute assignment on user classes.
        # Safety: sandbox code can only mutate objects it can reach.  call_tool
        # returns JSON-deserialized dicts (copies), not live internal state, so
        # mutation cannot affect server internals.
        "_write_": lambda obj: obj,
        "_inplacevar_": _inplacevar,
    }
    if inputs:
        glb.update(inputs)
    if external_functions:
        glb.update(external_functions)
    return glb


# ---------------------------------------------------------------------------
# RestrictedPythonSandbox
# ---------------------------------------------------------------------------


class RestrictedPythonSandbox:
    """Sandbox backed by RestrictedPython.

    Compiles user code with AST-level restrictions (no ``eval``, ``exec``,
    ``open``, dangerous attribute access, etc.) while allowing full Python
    semantics for safe operations — including ``int(s, 16)``, ``import
    struct``, and ``async``/``await``.
    """

    async def run(
        self,
        code: str,
        *,
        inputs: dict[str, Any] | None = None,
        external_functions: dict[str, Callable[..., Any]] | None = None,
    ) -> Any:
        # Wrap top-level code in an async function at the AST level so
        # await is valid syntax without text-based re-indentation (which
        # would corrupt multi-line string literals).
        tree = ast.parse(code, filename="<execute>", mode="exec")
        wrapper = ast.AsyncFunctionDef(
            name=_WRAPPER_NAME,
            args=ast.arguments(
                posonlyargs=[],
                args=[],
                vararg=None,
                kwonlyargs=[],
                kw_defaults=[],
                kwarg=None,
                defaults=[],
            ),
            body=tree.body or [ast.Pass()],
            decorator_list=[],
            returns=None,
        )
        tree.body = [wrapper]
        ast.fix_missing_locations(tree)

        bytecode = compile_restricted(
            tree,
            filename="<execute>",
            mode="exec",
            policy=_AsyncRestrictingNodeTransformer,
        )

        glb = _make_globals(inputs=inputs, external_functions=external_functions)
        exec(bytecode, glb)
        return await glb[_WRAPPER_NAME]()
