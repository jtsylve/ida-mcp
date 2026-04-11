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
import copy
import operator
from collections.abc import Callable
from typing import Any

from RestrictedPython import compile_restricted, safe_builtins
from RestrictedPython.Guards import guarded_unpack_sequence
from RestrictedPython.PrintCollector import PrintCollector
from RestrictedPython.transformer import (
    INSPECT_ATTRIBUTES,
    IOPERATOR_TO_STR,
    RestrictingNodeTransformer,
    copy_locations,
)

# ---------------------------------------------------------------------------
# Custom policy — allow async/await on top of standard restrictions
# ---------------------------------------------------------------------------

_WRAPPER_NAME = "sandboxmain"


def _is_forbidden_attr(name: str) -> bool:
    """True if *name* must be blocked as an attribute name in sandboxed code.

    The sandbox policy is more permissive than RestrictedPython's default:
    single-underscore "private" names (``_foo``) are allowed because they
    are a universal Python convention on user-defined classes and carry
    no capability beyond what the public API already exposes.  What
    remains blocked:

    - **Dunder names** (``__foo``, ``__foo__``): these expose CPython
      internals — ``__class__``, ``__bases__``, ``__mro__``,
      ``__subclasses__``, ``__globals__``, ``__code__``, ``__builtins__``,
      ``__dict__`` — any one of which lets sandbox code walk out of the
      sandbox to arbitrary objects and thereby bypass every other guard.
    - **``__roles__`` suffix**: a Zope-specific security marker; kept for
      parity with RestrictedPython's default policy.
    - **``INSPECT_ATTRIBUTES``**: frame / code / coroutine / generator
      introspection names (``f_globals``, ``cr_frame``, ``gi_code``, ...)
      that do *not* start with ``_`` but leak live frames and bytecode.
      Must be blocked explicitly.
    """
    if name.startswith("__"):
        return True
    if name.endswith("__roles__"):
        return True
    return name in INSPECT_ATTRIBUTES


def _forbidden_attr_message(name: str) -> str:
    """Human-readable reason for blocking *name* as an attribute."""
    return f'"{name}" is an invalid attribute name'


class _AsyncRestrictingNodeTransformer(RestrictingNodeTransformer):
    """Extends RestrictedPython's default policy to permit async constructs.

    ``async def``, ``await``, ``async for``, and ``async with`` are blocked
    by the upstream transformer.  This subclass mirrors the handling of their
    synchronous equivalents so that ``await call_tool(...)`` and
    ``asyncio.gather(...)`` work inside execute blocks.

    It also relaxes the upstream attribute-name policy: single-underscore
    "private" attributes (``self._name``) are permitted — see
    :func:`_is_forbidden_attr`.  Dunder access remains blocked.
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
        # Do not delegate to ``guard_iter``: it would wrap the iterable in
        # ``_getiter_(expr)`` (bound to the sync builtin ``iter``), which
        # fails on async iterators because they expose ``__aiter__`` /
        # ``__anext__`` rather than ``__iter__``.  The sandbox's ``_getiter_``
        # is already a pass-through for sync iteration, so skipping the wrap
        # here loses no real protection.
        return self.node_contents_visit(node)

    def visit_AsyncWith(self, node):
        node = self.node_contents_visit(node)
        for item in reversed(node.items):
            if isinstance(item.optional_vars, ast.Tuple):
                tmp_target, unpack = self.gen_unpack_wrapper(node, item.optional_vars)
                item.optional_vars = tmp_target
                node.body.insert(0, unpack)
        return node

    def visit_Attribute(self, node):
        """Rewrite attribute access and block dangerous names.

        Replaces the upstream ``visit_Attribute`` wholesale because the
        parent rejects every name that starts with ``_`` — even single-
        underscore conventional private names.  This override keeps the
        same AST rewrite (``a.b`` → ``_getattr_(a, "b")``,
        ``a.b = c`` → ``_write_(a).b = c``) but consults
        :func:`_is_forbidden_attr` for the name check, so ``self._x`` is
        legal while ``obj.__class__`` is still rejected at compile time.
        """
        if _is_forbidden_attr(node.attr):
            self.error(node, _forbidden_attr_message(node.attr))

        if isinstance(node.ctx, ast.Load):
            node = self.node_contents_visit(node)
            new_node = ast.Call(
                func=ast.Name("_getattr_", ast.Load()),
                args=[node.value, ast.Constant(node.attr)],
                keywords=[],
            )
            copy_locations(new_node, node)
            return new_node

        if isinstance(node.ctx, (ast.Store, ast.Del)):
            node = self.node_contents_visit(node)
            new_value = ast.Call(
                func=ast.Name("_write_", ast.Load()),
                args=[node.value],
                keywords=[],
            )
            copy_locations(new_value, node.value)
            node.value = new_value
            return node

        # ast.Attribute only has Load, Store, Del contexts — anything else
        # is a CPython-internal bug we want to surface loudly.
        raise NotImplementedError(f"Unknown ctx type: {type(node.ctx)}")

    def visit_AugAssign(self, node):
        """Allow augmented assignment on attribute targets.

        The upstream policy rejects ``obj.x += y`` outright.  We rewrite
        it into an ``Assign`` node that looks like
        ``_write_(obj).x = _inplacevar_("+=", _getattr_(obj, "x"), y)``
        — the same shape the transformer would produce for a plain
        ``obj.x`` read on one side and ``obj.x = ...`` write on the
        other — and return it directly.

        We cannot just return a raw ``Attribute`` AugAssign and let
        ``self.visit(...)`` walk it: re-visiting the freshly-built
        ``_inplacevar_`` ``Name`` would trip ``check_name``, which
        rejects underscore-prefixed variable names.  So we visit only
        the user-supplied subexpressions (``node.target.value`` and
        ``node.value``) and hand-assemble the guard-wrapped nodes
        around them.

        Subscript targets (``obj[k] += v``) are still forwarded to the
        parent, which rejects them.  Name targets also defer to the
        parent, which rewrites them via ``_inplacevar_`` identically.

        Evaluation order: CPython evaluates ``obj`` once for
        ``obj.x += y`` (DUP_TOP on the object); this rewrite evaluates
        ``obj`` twice.  For simple names — the common case — it's
        observationally identical.  Side-effectful ``obj`` expressions
        (``f().x += 1``) diverge; the sandbox does not promise
        CPython-identical semantics there.
        """
        if isinstance(node.target, ast.Attribute):
            target = node.target
            if _is_forbidden_attr(target.attr):
                self.error(node, _forbidden_attr_message(target.attr))
                return node

            op_str = IOPERATOR_TO_STR[type(node.op)]

            # Visit the user-supplied subexpressions first so any guards
            # they need (nested attribute reads, subscripts, ...) are
            # applied.  Everything below builds guard-wrapped nodes by
            # hand and must NOT be re-visited — ``_getattr_``, ``_write_``,
            # and ``_inplacevar_`` names would fail ``check_name``.
            obj_load = self.visit(target.value)
            rhs = self.visit(node.value)

            # Load side: ``_getattr_(obj, "x")``.
            load_call = ast.Call(
                func=ast.Name("_getattr_", ast.Load()),
                args=[obj_load, ast.Constant(target.attr)],
                keywords=[],
            )

            # Store side: ``_write_(obj).x = ...``.  Deep-copy ``obj_load``
            # so the Load and Store expressions own independent subtrees;
            # sharing would confuse the compiler's AST location tracking
            # and risks double-processing if the node is ever walked again.
            store_obj_wrapped = ast.Call(
                func=ast.Name("_write_", ast.Load()),
                args=[copy.deepcopy(obj_load)],
                keywords=[],
            )
            store_target = ast.Attribute(
                value=store_obj_wrapped,
                attr=target.attr,
                ctx=ast.Store(),
            )

            new_node = ast.Assign(
                targets=[store_target],
                value=ast.Call(
                    func=ast.Name("_inplacevar_", ast.Load()),
                    args=[ast.Constant(op_str), load_call, rhs],
                    keywords=[],
                ),
            )
            copy_locations(new_node, node)
            ast.fix_missing_locations(new_node)
            return new_node

        return super().visit_AugAssign(node)


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


def _apply(f: Any, *args: Any, **kwargs: Any) -> Any:
    """Guard for calls that use ``*args`` or ``**kwargs`` unpacking.

    RestrictedPython's transformer rewrites ``f(*args, **kwargs)`` into
    ``_apply_(f, *args, **kwargs)``.  A pass-through is safe here: the AST
    guards already wrap attribute/item access used to obtain ``f`` and to
    build the arg/kwarg iterables, so no additional wrapping is required.
    """
    return f(*args, **kwargs)


_NO_DEFAULT = object()


def _sandbox_getattr(
    obj: Any,
    name: str,
    default: Any = _NO_DEFAULT,
    getattr: Callable[..., Any] = getattr,
) -> Any:
    """``getattr`` variant matching the sandbox's relaxed name policy.

    Replaces :func:`RestrictedPython.Guards.safer_getattr` so that the
    runtime guard agrees with the compile-time check in
    :meth:`_AsyncRestrictingNodeTransformer.visit_Attribute`: dunder
    names, ``INSPECT_ATTRIBUTES``, and ``str.format`` / ``str.format_map``
    remain blocked, while single-underscore "private" names are allowed.

    Bound as ``_getattr_`` in the sandbox globals, so it is also invoked
    by the AST rewrite of every ``obj.attr`` read.  The builtin
    ``getattr`` alias in the sandbox builtins uses this same function.
    """
    if type(name) is not str:
        raise TypeError("type(name) must be str")
    if name in ("format", "format_map") and (
        isinstance(obj, str) or (isinstance(obj, type) and issubclass(obj, str))
    ):
        # CVE-class: str.format lets you pull attributes off any
        # argument, which would reach __class__ and friends regardless
        # of the AST guard.  See http://lucumr.pocoo.org/2016/12/29/careful-with-str-format/.
        raise NotImplementedError("Using the format*() methods of `str` is not safe")
    if _is_forbidden_attr(name):
        raise AttributeError(_forbidden_attr_message(name))
    if default is _NO_DEFAULT:
        return getattr(obj, name)
    return getattr(obj, name, default)


def _safe_hasattr(obj: Any, name: str) -> bool:
    """``hasattr`` that respects the sandbox's attribute-name policy."""
    try:
        _sandbox_getattr(obj, name)
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
    # Introspection — getattr/hasattr must go through the sandbox's
    # name-policy guard so dunder / frame-introspection attributes stay
    # out of reach even when user code bypasses attribute syntax.
    "type": type,
    "isinstance": isinstance,
    "hasattr": _safe_hasattr,
    "getattr": _sandbox_getattr,
    # Formatting
    "format": format,
    "super": super,
    # Class-definition helpers — required to use ``@classmethod`` /
    # ``@staticmethod`` / ``@property`` decorators inside user classes.
    # All three are pure descriptor wrappers and add no capability beyond
    # what ``class``/``def`` already permit.
    "classmethod": classmethod,
    "staticmethod": staticmethod,
    "property": property,
    # Note: ``print`` is intentionally not in builtins.  RestrictedPython's
    # transformer rewrites every ``print(...)`` call site to
    # ``_print._call_print(...)`` where ``_print`` is a ``PrintCollector``
    # instance injected at the top of the wrapper function.  Any ``print``
    # entry here would be dead code.  See ``_print_`` in ``_make_globals``.
}


def _make_globals(
    *,
    inputs: dict[str, Any] | None = None,
    external_functions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the restricted globals dict for ``exec()``."""
    glb: dict[str, Any] = {
        "__builtins__": _SANDBOX_BUILTINS,
        # CPython's class-creation bytecode reads ``__name__`` from the
        # enclosing namespace to set ``__module__`` on new classes.  Without
        # this entry, ``class C: ...`` raises ``NameError: name '__name__'
        # is not defined``.  Safe to expose: user code cannot read bare
        # ``__name__`` because the AST transformer rejects dunder names at
        # compile time.
        "__name__": "sandbox",
        "_getiter_": iter,
        "_getattr_": _sandbox_getattr,
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
        "_apply_": _apply,
        # ``_print_`` is the factory the transformer calls when user code
        # uses ``print(...)``.  Rewritten call sites become
        # ``_print._call_print(...)`` on an instance of this class, and the
        # ``printed`` magic name reads back the collected output.
        "_print_": PrintCollector,
        # ``__metaclass__`` is referenced by every ``class`` statement in
        # restricted code: the transformer rewrites ``class C(...)`` to
        # ``class C(..., metaclass=__metaclass__)``.  Plain ``type`` yields
        # ordinary classes — attribute access on instances still goes
        # through ``_sandbox_getattr`` via the ``_getattr_`` AST guard, so
        # no custom metaclass is needed.
        "__metaclass__": type,
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
