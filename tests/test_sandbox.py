# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Unit tests for the RestrictedPython sandbox.

These tests cover basic execution, async/await, import controls,
builtin availability, multiline strings, and blocked operations —
all without idalib.
"""

from __future__ import annotations

import asyncio

import pytest

from ida_mcp.sandbox import (
    _MAX_PRINT_CHARS,
    RestrictedPythonSandbox,
    _AsyncRestrictingNodeTransformer,
    _BoundedPrintCollector,
    _is_forbidden_attr,
    _rejected_stmt_placeholder,
)


@pytest.fixture
def sandbox():
    return RestrictedPythonSandbox()


# ---------------------------------------------------------------------------
# Basic execution
# ---------------------------------------------------------------------------


def test_basic_expression(sandbox):
    assert asyncio.run(sandbox.run("return 1 + 2")) == 3


def test_variables_and_control_flow(sandbox):
    code = """\
total = 0
for i in range(5):
    total += i
return total
"""
    assert asyncio.run(sandbox.run(code)) == 10


def test_no_return_gives_none(sandbox):
    assert asyncio.run(sandbox.run("x = 42")) is None


def test_inputs_available(sandbox):
    result = asyncio.run(sandbox.run("return x + 1", inputs={"x": 10}))
    assert result == 11


def test_external_functions(sandbox):
    async def add(a, b):
        return a + b

    result = asyncio.run(
        sandbox.run(
            "return await add(3, 4)",
            external_functions={"add": add},
        )
    )
    assert result == 7


# ---------------------------------------------------------------------------
# Multiline strings — regression test for AST-level wrapping
# ---------------------------------------------------------------------------


def test_multiline_string_preserved(sandbox):
    """Multiline string content must not be shifted by the wrapper."""
    code = '''\
x = """
hello
world
"""
return x
'''
    result = asyncio.run(sandbox.run(code))
    assert result == "\nhello\nworld\n"


def test_multiline_string_with_indentation(sandbox):
    """Indentation inside multiline strings must be preserved exactly."""
    code = '''\
x = """
    indented
        more
"""
return x
'''
    result = asyncio.run(sandbox.run(code))
    assert result == "\n    indented\n        more\n"


# ---------------------------------------------------------------------------
# Async / await
# ---------------------------------------------------------------------------


def test_await(sandbox):
    async def fetch(key):
        return {"key": key}

    result = asyncio.run(
        sandbox.run(
            'return await fetch("test")',
            external_functions={"fetch": fetch},
        )
    )
    assert result == {"key": "test"}


def test_asyncio_gather(sandbox):
    async def double(x):
        return x * 2

    code = """\
import asyncio
results = await asyncio.gather(double(1), double(2), double(3))
return list(results)
"""
    result = asyncio.run(sandbox.run(code, external_functions={"double": double}))
    assert result == [2, 4, 6]


# ---------------------------------------------------------------------------
# Argument unpacking — regression tests for ``_apply_`` guard
# ---------------------------------------------------------------------------


def test_star_args_call(sandbox):
    """``f(*args)`` — rewritten by RestrictedPython to ``_apply_(f, *args)``."""
    code = """\
def add(a, b, c):
    return a + b + c
args = [1, 2, 3]
return add(*args)
"""
    assert asyncio.run(sandbox.run(code)) == 6


def test_double_star_kwargs_call(sandbox):
    """``f(**kwargs)`` — rewritten by RestrictedPython to ``_apply_(f, **kwargs)``."""
    code = """\
def greet(greeting, name):
    return greeting + ", " + name
kw = {"greeting": "hello", "name": "world"}
return greet(**kw)
"""
    assert asyncio.run(sandbox.run(code)) == "hello, world"


def test_asyncio_gather_with_star_unpack(sandbox):
    """``asyncio.gather(*tasks)`` — the real-world pattern that triggered the bug."""

    async def double(x):
        return x * 2

    code = """\
import asyncio
tasks = [double(i) for i in range(4)]
results = await asyncio.gather(*tasks)
return list(results)
"""
    result = asyncio.run(sandbox.run(code, external_functions={"double": double}))
    assert result == [0, 2, 4, 6]


def test_async_for_over_async_generator(sandbox):
    """``async for`` — regression test; the default ``visit_AsyncFor`` would
    wrap the iterable with the sync ``iter`` builtin, breaking async iteration."""

    async def agen():
        for i in range(3):
            yield i

    code = """\
total = 0
async for x in agen():
    total += x
return total
"""
    result = asyncio.run(sandbox.run(code, external_functions={"agen": agen}))
    assert result == 3


# ---------------------------------------------------------------------------
# ``print`` — exercises the ``_print_`` / ``PrintCollector`` wiring
# ---------------------------------------------------------------------------


def test_print_and_printed(sandbox):
    """``print(...)`` is rewritten to ``_print._call_print(...)``; output is
    collected and available via the magic ``printed`` name."""
    code = """\
print("hello")
print("world")
return printed
"""
    result = asyncio.run(sandbox.run(code))
    assert result == "hello\nworld\n"


# ---------------------------------------------------------------------------
# Class definitions — exercise the ``__metaclass__`` wiring
# ---------------------------------------------------------------------------


def test_class_definition(sandbox):
    """``class C: ...`` — transformer rewrites to ``class C(metaclass=__metaclass__)``."""
    code = """\
class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y
    def sum(self):
        return self.x + self.y
p = Point(3, 4)
return p.sum()
"""
    assert asyncio.run(sandbox.run(code)) == 7


def test_class_with_inheritance(sandbox):
    code = """\
class Base:
    def greet(self):
        return "hi from base"
class Child(Base):
    pass
return Child().greet()
"""
    assert asyncio.run(sandbox.run(code)) == "hi from base"


def test_classmethod_staticmethod_property(sandbox):
    """``@classmethod``, ``@staticmethod``, and ``@property`` decorators."""
    code = """\
class C:
    counter = 10
    def __init__(self, x):
        self.x = x
    @classmethod
    def make(cls):
        return cls(cls.counter)
    @staticmethod
    def constant():
        return 42
    @property
    def doubled(self):
        return self.x * 2
c = C.make()
return (c.x, c.doubled, C.constant())
"""
    assert asyncio.run(sandbox.run(code)) == (10, 20, 42)


# ---------------------------------------------------------------------------
# Import controls
# ---------------------------------------------------------------------------


_ALLOWED_MODULES = [
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
]


@pytest.mark.parametrize("module", _ALLOWED_MODULES)
def test_allowed_import(sandbox, module):
    result = asyncio.run(sandbox.run(f"import {module}\nreturn True"))
    assert result is True


def test_submodule_import(sandbox):
    code = "from collections.abc import Sequence\nreturn issubclass(list, Sequence)"
    assert asyncio.run(sandbox.run(code)) is True


def test_submodule_import_direct(sandbox):
    code = "import collections.abc\nreturn issubclass(list, collections.abc.Sequence)"
    assert asyncio.run(sandbox.run(code)) is True


@pytest.mark.parametrize("module", ["os", "sys", "subprocess", "socket", "shutil"])
def test_blocked_import(sandbox, module):
    with pytest.raises(ImportError, match="not allowed"):
        asyncio.run(sandbox.run(f"import {module}"))


# ---------------------------------------------------------------------------
# Module-attribute denylist: asyncio exposes subprocess / network / loop
# capabilities that must stay unreachable even though the top-level import
# is allowed.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "submodule",
    [
        "asyncio.subprocess",
        "asyncio.base_subprocess",
        "asyncio.events",
        "asyncio.streams",
        "asyncio.unix_events",
    ],
)
def test_blocked_asyncio_submodule_import(sandbox, submodule):
    with pytest.raises(ImportError, match="not allowed"):
        asyncio.run(sandbox.run(f"import {submodule}"))


@pytest.mark.parametrize(
    "name",
    [
        "subprocess",
        "create_subprocess_exec",
        "open_connection",
        "start_server",
        "events",
        "to_thread",
    ],
)
def test_blocked_asyncio_fromlist(sandbox, name):
    with pytest.raises(ImportError, match="not allowed"):
        asyncio.run(sandbox.run(f"from asyncio import {name}"))


@pytest.mark.parametrize(
    "expr",
    [
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "asyncio.subprocess",
        "asyncio.open_connection",
        "asyncio.start_server",
        "asyncio.get_event_loop",
        "asyncio.get_running_loop",
        "asyncio.new_event_loop",
        "asyncio.to_thread",
        "asyncio.events",
    ],
)
def test_blocked_asyncio_attribute(sandbox, expr):
    code = f"import asyncio\nreturn {expr}"
    with pytest.raises(AttributeError, match="not available in the sandbox"):
        asyncio.run(sandbox.run(code))


def test_asyncio_gather_still_allowed(sandbox):
    """The documented parallel-call helpers remain reachable."""
    code = """\
import asyncio
return asyncio.gather
"""
    # Just confirm the attribute loads — we are not running it here.
    assert asyncio.run(sandbox.run(code)) is asyncio.gather


def test_event_loop_attribute_access_denied(sandbox):
    """Defence-in-depth: even if sandbox code obtains a loop, all attr
    access on it is refused."""

    async def expose_loop():
        return asyncio.get_running_loop()

    code = """\
loop = await expose_loop()
return loop.create_subprocess_exec
"""
    with pytest.raises(AttributeError, match="event loop is not permitted"):
        asyncio.run(sandbox.run(code, external_functions={"expose_loop": expose_loop}))


def test_future_get_loop_attribute_access_denied(sandbox):
    """``Future.get_loop()`` returns an AbstractEventLoop — the isinstance
    guard in ``_sandbox_getattr`` must catch any attribute access on it
    regardless of how the loop entered sandbox scope."""

    async def make_future():
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        fut.set_result(None)
        return fut

    code = """\
fut = await make_future()
loop = fut.get_loop()
return loop.create_subprocess_exec
"""
    with pytest.raises(AttributeError, match="event loop is not permitted"):
        asyncio.run(sandbox.run(code, external_functions={"make_future": make_future}))


# ---------------------------------------------------------------------------
# operator.attrgetter / methodcaller bypass the AST-level dunder block — they
# use CPython's C-level getattr directly.  Must be denylisted.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["attrgetter", "methodcaller"])
def test_blocked_operator_attr(sandbox, name):
    code = f"import operator\nreturn operator.{name}"
    with pytest.raises(AttributeError, match="not available in the sandbox"):
        asyncio.run(sandbox.run(code))


@pytest.mark.parametrize("name", ["attrgetter", "methodcaller"])
def test_blocked_operator_fromlist(sandbox, name):
    with pytest.raises(ImportError, match="not allowed"):
        asyncio.run(sandbox.run(f"from operator import {name}"))


def test_operator_itemgetter_still_allowed(sandbox):
    """``itemgetter`` uses ``__getitem__``, not ``getattr`` — safe to keep."""
    code = """\
import operator
g = operator.itemgetter(0)
return g([1, 2, 3])
"""
    assert asyncio.run(sandbox.run(code)) == 1


# ---------------------------------------------------------------------------
# typing.get_type_hints evaluates string annotations via builtin eval() —
# unconstrained by the sandbox's restricted compile.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["get_type_hints", "_eval_type"])
def test_blocked_typing_eval_paths(sandbox, name):
    code = f"import typing\nreturn typing.{name}"
    with pytest.raises(AttributeError, match="not available in the sandbox"):
        asyncio.run(sandbox.run(code))


def test_blocked_typing_fromlist(sandbox):
    with pytest.raises(ImportError, match="not allowed"):
        asyncio.run(sandbox.run("from typing import get_type_hints"))


# ---------------------------------------------------------------------------
# Builtins
# ---------------------------------------------------------------------------


def test_hex_builtin(sandbox):
    assert asyncio.run(sandbox.run("return hex(255)")) == "0xff"


def test_oct_builtin(sandbox):
    assert asyncio.run(sandbox.run("return oct(8)")) == "0o10"


def test_bin_builtin(sandbox):
    assert asyncio.run(sandbox.run("return bin(10)")) == "0b1010"


def test_int_base_conversion(sandbox):
    assert asyncio.run(sandbox.run('return int("ff", 16)')) == 255


def test_container_builtins(sandbox):
    code = """\
d = dict(a=1)
s = set([1, 2, 3])
return len(d) + len(s)
"""
    assert asyncio.run(sandbox.run(code)) == 4


def test_struct_unpack(sandbox):
    code = """\
import struct
return struct.unpack('<I', b'\\x01\\x00\\x00\\x00')[0]
"""
    assert asyncio.run(sandbox.run(code)) == 1


# ---------------------------------------------------------------------------
# Blocked operations
# ---------------------------------------------------------------------------


def test_eval_blocked(sandbox):
    with pytest.raises(SyntaxError):
        asyncio.run(sandbox.run('eval("1")'))


def test_exec_blocked(sandbox):
    with pytest.raises(SyntaxError):
        asyncio.run(sandbox.run('exec("x = 1")'))


def test_open_blocked(sandbox):
    with pytest.raises((SyntaxError, ImportError, NameError)):
        asyncio.run(sandbox.run('open("/etc/passwd")'))


def test_dunder_access_blocked(sandbox):
    with pytest.raises(SyntaxError, match="invalid attribute name"):
        asyncio.run(sandbox.run("return ().__class__.__bases__"))


def test_frame_introspection_blocked_at_compile_time(sandbox):
    """Dunder access (``__code__``) is rejected at compile time by the
    dunder rule — the first line of defence against frame / bytecode
    introspection."""
    code = """\
def f():
    pass
return f.__code__
"""
    with pytest.raises(SyntaxError, match="invalid attribute name"):
        asyncio.run(sandbox.run(code))


def test_frame_introspection_blocked_at_runtime(sandbox):
    """``INSPECT_ATTRIBUTES`` names (``f_globals``, ``co_code``, ...) do
    not start with ``_`` so the dunder heuristic misses them.  The
    sandbox ``getattr`` guard must block them explicitly, otherwise
    runtime ``getattr(obj, "f_globals")`` would leak a live frame."""
    # Any INSPECT_ATTRIBUTES name will do — we ask for it via getattr
    # on a harmless target; the guard should reject the name regardless
    # of whether the attribute would actually exist on the object.
    with pytest.raises(AttributeError, match="invalid attribute name"):
        asyncio.run(sandbox.run('return getattr(0, "f_globals")'))


# ---------------------------------------------------------------------------
# Single-underscore "private" attribute access — allowed (conventional
# Python idiom on user classes).  Dunders stay blocked.
# ---------------------------------------------------------------------------


def test_single_underscore_attribute_read_write(sandbox):
    code = """\
class Box:
    def __init__(self, v):
        self._value = v
    def get(self):
        return self._value
b = Box(7)
b._value = 99
return b.get()
"""
    assert asyncio.run(sandbox.run(code)) == 99


def test_single_underscore_not_dunder(sandbox):
    """``obj._foo`` is allowed; ``obj.__foo`` is still blocked.

    This relaxation only touches attribute access.  Single-underscore
    *variable* names (``_x = 1``) are still rejected by the upstream
    ``check_name`` policy — that's a separate restriction and out of
    scope for this fix.
    """
    code = """\
class C:
    def __init__(self):
        self.foo = 1
        self._bar = 2
c = C()
return (c.foo, c._bar)
"""
    assert asyncio.run(sandbox.run(code)) == (1, 2)

    with pytest.raises(SyntaxError, match="invalid attribute name"):
        asyncio.run(sandbox.run("class C: pass\nc = C()\nreturn c.__bar"))


def test_getattr_builtin_allows_single_underscore(sandbox):
    """``getattr(obj, '_priv')`` at runtime matches the AST rule."""
    code = """\
class C:
    def __init__(self):
        self._priv = 42
c = C()
return getattr(c, '_priv')
"""
    assert asyncio.run(sandbox.run(code)) == 42


def test_getattr_builtin_blocks_dunder(sandbox):
    code = "return getattr((), '__class__')"
    with pytest.raises(AttributeError, match="invalid attribute name"):
        asyncio.run(sandbox.run(code))


def test_hasattr_respects_policy(sandbox):
    code = """\
class C:
    def __init__(self):
        self._priv = 1
c = C()
return (hasattr(c, '_priv'), hasattr((), '__class__'))
"""
    # _priv is visible; __class__ is hidden by the guard.
    assert asyncio.run(sandbox.run(code)) == (True, False)


# ---------------------------------------------------------------------------
# Augmented assignment to attribute targets — ``obj.x += y``
# ---------------------------------------------------------------------------


def test_augassign_attribute_on_instance(sandbox):
    code = """\
class Counter:
    def __init__(self):
        self.n = 0
c = Counter()
c.n += 5
c.n += 3
return c.n
"""
    assert asyncio.run(sandbox.run(code)) == 8


def test_augassign_attribute_on_classvar(sandbox):
    """``cls.count += 1`` inside a classmethod — the original failing pattern."""
    code = """\
class Counter:
    count = 0
    @classmethod
    def bump(cls):
        cls.count += 1
        return cls.count
Counter.bump()
Counter.bump()
Counter.bump()
return Counter.count
"""
    assert asyncio.run(sandbox.run(code)) == 3


def test_augassign_attribute_blocks_dunder(sandbox):
    """``obj.__dunder__ += y`` stays rejected — augmented assignment
    must not be an escape hatch around the attribute-name check."""
    with pytest.raises(SyntaxError, match="invalid attribute name"):
        asyncio.run(sandbox.run("class C:\n    pass\nc = C()\nc.__x += 1"))


def test_augassign_subscript_still_blocked(sandbox):
    """Augmented subscript assignment (``d[k] += v``) is still rejected
    — we only relaxed the Attribute case."""
    with pytest.raises(SyntaxError, match="Augmented assignment"):
        asyncio.run(sandbox.run("d = {'a': 1}\nd['a'] += 1"))


def test_augassign_rejects_call_on_target(sandbox):
    """``f().x += 1`` is rejected at compile time because the rewrite
    would evaluate ``f()`` twice and silently drop the store."""
    # Baseline: plain reads of ``make().n`` work — the augassign form
    # is what this test targets.
    baseline = """\
class Counter:
    def __init__(self):
        self.n = 0
def make():
    return Counter()
return make().n
"""
    assert asyncio.run(sandbox.run(baseline)) == 0

    with pytest.raises(SyntaxError, match="plain dotted name"):
        asyncio.run(
            sandbox.run(
                """\
class Counter:
    def __init__(self):
        self.n = 0
def make():
    return Counter()
make().n += 1
return 0
"""
            )
        )


def test_augassign_call_escape_hatch_via_temporary(sandbox):
    """The recommended workaround from the error message must work."""
    code = """\
class Counter:
    def __init__(self):
        self.n = 0
def make():
    return Counter()
tmp = make()
tmp.n += 5
return tmp.n
"""
    assert asyncio.run(sandbox.run(code)) == 5


def test_augassign_rejects_method_call_on_target(sandbox):
    """Method calls on the augassign target chain are also rejected."""
    code = """\
class Holder:
    def __init__(self):
        self.inner = object()
    def get(self):
        return self
h = Holder()
h.get().inner += 1
return 0
"""
    with pytest.raises(SyntaxError, match="plain dotted name"):
        asyncio.run(sandbox.run(code))


def test_augassign_rejects_subscript_on_target(sandbox):
    """``obj[i].x += 1`` is rejected — the rewrite would evaluate ``obj[i]`` twice."""
    code = """\
class Box:
    def __init__(self, n):
        self.n = n
boxes = [Box(0), Box(0)]
boxes[0].n += 1
return boxes[0].n
"""
    with pytest.raises(SyntaxError, match="plain dotted name"):
        asyncio.run(sandbox.run(code))


def test_augassign_rejected_attribute_returns_pass_placeholder():
    """Defense-in-depth: rejected AugAssign is replaced with ``ast.Pass``.

    Upstream RestrictedPython collects errors and raises ``SyntaxError``
    at the end of ``compile_restricted``, so returning the original
    (unvisited) rejected node would be safe *today* — the bytecode is
    never emitted.  But if the error-collection contract were ever
    relaxed, leaving the original AugAssign in the tree would let a
    rejected dunder write or non-dotted-name target compile to real
    bytecode.

    This test calls the transformer directly without going through
    ``compile_restricted``, so the returned tree reflects what we would
    emit if the compile-time error were suppressed.  Both error paths
    in :meth:`visit_AugAssign` must produce ``ast.Pass``, never the
    original node.
    """
    import ast  # noqa: PLC0415

    # Dunder attribute target — rejected by the attribute-name guard.
    tree = ast.parse("obj.__x += 1")
    transformer = _AsyncRestrictingNodeTransformer()
    transformer.visit(tree)
    # The error must be recorded (compile would fail on this).
    assert any("__x" in err for err in transformer.errors)
    # The AugAssign must be replaced with Pass in the rewritten tree.
    top = tree.body[0]
    assert isinstance(top, ast.Pass), f"expected ast.Pass placeholder, got {type(top).__name__}"
    assert top.lineno == 1

    # Non-simple chain target — rejected by the dotted-name guard.
    tree = ast.parse("f().x += 1")
    transformer = _AsyncRestrictingNodeTransformer()
    transformer.visit(tree)
    assert any("plain dotted name" in err for err in transformer.errors)
    top = tree.body[0]
    assert isinstance(top, ast.Pass)


def test_rejected_stmt_placeholder_copies_locations():
    """The helper must copy source locations from the rejected node."""
    import ast  # noqa: PLC0415

    node = ast.parse("x += 1").body[0]
    assert node.lineno == 1
    placeholder = _rejected_stmt_placeholder(node)
    assert isinstance(placeholder, ast.Pass)
    assert placeholder.lineno == node.lineno
    assert placeholder.col_offset == node.col_offset


def test_augassign_rejects_nested_subscript_on_target(sandbox):
    """Subscripts anywhere in the target chain are rejected — the
    dotted-name check bottoms out at the first non-Attribute node."""
    code = """\
class Inner:
    def __init__(self):
        self.n = 0
class Holder:
    def __init__(self):
        self.bag = [Inner()]
h = Holder()
h.bag[0].n += 1
return 0
"""
    with pytest.raises(SyntaxError, match="plain dotted name"):
        asyncio.run(sandbox.run(code))


def test_augassign_rejects_ifexp_on_target(sandbox):
    """``(a if cond else b).x += 1`` — IfExp is not a dotted name, so the
    sandbox refuses it even though neither side contains a Call/Subscript.

    This is the gap the ``plain dotted name`` rule closes over the old
    "Call/Subscript only" check: CPython evaluates the IfExp once, but
    the sandbox rewrite would evaluate it twice and potentially take
    different branches if ``cond`` depends on state the RHS mutates.
    """
    code = """\
class Box:
    def __init__(self, n):
        self.n = n
a = Box(0)
b = Box(0)
cond = True
(a if cond else b).n += 1
return 0
"""
    with pytest.raises(SyntaxError, match="plain dotted name"):
        asyncio.run(sandbox.run(code))


def test_augassign_rejects_binop_on_target(sandbox):
    """``(a + b).x += 1`` — arithmetic is not a dotted name.

    A forced cast through ``BinOp`` cannot appear on the LHS of a
    simple augmented assignment, but the rule still catches the
    pathological form for completeness.
    """
    # ``BinOp`` as an attribute target is syntactically valid but
    # semantically nonsense — still, the sandbox must not rewrite it.
    code = """\
class Box:
    def __init__(self, n):
        self.n = n
    def __add__(self, other):
        return Box(self.n + other.n)
a = Box(1)
b = Box(2)
(a + b).n += 1
return 0
"""
    with pytest.raises(SyntaxError, match="plain dotted name"):
        asyncio.run(sandbox.run(code))


def test_augassign_accepts_deep_dotted_chain(sandbox):
    """``a.b.c.d += 1`` — a deep chain of plain attribute lookups passes
    the dotted-name check; the sandbox rewrites it correctly."""
    code = """\
class D:
    def __init__(self):
        self.v = 0
class C:
    def __init__(self):
        self.d = D()
class B:
    def __init__(self):
        self.c = C()
class A:
    def __init__(self):
        self.b = B()
a = A()
a.b.c.d.v += 7
a.b.c.d.v += 3
return a.b.c.d.v
"""
    assert asyncio.run(sandbox.run(code)) == 10


def test_augassign_subscript_escape_hatch_via_temporary(sandbox):
    """The documented workaround (assign to a temporary first) works here too."""
    code = """\
class Box:
    def __init__(self, n):
        self.n = n
boxes = [Box(0), Box(0)]
tmp = boxes[0]
tmp.n += 5
return boxes[0].n
"""
    assert asyncio.run(sandbox.run(code)) == 5


# ---------------------------------------------------------------------------
# Class-based escape attempts — defense-in-depth for the new class
# definition / classmethod support.
# ---------------------------------------------------------------------------


def test_classmethod_cannot_walk_bases(sandbox):
    """A classmethod cannot reach ``cls.__bases__`` at compile time."""
    code = """\
class C:
    @classmethod
    def attack(cls):
        return cls.__bases__
return C.attack()
"""
    with pytest.raises(SyntaxError, match="invalid attribute name"):
        asyncio.run(sandbox.run(code))


def test_instance_cannot_read_dict(sandbox):
    """``self.__dict__`` — dunder rule catches it at compile time."""
    code = """\
class C:
    def __init__(self):
        self.x = 1
    def attack(self):
        return self.__dict__
return C().attack()
"""
    with pytest.raises(SyntaxError, match="invalid attribute name"):
        asyncio.run(sandbox.run(code))


def test_classmethod_cannot_walk_class(sandbox):
    """``cls.__class__`` — even via a classmethod, still blocked."""
    code = """\
class C:
    @classmethod
    def attack(cls):
        return cls.__class__
return C.attack()
"""
    with pytest.raises(SyntaxError, match="invalid attribute name"):
        asyncio.run(sandbox.run(code))


def test_type_of_instance_blocks_bases(sandbox):
    """``type(x).__bases__`` — ``type`` is a builtin but the dunder
    attribute chain is still rejected at compile time."""
    code = """\
class C:
    pass
return type(C()).__bases__
"""
    with pytest.raises(SyntaxError, match="invalid attribute name"):
        asyncio.run(sandbox.run(code))


def test_classmethod_cannot_runtime_escape_via_getattr(sandbox):
    """Runtime ``getattr(cls, "__bases__")`` is rejected by the sandbox
    guard even when the target is obtained inside a classmethod."""
    code = """\
class C:
    @classmethod
    def attack(cls):
        return getattr(cls, '__bases__')
return C.attack()
"""
    with pytest.raises(AttributeError, match="invalid attribute name"):
        asyncio.run(sandbox.run(code))


def test_classmethod_cannot_runtime_escape_via_getattr_inspect(sandbox):
    """``INSPECT_ATTRIBUTES`` names (``f_globals``, ``gi_code``, ...) are
    blocked by the runtime ``getattr`` guard even when reached through a
    classmethod — second line of defence behind the compile-time dunder
    rule."""
    code = """\
class C:
    @classmethod
    def attack(cls):
        return getattr(cls, 'f_globals')
return C.attack()
"""
    with pytest.raises(AttributeError, match="invalid attribute name"):
        asyncio.run(sandbox.run(code))


def test_str_format_blocked_on_subclass(sandbox):
    """A user-defined ``str`` subclass cannot evade the ``format``
    block by inheriting — the guard uses ``isinstance``/``issubclass``
    against ``str``, so any string type is caught."""
    code = """\
class Safe(str):
    pass
s = Safe("{0}")
return s.format(object())
"""
    with pytest.raises(NotImplementedError, match="format"):
        asyncio.run(sandbox.run(code))


def test_class_body_cannot_reference_metaclass_directly(sandbox):
    """``__metaclass__`` is injected into globals for ``class`` to work,
    but the user's own code must not be able to rebind or inspect it."""
    with pytest.raises(SyntaxError, match=r'"__metaclass__" is an invalid variable name'):
        asyncio.run(sandbox.run("return __metaclass__"))


# ---------------------------------------------------------------------------
# Upstream-API canaries — fail loudly when RestrictedPython internals move
# ---------------------------------------------------------------------------


def test_inspect_attributes_canary():
    """Canary for RestrictedPython's ``INSPECT_ATTRIBUTES`` contract.

    ``_is_forbidden_attr`` layers on top of
    ``RestrictedPython.transformer.INSPECT_ATTRIBUTES`` to block
    frame/code/generator/coroutine/traceback introspection names that
    do not start with ``_`` (``f_globals``, ``co_code``, ``gi_code``,
    ...).  If upstream renames or removes any of these, our blocklist
    silently shrinks.  Pin a known subset so a RestrictedPython
    version bump fails loudly and forces a manual re-audit of
    :meth:`_AsyncRestrictingNodeTransformer.visit_Attribute` and
    :func:`_sandbox_getattr`.
    """
    # Names confirmed present in RestrictedPython 8.1.  Keeping this
    # list small and conservative — the goal is to detect a breaking
    # rename / removal, not to enumerate every blocked name.
    pinned = {
        # Frame introspection.
        "f_back",
        "f_builtins",
        "f_code",
        "f_globals",
        "f_locals",
        "f_trace",
        # Code object internals.
        "co_code",
        # Generator / coroutine introspection.
        "gi_code",
        "gi_frame",
        "cr_code",
        "cr_frame",
        # Traceback walking.
        "tb_frame",
        "tb_next",
    }
    from RestrictedPython.transformer import INSPECT_ATTRIBUTES  # noqa: PLC0415

    missing = pinned - set(INSPECT_ATTRIBUTES)
    assert not missing, (
        "RestrictedPython INSPECT_ATTRIBUTES lost pinned introspection "
        f"names: {sorted(missing)}.  Re-audit sandbox.py._is_forbidden_attr "
        "and _sandbox_getattr after the upgrade — names missing from "
        "the upstream set will no longer be blocked at runtime."
    )
    # Every pinned name must also be rejected by our own helper, which
    # composes the upstream set with the dunder rule.  If either side
    # drifts, this catches it.
    for name in pinned:
        assert _is_forbidden_attr(name), (
            f"_is_forbidden_attr({name!r}) returned False — the sandbox "
            "attribute-name guard has regressed."
        )


# ---------------------------------------------------------------------------
# Bounded PrintCollector — runaway print() loops must be killed before
# they exhaust memory.
# ---------------------------------------------------------------------------


def test_print_cap_allows_reasonable_output(sandbox):
    """Output under the cap is returned normally."""
    code = """\
for i in range(10):
    print("line", i)
return len(printed)
"""
    assert asyncio.run(sandbox.run(code)) > 0


def test_print_cap_kills_runaway_loop(sandbox):
    """An unbounded print loop hits the character cap and raises."""
    # 4096 * 1024 ~= 4 MiB, well past the ~1 MiB cap.
    code = """\
chunk = "x" * 1024
for i in range(4096):
    print(chunk)
return len(printed)
"""
    with pytest.raises(RuntimeError, match=r"print\(\) output exceeded"):
        asyncio.run(sandbox.run(code))


def test_bounded_print_collector_tracks_cumulative_total():
    """The cap is against cumulative writes; clearing ``txt`` does not reset it."""
    collector = _BoundedPrintCollector()
    first = "x" * (_MAX_PRINT_CHARS // 2)
    collector.write(first)
    assert collector._total_chars == len(first)

    # Clearing the buffer must not reset the running total.
    collector.txt.clear()

    with pytest.raises(RuntimeError, match=r"print\(\) output exceeded"):
        collector.write("y" * ((_MAX_PRINT_CHARS // 2) + 1))


def test_bounded_print_collector_rejects_oversized_single_write():
    """Rejected writes leave both ``_total_chars`` and ``txt`` untouched."""
    collector = _BoundedPrintCollector()
    collector.write("a" * 100)
    before_total = collector._total_chars
    before_txt = list(collector.txt)

    with pytest.raises(RuntimeError, match=r"print\(\) output exceeded"):
        collector.write("b" * (_MAX_PRINT_CHARS + 1))

    assert collector._total_chars == before_total
    assert collector.txt == before_txt


# ---------------------------------------------------------------------------
# In-place operations
# ---------------------------------------------------------------------------


def test_inplace_add(sandbox):
    code = """\
x = 10
x += 5
return x
"""
    assert asyncio.run(sandbox.run(code)) == 15


def test_inplace_list_extend(sandbox):
    code = """\
x = [1, 2]
x += [3, 4]
return x
"""
    assert asyncio.run(sandbox.run(code)) == [1, 2, 3, 4]
