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

from ida_mcp.sandbox import RestrictedPythonSandbox


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

    with pytest.raises(SyntaxError, match="evaluated twice"):
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
    with pytest.raises(SyntaxError, match="evaluated twice"):
        asyncio.run(sandbox.run(code))


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
    with pytest.raises(SyntaxError, match="invalid"):
        asyncio.run(sandbox.run("return __metaclass__"))


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
