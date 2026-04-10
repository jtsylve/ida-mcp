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
