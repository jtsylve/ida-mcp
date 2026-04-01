# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Unit tests for server.py pure functions (_auto_title, _ensure_title)
and Pydantic output-schema validation against representative tool outputs.

These tests run without idalib — the pure helpers in server.py are defined
before any idalib bootstrap, so importing them does not trigger idalib init.
IDA modules are stubbed for tool model imports.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ida_mcp.models import RenameResult
from ida_mcp.server import _auto_title, _ensure_title
from ida_mcp.tools.functions import (
    DecompilationResult,
    DisassemblyResult,
    FunctionDetail,
    FunctionListResult,
)
from ida_mcp.tools.xrefs import CallGraphResult, XrefFromResult, XrefToResult

# ---------------------------------------------------------------------------
# _auto_title
# ---------------------------------------------------------------------------


def test_auto_title_basic():
    assert _auto_title("get_function") == "Get Function"


def test_auto_title_uppercase_words():
    assert _auto_title("get_cfg_edges") == "Get CFG Edges"
    assert _auto_title("apply_flirt_signature") == "Apply FLIRT Signature"
    assert _auto_title("get_elf_debug_file_directory") == "Get ELF Debug File Directory"


def test_auto_title_single_word():
    assert _auto_title("undo") == "Undo"


def test_auto_title_single_uppercase_word():
    assert _auto_title("ida") == "IDA"


def test_auto_title_leading_underscore():
    """Leading underscores should not produce leading spaces."""
    result = _auto_title("_private_func")
    assert not result.startswith(" ")
    assert result == "Private Func"


def test_auto_title_double_underscore():
    """Double underscores should not produce double spaces."""
    result = _auto_title("get__thing")
    assert "  " not in result
    assert result == "Get Thing"


# ---------------------------------------------------------------------------
# _ensure_title
# ---------------------------------------------------------------------------


def test_ensure_title_adds_title():
    kwargs: dict = {"annotations": {"readOnlyHint": True}}
    _ensure_title(kwargs, "get_function", None)
    assert kwargs["title"] == "Get Function"


def test_ensure_title_does_not_overwrite():
    kwargs: dict = {"title": "Custom Title"}
    _ensure_title(kwargs, "get_function", None)
    assert kwargs["title"] == "Custom Title"


def test_ensure_title_creates_if_missing():
    kwargs: dict = {}
    _ensure_title(kwargs, "get_function", None)
    assert kwargs["title"] == "Get Function"


def test_ensure_title_from_fn():
    def my_tool():
        pass

    kwargs: dict = {}
    _ensure_title(kwargs, None, my_tool)
    assert kwargs["title"] == "My Tool"


def test_ensure_title_name_takes_precedence_over_fn():
    def fallback():
        pass

    kwargs: dict = {}
    _ensure_title(kwargs, "get_xrefs_to", fallback)
    assert kwargs["title"] == "Get Xrefs To"


# ---------------------------------------------------------------------------
# Output schema validation — representative tool output dicts
# ---------------------------------------------------------------------------


class TestFunctionListResultSchema:
    def test_valid(self):
        data = {
            "items": [
                {"name": "main", "start": "0x401000", "end": "0x401100", "size": 256},
                {"name": "foo", "start": "0x401100", "end": "0x401150", "size": 80},
            ],
            "total": 2,
            "offset": 0,
            "limit": 100,
            "has_more": False,
        }
        obj = FunctionListResult.model_validate(data)
        assert len(obj.items) == 2
        assert obj.items[0].name == "main"

    def test_missing_item_field(self):
        data = {
            "items": [{"name": "main", "start": "0x401000"}],  # missing end, size
            "total": 1,
            "offset": 0,
            "limit": 100,
            "has_more": False,
        }
        with pytest.raises(ValidationError):
            FunctionListResult.model_validate(data)


class TestFunctionDetailSchema:
    def test_valid_without_chunks(self):
        data = {
            "name": "main",
            "start": "0x401000",
            "end": "0x401100",
            "size": 256,
            "flags": 0,
            "does_return": True,
            "is_library": False,
            "is_thunk": False,
            "comment": "",
            "repeatable_comment": "",
            "chunks": None,
        }
        obj = FunctionDetail.model_validate(data)
        assert obj.chunks is None

    def test_valid_with_chunks(self):
        data = {
            "name": "fragmented",
            "start": "0x401000",
            "end": "0x401200",
            "size": 512,
            "flags": 0,
            "does_return": True,
            "is_library": False,
            "is_thunk": False,
            "comment": "",
            "repeatable_comment": "",
            "chunks": [
                {"start": "0x401000", "end": "0x401100", "size": 256},
                {"start": "0x401200", "end": "0x401300", "size": 256},
            ],
        }
        obj = FunctionDetail.model_validate(data)
        assert len(obj.chunks) == 2

    def test_missing_required_field(self):
        data = {
            "name": "main",
            "start": "0x401000",
            # missing end, size, flags, etc.
        }
        with pytest.raises(ValidationError):
            FunctionDetail.model_validate(data)


class TestDecompilationResultSchema:
    def test_valid(self):
        data = {
            "address": "0x401000",
            "name": "main",
            "pseudocode": "int main() { return 0; }",
        }
        obj = DecompilationResult.model_validate(data)
        assert obj.pseudocode == "int main() { return 0; }"

    def test_missing_pseudocode(self):
        with pytest.raises(ValidationError):
            DecompilationResult.model_validate({"address": "0x401000", "name": "main"})


class TestDisassemblyResultSchema:
    def test_valid(self):
        data = {
            "address": "0x401000",
            "name": "main",
            "instruction_count": 2,
            "instructions": [
                {"address": "0x401000", "disasm": "push rbp"},
                {"address": "0x401001", "disasm": "mov rbp, rsp"},
            ],
        }
        obj = DisassemblyResult.model_validate(data)
        assert obj.instruction_count == 2


class TestRenameResultSchema:
    def test_valid(self):
        data = {
            "address": "0x401000",
            "old_name": "sub_401000",
            "new_name": "main",
        }
        obj = RenameResult.model_validate(data)
        assert obj.old_name == "sub_401000"


class TestXrefToResultSchema:
    def test_valid(self):
        data = {
            "address": "0x401000",
            "items": [
                {
                    "from": "0x402000",
                    "from_name": "caller",
                    "type": "Code_Near_Call",
                    "is_code": True,
                },
            ],
            "total": 1,
            "offset": 0,
            "limit": 100,
            "has_more": False,
        }
        obj = XrefToResult.model_validate(data)
        assert len(obj.items) == 1


class TestXrefFromResultSchema:
    def test_valid(self):
        data = {
            "address": "0x401000",
            "items": [
                {
                    "to": "0x403000",
                    "to_name": "callee",
                    "type": "Code_Near_Call",
                    "is_code": True,
                },
            ],
            "total": 1,
            "offset": 0,
            "limit": 100,
            "has_more": False,
        }
        obj = XrefFromResult.model_validate(data)
        assert obj.items[0].to == "0x403000"


class TestCallGraphResultSchema:
    def test_valid(self):
        data = {
            "function": {"address": "0x401000", "name": "main"},
            "callers": [{"address": "0x400000", "name": "_start"}],
            "callees": [
                {
                    "address": "0x402000",
                    "name": "init",
                    "callees": [{"address": "0x403000", "name": "setup"}],
                },
            ],
        }
        obj = CallGraphResult.model_validate(data)
        assert obj.function.name == "main"
        assert len(obj.callees) == 1

    def test_missing_function(self):
        with pytest.raises(ValidationError):
            CallGraphResult.model_validate({"callers": [], "callees": []})
