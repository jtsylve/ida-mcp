# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Unit tests for server.py pure functions (_auto_title, _inject_title)
and Pydantic output-schema validation against representative tool outputs.

These tests run without idalib — IDA modules are stubbed out.
"""

from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock

# Stub out IDA modules so server/models can be imported without idalib.
_IDA_MODULES = [
    "idapro",
    "idaapi",
    "idc",
    "idautils",
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
]

_stubs: dict[str, ModuleType] = {}
for mod_name in _IDA_MODULES:
    if mod_name not in sys.modules:
        _stubs[mod_name] = MagicMock()
        sys.modules[mod_name] = _stubs[mod_name]

import pytest  # noqa: E402
from pydantic import ValidationError  # noqa: E402

from ida_mcp.models import (  # noqa: E402
    CallGraphResult,
    DecompilationResult,
    DisassemblyResult,
    FunctionDetail,
    FunctionListResult,
    RenameResult,
    XrefFromResult,
    XrefToResult,
)
from ida_mcp.server import _auto_title, _inject_title  # noqa: E402

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
# _inject_title
# ---------------------------------------------------------------------------


def test_inject_title_adds_title():
    kwargs: dict = {"annotations": {"readOnlyHint": True}}
    _inject_title(kwargs, "get_function", None)
    assert kwargs["annotations"]["title"] == "Get Function"


def test_inject_title_does_not_overwrite():
    kwargs: dict = {"annotations": {"title": "Custom Title"}}
    _inject_title(kwargs, "get_function", None)
    assert kwargs["annotations"]["title"] == "Custom Title"


def test_inject_title_creates_annotations_if_missing():
    kwargs: dict = {}
    _inject_title(kwargs, "get_function", None)
    assert kwargs["annotations"]["title"] == "Get Function"


def test_inject_title_does_not_mutate_original():
    original = {"readOnlyHint": True}
    kwargs: dict = {"annotations": original}
    _inject_title(kwargs, "get_function", None)
    # The original dict should not have been modified.
    assert "title" not in original


def test_inject_title_from_fn():
    def my_tool():
        pass

    kwargs: dict = {}
    _inject_title(kwargs, None, my_tool)
    assert kwargs["annotations"]["title"] == "My Tool"


def test_inject_title_name_takes_precedence_over_fn():
    def fallback():
        pass

    kwargs: dict = {}
    _inject_title(kwargs, "get_xrefs_to", fallback)
    assert kwargs["annotations"]["title"] == "Get Xrefs To"


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
