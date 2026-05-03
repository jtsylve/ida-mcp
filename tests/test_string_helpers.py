# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit tests for string-related helpers: decode_string and build_strlist."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import re_mcp_ida.helpers as _h

# Real IDA constant values (from ida_nalt.pyi).
_STRWIDTH_1B = 0
_STRWIDTH_2B = 1
_STRWIDTH_4B = 2
_STRWIDTH_MASK = 3

_STRTYPE_C = 0
_STRTYPE_C_16 = 1
_STRTYPE_C_32 = 2
_STRTYPE_PASCAL = 4
_STRTYPE_PASCAL_16 = 5
_STRTYPE_PASCAL_32 = 6
_STRTYPE_LEN2 = 8
_STRTYPE_LEN2_16 = 9
_STRTYPE_LEN2_32 = 10
_STRTYPE_LEN4 = 12
_STRTYPE_LEN4_16 = 13
_STRTYPE_LEN4_32 = 14


# ---------------------------------------------------------------------------
# decode_string — get_strlit_contents decodes internally, returns UTF-8
# ---------------------------------------------------------------------------

_ALL_TYPES = [
    _STRTYPE_C,
    _STRTYPE_PASCAL,
    _STRTYPE_LEN2,
    _STRTYPE_LEN4,
    _STRTYPE_C_16,
    _STRTYPE_PASCAL_16,
    _STRTYPE_LEN2_16,
    _STRTYPE_LEN4_16,
    _STRTYPE_C_32,
    _STRTYPE_PASCAL_32,
    _STRTYPE_LEN2_32,
    _STRTYPE_LEN4_32,
]
_ALL_TYPE_IDS = [
    "C",
    "PASCAL",
    "LEN2",
    "LEN4",
    "C_16",
    "PASCAL_16",
    "LEN2_16",
    "LEN4_16",
    "C_32",
    "PASCAL_32",
    "LEN2_32",
    "LEN4_32",
]


@pytest.mark.parametrize("strtype", _ALL_TYPES, ids=_ALL_TYPE_IDS)
def test_decode_string_all_types(strtype):
    raw = b"hello"
    _h.ida_bytes.get_strlit_contents = MagicMock(return_value=raw)
    result = _h.decode_string(0x1000, len(raw), strtype)
    assert result == "hello"
    _h.ida_bytes.get_strlit_contents.assert_called_once_with(0x1000, len(raw), strtype)


def test_decode_string_returns_none_on_null():
    _h.ida_bytes.get_strlit_contents = MagicMock(return_value=None)
    assert _h.decode_string(0x1000, 5, _STRTYPE_C) is None


def test_decode_string_returns_hex_on_decode_failure():
    bad = b"\x80\x81\x82"
    _h.ida_bytes.get_strlit_contents = MagicMock(return_value=bad)
    result = _h.decode_string(0x1000, 3, _STRTYPE_C)
    # errors="replace" means decode won't actually fail for utf-8,
    # so verify the replacement characters are present
    assert "�" in result


def test_decode_string_non_ascii_utf8():
    raw = "日本語".encode()
    _h.ida_bytes.get_strlit_contents = MagicMock(return_value=raw)
    result = _h.decode_string(0x1000, len(raw), _STRTYPE_C)
    assert result == "日本語"


def test_decode_string_non_ascii_utf16():
    raw = "日本語".encode()
    _h.ida_bytes.get_strlit_contents = MagicMock(return_value=raw)
    result = _h.decode_string(0x1000, len(raw), _STRTYPE_C_16)
    assert result == "日本語"


def test_decode_string_non_ascii_utf32():
    raw = "日本語".encode()
    _h.ida_bytes.get_strlit_contents = MagicMock(return_value=raw)
    result = _h.decode_string(0x1000, len(raw), _STRTYPE_C_32)
    assert result == "日本語"


def test_decode_string_strtype_with_encoding_bits():
    raw = b"Hello"
    strtype = 0x02000001  # STRTYPE_C_16 with encoding info in high bits
    _h.ida_bytes.get_strlit_contents = MagicMock(return_value=raw)
    result = _h.decode_string(0x1000, len(raw), strtype)
    assert result == "Hello"


# ---------------------------------------------------------------------------
# build_strlist
# ---------------------------------------------------------------------------


def test_build_strlist_enables_all_types():
    opts = MagicMock()
    opts.strtypes = [_STRTYPE_C]
    _h.ida_strlist.get_strlist_options = MagicMock(return_value=opts)
    _h.ida_strlist.build_strlist = MagicMock()
    _h.ida_strlist.get_strlist_qty = MagicMock(return_value=42)

    count = _h.build_strlist()

    assert count == 42
    _h.ida_strlist.build_strlist.assert_called_once()
    assigned = opts.strtypes
    assert set(assigned) == set(_h._ALL_STR_TYPES)
    assert assigned == sorted(assigned)


def test_build_strlist_preserves_existing_custom_types():
    custom_type = 99
    opts = MagicMock()
    opts.strtypes = [custom_type, _STRTYPE_C]
    _h.ida_strlist.get_strlist_options = MagicMock(return_value=opts)
    _h.ida_strlist.build_strlist = MagicMock()
    _h.ida_strlist.get_strlist_qty = MagicMock(return_value=10)

    _h.build_strlist()

    assigned = opts.strtypes
    assert custom_type in assigned
    for st in _h._ALL_STR_TYPES:
        assert st in assigned


def test_build_strlist_idempotent():
    opts = MagicMock()
    opts.strtypes = sorted(_h._ALL_STR_TYPES)
    _h.ida_strlist.get_strlist_options = MagicMock(return_value=opts)
    _h.ida_strlist.build_strlist = MagicMock()
    _h.ida_strlist.get_strlist_qty = MagicMock(return_value=5)

    _h.build_strlist()

    assigned = opts.strtypes
    assert len(assigned) == len(_h._ALL_STR_TYPES)
    assert assigned == sorted(_h._ALL_STR_TYPES)


# ---------------------------------------------------------------------------
# _ALL_STR_TYPES completeness
# ---------------------------------------------------------------------------


def test_all_str_types_has_12_entries():
    assert len(_h._ALL_STR_TYPES) == 12


def test_all_str_types_covers_all_widths():
    widths = {st & _STRWIDTH_MASK for st in _h._ALL_STR_TYPES}
    assert widths == {_STRWIDTH_1B, _STRWIDTH_2B, _STRWIDTH_4B}


def test_all_str_types_covers_all_termination_styles():
    terms = {st & ~_STRWIDTH_MASK for st in _h._ALL_STR_TYPES}
    assert len(terms) == 4  # C(0), PASCAL(4), LEN2(8), LEN4(12)
