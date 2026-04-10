# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Unit tests for exceptions.py — processor ambiguity detection and IDAError.

These tests cover check_processor_ambiguity and PRIMARY_IDB_EXTENSIONS —
all functions that can run without idalib.
"""

from __future__ import annotations

import json

import pytest

from ida_mcp.exceptions import (
    AMBIGUOUS_PROCESSORS,
    IDAError,
    check_processor_ambiguity,
)

# ---------------------------------------------------------------------------
# check_processor_ambiguity — should raise
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("processor", ["arm", "ARM", "Arm"])
def test_ambiguous_arm_raw_binary(tmp_path, processor):
    raw = tmp_path / "firmware.bin"
    raw.write_bytes(b"\x00" * 16)
    with pytest.raises(IDAError, match="AmbiguousProcessor"):
        check_processor_ambiguity(processor, str(raw), force_new=False)


@pytest.mark.parametrize("processor", ["metapc", "pc", "mips", "mipsl", "ppc", "riscv"])
def test_ambiguous_processors(tmp_path, processor):
    raw = tmp_path / "firmware.bin"
    raw.write_bytes(b"\x00" * 16)
    with pytest.raises(IDAError, match="AmbiguousProcessor"):
        check_processor_ambiguity(processor, str(raw), force_new=False)


def test_ambiguous_with_force_new_and_existing_db(tmp_path):
    """force_new=True should still raise even when a sidecar .i64 exists."""
    raw = tmp_path / "firmware.bin"
    raw.write_bytes(b"\x00" * 16)
    sidecar = tmp_path / "firmware.bin.i64"
    sidecar.write_bytes(b"\x00")
    with pytest.raises(IDAError):
        check_processor_ambiguity("arm", str(raw), force_new=True)


# ---------------------------------------------------------------------------
# check_processor_ambiguity — should NOT raise
# ---------------------------------------------------------------------------


def test_variant_specified(tmp_path):
    """Processor with a variant (colon) should not raise."""
    raw = tmp_path / "firmware.bin"
    raw.write_bytes(b"\x00" * 16)
    check_processor_ambiguity("arm:ARMv7-M", str(raw), force_new=False)


def test_no_processor():
    """Empty processor (auto-detect) should not raise."""
    check_processor_ambiguity("", "/some/file.bin", force_new=False)


def test_opening_existing_idb(tmp_path):
    """Opening an .i64 database should not raise regardless of processor."""
    db = tmp_path / "firmware.i64"
    db.write_bytes(b"\x00")
    check_processor_ambiguity("arm", str(db), force_new=False)


def test_opening_existing_idb_idb_ext(tmp_path):
    """Opening an .idb database should not raise."""
    db = tmp_path / "firmware.idb"
    db.write_bytes(b"\x00")
    check_processor_ambiguity("arm", str(db), force_new=False)


def test_existing_sidecar_skips_check(tmp_path):
    """When a sidecar .i64 exists and force_new=False, no ambiguity error."""
    raw = tmp_path / "firmware.bin"
    raw.write_bytes(b"\x00" * 16)
    sidecar = tmp_path / "firmware.bin.i64"
    sidecar.write_bytes(b"\x00")
    check_processor_ambiguity("arm", str(raw), force_new=False)


def test_unambiguous_processor(tmp_path):
    """A processor not in the ambiguous set should not raise."""
    raw = tmp_path / "firmware.bin"
    raw.write_bytes(b"\x00" * 16)
    check_processor_ambiguity("aarch64", str(raw), force_new=False)


# ---------------------------------------------------------------------------
# AMBIGUOUS_PROCESSORS coverage
# ---------------------------------------------------------------------------


def test_all_ambiguous_processors_have_hints():
    """Every entry in AMBIGUOUS_PROCESSORS should have a non-empty hint."""
    for proc, hint in AMBIGUOUS_PROCESSORS.items():
        assert isinstance(hint, str) and len(hint) > 0, f"{proc} has empty hint"


# ---------------------------------------------------------------------------
# IDAError
# ---------------------------------------------------------------------------


def test_ida_error_str_json():
    err = IDAError("something failed", error_type="TestError")
    parsed = json.loads(str(err))
    assert parsed["error"] == "something failed"
    assert parsed["error_type"] == "TestError"


def test_ida_error_with_details():
    err = IDAError("bad", error_type="X", valid_values=["a", "b"])
    parsed = json.loads(str(err))
    assert parsed["valid_values"] == ["a", "b"]
