# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Unit tests for exceptions.py — processor ambiguity detection and IDAError.

These tests cover check_processor_ambiguity, check_fat_binary,
detect_fat_slices and PRIMARY_IDB_EXTENSIONS — all functions that can
run without idalib.
"""

from __future__ import annotations

import json
import os
import struct

import pytest

from ida_mcp.exceptions import (
    AMBIGUOUS_PROCESSORS,
    IDAError,
    append_output_flag,
    build_ida_args,
    check_fat_binary,
    check_processor_ambiguity,
    detect_fat_slices,
    slice_sidecar_stem,
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


def test_processor_ambiguity_uses_slice_specific_sidecar(tmp_path):
    """fat_arch routes the stored-analysis short-circuit to the per-slice sidecar."""
    raw = tmp_path / "universal"
    raw.write_bytes(b"\x00" * 16)
    # Default sidecar doesn't exist, but a slice-specific one does.
    (tmp_path / "universal.arm64.i64").write_bytes(b"\x00")
    # With fat_arch="arm64", the slice sidecar suppresses the check —
    # stored analysis pins everything including the processor.
    check_processor_ambiguity("arm", str(raw), force_new=False, fat_arch="arm64")
    # Without fat_arch, there's no default sidecar — the check fires.
    with pytest.raises(IDAError, match="AmbiguousProcessor"):
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


# ---------------------------------------------------------------------------
# build_ida_args
# ---------------------------------------------------------------------------


def test_build_ida_args_empty():
    """No parameters produces None."""
    assert build_ida_args() is None


def test_build_ida_args_processor_only():
    assert build_ida_args(processor="arm:ARMv7-M") == "-parm:ARMv7-M"


def test_build_ida_args_loader_only():
    assert build_ida_args(loader="ELF") == "-TELF"


def test_build_ida_args_loader_with_spaces():
    """Loader names with spaces must be quoted."""
    result = build_ida_args(loader="Binary file")
    assert result == '-T"Binary file"'


def test_build_ida_args_base_address_hex():
    result = build_ida_args(base_address="0x20000")
    assert result == "-b0x2000"


def test_build_ida_args_base_address_decimal():
    result = build_ida_args(base_address="131072")
    # 131072 == 0x20000, paragraph = 0x2000
    assert result == "-b0x2000"


def test_build_ida_args_base_address_not_aligned():
    with pytest.raises(IDAError, match="not 16-byte aligned"):
        build_ida_args(base_address="0x20001")


def test_build_ida_args_base_address_invalid():
    with pytest.raises(IDAError, match="Invalid base_address"):
        build_ida_args(base_address="not_a_number")


def test_build_ida_args_all_params():
    result = build_ida_args(
        processor="arm:ARMv7-M",
        loader="Binary file",
        base_address="0x8000000",
    )
    assert result == '-parm:ARMv7-M -T"Binary file" -b0x800000'


def test_build_ida_args_options_passthrough():
    result = build_ida_args(options="-a")
    assert result == "-a"


def test_build_ida_args_combined_with_options():
    result = build_ida_args(processor="arm:ARMv7-M", options="-a")
    assert result == "-parm:ARMv7-M -a"


def test_build_ida_args_conflicting_processor_in_options():
    """options containing -p should be rejected when processor is set."""
    with pytest.raises(IDAError, match="processor"):
        build_ida_args(processor="arm:ARMv7-M", options="-pmetapc")


def test_build_ida_args_conflicting_loader_in_options():
    with pytest.raises(IDAError, match="loader"):
        build_ida_args(loader="ELF", options="-TBinary")


def test_build_ida_args_conflicting_base_in_options():
    with pytest.raises(IDAError, match="base_address"):
        build_ida_args(base_address="0x10000", options="-b0x100")


def test_build_ida_args_flag_in_options_without_structured_param():
    """Flags in options are allowed when the corresponding structured param is empty."""
    result = build_ida_args(options="-parm:ARMv7-M")
    assert result == "-parm:ARMv7-M"


def test_build_ida_args_no_false_positive_on_longer_flags():
    """Substring matches inside longer flags must not trigger conflict detection."""
    # "-p" should not match inside "--prefer-something"
    result = build_ida_args(processor="arm:ARMv7-M", options="--prefer-something")
    assert "-parm:ARMv7-M" in result
    assert "--prefer-something" in result


# ---------------------------------------------------------------------------
# Fat Mach-O detection + validation
# ---------------------------------------------------------------------------

# Mach-O cputype constants (from /usr/include/mach/machine.h).
_CPUTYPE_X86_64 = 0x01000007
_CPUTYPE_ARM64 = 0x0100000C
_CPUTYPE_ARM = 12
_CPU_SUBTYPE_ARM_V7 = 9
_CPU_SUBTYPE_ARM64_E = 2


def _write_fat_header(
    path,
    slices: list[tuple[int, int]],
    *,
    magic: int = 0xCAFEBABE,
) -> None:
    """Write a minimal fat Mach-O header (no slice payloads) to *path*.

    *slices* is a list of (cputype, cpusubtype) tuples.
    """
    data = bytearray(struct.pack(">II", magic, len(slices)))
    for cputype, cpusubtype in slices:
        if magic == 0xCAFEBABE:
            # cputype, cpusubtype, offset, size, align
            data += struct.pack(">IIIII", cputype, cpusubtype, 0x1000, 0x1000, 12)
        else:
            # cputype, cpusubtype, offset (u64), size (u64), align, reserved
            data += struct.pack(">IIQQII", cputype, cpusubtype, 0x1000, 0x1000, 12, 0)
    path.write_bytes(bytes(data))


# detect_fat_slices ---------------------------------------------------------


def test_detect_fat_slices_fat_magic_32(tmp_path):
    fat = tmp_path / "universal"
    _write_fat_header(fat, [(_CPUTYPE_X86_64, 3), (_CPUTYPE_ARM64, 0)])
    assert detect_fat_slices(str(fat)) == ["x86_64", "arm64"]


def test_detect_fat_slices_fat_magic_64(tmp_path):
    fat = tmp_path / "universal64"
    _write_fat_header(fat, [(_CPUTYPE_X86_64, 3), (_CPUTYPE_ARM64, 0)], magic=0xCAFEBABF)
    assert detect_fat_slices(str(fat)) == ["x86_64", "arm64"]


def test_detect_fat_slices_arm_subtype_refinement(tmp_path):
    """arm64e and armv7 should surface via cpusubtype refinement."""
    fat = tmp_path / "refined"
    _write_fat_header(
        fat,
        [
            (_CPUTYPE_ARM64, _CPU_SUBTYPE_ARM64_E),
            (_CPUTYPE_ARM, _CPU_SUBTYPE_ARM_V7),
        ],
    )
    assert detect_fat_slices(str(fat)) == ["arm64e", "armv7"]


def test_detect_fat_slices_thin_file(tmp_path):
    """A non-fat file returns None."""
    thin = tmp_path / "thin.bin"
    thin.write_bytes(b"\x00" * 64)
    assert detect_fat_slices(str(thin)) is None


def test_detect_fat_slices_java_class_file(tmp_path):
    """Java .class files share CAFEBABE magic but have a huge nfat_arch.

    The parser must reject them — either via the 32-slice sanity cap or
    because their "cpu type" field doesn't match any known Mach-O arch.
    """
    java = tmp_path / "Foo.class"
    # CAFEBABE + minor(0) << 16 | major(65) → typical Java class header.
    # nfat_arch reads as 0x00000041 = 65 → caught by _MAX_FAT_SLICES cap.
    java.write_bytes(bytes.fromhex("cafebabe00000041") + b"\x00" * 32)
    assert detect_fat_slices(str(java)) is None


def test_detect_fat_slices_nonexistent_path(tmp_path):
    """Missing file → None, no exception."""
    assert detect_fat_slices(str(tmp_path / "does_not_exist")) is None


def test_detect_fat_slices_unknown_cputype_rejected(tmp_path):
    """Valid fat header but with a nonsense cputype is treated as not-fat."""
    fat = tmp_path / "weird"
    # 0x99 is not a valid Mach-O base cputype.
    _write_fat_header(fat, [(0x99, 0)])
    assert detect_fat_slices(str(fat)) is None


def test_detect_fat_slices_truncated(tmp_path):
    """Header claims 2 slices but the file only contains 1 — return None."""
    fat = tmp_path / "truncated"
    # nfat_arch=2 but only one entry's worth of data follows.
    data = struct.pack(">II", 0xCAFEBABE, 2)
    data += struct.pack(">IIIII", _CPUTYPE_X86_64, 3, 0x1000, 0x1000, 12)
    fat.write_bytes(data)
    assert detect_fat_slices(str(fat)) is None


# check_fat_binary ----------------------------------------------------------


def test_check_fat_binary_ambiguous(tmp_path):
    fat = tmp_path / "universal"
    _write_fat_header(fat, [(_CPUTYPE_X86_64, 3), (_CPUTYPE_ARM64, 0)])
    with pytest.raises(IDAError, match="AmbiguousFatBinary") as exc:
        check_fat_binary(str(fat), fat_arch="", force_new=False)
    payload = json.loads(str(exc.value))
    assert payload["error_type"] == "AmbiguousFatBinary"
    assert payload["available"] == ["x86_64", "arm64"]


def test_check_fat_binary_valid_arch_returns_index(tmp_path):
    """A valid fat_arch returns its 1-based slice index."""
    fat = tmp_path / "universal"
    _write_fat_header(
        fat,
        [
            (_CPUTYPE_X86_64, 3),
            (_CPUTYPE_ARM64, 0),
            (_CPUTYPE_ARM64, _CPU_SUBTYPE_ARM64_E),
        ],
    )
    # Slice index is 1-based, in on-disk header order — IDA's -T flag
    # references slices by this index.
    assert check_fat_binary(str(fat), fat_arch="x86_64", force_new=False) == 1
    assert check_fat_binary(str(fat), fat_arch="arm64", force_new=False) == 2
    assert check_fat_binary(str(fat), fat_arch="arm64e", force_new=False) == 3


def test_check_fat_binary_unknown_arch(tmp_path):
    fat = tmp_path / "universal"
    _write_fat_header(fat, [(_CPUTYPE_X86_64, 3), (_CPUTYPE_ARM64, 0)])
    with pytest.raises(IDAError, match="UnknownFatArch") as exc:
        check_fat_binary(str(fat), fat_arch="mips", force_new=False)
    payload = json.loads(str(exc.value))
    assert payload["error_type"] == "UnknownFatArch"
    assert payload["available"] == ["x86_64", "arm64"]


def test_check_fat_binary_rejects_duplicate_slice_names(tmp_path):
    """Two slices that resolve to the same lipo-style name are rejected.

    Hand-crafted header with two arm64 entries (different cpusubtypes that
    both collapse to ``arm64``).  ``slices.index(fat_arch)`` would silently
    pick the first match and hand IDA an index the user may not have
    intended, so ``check_fat_binary`` raises ``DuplicateFatSlice`` up front
    instead.  No ``lipo``-produced file hits this case, but malformed or
    hand-crafted fat headers can.
    """
    fat = tmp_path / "weird"
    # Two ARM64 entries with subtypes that are NOT in _CPU_SUBTYPE_NAMES
    # (so both fall through to the bare "arm64" name).  Subtype 0 is
    # ALL, subtype 100 is unknown — neither matches ARM64E (2).
    _write_fat_header(fat, [(_CPUTYPE_ARM64, 0), (_CPUTYPE_ARM64, 100)])
    # The check must fail regardless of whether fat_arch is set — the
    # file is structurally ambiguous and unusable either way.
    with pytest.raises(IDAError, match="DuplicateFatSlice") as exc:
        check_fat_binary(str(fat), fat_arch="arm64", force_new=False)
    payload = json.loads(str(exc.value))
    assert payload["error_type"] == "DuplicateFatSlice"
    assert payload["available"] == ["arm64", "arm64"]
    assert payload["duplicates"] == ["arm64"]

    with pytest.raises(IDAError, match="DuplicateFatSlice"):
        check_fat_binary(str(fat), fat_arch="", force_new=False)


def test_check_fat_binary_reports_each_duplicate_once(tmp_path):
    """Multiple distinct duplicates are listed once each, not repeated."""
    fat = tmp_path / "weirder"
    # Three arm64 entries — the duplicate list should contain ``arm64``
    # once, not twice.
    _write_fat_header(
        fat,
        [
            (_CPUTYPE_ARM64, 0),
            (_CPUTYPE_ARM64, 100),
            (_CPUTYPE_ARM64, 101),
            (_CPUTYPE_X86_64, 3),
        ],
    )
    with pytest.raises(IDAError, match="DuplicateFatSlice") as exc:
        check_fat_binary(str(fat), fat_arch="arm64", force_new=False)
    payload = json.loads(str(exc.value))
    assert payload["duplicates"] == ["arm64"]
    assert payload["available"] == ["arm64", "arm64", "arm64", "x86_64"]


def test_check_fat_binary_idb_short_circuits(tmp_path):
    """Opening an existing .i64 database returns None (no -T flag needed)."""
    db = tmp_path / "thing.i64"
    # Intentionally write a valid fat header to the .i64 — the check
    # should still return None because the extension takes precedence
    # (IDA reuses the stored slice).
    _write_fat_header(db, [(_CPUTYPE_X86_64, 3), (_CPUTYPE_ARM64, 0)])
    assert check_fat_binary(str(db), fat_arch="", force_new=False) is None


def test_check_fat_binary_idb_with_fat_arch_raises(tmp_path):
    """Passing fat_arch alongside an explicit .i64/.idb path is rejected.

    The stored database already pins a slice — accepting fat_arch would
    either be contradictory (stored analysis for a different slice) or
    redundant (same slice).  Fail fast with InvalidArgument so the user
    cannot expect a slice swap that is not going to happen.
    """
    db = tmp_path / "thing.i64"
    _write_fat_header(db, [(_CPUTYPE_X86_64, 3), (_CPUTYPE_ARM64, 0)])
    with pytest.raises(IDAError, match="InvalidArgument") as exc:
        check_fat_binary(str(db), fat_arch="arm64", force_new=False)
    payload = json.loads(str(exc.value))
    assert payload["error_type"] == "InvalidArgument"
    assert "existing IDA database" in payload["error"]

    # Same for .idb extension.
    db_idb = tmp_path / "thing.idb"
    db_idb.write_bytes(b"\x00")
    with pytest.raises(IDAError, match="InvalidArgument"):
        check_fat_binary(str(db_idb), fat_arch="x86_64", force_new=False)


def test_check_fat_binary_symlink_to_idb_with_fat_arch_raises(tmp_path):
    """A symlink-without-extension pointing at an ``.i64`` is still rejected.

    Fail-fast parity with :meth:`session.Session.open`: the supervisor
    path must catch the same mistake that session.open does, otherwise a
    symlink name like ``./shortcut`` → ``real.i64`` combined with
    ``fat_arch=arm64`` would slip past the fail-fast check and only error
    later inside the worker.  ``check_fat_binary`` resolves the symlink
    up front so the extension-based guard sees the real target.
    """
    db = tmp_path / "thing.i64"
    db.write_bytes(b"\x00")
    link = tmp_path / "shortcut"  # No extension — extension guard would miss
    link.symlink_to(db)
    with pytest.raises(IDAError, match="InvalidArgument") as exc:
        check_fat_binary(str(link), fat_arch="arm64", force_new=False)
    payload = json.loads(str(exc.value))
    assert payload["error_type"] == "InvalidArgument"
    assert "existing IDA database" in payload["error"]


def test_check_fat_binary_symlink_to_idb_without_fat_arch_short_circuits(tmp_path):
    """A symlink-without-extension pointing at an ``.i64`` is treated as stored."""
    db = tmp_path / "thing.i64"
    db.write_bytes(b"\x00")
    link = tmp_path / "shortcut"
    link.symlink_to(db)
    assert check_fat_binary(str(link), fat_arch="", force_new=False) is None


def test_check_fat_binary_slice_specific_sidecar_short_circuits(tmp_path):
    """A per-slice sidecar (foo.arm64.i64) short-circuits the check for that slice."""
    fat = tmp_path / "universal"
    _write_fat_header(fat, [(_CPUTYPE_X86_64, 3), (_CPUTYPE_ARM64, 0)])
    # Stored analysis for the arm64 slice lives at the suffixed path
    # so other slices remain distinct on disk.
    (tmp_path / "universal.arm64.i64").write_bytes(b"\x00")
    # arm64 short-circuits — stored analysis pins the slice.
    assert check_fat_binary(str(fat), fat_arch="arm64", force_new=False) is None
    # x86_64 does NOT short-circuit — different slice, different sidecar.
    assert check_fat_binary(str(fat), fat_arch="x86_64", force_new=False) == 1


def test_check_fat_binary_default_sidecar_does_not_short_circuit_slice_open(tmp_path):
    """A default sidecar (foo.i64) must not hide a slice-specific check."""
    fat = tmp_path / "universal"
    _write_fat_header(fat, [(_CPUTYPE_X86_64, 3), (_CPUTYPE_ARM64, 0)])
    # Default sidecar exists — it represents a prior open of the default
    # (slice 1) analysis.  A new call with fat_arch="arm64" must
    # recognize that no arm64-specific sidecar exists yet and return
    # the arm64 slice index so session.open can create one.
    (tmp_path / "universal.i64").write_bytes(b"\x00")
    assert check_fat_binary(str(fat), fat_arch="arm64", force_new=False) == 2


def test_check_fat_binary_default_sidecar_short_circuits_default_open(tmp_path):
    """Opening a fat binary without fat_arch reuses the default sidecar."""
    fat = tmp_path / "universal"
    _write_fat_header(fat, [(_CPUTYPE_X86_64, 3), (_CPUTYPE_ARM64, 0)])
    (tmp_path / "universal.i64").write_bytes(b"\x00")
    # No fat_arch + default sidecar exists → None (reuse).
    assert check_fat_binary(str(fat), fat_arch="", force_new=False) is None


def test_check_fat_binary_force_new_still_checks(tmp_path):
    """force_new=True should still fail-fast on a fat binary."""
    fat = tmp_path / "universal"
    _write_fat_header(fat, [(_CPUTYPE_X86_64, 3), (_CPUTYPE_ARM64, 0)])
    (tmp_path / "universal.i64").write_bytes(b"\x00")
    with pytest.raises(IDAError, match="AmbiguousFatBinary"):
        check_fat_binary(str(fat), fat_arch="", force_new=True)


def test_check_fat_binary_force_new_on_slice_with_sidecar(tmp_path):
    """force_new=True ignores a slice-specific sidecar and re-validates."""
    fat = tmp_path / "universal"
    _write_fat_header(fat, [(_CPUTYPE_X86_64, 3), (_CPUTYPE_ARM64, 0)])
    (tmp_path / "universal.arm64.i64").write_bytes(b"\x00")
    # Even though the sidecar exists, force_new forces re-parsing and
    # returns the slice index so session.open creates it fresh.
    assert check_fat_binary(str(fat), fat_arch="arm64", force_new=True) == 2


def test_check_fat_binary_thin_file_noop(tmp_path):
    """Thin (non-fat) files return None when no fat_arch is requested
    — check_fat_binary is a no-op for ELF, PE, and raw binaries."""
    thin = tmp_path / "thin.bin"
    thin.write_bytes(b"\x00" * 64)
    assert check_fat_binary(str(thin), fat_arch="", force_new=False) is None


def test_check_fat_binary_thin_file_with_fat_arch_raises(tmp_path):
    """fat_arch set on a non-fat file raises InvalidArgument.

    Silently ignoring would let a typo (``fat_arch="arm64"`` on an ELF,
    or on a raw firmware blob) slip through and produce a confusingly
    suffixed sidecar on disk.  Surfacing the error makes the mistake
    immediate.
    """
    thin = tmp_path / "thin.bin"
    thin.write_bytes(b"\x00" * 64)
    with pytest.raises(IDAError, match="InvalidArgument") as exc:
        check_fat_binary(str(thin), fat_arch="arm64", force_new=False)
    payload = json.loads(str(exc.value))
    assert payload["error_type"] == "InvalidArgument"
    assert "is not a Mach-O fat" in payload["error"]


# slice_sidecar_stem --------------------------------------------------------


def test_slice_sidecar_stem_default(tmp_path):
    """Without fat_arch, the stem is the realpath'd binary path."""
    raw = tmp_path / "firmware.bin"
    # realpath() because pytest's tmp_path on macOS is under /var -> /private/var.
    expected = os.path.realpath(str(raw))
    assert slice_sidecar_stem(str(raw)) == expected


def test_slice_sidecar_stem_with_fat_arch(tmp_path):
    """With fat_arch, the stem gets a slice suffix for per-slice sidecars."""
    raw = tmp_path / "universal"
    expected = f"{os.path.realpath(str(raw))}.arm64"
    assert slice_sidecar_stem(str(raw), "arm64") == expected


def test_slice_sidecar_stem_idb_path_ignores_fat_arch(tmp_path):
    """An .i64 / .idb input pins a slice — fat_arch is dropped and the
    stem is the path with the extension stripped."""
    db = tmp_path / "universal.arm64.i64"
    expected = os.path.splitext(os.path.realpath(str(db)))[0]
    assert slice_sidecar_stem(str(db)) == expected
    assert slice_sidecar_stem(str(db), fat_arch="x86_64") == expected


def test_slice_sidecar_stem_resolves_symlink(tmp_path):
    """Symlinks collapse to the real file — matches _canonical_path dedup."""
    real = tmp_path / "real_binary"
    real.write_bytes(b"\x00")
    link = tmp_path / "link"
    link.symlink_to(real)
    assert slice_sidecar_stem(str(link)) == slice_sidecar_stem(str(real))
    assert slice_sidecar_stem(str(link), "arm64") == slice_sidecar_stem(str(real), "arm64")


# build_ida_args + fat_slice_index ------------------------------------------


def test_build_ida_args_fat_slice_index_emits_fat_macho_loader():
    """fat_slice_index emits -T"Fat Mach-O file, <N>" — IDA's only
    documented way to pick a slice in headless mode."""
    assert build_ida_args(fat_slice_index=2) == '-T"Fat Mach-O file, 2"'


def test_build_ida_args_fat_slice_index_rejects_explicit_loader():
    """loader and fat_slice_index both map to -T — reject the combination."""
    with pytest.raises(IDAError, match="loader and fat_arch"):
        build_ida_args(loader="Binary file", fat_slice_index=2)


def test_build_ida_args_fat_slice_index_combined():
    """fat_slice_index composes with processor and base_address in the usual order."""
    # processor is typically auto-detected for Mach-O, but pinning it
    # shouldn't conflict with the fat loader selection.
    result = build_ida_args(
        processor="arm:ARMv8-A",
        fat_slice_index=2,
        base_address="0x100000000",
    )
    # -b emits in paragraphs (addr >> 4), so 0x100000000 → 0x10000000.
    assert result == '-parm:ARMv8-A -T"Fat Mach-O file, 2" -b0x10000000'


def test_build_ida_args_fat_slice_index_rejects_t_in_options():
    """Even without an explicit loader, -T in options conflicts with fat_slice_index."""
    with pytest.raises(IDAError, match="loader"):
        build_ida_args(fat_slice_index=2, options="-TELF")


def test_build_ida_args_fat_slice_index_large_number():
    """Large fat indices (up to the 32-slice cap) format correctly."""
    assert build_ida_args(fat_slice_index=10) == '-T"Fat Mach-O file, 10"'


# build_ida_args — -o is reserved for Session.open's sidecar redirection
# -----------------------------------------------------------------------


def test_build_ida_args_rejects_dash_o_in_options():
    """``-o`` is reserved for Session.open's sidecar redirection."""
    with pytest.raises(IDAError, match="-o"):
        build_ida_args(options="-omycustom.i64")


def test_build_ida_args_rejects_dash_o_after_whitespace():
    """``-o`` is caught even when preceded by another flag."""
    with pytest.raises(IDAError, match="-o"):
        build_ida_args(options="--some-other-flag -omycustom.i64")


def test_build_ida_args_rejects_dash_o_with_fat_slice_index():
    """The -o reject fires before Session.open appends its own -o<stem>."""
    with pytest.raises(IDAError, match="-o"):
        build_ida_args(fat_slice_index=2, options="-osomewhere")


def test_build_ida_args_dash_o_check_no_false_positive_on_long_option():
    """``--no-output`` contains ``-o`` but the anchor skips it."""
    result = build_ida_args(options="--no-output")
    assert result == "--no-output"


# append_output_flag --------------------------------------------------------


def test_append_output_flag_none_options():
    """``None`` options yields just the -o flag."""
    assert append_output_flag(None, "/tmp/foo.arm64") == "-o/tmp/foo.arm64"


def test_append_output_flag_empty_options():
    """Empty-string options yields just the -o flag."""
    assert append_output_flag("", "/tmp/foo.arm64") == "-o/tmp/foo.arm64"


def test_append_output_flag_all_whitespace_options():
    """All-whitespace options is treated the same as empty — no double space."""
    assert append_output_flag("   ", "/tmp/foo.arm64") == "-o/tmp/foo.arm64"


def test_append_output_flag_normal_options():
    """Normal options get a single separator space before the -o flag."""
    assert append_output_flag("-parm:ARMv8-A", "/tmp/foo.arm64") == "-parm:ARMv8-A -o/tmp/foo.arm64"


def test_append_output_flag_strips_trailing_whitespace():
    """Trailing whitespace in options must not produce a double space.

    Regression guard: concatenating ``'-parm '`` and ``' -o...'`` with a
    space separator would yield ``'-parm  -o...'``.  Harmless for IDA's
    parser but ugly in debug logs, and this helper should normalize it.
    """
    assert (
        append_output_flag("-parm:ARMv8-A ", "/tmp/foo.arm64") == "-parm:ARMv8-A -o/tmp/foo.arm64"
    )
    # Leading whitespace is stripped too, for symmetry.
    assert (
        append_output_flag("   -parm:ARMv8-A   ", "/tmp/foo.arm64")
        == "-parm:ARMv8-A -o/tmp/foo.arm64"
    )


def test_append_output_flag_quotes_path_with_spaces():
    """Paths containing spaces are double-quoted via quote_ida_arg."""
    result = append_output_flag(None, "/tmp/my stem.arm64")
    assert result == '-o"/tmp/my stem.arm64"'


def test_append_output_flag_quotes_path_with_spaces_and_options():
    """Stem quoting composes correctly with a non-empty options string."""
    result = append_output_flag("-parm:ARMv8-A", "/tmp/my stem.arm64")
    assert result == '-parm:ARMv8-A -o"/tmp/my stem.arm64"'
