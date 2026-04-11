# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""IDA MCP error types and idalib-safe validation.

Separated from ``helpers`` so that modules which cannot load idalib (e.g.
the supervisor process) can still raise structured errors and validate
parameters before spawning worker processes.
"""

from __future__ import annotations

import json
import os
import re
import struct
from collections import Counter

# ToolError is not re-exported from the top-level fastmcp package as of v3.1;
# if FastMCP reorganizes its internals this import path may need updating.
from fastmcp.exceptions import ToolError


class IDAError(ToolError):
    """Raised when an IDA operation fails.

    Subclasses ``ToolError`` so fastmcp automatically returns ``isError=True``
    with the message as text content.  The *error_type* attribute preserves the
    existing error taxonomy (e.g. ``InvalidAddress``, ``NotFound``).

    Optional *details* carry structured context (valid values, available names,
    etc.).  ``__str__`` returns a JSON object so the MCP error text is
    machine-parseable — the supervisor's ``parse_result`` decodes it
    transparently.
    """

    def __init__(self, message: str, error_type: str = "Error", **details: object):
        super().__init__(message)
        self.error_type = error_type
        self.details = details

    def __str__(self) -> str:
        d: dict[str, object] = {"error": self.args[0], "error_type": self.error_type}
        if self.details:
            d.update(self.details)
        return json.dumps(d, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Primary IDA database extensions
# ---------------------------------------------------------------------------

PRIMARY_IDB_EXTENSIONS: frozenset[str] = frozenset((".i64", ".idb"))


# ---------------------------------------------------------------------------
# Processor ambiguity detection
# ---------------------------------------------------------------------------


def _bitness_ambiguity_hint(name: str, description: str) -> str:
    """Build a standard hint for processors with ambiguous bitness on raw binaries."""
    return (
        f'"{name}" {description} that cannot be auto-detected for raw binaries.  '
        "In IDA's GUI a dialog prompts for the mode; headless mode picks a "
        "default that may be wrong.  Use list_targets and pass a specific "
        "variant via the processor parameter (processor:variant) or set "
        "bitness after opening."
    )


_X86_VARIANTS = (
    "  metapc:8086     — 16-bit real mode\n"
    "  metapc:80386p   — 32-bit protected mode\n"
    "  metapc:80386r   — 32-bit real mode\n"
    "  metapc:80486p   — 32-bit protected (486+)"
)


AMBIGUOUS_PROCESSORS: dict[str, str] = {
    "arm": (
        '"arm" is ambiguous for raw binaries — it defaults to AArch64 '
        "(64-bit) in headless mode.  Use a specific variant:\n"
        "  arm:ARMv7-M    — Cortex-M (32-bit Thumb-2)\n"
        "  arm:ARMv7-A    — 32-bit A-profile\n"
        "  arm:ARMv7-R    — 32-bit R-profile\n"
        "  arm:ARMv8-M    — ARMv8-M (32-bit)\n"
        "  arm:ARMv8-A    — ARMv8 A-profile (32-bit)\n"
        "  arm:ARMv9-A    — ARMv9 A-profile (32-bit)\n"
        'For 64-bit ARM, use "aarch64" as the processor.'
    ),
    "metapc": (
        '"metapc" supports 16-bit, 32-bit, and 64-bit x86 modes.  '
        "For raw binaries IDA cannot auto-detect the mode.  "
        f"Use a variant to select:\n{_X86_VARIANTS}\n"
        'For 64-bit x86, the default may work or try "metapc:Pentium 4".'
    ),
    "pc": (
        '"pc" supports 16-bit, 32-bit, and 64-bit x86 modes.  '
        "For raw binaries IDA cannot auto-detect the mode.  "
        f"Use a variant to select:\n{_X86_VARIANTS}\n"
        'The canonical processor name is "metapc", not "pc".'
    ),
    "mips": _bitness_ambiguity_hint("mips", "has 32-bit and 64-bit modes"),
    "mipsl": _bitness_ambiguity_hint("mipsl", "(MIPS little-endian) has 32-bit and 64-bit modes"),
    "ppc": _bitness_ambiguity_hint("ppc", "has 32-bit and 64-bit modes"),
    "riscv": _bitness_ambiguity_hint("riscv", "has 32-bit (RV32) and 64-bit (RV64) modes"),
}


def slice_sidecar_stem(file_path: str, fat_arch: str = "") -> str:
    """Return the stored-database stem for *file_path* / *fat_arch*.

    For a raw binary ``foo`` with no *fat_arch* the stem is ``foo`` and
    IDA's sidecars live at ``foo.i64`` / ``foo.id0`` / ...  When
    *fat_arch* is set, per-slice sidecars are kept under a slice-suffixed
    stem (``foo.arm64``) so multiple architectures from the same
    universal binary can coexist on disk.  When *file_path* is itself
    an ``.i64`` / ``.idb``, the stem is the path with the extension
    stripped — *fat_arch* is ignored because the stored DB already pins
    the slice.

    Uses :func:`os.path.realpath` (not just ``abspath``) so that two
    symlinks pointing at the same binary produce the same stem, keeping
    this in lock-step with :func:`worker_provider._canonical_path`'s
    dedup key.
    """
    resolved = os.path.realpath(os.path.expanduser(file_path))
    base, ext = os.path.splitext(resolved)
    if ext.lower() in PRIMARY_IDB_EXTENSIONS:
        return base
    if fat_arch:
        return f"{resolved}.{fat_arch}"
    return resolved


def _has_stored_analysis(file_path: str, force_new: bool, fat_arch: str = "") -> bool:
    """True if opening *file_path* will reuse an existing IDA database.

    Either *file_path* itself is an ``.i64``/``.idb``, or (when
    ``force_new`` is False) there's a sidecar database at the expected
    stored location that IDA will pick up.  When *fat_arch* is set the
    check targets the slice-specific sidecar (``foo.arm64.i64``), so
    different slices of the same fat binary are tracked independently.
    Callers skip their fail-fast validation in either case since the
    stored analysis already pins the answer.
    """
    _, ext = os.path.splitext(file_path)
    if ext.lower() in PRIMARY_IDB_EXTENSIONS:
        return True
    if force_new:
        return False
    stem = slice_sidecar_stem(file_path, fat_arch)
    return any(os.path.isfile(stem + db_ext) for db_ext in PRIMARY_IDB_EXTENSIONS)


def check_processor_ambiguity(
    processor: str, file_path: str, force_new: bool, fat_arch: str = ""
) -> None:
    """Raise :class:`IDAError` if *processor* is ambiguous for a raw binary.

    Processors like ``arm`` and ``metapc`` support multiple bitness modes.
    For structured formats (ELF, PE, ...) IDA reads the bitness from file
    headers, but for raw binaries it shows an interactive dialog — which
    is suppressed in headless mode, silently picking a (often wrong) default.

    *fat_arch* is plumbed through so the stored-analysis short-circuit
    finds the slice-specific sidecar (``foo.arm64.i64``) rather than the
    default one.
    """
    if not processor or ":" in processor:
        return  # Auto-detect or variant already specified.

    if _has_stored_analysis(file_path, force_new, fat_arch):
        return

    hint = AMBIGUOUS_PROCESSORS.get(processor.lower())
    if hint:
        raise IDAError(hint, error_type="AmbiguousProcessor")


# ---------------------------------------------------------------------------
# IDA command-line args builder (idalib-safe)
# ---------------------------------------------------------------------------


def quote_ida_arg(value: str) -> str:
    """Double-quote *value* if it contains whitespace.

    IDA's C-level arg parser understands ``"double quoted"`` values but
    not POSIX single quotes; paths / loader names with spaces must be
    wrapped before being concatenated into the ``-T`` / ``-o`` / ...
    flags handed to ``idapro.open_database``.
    """
    return f'"{value}"' if " " in value else value


def append_output_flag(options: str | None, target_stem: str) -> str:
    """Return *options* with a ``-o<target_stem>`` flag appended.

    Used for a first-time fat-slice open in :meth:`session.Session.open`:
    IDA writes the new ``.i64`` at ``target_stem.i64`` instead of the
    default stem-alongside-input location.  ``options`` is stripped
    before concatenation so a trailing space in the caller-supplied
    string does not produce a double space in the final args — harmless
    for IDA's parser but unsightly in debug logs.  ``None`` and
    all-whitespace inputs are treated the same as the empty string.
    """
    flag = f"-o{quote_ida_arg(target_stem)}"
    if options is None:
        return flag
    stripped = options.strip()
    if not stripped:
        return flag
    return f"{stripped} {flag}"


def build_ida_args(
    *,
    processor: str = "",
    loader: str = "",
    base_address: str = "",
    fat_slice_index: int | None = None,
    options: str = "",
) -> str | None:
    """Build an IDA command-line args string from structured parameters.

    Returns ``None`` when no arguments are needed.  Raises :class:`IDAError`
    on invalid *base_address*, on a *loader* / *fat_slice_index* conflict,
    or when *options* duplicates a flag that is already provided by a
    structured parameter.  ``-o`` is also reserved — :meth:`Session.open`
    owns it for fresh fat-slice sidecar redirection.

    When *fat_slice_index* is set it overrides *loader*: IDA's ``-T``
    flag is emitted as ``-T"Fat Mach-O file, <index>"``, which is the
    only documented way to pick a specific slice of a Mach-O universal
    binary in headless mode.  The slice index is 1-based, in the order
    the slices appear in the on-disk fat header.  *loader* and
    *fat_slice_index* both use ``-T`` under the hood, so callers must
    pick one — setting both raises ``InvalidArgument``.
    """
    if fat_slice_index is not None and loader:
        raise IDAError(
            "loader and fat_arch cannot both be specified — both map to "
            "IDA's -T flag, and fat_arch selects the Fat Mach-O slice "
            "loader implicitly.",
            error_type="InvalidArgument",
        )

    # When a fat slice is requested, the ``-T`` value is a synthetic
    # loader name built from the slice index.  Otherwise use the
    # caller-provided loader string (possibly empty).
    if fat_slice_index is not None:
        effective_loader = f"Fat Mach-O file, {fat_slice_index}"
    else:
        effective_loader = loader

    # Reject options that duplicate a structured parameter already in use.
    # Match flags only at the start of the string or after whitespace to
    # avoid false positives on longer flags (e.g. "-p" inside "--prefer").
    # ``-o`` is reserved unconditionally — owned by Session.open's
    # per-slice sidecar redirect.
    if options:
        for flag, value, param_name in (
            ("-p", processor, "processor"),
            ("-T", effective_loader, "loader"),
            ("-b", base_address, "base_address"),
        ):
            if value and re.search(rf"(?:^|\s){re.escape(flag)}", options):
                raise IDAError(
                    f"options contains '{flag}' — use the {param_name} parameter instead "
                    f"of passing '{flag}' in options to avoid duplicate flags.",
                    error_type="InvalidArgument",
                )
        if re.search(r"(?:^|\s)-o", options):
            raise IDAError(
                "options contains '-o' — the -o<stem> flag is reserved "
                "for Session.open's per-slice sidecar redirection and "
                "must not be passed through the options parameter.",
                error_type="InvalidArgument",
            )

    args_parts: list[str] = []
    if processor:
        args_parts.append(f"-p{processor}")
    if effective_loader:
        args_parts.append(f"-T{quote_ida_arg(effective_loader)}")
    if base_address:
        try:
            addr = int(base_address, 0)
        except ValueError:
            raise IDAError(
                f"Invalid base_address: {base_address!r}. "
                "Provide a hex (0x...) or decimal integer.",
                error_type="InvalidArgument",
            ) from None
        if addr & 0xF:
            raise IDAError(
                f"base_address {base_address} is not 16-byte aligned. "
                "IDA requires paragraph alignment (multiple of 0x10).",
                error_type="InvalidArgument",
            )
        args_parts.append(f"-b{addr >> 4:#x}")
    if options:
        args_parts.append(options)
    return " ".join(args_parts) or None


# ---------------------------------------------------------------------------
# Mach-O fat binary detection (idalib-safe)
# ---------------------------------------------------------------------------

# Big-endian magics that appear on disk for Mach-O universal binaries.
# FAT_MAGIC uses 32-bit offsets; FAT_MAGIC_64 uses 64-bit offsets.  The
# "swapped" forms (BEBAFECA / BFBAFECA) are only produced on byte-swapping
# hosts and never appear in on-disk files.
_FAT_MAGIC = 0xCAFEBABE
_FAT_MAGIC_64 = 0xCAFEBABF

# Cap the number of slices we'll accept in a fat header.  Real fat
# binaries almost never exceed a handful of architectures; a large
# nfat_arch is a strong signal the file is a Java ``.class`` (which
# shares the CAFEBABE magic but stores a version number next).
_MAX_FAT_SLICES = 32

# Mach-O cputype constants.  The CPU_ARCH_ABI64 bit (0x01000000) flags
# 64-bit variants, CPU_ARCH_ABI64_32 (0x02000000) flags ILP32 on 64-bit
# (arm64_32).  See /usr/include/mach/machine.h.
_CPU_TYPE_NAMES: dict[int, str] = {
    7: "i386",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "arm64",
    0x0200000C: "arm64_32",
    18: "ppc",
    0x01000012: "ppc64",
}

# XNU's CPU_SUBTYPE_MASK (see ``mach/machine.h``) covers the top 8 bits
# of the cpusubtype field, where feature flags live — the low 24 bits
# hold the actual subtype identifier (e.g. CPU_SUBTYPE_ARM64E).  Named
# to match the XNU header so readers can grep across both sources.
_CPU_SUBTYPE_MASK = 0xFF000000

# Well-known cpusubtype refinements we want to surface as distinct names,
# matching lipo(1)'s output.  Key is (cputype, cpusubtype & mask).
_CPU_SUBTYPE_NAMES: dict[tuple[int, int], str] = {
    (0x01000007, 8): "x86_64h",  # CPU_SUBTYPE_X86_64_H (Haswell)
    (0x0100000C, 2): "arm64e",  # CPU_SUBTYPE_ARM64E
    (12, 9): "armv7",  # CPU_SUBTYPE_ARM_V7
    (12, 11): "armv7s",  # CPU_SUBTYPE_ARM_V7S
    (12, 12): "armv7k",  # CPU_SUBTYPE_ARM_V7K
    (12, 6): "armv6",  # CPU_SUBTYPE_ARM_V6
}


def _fat_slice_name(cputype: int, cpusubtype: int) -> str | None:
    """Resolve a (cputype, cpusubtype) pair to a human-readable slice name.

    Returns ``None`` when the cputype is not a recognised Mach-O arch —
    the caller treats that as "this is not a fat Mach-O" and bails out.
    This is the Java ``.class`` defence: unknown cputypes fall through
    rather than being wrapped in a synthetic name.
    """
    if cputype not in _CPU_TYPE_NAMES:
        return None
    sub = cpusubtype & ~_CPU_SUBTYPE_MASK
    return _CPU_SUBTYPE_NAMES.get((cputype, sub)) or _CPU_TYPE_NAMES[cputype]


def detect_fat_slices(file_path: str) -> list[str] | None:
    """Return the list of architecture slices in a Mach-O fat binary.

    Parses the on-disk FAT_MAGIC / FAT_MAGIC_64 header and resolves each
    entry's ``cputype``/``cpusubtype`` to a ``lipo``-style name.

    Returns ``None`` when *file_path* is not a fat Mach-O — missing
    file, too short, wrong magic, absurd ``nfat_arch``, or any entry
    whose cputype is not a recognised Mach-O architecture.  This is a
    deliberately conservative detector: Java ``.class`` files share
    the ``CAFEBABE`` magic, and we must not misclassify them.
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(8)
            if len(header) < 8:
                return None
            magic, nfat_arch = struct.unpack(">II", header)
            if magic == _FAT_MAGIC:
                fmt = ">IIIII"  # struct fat_arch: cputype, cpusubtype, offset, size, align
            elif magic == _FAT_MAGIC_64:
                fmt = ">IIQQII"  # struct fat_arch_64: + reserved; 64-bit offset/size
            else:
                return None
            if nfat_arch == 0 or nfat_arch > _MAX_FAT_SLICES:
                return None
            want = struct.calcsize(fmt) * nfat_arch
            entries_raw = f.read(want)
            if len(entries_raw) < want:
                return None
    except OSError:
        return None

    slices: list[str] = []
    for cputype, cpusubtype, *_ in struct.iter_unpack(fmt, entries_raw):
        name = _fat_slice_name(cputype, cpusubtype)
        if name is None:
            # Unknown cputype — treat the whole file as not-fat rather
            # than returning a half-parsed list.  This is the Java
            # ``.class`` defence.
            return None
        slices.append(name)
    return slices


def _is_primary_idb_path(file_path: str) -> bool:
    """True if *file_path* resolves to an ``.i64``/``.idb`` database path.

    Resolves symlinks and ``~`` internally so a link-without-extension
    pointing at a stored database (``./shortcut`` → ``real.i64``) is
    classified the same as a direct path.  Callers that need the
    resolved path for other work should call :func:`os.path.realpath`
    themselves — this helper is a pure predicate.
    """
    resolved = os.path.realpath(os.path.expanduser(file_path))
    _, ext = os.path.splitext(resolved)
    return ext.lower() in PRIMARY_IDB_EXTENSIONS


def reject_fat_arch_on_database(file_path: str, fat_arch: str) -> None:
    """Raise ``InvalidArgument`` when *fat_arch* is set on an ``.i64``/``.idb`` path.

    Stored databases already pin a specific slice, so ``fat_arch`` on
    top is either contradictory (the stored analysis belongs to a
    different slice) or redundant (same slice, the arg does nothing).
    Both sites that accept user input for ``(file_path, fat_arch)`` —
    the supervisor's fail-fast path in :func:`check_fat_binary` and
    :meth:`session.Session.open` for direct callers — share this
    check, so the message lives here to keep them in sync.

    *file_path* is resolved internally (see :func:`_is_primary_idb_path`)
    so a symlink without a ``.i64`` extension pointing at a stored
    database is still caught.  The **original** path is shown in the
    error message so the user sees what they typed, not the resolved
    path under the hood — matching the rest of :func:`check_fat_binary`.
    """
    if not fat_arch:
        return
    if not _is_primary_idb_path(file_path):
        return
    raise IDAError(
        f"fat_arch={fat_arch!r} was specified but {file_path!r} "
        "is an existing IDA database (.i64/.idb).  The stored "
        "database already pins a specific slice — remove fat_arch "
        "to reopen it, or point file_path at the original binary "
        "to analyze a different slice.",
        error_type="InvalidArgument",
    )


def reject_force_new_on_database(file_path: str, force_new: bool) -> None:
    """Raise ``InvalidArgument`` when *force_new* is set on an ``.i64``/``.idb`` path.

    ``force_new`` means *"discard the stored analysis and re-analyze
    from the original binary"*.  That only makes sense when *file_path*
    names the binary — if it names the database itself (``.i64`` /
    ``.idb``), :meth:`session.Session.open` would strip the extension,
    delete the database files, and then try to open the (possibly
    missing) binary at the stem path.  When the binary is absent, the
    stored analysis is destroyed with nothing to re-analyze from and no
    recovery path.  Even when the binary *is* present, passing the
    database path with ``force_new=True`` is confusing — the path
    refers to the thing being destroyed rather than the thing being
    opened.

    Fail fast at every entry point (supervisor, worker tool,
    :meth:`Session.open`) so the user cannot destroy their stored
    analysis by pointing ``file_path`` at the wrong thing.  *file_path*
    is resolved internally (see :func:`_is_primary_idb_path`) so a
    symlink-without-extension pointing at an ``.i64`` is also rejected.
    """
    if not force_new:
        return
    if not _is_primary_idb_path(file_path):
        return
    raise IDAError(
        f"force_new=True cannot be combined with an existing IDA "
        f"database path ({file_path!r}).  force_new deletes the "
        "stored analysis and re-analyzes from the original binary, "
        "so it needs the binary path — not the database path — as "
        "file_path.  Pass the original binary (raw file without "
        "the .i64/.idb extension) instead, or call with "
        "force_new=False to reuse the existing database.",
        error_type="InvalidArgument",
    )


def check_fat_binary(file_path: str, fat_arch: str, force_new: bool) -> int | None:
    """Validate *fat_arch* for *file_path* and return the slice index.

    Returns the **1-based** slice index suitable for passing to
    :func:`build_ida_args` as ``fat_slice_index``, or ``None`` when no
    fat-slice ``-T`` flag is needed — specifically:

    - *file_path* is already an ``.i64`` / ``.idb`` database (stored
      analysis pins the slice; *fat_arch* **must** be empty in that
      case — see below);
    - a slice-specific sidecar exists next to the binary and
      ``force_new`` is False (we'll reopen the stored DB below);
    - the file is not a fat Mach-O at all and *fat_arch* is empty
      (thin binary, ELF, PE, ...).

    Raises :class:`IDAError`:

    - ``AmbiguousFatBinary`` — file is fat but *fat_arch* is empty.
    - ``UnknownFatArch`` — *fat_arch* is not present in the fat header.
    - ``InvalidArgument`` — *fat_arch* was set but the file is **not**
      a fat Mach-O (thin binary, non-Mach-O, ...), **or** *file_path*
      is an explicit ``.i64``/``.idb`` path, **or** *force_new* is
      set on an ``.i64``/``.idb`` path (which would delete the stored
      analysis before :meth:`Session.open` could find the binary to
      re-analyze).  Silently ignoring any of these would let a user
      mis-select a non-existent slice, expect a re-analysis that is
      not going to happen, or destroy their stored analysis with no
      recovery path; surfacing the error makes the mistake immediate,
      before IDA writes a confusingly named sidecar or we delete the
      wrong files.

    The ambiguous / unknown errors carry an ``available=`` detail
    listing the slice names.  The index is the slice's 1-based
    position in the on-disk fat header, which is the value IDA expects
    in ``-T"Fat Mach-O file, <N>"`` — the only documented way to pick
    a fat slice in headless mode.
    """
    # ``reject_fat_arch_on_database`` / ``reject_force_new_on_database``
    # resolve symlinks internally so a symlink-without-extension
    # pointing at a ``.i64`` is caught the same as a direct path.  Both
    # are no-ops on thin/raw files, so calling them unconditionally is
    # safe.  Ordering: reject force_new+database first so the user sees
    # the most direct "wrong path type" error before we start parsing
    # fat headers.
    reject_force_new_on_database(file_path, force_new)
    reject_fat_arch_on_database(file_path, fat_arch)

    # The rest of the check needs a resolved path to read the file and
    # to key the slice-specific sidecar lookup off the real name.
    resolved = os.path.realpath(os.path.expanduser(file_path))

    if _has_stored_analysis(resolved, force_new, fat_arch):
        return None

    slices = detect_fat_slices(resolved)
    if slices is None:
        if fat_arch:
            raise IDAError(
                f"fat_arch={fat_arch!r} was specified but {file_path!r} "
                "is not a Mach-O fat (universal) binary.  Remove "
                "fat_arch for thin binaries and non-Mach-O files.",
                error_type="InvalidArgument",
            )
        return None

    # Defensive: two (cputype, cpusubtype) pairs that both collapse to
    # the same lipo-style slice name would make ``slices.index(fat_arch)``
    # ambiguous — we would silently pick the first match and hand IDA an
    # index the user may not have intended.  No ``lipo``-produced file
    # hits this case (real universal binaries never repeat an arch, and
    # _CPU_SUBTYPE_NAMES only refines a small well-known set of pairs),
    # but malformed / hand-crafted fat headers can.  Reject explicitly
    # so the ambiguity is never silent.  ``Counter`` preserves insertion
    # order so ``duplicates`` matches on-disk slice order.
    duplicates = [name for name, count in Counter(slices).items() if count > 1]
    if duplicates:
        raise IDAError(
            "Fat binary contains multiple slices that resolve to the "
            f"same architecture name: {', '.join(duplicates)}.  The "
            "slice cannot be selected unambiguously by fat_arch; "
            "re-create the binary with lipo(1) to deduplicate, or "
            "extract the desired slice with ``lipo -thin`` and open "
            "the thin file directly.\n\n"
            f"Slices (in on-disk order): {', '.join(slices)}",
            error_type="DuplicateFatSlice",
            available=slices,
            duplicates=duplicates,
        )

    if not fat_arch:
        raise IDAError(
            "File is a Mach-O fat binary with multiple architecture "
            "slices.  Pass fat_arch= to pick one.\n\n"
            f"Available: {', '.join(slices)}",
            error_type="AmbiguousFatBinary",
            available=slices,
        )
    if fat_arch not in slices:
        raise IDAError(
            f"fat_arch={fat_arch!r} is not present in this fat binary.\n\n"
            f"Available: {', '.join(slices)}",
            error_type="UnknownFatArch",
            available=slices,
        )
    # IDA's ``-T"Fat Mach-O file, <N>"`` uses 1-based indices in
    # on-disk fat-header order.  detect_fat_slices preserves that order,
    # and the duplicate check above guarantees ``slices.index`` is
    # unambiguous.
    return slices.index(fat_arch) + 1
