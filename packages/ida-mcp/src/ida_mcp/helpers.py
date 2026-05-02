# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""IDA-specific utilities for address resolution, dispatching, and tool helpers.

Imports and re-exports shared helpers from :mod:`re_mcp.helpers` so that
tool modules can import everything from a single place.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Annotated, Any

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_segment
import ida_strlist
import ida_typeinf
import ida_ua
import idautils
import idc
from pydantic import Field
from re_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_MUTATE_NON_IDEMPOTENT,
    ANNO_READ_ONLY,
    HEX_RE,
    Address,
    FilterPattern,
    HexBytes,
    Limit,
    Offset,
    async_paginate_iter,
    compile_filter,
    dispatch_to_main,
    format_address,
    paginate,
    paginate_iter,
    set_main_executor,
)

from ida_mcp.exceptions import IDAError

log = logging.getLogger(__name__)

__all__ = [
    "ANNO_DESTRUCTIVE",
    "ANNO_MUTATE",
    "ANNO_MUTATE_NON_IDEMPOTENT",
    "ANNO_READ_ONLY",
    "META_BATCH",
    "META_DECOMPILER",
    "META_READS_FILES",
    "META_WRITES_FILES",
    "Address",
    "Cancelled",
    "FilterPattern",
    "HexBytes",
    "IDAError",
    "Limit",
    "Offset",
    "OperandIndex",
    "async_paginate_iter",
    "build_strlist",
    "call_ida",
    "check_cancelled",
    "clean_disasm_line",
    "compile_filter",
    "decode_insn_at",
    "decode_string",
    "decompile_at",
    "format_address",
    "format_permissions",
    "get_func_name",
    "get_old_item_info",
    "ida_dispatch",
    "is_bad_addr",
    "is_cancelled",
    "paginate",
    "paginate_iter",
    "parse_address",
    "parse_permissions",
    "parse_type",
    "resolve_address",
    "resolve_enum",
    "resolve_function",
    "resolve_segment",
    "resolve_struct",
    "safe_type_size",
    "segment_bitness",
    "set_main_executor",
    "validate_operand_num",
    "xref_type_name",
]

# Backend dispatch alias
call_ida = dispatch_to_main


# ---------------------------------------------------------------------------
# IDA-specific Annotated type alias
# ---------------------------------------------------------------------------

OperandIndex = Annotated[int, Field(description="Operand index (0-based).", ge=0)]


# ---------------------------------------------------------------------------
# IDA-specific decorator
# ---------------------------------------------------------------------------


def ida_dispatch(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Mark a function as requiring main-thread dispatch.

    Functions decorated with ``@ida_dispatch`` contain IDA API calls and
    must be invoked via :func:`call_ida` or :func:`async_paginate_iter`
    when called from async code.  The lint script
    (``scripts/lint_ida_threading.py``) enforces this at CI time.
    """
    fn._ida_dispatch = True  # type: ignore[attr-defined]
    return fn


# ---------------------------------------------------------------------------
# MCP tool meta presets — static metadata exposed to clients
# ---------------------------------------------------------------------------

META_DECOMPILER: dict[str, object] = {"requires_decompiler": True}
META_BATCH: dict[str, object] = {"batch": True}
META_READS_FILES: dict[str, object] = {"reads_files": True}
META_WRITES_FILES: dict[str, object] = {"writes_files": True}


# ---------------------------------------------------------------------------
# IDA sentinel values
# ---------------------------------------------------------------------------

_BADADDR32 = 0xFFFFFFFF
_BADADDR64 = 0xFFFFFFFFFFFFFFFF


def is_bad_addr(val: int) -> bool:
    """Return True if *val* is an IDA BADADDR / invalid-ID sentinel."""
    return val in (_BADADDR32, _BADADDR64)


# ---------------------------------------------------------------------------
# Cancellation helpers
# ---------------------------------------------------------------------------


class Cancelled(Exception):
    """Raised by :func:`check_cancelled` when IDA's cancellation flag is set."""

    def __init__(self):
        super().__init__("Operation cancelled")


@ida_dispatch
def check_cancelled() -> None:
    """Raise :class:`Cancelled` if the IDA cancellation flag is set.

    Call this between iterations in batch loops so that a SIGUSR1 from
    the supervisor (which sets the flag via ``ida_kernwin.set_cancelled()``)
    can interrupt long-running operations cooperatively.
    """
    if ida_kernwin.user_cancelled():
        raise Cancelled


@ida_dispatch
def is_cancelled() -> bool:
    """Return ``True`` if the IDA cancellation flag is set.

    Use this in loops that need to ``break`` on cancellation rather
    than propagate an exception.
    """
    return ida_kernwin.user_cancelled()


# ---------------------------------------------------------------------------
# IDA-specific address parsing (extends shared parse_address with symbols)
# ---------------------------------------------------------------------------


@ida_dispatch
def parse_address(addr: str | int) -> int:
    """Parse an address from various formats, including IDA symbol names.

    Accepts:
    - Hex with prefix: "0x401000"
    - Decimal (pure digits): "4198400"
    - Symbol name: "main", "add", "_start"
    - Bare hex (fallback): "4010a0"

    Symbol names are checked before bare hex so that names like ``add``,
    ``dead``, or ``cafe`` resolve to the named symbol rather than being
    parsed as hexadecimal.  Use the ``0x`` prefix for explicit hex
    (e.g. ``0xADD`` instead of ``add``).
    """
    if isinstance(addr, int):
        return addr

    addr = addr.strip()
    if not addr:
        raise ValueError("Empty address")

    # Try 0x-prefixed hex (unambiguous)
    if addr.lower().startswith("0x"):
        return int(addr, 16)

    # Try pure decimal (all digits → always decimal)
    if addr.isdigit():
        return int(addr)

    # Try as symbol name before bare hex so that names like "add" or
    # "dead" are not silently swallowed as hex values.
    ea = idc.get_name_ea_simple(addr)
    if not is_bad_addr(ea):
        return ea

    ea = ida_name.get_name_ea(0, addr)
    if not is_bad_addr(ea):
        return ea

    # Bare hex fallback (contains a-f chars)
    if HEX_RE.match(addr):
        return int(addr, 16)

    raise ValueError(f"Cannot resolve address: {addr!r}")


# ---------------------------------------------------------------------------
# High-level resolution helpers — reduce boilerplate in tool modules.
# Each raises IDAError on failure.
# ---------------------------------------------------------------------------


@ida_dispatch
def resolve_address(addr: str | int) -> int:
    """Parse and validate an address.

    Raises :class:`IDAError` with ``error_type="InvalidAddress"`` on failure.
    """
    try:
        return parse_address(addr)
    except ValueError as e:
        raise IDAError(str(e), error_type="InvalidAddress") from e


@ida_dispatch
def resolve_function(addr: str | int) -> ida_funcs.func_t:
    """Resolve an address to its containing function.

    Raises :class:`IDAError` if the address is invalid or not in a function.
    """
    ea = resolve_address(addr)
    func = ida_funcs.get_func(ea)
    if func is None:
        raise IDAError(f"No function at {format_address(ea)}", error_type="NotFound")
    return func


@ida_dispatch
def decompile_at(
    addr: str | int,
) -> tuple[ida_hexrays.cfunc_t, ida_funcs.func_t]:
    """Resolve address, get function, and decompile with Hex-Rays.

    Returns ``(cfunc, func_t)``.  Raises :class:`IDAError` on failure.
    """
    from ida_mcp.session import session  # noqa: PLC0415

    if not session.capabilities.get("decompiler"):
        raise IDAError(
            "No decompiler available for this architecture/license",
            error_type="NoDecompiler",
        )
    ea = resolve_address(addr)
    func = ida_funcs.get_func(ea)
    if func is None:
        raise IDAError(f"No function at {format_address(ea)}", error_type="NotFound")
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
    except ida_hexrays.DecompilationFailure as e:
        raise IDAError(str(e), error_type="DecompilationFailed") from e
    except Exception as e:
        raise IDAError(f"Decompilation error: {e}", error_type="DecompilationFailed") from e
    if cfunc is None:
        raise IDAError("Decompilation returned no result", error_type="DecompilationFailed")
    return cfunc, func


@ida_dispatch
def decode_insn_at(ea: int) -> ida_ua.insn_t:
    """Decode an instruction at *ea*.

    Raises :class:`IDAError` with ``error_type="DecodeFailed"`` on failure.
    """
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) == 0:
        raise IDAError(
            f"Cannot decode instruction at {format_address(ea)}", error_type="DecodeFailed"
        )
    return insn


@ida_dispatch
def resolve_segment(address: str | int) -> ida_segment.segment_t:
    """Resolve an address to its containing segment.

    Raises :class:`IDAError` if the address is invalid or not in a segment.
    """
    ea = resolve_address(address)
    seg = ida_segment.getseg(ea)
    if seg is None:
        raise IDAError(f"No segment at {format_address(ea)}", error_type="NotFound")
    return seg


@ida_dispatch
def resolve_struct(name: str) -> int:
    """Resolve a struct name to its type ID.

    Raises :class:`IDAError` with ``error_type="NotFound"`` if the struct does not exist.
    """
    sid = idc.get_struc_id(name)
    if is_bad_addr(sid):
        raise IDAError(f"Structure not found: {name}", error_type="NotFound")
    return sid


@ida_dispatch
def resolve_enum(name: str) -> int:
    """Resolve an enum name to its type ID (tid).

    Raises :class:`IDAError` if the enum does not exist or is not an enum.
    """
    tid = ida_typeinf.get_named_type_tid(name)
    if is_bad_addr(tid):
        raise IDAError(f"Enum not found: {name}", error_type="NotFound")
    tif = ida_typeinf.tinfo_t()
    tif.get_type_by_tid(tid)
    if not tif.is_enum():
        raise IDAError(f"Not an enum: {name}", error_type="NotFound")
    return tid


# ---------------------------------------------------------------------------
# Disassembly and naming helpers
# ---------------------------------------------------------------------------


@ida_dispatch
def clean_disasm_line(ea: int) -> str:
    """Get a clean disassembly line (no color codes) for an address."""
    line = ida_lines.generate_disasm_line(ea, 0)
    if line:
        return ida_lines.tag_remove(line)
    return ""


@ida_dispatch
def get_func_name(ea: int) -> str:
    """Get function name at address, or formatted address if unnamed."""
    return ida_name.get_name(ea) or format_address(ea)


@ida_dispatch
def xref_type_name(xref_type: int) -> str:
    """Get human-readable name for an xref type."""
    return idautils.XrefTypeName(xref_type)


# ---------------------------------------------------------------------------
# Segment helpers
# ---------------------------------------------------------------------------

_BITNESS_MAP = {0: 16, 1: 32, 2: 64}
_VALID_PERM_CHARS = frozenset("RWX-")


def segment_bitness(raw: int) -> int:
    """Convert IDA's segment bitness encoding (0/1/2) to bit count (16/32/64)."""
    return _BITNESS_MAP.get(raw, raw)


def format_permissions(perm: int) -> str:
    """Format IDA segment permission flags as a human-readable string like ``"RWX"``."""
    s = "R" if perm & ida_segment.SEGPERM_READ else "-"
    s += "W" if perm & ida_segment.SEGPERM_WRITE else "-"
    s += "X" if perm & ida_segment.SEGPERM_EXEC else "-"
    return s


def parse_permissions(permissions: str) -> int:
    """Parse a permission string like ``"RWX"`` or ``"R-X"`` into IDA segment flags.

    Raises :class:`IDAError` with ``error_type="InvalidArgument"`` on bad input.
    """
    perms_upper = permissions.upper()
    if not perms_upper or not all(c in _VALID_PERM_CHARS for c in perms_upper):
        raise IDAError(
            f"Invalid permission string: {permissions!r} "
            f"(each character must be one of R, W, X, or -)",
            error_type="InvalidArgument",
        )
    perm = 0
    if "R" in perms_upper:
        perm |= ida_segment.SEGPERM_READ
    if "W" in perms_upper:
        perm |= ida_segment.SEGPERM_WRITE
    if "X" in perms_upper:
        perm |= ida_segment.SEGPERM_EXEC
    return perm


def validate_operand_num(operand_num: int) -> None:
    """Raise :class:`IDAError` if *operand_num* is negative."""
    if operand_num < 0:
        raise IDAError(
            f"Operand index must be >= 0, got {operand_num}",
            error_type="InvalidArgument",
        )


# ---------------------------------------------------------------------------
# Type helpers
# ---------------------------------------------------------------------------


def parse_type(type_str: str) -> ida_typeinf.tinfo_t:
    """Parse a C type declaration string.

    Raises :class:`IDAError` with ``error_type="ParseError"`` on failure.
    """
    tinfo = ida_typeinf.tinfo_t()
    til = ida_typeinf.get_idati()
    parsed = ida_typeinf.parse_decl(tinfo, til, f"{type_str};", ida_typeinf.PT_TYP)
    if parsed is None:
        raise IDAError(f"Failed to parse type: {type_str!r}", error_type="ParseError")
    return tinfo


def safe_type_size(size: int) -> int | None:
    """Return *size* unless it is an IDA sentinel value, in which case return ``None``.

    ``tinfo_t.get_size()`` returns ``BADADDR`` for types whose size is unknown.
    """
    return None if is_bad_addr(size) else size


# ---------------------------------------------------------------------------
# String helpers
# ---------------------------------------------------------------------------

_ALL_STR_TYPES = (
    ida_nalt.STRTYPE_C,
    ida_nalt.STRTYPE_C_16,
    ida_nalt.STRTYPE_C_32,
    ida_nalt.STRTYPE_PASCAL,
    ida_nalt.STRTYPE_PASCAL_16,
    ida_nalt.STRTYPE_PASCAL_32,
    ida_nalt.STRTYPE_LEN2,
    ida_nalt.STRTYPE_LEN2_16,
    ida_nalt.STRTYPE_LEN2_32,
    ida_nalt.STRTYPE_LEN4,
    ida_nalt.STRTYPE_LEN4_16,
    ida_nalt.STRTYPE_LEN4_32,
)


def build_strlist() -> int:
    """Build the string list with all string types enabled.

    Enables every combination of character width (1/2/4-byte) and
    termination style (null-terminated, Pascal 1/2/4-byte length prefix).
    Returns the string count after building.
    """
    opts = ida_strlist.get_strlist_options()
    existing = set(opts.strtypes)
    existing.update(_ALL_STR_TYPES)
    opts.strtypes = sorted(existing)
    ida_strlist.build_strlist()
    return ida_strlist.get_strlist_qty()


def decode_string(ea: int, length: int, strtype: int) -> str | None:
    """Decode a string from the database, returning ``None`` on failure."""
    raw = ida_bytes.get_strlit_contents(ea, length, strtype)
    if raw is None:
        return None
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return raw.hex()


def get_old_item_info(ea: int) -> tuple[str, int]:
    """Read the current item type and size at an address.

    Returns ``(item_type, item_size)`` where *item_type* is one of
    ``"code"``, ``"data"``, ``"tail"``, or ``"unknown"``.
    """
    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_code(flags):
        item_type = "code"
    elif ida_bytes.is_data(flags):
        item_type = "data"
    elif ida_bytes.is_tail(flags):
        item_type = "tail"
    else:
        item_type = "unknown"
    return item_type, ida_bytes.get_item_size(ea)
