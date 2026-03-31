# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Shared utilities for address parsing, formatting, and pagination."""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from typing import TYPE_CHECKING, Annotated, Any

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import ida_ua
import idautils
import idc
from pydantic import Field

from ida_mcp.exceptions import IDAError, tool_timeout  # noqa: F401 — re-exported

if TYPE_CHECKING:
    from fastmcp.server.context import Context

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Reusable Annotated type aliases for tool parameters
# ---------------------------------------------------------------------------

Address = Annotated[str, Field(description="Address (hex string, decimal, or symbol name).")]
Offset = Annotated[int, Field(description="Pagination offset.", ge=0)]
Limit = Annotated[int, Field(description="Maximum number of results.", ge=1)]
FilterPattern = Annotated[str, Field(description="Optional regex to filter results.")]
OperandIndex = Annotated[int, Field(description="Operand index (0-based).", ge=0)]
HexBytes = Annotated[str, Field(description="Hex string of bytes (e.g. '90 90 90' or '909090').")]

# ---------------------------------------------------------------------------
# MCP tool annotation presets (readOnlyHint, destructiveHint, etc.)
# ---------------------------------------------------------------------------

ANNO_READ_ONLY: dict[str, bool] = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
ANNO_MUTATE: dict[str, bool] = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
ANNO_MUTATE_NON_IDEMPOTENT: dict[str, bool] = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": False,
}
ANNO_DESTRUCTIVE: dict[str, bool] = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": False,
}

# ---------------------------------------------------------------------------
# MCP tool meta presets — static metadata exposed to clients
# ---------------------------------------------------------------------------

META_DECOMPILER: dict[str, object] = {"requires_decompiler": True}
META_BATCH: dict[str, object] = {"batch": True}
META_READS_FILES: dict[str, object] = {"reads_files": True}
META_WRITES_FILES: dict[str, object] = {"writes_files": True}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# IDA sentinel values for invalid addresses/IDs.  We check both 32-bit and
# 64-bit forms because some IDA APIs (enum IDs, struct IDs) return the 32-bit
# sentinel even in a 64-bit database.
_BADADDR32 = 0xFFFFFFFF
_BADADDR64 = 0xFFFFFFFFFFFFFFFF


def is_bad_addr(val: int) -> bool:
    """Return True if *val* is an IDA BADADDR / invalid-ID sentinel."""
    return val in (_BADADDR32, _BADADDR64)


class Cancelled(Exception):
    """Raised by :func:`check_cancelled` when IDA's cancellation flag is set."""

    def __init__(self):
        super().__init__("Operation cancelled")


def try_get_context() -> Context | None:
    """Return the current FastMCP :class:`Context`, or ``None`` outside a request.

    Safe to call anywhere — never raises.  Use this in shared helpers that
    want to report progress or log without requiring a context parameter.
    """
    try:
        from fastmcp.server.dependencies import get_context  # noqa: PLC0415

        return get_context()
    except (RuntimeError, ImportError):
        return None


def check_cancelled() -> None:
    """Raise :class:`Cancelled` if the IDA cancellation flag is set.

    Call this between iterations in batch loops so that a SIGUSR1 from
    the supervisor (which sets the flag via ``ida_kernwin.set_cancelled()``)
    can interrupt long-running operations cooperatively.
    """
    if ida_kernwin.user_cancelled():
        raise Cancelled


def is_cancelled() -> bool:
    """Return ``True`` if the IDA cancellation flag is set.

    Use this in loops that simply need to ``break`` on cancellation
    rather than propagate an exception.
    """
    return ida_kernwin.user_cancelled()


def parse_address(addr: str | int) -> int:
    """Parse an address from various formats.

    Accepts:
    - Hex with prefix: "0x401000"
    - Bare hex (must contain a-f): "4010a0"
    - Decimal (pure digits): "4198400"
    - Symbol name: "main", "_start"

    Note: All-digit strings are treated as decimal.  Use the "0x" prefix for
    hex addresses that contain only digits (e.g. "0x401000", not "401000").
    """
    if isinstance(addr, int):
        return addr

    addr = addr.strip()
    if not addr:
        raise ValueError("Empty address")

    # Try 0x-prefixed hex
    if addr.lower().startswith("0x"):
        return int(addr, 16)

    # Try pure decimal (all digits → always decimal)
    if addr.isdigit():
        return int(addr)

    # Try bare hex (contains a-f chars, so won't collide with decimal)
    if _HEX_RE.match(addr):
        return int(addr, 16)

    # Try as symbol name
    ea = idc.get_name_ea_simple(addr)
    if not is_bad_addr(ea):
        return ea

    # Also try with ida_name
    ea = ida_name.get_name_ea(0, addr)
    if not is_bad_addr(ea):
        return ea

    raise ValueError(f"Cannot resolve address: {addr!r}")


def format_address(ea: int) -> str:
    """Format an address as a hex string."""
    return f"0x{ea:X}"


def paginate(items: list, offset: int = 0, limit: int = 100) -> dict:
    """Apply pagination to a list of items."""
    offset = max(0, offset)
    limit = max(1, limit)
    total = len(items)
    sliced = items[offset : offset + limit]
    return {
        "items": sliced,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": offset + limit < total,
    }


def paginate_iter(items: Iterable[Any], offset: int = 0, limit: int = 100) -> dict:
    """Apply pagination to an iterable without materializing the full list.

    Unlike ``paginate``, this consumes a generator/iterator one item at a time,
    keeping only the current page in memory.  Use for large collections where
    building a complete list would be wasteful.

    After the requested page is collected the iterator is consumed for at most
    ``_COUNT_AHEAD`` additional items to determine *has_more* and provide a
    bounded *total*.  If the iterator is longer than that, *total* reports the
    items seen so far and *has_more* is ``True``.
    """
    _COUNT_AHEAD = 10_000
    offset = max(0, offset)
    limit = max(1, limit)
    result: list = []
    total = 0
    it = iter(items)

    # Skip to offset, then collect up to limit items
    for item in it:
        if total >= offset:
            result.append(item)
            total += 1
            if len(result) >= limit:
                break
            continue
        total += 1

    # Count ahead a bounded amount to determine has_more / approximate total
    has_more = False
    for _item in it:
        total += 1
        if total - offset - limit >= _COUNT_AHEAD:
            has_more = True
            break
    else:
        has_more = offset + limit < total

    return {
        "items": result,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": has_more,
    }


async def async_paginate_iter(
    items: Iterable[Any],
    offset: int = 0,
    limit: int = 100,
    *,
    progress_label: str = "",
) -> dict:
    """Async version of :func:`paginate_iter` with progress reporting.

    Must be called from an ``async def`` tool so that ``await`` yields
    control back to the event loop, allowing progress notifications to
    actually reach the client.  In workers, sync tools block the event
    loop, so fire-and-forget progress never sends — use this variant
    instead when progress matters.

    When *progress_label* is non-empty **and** a FastMCP request context
    is active, ``ctx.report_progress()`` and ``ctx.info()`` are awaited
    periodically as items are collected.

    Note: intentionally duplicates :func:`paginate_iter` logic rather than
    delegating to it — the ``await`` points inside the collection loop
    make it impractical to share the iteration body.
    """
    _COUNT_AHEAD = 10_000
    offset = max(0, offset)
    limit = max(1, limit)
    result: list = []
    total = 0
    it = iter(items)

    ctx = try_get_context() if progress_label else None

    for item in it:
        if total >= offset:
            result.append(item)
            total += 1
            if ctx and len(result) % 50 == 0:
                await ctx.report_progress(len(result), limit)
                await ctx.info(f"{progress_label}: {len(result)}/{limit}")
            if len(result) >= limit:
                break
            continue
        total += 1

    has_more = False
    for _item in it:
        total += 1
        if total - offset - limit >= _COUNT_AHEAD:
            has_more = True
            break
    else:
        has_more = offset + limit < total

    if ctx:
        await ctx.report_progress(len(result), len(result))

    return {
        "items": result,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": has_more,
    }


def clean_disasm_line(ea: int) -> str:
    """Get a clean disassembly line (no color codes) for an address."""
    line = ida_lines.generate_disasm_line(ea, 0)
    if line:
        return ida_lines.tag_remove(line)
    return ""


def get_func_name(ea: int) -> str:
    """Get function name at address, or formatted address if unnamed."""
    return ida_name.get_name(ea) or format_address(ea)


def xref_type_name(xref_type: int) -> str:
    """Get human-readable name for an xref type."""
    return idautils.XrefTypeName(xref_type)


# ---------------------------------------------------------------------------
# High-level resolution helpers — reduce boilerplate in tool modules.
# Each raises IDAError on failure.
# ---------------------------------------------------------------------------


def resolve_address(addr: str | int) -> int:
    """Parse and validate an address.

    Raises :class:`IDAError` with ``error_type="InvalidAddress"`` on failure.
    """
    try:
        return parse_address(addr)
    except ValueError as e:
        raise IDAError(str(e), error_type="InvalidAddress") from e


def resolve_function(addr: str | int) -> ida_funcs.func_t:
    """Resolve an address to its containing function.

    Raises :class:`IDAError` if the address is invalid or not in a function.
    """
    ea = resolve_address(addr)
    func = ida_funcs.get_func(ea)
    if func is None:
        raise IDAError(f"No function at {format_address(ea)}", error_type="NotFound")
    return func


def decompile_at(addr: str | int) -> tuple[ida_hexrays.cfunc_t, ida_funcs.func_t]:
    """Resolve address, get function, and decompile with Hex-Rays.

    Returns ``(cfunc, func_t)``.  Raises :class:`IDAError` on failure.
    """
    from ida_mcp.session import session  # noqa: PLC0415

    if not session.capabilities.get("decompiler"):
        raise IDAError(
            "No decompiler available for this architecture/license",
            error_type="NoDecompiler",
        )
    func = resolve_function(addr)
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
    except ida_hexrays.DecompilationFailure as e:
        raise IDAError(str(e), error_type="DecompilationFailed") from e
    except Exception as e:
        raise IDAError(f"Decompilation error: {e}", error_type="DecompilationFailed") from e
    if cfunc is None:
        raise IDAError("Decompilation returned no result", error_type="DecompilationFailed")
    return cfunc, func


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


def resolve_segment(address: str | int) -> ida_segment.segment_t:
    """Resolve an address to its containing segment.

    Raises :class:`IDAError` if the address is invalid or not in a segment.
    """
    ea = resolve_address(address)
    seg = ida_segment.getseg(ea)
    if seg is None:
        raise IDAError(f"No segment at {format_address(ea)}", error_type="NotFound")
    return seg


def resolve_struct(name: str) -> int:
    """Resolve a struct name to its type ID.

    Raises :class:`IDAError` with ``error_type="NotFound"`` if the struct does not exist.
    """
    sid = idc.get_struc_id(name)
    if is_bad_addr(sid):
        raise IDAError(f"Structure not found: {name}", error_type="NotFound")
    return sid


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


def compile_filter(pattern: str) -> re.Pattern | None:
    """Compile an optional regex filter pattern.

    Returns the compiled pattern, or ``None`` if *pattern* is empty (match everything).
    Raises :class:`IDAError` with ``error_type="InvalidArgument"`` on bad regex.
    """
    if not pattern:
        return None
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        raise IDAError(f"Invalid regex: {e}", error_type="InvalidArgument") from e


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


def decode_string(ea: int, length: int, strtype: int) -> str | None:
    """Decode a string from the database, returning ``None`` on failure."""
    raw = ida_bytes.get_bytes(ea, length)
    if raw is None:
        return None
    try:
        if strtype == ida_nalt.STRTYPE_C_32:
            return raw.decode("utf-32-le", errors="replace")
        if strtype == ida_nalt.STRTYPE_C_16:
            return raw.decode("utf-16-le", errors="replace")
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
