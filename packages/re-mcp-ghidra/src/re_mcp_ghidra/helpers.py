# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Ghidra-specific utilities for address resolution, dispatching, and tool helpers.

Imports and re-exports shared helpers from :mod:`re_mcp.helpers` so that
tool modules can import everything from a single place.
"""

from __future__ import annotations

import logging

from re_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_MUTATE_NON_IDEMPOTENT,
    ANNO_READ_ONLY,
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
    parse_address,
    set_main_executor,
)

from re_mcp_ghidra.exceptions import GhidraError

log = logging.getLogger(__name__)

__all__ = [
    "ANNO_DESTRUCTIVE",
    "ANNO_MUTATE",
    "ANNO_MUTATE_NON_IDEMPOTENT",
    "ANNO_READ_ONLY",
    "Address",
    "FilterPattern",
    "GhidraError",
    "HexBytes",
    "Limit",
    "Offset",
    "async_paginate_iter",
    "call_ghidra",
    "compile_filter",
    "format_address",
    "format_permissions",
    "paginate",
    "paginate_iter",
    "parse_address",
    "resolve_address",
    "resolve_address_value",
    "resolve_function",
    "set_main_executor",
    "to_ghidra_address",
]

# Backend dispatch alias
call_ghidra = dispatch_to_main


# ---------------------------------------------------------------------------
# Ghidra-specific address resolution (extends parse_address with symbol lookup)
# ---------------------------------------------------------------------------


def resolve_address_value(addr: str | int) -> int:
    """Parse an address string into an integer, checking Ghidra symbols if needed.

    This is called from within a Ghidra context where the program is available.
    Raises :class:`GhidraError` on failure.
    """
    from re_mcp_ghidra.session import session  # noqa: PLC0415

    if isinstance(addr, int):
        return addr

    addr_str = str(addr).strip()
    if not addr_str:
        raise GhidraError("Empty address", error_type="InvalidAddress")

    # Try numeric parsing first
    try:
        return parse_address(addr_str)
    except ValueError:
        pass

    # Try as symbol name via Ghidra
    program = session.program
    if program is None:
        raise GhidraError("No database is open", error_type="NoDatabase")

    symbol_table = program.getSymbolTable()
    symbols = symbol_table.getGlobalSymbols(addr_str)
    if symbols:
        return symbols[0].getAddress().getOffset()

    # Try namespace-qualified symbols via targeted lookup
    sym_iter = symbol_table.getSymbols(addr_str)
    if sym_iter.hasNext():
        return sym_iter.next().getAddress().getOffset()

    raise GhidraError(f"Cannot resolve address: {addr_str!r}", error_type="InvalidAddress")


def to_ghidra_address(offset: int):
    """Convert an integer offset to a Ghidra Address object."""
    from re_mcp_ghidra.session import session  # noqa: PLC0415

    program = session.program
    if program is None:
        raise GhidraError("No database is open", error_type="NoDatabase")
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)


def resolve_address(addr: str | int):
    """Parse and validate an address, returning a Ghidra Address object.

    Raises :class:`GhidraError` with ``error_type="InvalidAddress"`` on failure.
    """
    offset = resolve_address_value(addr)
    return to_ghidra_address(offset)


def resolve_function(addr: str | int):
    """Resolve an address to its containing function.

    Returns a Ghidra Function object. Raises :class:`GhidraError` if not found.
    """
    from re_mcp_ghidra.session import session  # noqa: PLC0415

    program = session.program
    if program is None:
        raise GhidraError("No database is open", error_type="NoDatabase")

    ghidra_addr = resolve_address(addr)
    func = program.getFunctionManager().getFunctionContaining(ghidra_addr)
    if func is None:
        raise GhidraError(
            f"No function at {format_address(ghidra_addr.getOffset())}",
            error_type="NotFound",
        )
    return func


# ---------------------------------------------------------------------------
# Ghidra-specific permission formatting
# ---------------------------------------------------------------------------


def format_permissions(read: bool, write: bool, execute: bool) -> str:
    """Format permission flags as a string like ``"RWX"``."""
    s = "R" if read else "-"
    s += "W" if write else "-"
    s += "X" if execute else "-"
    return s
