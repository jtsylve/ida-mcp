# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Data creation tools — define bytes, words, dwords, strings, arrays at addresses."""

from __future__ import annotations

from typing import Annotated

import ida_bytes
import ida_idaapi
import ida_nalt
from fastmcp import FastMCP
from pydantic import Field

from ida_mcp.helpers import (
    ANNO_MUTATE,
    Address,
    IDAError,
    format_address,
    get_old_item_info,
    resolve_address,
)
from ida_mcp.models import MakeArrayResult, MakeDataResult, MakeStringResult
from ida_mcp.session import session

_MAX_COUNT = 1_000_000


def _create_typed_data(ea: int, flag_fn, elem_size: int, count: int) -> bool:
    """Create a data item (or array) using the correct create_data signature.

    ``create_data(ea, flags, total_size, tid)`` — *tid* is a type ID
    (e.g. structure ID); for basic types it must be BADADDR.
    *count* must be >= 1.
    """
    total = elem_size * count
    return ida_bytes.create_data(ea, flag_fn(), total, ida_idaapi.BADADDR)


def _validate_count(count: int) -> None:
    if count < 1:
        raise IDAError(f"Count must be >= 1, got {count}", error_type="InvalidArgument")
    if count > _MAX_COUNT:
        raise IDAError(f"Count too large ({count}), max {_MAX_COUNT}", error_type="InvalidArgument")


def _make_data_tool(mcp: FastMCP, type_name: str, flag_fn, elem_size: int, doc: str):
    """Register a make_<type> tool using the common pattern."""

    @mcp.tool(
        name=f"make_{type_name}",
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def _tool(
        address: Address,
        count: Annotated[
            int, Field(description="Number of elements (>1 creates an array).", ge=1)
        ] = 1,
    ) -> MakeDataResult:
        ea = resolve_address(address)
        _validate_count(count)

        old_item_type, old_item_size = get_old_item_info(ea)
        if not _create_typed_data(ea, flag_fn, elem_size, count):
            raise IDAError(
                f"Failed to define {type_name}(s) at {format_address(ea)}",
                error_type="MakeDataFailed",
            )
        return MakeDataResult(
            address=format_address(ea),
            old_item_type=old_item_type,
            old_item_size=old_item_size,
            size=elem_size * count,
        )

    _tool.__doc__ = doc
    return _tool


_DATA_TYPES = [
    (
        "byte",
        ida_bytes.byte_flag,
        1,
        "Define data as byte(s) at an address.\n\nArgs:\n    address: Address to define.\n    count: Number of bytes (>1 creates an array).",
    ),
    (
        "word",
        ida_bytes.word_flag,
        2,
        "Define data as 16-bit word(s) at an address.\n\nArgs:\n    address: Address to define.\n    count: Number of words (>1 creates an array).",
    ),
    (
        "dword",
        ida_bytes.dword_flag,
        4,
        "Define data as 32-bit dword(s) at an address.\n\nArgs:\n    address: Address to define.\n    count: Number of dwords (>1 creates an array).",
    ),
    (
        "qword",
        ida_bytes.qword_flag,
        8,
        "Define data as 64-bit qword(s) at an address.\n\nArgs:\n    address: Address to define.\n    count: Number of qwords (>1 creates an array).",
    ),
    (
        "float",
        ida_bytes.float_flag,
        4,
        "Define data as 32-bit float(s) at an address.\n\nArgs:\n    address: Address to define.\n    count: Number of floats (>1 creates an array).",
    ),
    (
        "double",
        ida_bytes.double_flag,
        8,
        "Define data as 64-bit double(s) at an address.\n\nArgs:\n    address: Address to define.\n    count: Number of doubles (>1 creates an array).",
    ),
]


def register(mcp: FastMCP):
    for type_name, flag_fn, elem_size, doc in _DATA_TYPES:
        _make_data_tool(mcp, type_name, flag_fn, elem_size, doc)

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def make_string(
        address: Address,
        length: int = 0,
        string_type: str = "c",
    ) -> MakeStringResult:
        """Define data as a string at an address.

        Args:
            address: Address of the string.
            length: String length in bytes (0 for auto-detect null-terminated).
            string_type: String encoding — "c" (ASCII), "utf16" (wide), "utf32".
        """
        ea = resolve_address(address)

        type_map = {
            "c": ida_nalt.STRTYPE_C,
            "utf16": ida_nalt.STRTYPE_C_16,
            "utf32": ida_nalt.STRTYPE_C_32,
        }
        strtype = type_map.get(string_type)
        if strtype is None:
            raise IDAError(
                f"Invalid string type: {string_type!r}",
                error_type="InvalidArgument",
                valid_types=list(type_map),
            )

        old_item_type, old_item_size = get_old_item_info(ea)
        if not ida_bytes.create_strlit(ea, length, strtype):
            raise IDAError(
                f"Failed to define string at {format_address(ea)}", error_type="MakeDataFailed"
            )
        return MakeStringResult(
            address=format_address(ea),
            old_item_type=old_item_type,
            old_item_size=old_item_size,
            length=length,
            string_type=string_type,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def make_array(
        address: Address,
        element_size: int,
        count: Annotated[int, Field(description="Number of elements in the array.", ge=1)],
    ) -> MakeArrayResult:
        """Create an array of data elements at an address.

        Args:
            address: Address of the array start.
            element_size: Size of each element in bytes (1, 2, 4, or 8).
            count: Number of elements in the array.
        """
        ea = resolve_address(address)
        _validate_count(count)

        flag_map = {
            1: ida_bytes.byte_flag,
            2: ida_bytes.word_flag,
            4: ida_bytes.dword_flag,
            8: ida_bytes.qword_flag,
        }
        flag_fn = flag_map.get(element_size)
        if flag_fn is None:
            raise IDAError(
                f"Invalid element size: {element_size}. Must be 1, 2, 4, or 8.",
                error_type="InvalidArgument",
            )

        old_item_type, old_item_size = get_old_item_info(ea)
        if not _create_typed_data(ea, flag_fn, element_size, count):
            raise IDAError(
                f"Failed to create array at {format_address(ea)}", error_type="MakeDataFailed"
            )
        return MakeArrayResult(
            address=format_address(ea),
            old_item_type=old_item_type,
            old_item_size=old_item_size,
            element_size=element_size,
            count=count,
            total_size=element_size * count,
        )
