# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Data creation tools — define bytes, words, dwords, strings, arrays at addresses."""

from __future__ import annotations

from typing import Annotated, Literal

import ida_bytes
import ida_idaapi
import ida_nalt
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ida.helpers import (
    ANNO_MUTATE,
    Address,
    IDAError,
    format_address,
    get_old_item_info,
    resolve_address,
)
from re_mcp_ida.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class MakeDataResult(BaseModel):
    """Result of a make-data operation (byte/word/dword/qword/float/double)."""

    address: str = Field(description="Target address (hex).")
    old_item_type: str = Field(description="Previous item type at address.")
    old_item_size: int = Field(description="Previous item size in bytes.")
    size: int = Field(description="New data item size in bytes.")


class MakeStringResult(BaseModel):
    """Result of creating a string."""

    address: str = Field(description="String address (hex).")
    old_item_type: str = Field(description="Previous item type at address.")
    old_item_size: int = Field(description="Previous item size in bytes.")
    length: int = Field(description="String length.")
    string_type: str = Field(description="String encoding type.")


class MakeArrayResult(BaseModel):
    """Result of creating an array."""

    address: str = Field(description="Array address (hex).")
    old_item_type: str = Field(description="Previous item type at address.")
    old_item_size: int = Field(description="Previous item size in bytes.")
    element_size: int = Field(description="Size of each element in bytes.")
    count: int = Field(description="Number of elements.")
    total_size: int = Field(description="Total array size in bytes.")


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


def _make_data(ea: int, type_name: str, flag_fn, elem_size: int, count: int) -> MakeDataResult:
    """Shared implementation for all make_<type> tools."""
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


_DATA_TYPE_MAP = {
    "byte": (ida_bytes.byte_flag, 1),
    "word": (ida_bytes.word_flag, 2),
    "dword": (ida_bytes.dword_flag, 4),
    "qword": (ida_bytes.qword_flag, 8),
    "float": (ida_bytes.float_flag, 4),
    "double": (ida_bytes.double_flag, 8),
}

_SIZE_TO_FLAG = {
    1: ida_bytes.byte_flag,
    2: ida_bytes.word_flag,
    4: ida_bytes.dword_flag,
    8: ida_bytes.qword_flag,
}


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"modification"},
    )
    @session.require_open
    def make_data(
        address: Address,
        data_type: Literal["byte", "word", "dword", "qword", "float", "double"],
        count: Annotated[
            int, Field(description="Number of elements (>1 creates an array).", ge=1)
        ] = 1,
    ) -> MakeDataResult:
        """Mark bytes as a primitive data type (byte/word/dword/qword/float/double).

        Args:
            address: Address to define.
            data_type: Data type — "byte", "word" (16-bit), "dword" (32-bit),
                "qword" (64-bit), "float" (32-bit), or "double" (64-bit).
            count: Number of elements (>1 creates an array).
        """
        flag_fn, elem_size = _DATA_TYPE_MAP[data_type]
        return _make_data(resolve_address(address), data_type, flag_fn, elem_size, count)

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
        """Mark bytes as a C/Pascal/Unicode string (auto-sized if length omitted).

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
        """Mark a contiguous run of bytes as an array of an already-defined typed element.

        Args:
            address: Address of the array start.
            element_size: Size of each element in bytes (1, 2, 4, or 8).
            count: Number of elements in the array.
        """
        ea = resolve_address(address)
        _validate_count(count)

        flag_fn = _SIZE_TO_FLAG.get(element_size)
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
