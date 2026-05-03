# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Data type definition tools -- define bytes, words, strings, arrays at addresses."""

from __future__ import annotations

from typing import Annotated, Literal

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_MUTATE,
    Address,
    format_address,
    resolve_address,
)
from re_mcp_ghidra.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class MakeDataResult(BaseModel):
    """Result of a make-data operation (byte/word/dword/qword/float/double)."""

    address: str = Field(description="Target address (hex).")
    data_type: str = Field(description="Data type applied.")
    size: int = Field(description="Total data size in bytes.")
    count: int = Field(description="Number of elements.")
    status: str = Field(description="Operation status.")


class MakeStringResult(BaseModel):
    """Result of creating a string."""

    address: str = Field(description="String address (hex).")
    length: int = Field(description="String length in bytes.")
    string_type: str = Field(description="String encoding type.")
    status: str = Field(description="Operation status.")


class MakeArrayResult(BaseModel):
    """Result of creating an array."""

    address: str = Field(description="Array address (hex).")
    element_size: int = Field(description="Size of each element in bytes.")
    count: int = Field(description="Number of elements.")
    total_size: int = Field(description="Total array size in bytes.")
    status: str = Field(description="Operation status.")


_MAX_COUNT = 1_000_000


def _validate_count(count: int) -> None:
    if count < 1:
        raise GhidraError(f"Count must be >= 1, got {count}", error_type="InvalidArgument")
    if count > _MAX_COUNT:
        raise GhidraError(
            f"Count too large ({count}), max {_MAX_COUNT}", error_type="InvalidArgument"
        )


def _get_data_type(type_name: str):
    """Return a Ghidra DataType for the given type name."""
    from ghidra.program.model.data import (  # noqa: PLC0415
        ByteDataType,
        DoubleDataType,
        FloatDataType,
        QWordDataType,
        WordDataType,
    )
    from ghidra.program.model.data import DWordDataType as DWordDT  # noqa: PLC0415

    type_map = {
        "byte": (ByteDataType.dataType, 1),
        "word": (WordDataType.dataType, 2),
        "dword": (DWordDT.dataType, 4),
        "qword": (QWordDataType.dataType, 8),
        "float": (FloatDataType.dataType, 4),
        "double": (DoubleDataType.dataType, 8),
    }
    entry = type_map.get(type_name)
    if entry is None:
        raise GhidraError(
            f"Unknown data type: {type_name!r}. Valid: {', '.join(type_map)}",
            error_type="InvalidArgument",
        )
    return entry


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"modification"})
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
            data_type: Data type -- "byte", "word" (16-bit), "dword" (32-bit),
                "qword" (64-bit), "float" (32-bit), or "double" (64-bit).
            count: Number of elements (>1 creates an array).
        """
        from ghidra.program.model.data import ArrayDataType  # noqa: PLC0415

        _validate_count(count)
        dt, elem_size = _get_data_type(data_type)
        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)

        tx_id = program.startTransaction("Make data")
        try:
            # Clear existing data first
            listing.clearCodeUnits(addr, addr.add(elem_size * count - 1), False)

            if count > 1:
                arr_dt = ArrayDataType(dt, count, elem_size)
                listing.createData(addr, arr_dt)
            else:
                listing.createData(addr, dt)

            program.endTransaction(tx_id, True)
        except GhidraError:
            program.endTransaction(tx_id, False)
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to define {data_type} at {format_address(addr.getOffset())}: {e}",
                error_type="MakeDataFailed",
            ) from e

        return MakeDataResult(
            address=format_address(addr.getOffset()),
            data_type=data_type,
            size=elem_size * count,
            count=count,
            status="ok",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"modification"})
    @session.require_open
    def make_string(
        address: Address,
        length: int = 0,
        string_type: str = "c",
    ) -> MakeStringResult:
        """Mark bytes as a string (auto-detect length if omitted).

        Args:
            address: Address of the string.
            length: String length in bytes (0 for auto-detect null-terminated).
            string_type: String encoding -- "c" (ASCII/UTF-8), "utf16" (UTF-16),
                "utf32" (UTF-32).
        """
        from ghidra.program.model.data import (  # noqa: PLC0415
            StringDataType,
            TerminatedStringDataType,
            TerminatedUnicode32DataType,
            UnicodeDataType,
        )

        type_map = {
            "c": TerminatedStringDataType.dataType,
            "utf16": UnicodeDataType.dataType,
            "utf32": TerminatedUnicode32DataType.dataType,
        }
        dt = type_map.get(string_type)
        if dt is None:
            raise GhidraError(
                f"Invalid string type: {string_type!r}. Valid: {', '.join(type_map)}",
                error_type="InvalidArgument",
            )

        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)

        tx_id = program.startTransaction("Make string")
        try:
            if length > 0:
                listing.clearCodeUnits(addr, addr.add(length - 1), False)
                # For fixed-length strings, use plain StringDataType with explicit length
                listing.createData(addr, StringDataType.dataType, length)
            else:
                # Auto-detect length by clearing a reasonable area and using terminated type
                # Clear conservatively -- 1 byte at minimum for the terminated type to probe
                listing.clearCodeUnits(addr, addr, False)
                listing.createData(addr, dt)

            # Read back the actual length
            created = listing.getDataAt(addr)
            actual_length = created.getLength() if created else length

            program.endTransaction(tx_id, True)
        except GhidraError:
            program.endTransaction(tx_id, False)
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to define string at {format_address(addr.getOffset())}: {e}",
                error_type="MakeDataFailed",
            ) from e

        return MakeStringResult(
            address=format_address(addr.getOffset()),
            length=actual_length,
            string_type=string_type,
            status="ok",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"modification"})
    @session.require_open
    def make_array(
        address: Address,
        element_size: int,
        count: Annotated[int, Field(description="Number of elements in the array.", ge=1)],
    ) -> MakeArrayResult:
        """Mark a contiguous run of bytes as an array.

        Args:
            address: Address of the array start.
            element_size: Size of each element in bytes (1, 2, 4, or 8).
            count: Number of elements in the array.
        """
        from ghidra.program.model.data import (  # noqa: PLC0415
            ArrayDataType,
            ByteDataType,
            QWordDataType,
            WordDataType,
        )
        from ghidra.program.model.data import DWordDataType as DWordDT  # noqa: PLC0415

        _validate_count(count)

        size_to_dt = {
            1: ByteDataType.dataType,
            2: WordDataType.dataType,
            4: DWordDT.dataType,
            8: QWordDataType.dataType,
        }
        elem_dt = size_to_dt.get(element_size)
        if elem_dt is None:
            raise GhidraError(
                f"Invalid element size: {element_size}. Must be 1, 2, 4, or 8.",
                error_type="InvalidArgument",
            )

        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)
        total_size = element_size * count

        tx_id = program.startTransaction("Make array")
        try:
            listing.clearCodeUnits(addr, addr.add(total_size - 1), False)
            arr_dt = ArrayDataType(elem_dt, count, element_size)
            listing.createData(addr, arr_dt)
            program.endTransaction(tx_id, True)
        except GhidraError:
            program.endTransaction(tx_id, False)
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to create array at {format_address(addr.getOffset())}: {e}",
                error_type="MakeDataFailed",
            ) from e

        return MakeArrayResult(
            address=format_address(addr.getOffset()),
            element_size=element_size,
            count=count,
            total_size=total_size,
            status="ok",
        )
