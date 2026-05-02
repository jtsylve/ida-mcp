# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Utility tools — number conversion."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ghidra_mcp.exceptions import GhidraError
from ghidra_mcp.helpers import ANNO_READ_ONLY


class ConvertNumberResult(BaseModel):
    """Number in multiple bases."""

    decimal: str = Field(description="Decimal representation.")
    hex: str = Field(description="Hexadecimal representation.")
    octal: str = Field(description="Octal representation.")
    binary: str = Field(description="Binary representation.")
    signed_32: int | None = Field(description="Signed 32-bit interpretation.")
    signed_64: int | None = Field(description="Signed 64-bit interpretation.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"utility"})
    def convert_number(value: str) -> ConvertNumberResult:
        """Convert a number between hex, decimal, octal, and binary representations.

        This is useful because LLMs frequently make errors with base conversions.
        Also returns signed 32-bit and 64-bit interpretations when the value fits,
        useful for understanding sign-extended values in disassembly.

        Args:
            value: Number to convert (prefix with 0x for hex, 0o for octal, 0b for binary).
        """
        value = value.strip()
        try:
            if value.lower().startswith("0x"):
                n = int(value, 16)
            elif value.lower().startswith("0o"):
                n = int(value, 8)
            elif value.lower().startswith("0b"):
                n = int(value, 2)
            else:
                n = int(value, 0)
        except ValueError:
            raise GhidraError(
                f"Cannot parse number: {value!r}", error_type="InvalidArgument"
            ) from None

        # Compute signed value for common widths
        signed_32 = n if n < 0x80000000 else n - 0x100000000
        signed_64 = n if n < 0x8000000000000000 else n - 0x10000000000000000

        return ConvertNumberResult(
            decimal=str(n),
            hex=hex(n),
            octal=oct(n),
            binary=bin(n),
            signed_32=signed_32 if 0 <= n <= 0xFFFFFFFF else None,
            signed_64=signed_64 if 0 <= n <= 0xFFFFFFFFFFFFFFFF else None,
        )
