# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Program rebasing tools."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ghidra_mcp.exceptions import GhidraError
from ghidra_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    format_address,
    parse_address,
)
from ghidra_mcp.session import session


class RebaseProgramResult(BaseModel):
    """Result of rebasing the program."""

    old_base: str = Field(description="Previous image base address (hex).")
    new_base: str = Field(description="New image base address (hex).")
    delta: str = Field(description="Rebase delta (hex).")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"segments"})
    @session.require_open
    def rebase_program(delta: str) -> RebaseProgramResult:
        """Shift all addresses by a signed delta (destructive, global).

        Computes a new image base by adding the delta to the current base
        and calls ``program.setImageBase()``.

        Args:
            delta: Address delta to shift by (e.g. "0x1000" to shift forward,
                "-0x1000" to shift back).
        """
        try:
            delta_val = -parse_address(delta[1:]) if delta.startswith("-") else parse_address(delta)
        except ValueError as e:
            raise GhidraError(str(e), error_type="InvalidAddress") from e

        program = session.program
        old_base = program.getImageBase()
        old_offset = old_base.getOffset()

        new_offset = old_offset + delta_val
        addr_factory = program.getAddressFactory()
        new_base = addr_factory.getDefaultAddressSpace().getAddress(new_offset)

        tx_id = program.startTransaction("Rebase program")
        try:
            program.setImageBase(new_base, True)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to rebase program: {e}", error_type="RebaseFailed") from e

        delta_str = (
            format_address(delta_val) if delta_val >= 0 else f"-{format_address(-delta_val)}"
        )

        return RebaseProgramResult(
            old_base=format_address(old_offset),
            new_base=format_address(new_offset),
            delta=delta_str,
        )
