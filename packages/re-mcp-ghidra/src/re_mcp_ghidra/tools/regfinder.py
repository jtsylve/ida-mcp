# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Register value tracking tools (simplified).

Full register tracking in Ghidra headless mode would require PCode
emulation. This module provides a simplified heuristic that examines
preceding instructions for scalar loads into the requested register.
"""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_READ_ONLY,
    Address,
    format_address,
    resolve_address,
)
from re_mcp_ghidra.session import session


class FindRegisterValueResult(BaseModel):
    """Result of finding a register value."""

    address: str = Field(description="Address (hex).")
    register_name: str = Field(description="Register name.")
    found: bool = Field(description="Whether the value was determined.")
    reason: str | None = Field(default=None, description="Reason value could not be determined.")
    value: str | None = Field(default=None, description="Register value (hex).")
    source_address: str | None = Field(
        default=None, description="Address of the instruction that set the value (hex)."
    )


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def find_register_value(
        address: Address,
        register_name: str,
    ) -> FindRegisterValueResult:
        """Try to determine a register value at an address by examining preceding instructions.

        This is a simplified heuristic that walks backwards from the given
        address looking for scalar loads (MOV, LEA, etc.) into the target
        register. Does not perform full dataflow or PCode emulation.

        Args:
            address: Address at which to find the register value.
            register_name: Register name (e.g. "RAX", "EAX", "R8", "ECX").
        """
        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)

        # Validate that the register exists for this processor
        lang = program.getLanguage()
        reg = lang.getRegister(register_name)
        if reg is None:
            # Try case-insensitive lookup
            reg = lang.getRegister(register_name.upper())
            if reg is None:
                reg = lang.getRegister(register_name.lower())
            if reg is None:
                raise GhidraError(
                    f"Unknown register: {register_name!r}",
                    error_type="InvalidArgument",
                )

        # Walk backwards up to 32 instructions looking for a scalar assignment
        current = listing.getInstructionAt(addr)
        if current is None:
            raise GhidraError(
                f"No instruction at {format_address(addr.getOffset())}",
                error_type="NotFound",
            )

        max_lookback = 32
        insn = current.getPrevious()
        for _ in range(max_lookback):
            if insn is None:
                break

            # Check each operand: if the instruction writes to our register
            # and has a scalar source, we found a candidate
            num_operands = insn.getNumOperands()
            for _op_idx in range(num_operands):
                result_objs = insn.getResultObjects()
                for obj in result_objs:
                    # Check if this result is our target register
                    if hasattr(obj, "getName") and obj.getName() == reg.getName():
                        # Look for scalar input operands
                        for inp_idx in range(num_operands):
                            scalars = insn.getScalar(inp_idx)
                            if scalars is not None:
                                value = scalars.getUnsignedValue()
                                return FindRegisterValueResult(
                                    address=format_address(addr.getOffset()),
                                    register_name=register_name,
                                    found=True,
                                    value=format_address(value),
                                    source_address=format_address(insn.getAddress().getOffset()),
                                )
                        # Found write to register but no scalar source
                        break

            insn = insn.getPrevious()

        return FindRegisterValueResult(
            address=format_address(addr.getOffset()),
            register_name=register_name,
            found=False,
            reason="Could not determine value by backward scan (no scalar load found within 32 instructions)",
        )
