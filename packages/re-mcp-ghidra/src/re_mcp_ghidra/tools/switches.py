# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Switch/jump table analysis tools."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_READ_ONLY,
    Address,
    Limit,
    Offset,
    format_address,
    paginate_iter,
    resolve_address,
)
from re_mcp_ghidra.session import session


class SwitchCase(BaseModel):
    """A switch case entry."""

    case_values: list[int] = Field(description="Case values mapping to this target.")
    target: str = Field(description="Target address (hex).")


class GetSwitchInfoResult(BaseModel):
    """Switch table information at a computed jump."""

    address: str = Field(description="Switch instruction address (hex).")
    num_cases: int = Field(description="Number of switch cases.")
    cases: list[SwitchCase] = Field(description="Switch cases.")


class SwitchSummary(BaseModel):
    """Brief switch info."""

    address: str = Field(description="Switch instruction address (hex).")
    function: str = Field(description="Containing function name.")
    num_cases: int = Field(description="Number of reference targets.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def get_switch_info(address: Address) -> GetSwitchInfoResult:
        """Get switch/jump table structure at a computed jump instruction.

        Examines the instruction at the given address for a computed jump
        (indirect jump) and returns the reference targets that form the
        switch table.

        Args:
            address: Address of the switch/indirect jump instruction.
        """
        program = session.program
        listing = program.getListing()
        ref_mgr = program.getReferenceManager()
        addr = resolve_address(address)

        insn = listing.getInstructionAt(addr)
        if insn is None:
            raise GhidraError(
                f"No instruction at {format_address(addr.getOffset())}",
                error_type="NotFound",
            )

        # Check if this instruction has a computed jump flow type
        flow = insn.getFlowType()
        if not flow.isComputed() or not flow.isJump():
            raise GhidraError(
                f"Instruction at {format_address(addr.getOffset())} is not a computed jump",
                error_type="NotFound",
            )

        # Collect reference targets from this instruction
        refs = ref_mgr.getReferencesFrom(addr)
        targets: dict[int, list[int]] = {}
        for ref in refs:
            to_addr = ref.getToAddress()
            offset = to_addr.getOffset()
            # Group by target address; case values are not directly available
            # in Ghidra's reference model, so we use sequential indices
            if offset not in targets:
                targets[offset] = []

        cases = []
        for i, (target_offset, _) in enumerate(sorted(targets.items())):
            cases.append(
                SwitchCase(
                    case_values=[i],
                    target=format_address(target_offset),
                )
            )

        return GetSwitchInfoResult(
            address=format_address(addr.getOffset()),
            num_cases=len(cases),
            cases=cases,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def list_switches(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """Find all switch/jump tables by scanning for computed jump instructions.

        Iterates all functions and finds instructions with computed jump
        flow types. May be slow on large binaries.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        program = session.program
        listing = program.getListing()
        func_mgr = program.getFunctionManager()
        ref_mgr = program.getReferenceManager()

        def _gen():
            func_iter = func_mgr.getFunctions(True)
            while func_iter.hasNext():
                func = func_iter.next()
                body = func.getBody()
                insn_iter = listing.getInstructions(body, True)
                while insn_iter.hasNext():
                    insn = insn_iter.next()
                    flow = insn.getFlowType()
                    if flow.isComputed() and flow.isJump():
                        addr = insn.getAddress()
                        refs = ref_mgr.getReferencesFrom(addr)
                        num_targets = sum(1 for _ in refs)
                        yield SwitchSummary(
                            address=format_address(addr.getOffset()),
                            function=func.getName(),
                            num_cases=num_targets,
                        ).model_dump()

        return paginate_iter(_gen(), offset, limit)
