# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Batch export tools for disassembly and pseudocode."""

from __future__ import annotations

import re

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.helpers import (
    ANNO_READ_ONLY,
    FilterPattern,
    Limit,
    Offset,
    compile_filter,
    format_address,
    paginate,
)
from re_mcp_ghidra.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ExportedPseudocode(BaseModel):
    """Exported pseudocode for a function."""

    name: str = Field(description="Function name.")
    address: str = Field(description="Function address (hex).")
    pseudocode: str = Field(description="Decompiled pseudocode.")


class ExportError(BaseModel):
    """An error during batch export."""

    name: str = Field(description="Function name.")
    address: str = Field(description="Function address (hex).")
    error: str = Field(description="Error message.")


class ExportPseudocodeResult(BaseModel):
    """Result of batch pseudocode export."""

    functions: list[ExportedPseudocode] = Field(description="Exported functions.")
    errors: list[ExportError] = Field(description="Functions that failed.")
    total: int = Field(description="Total matching functions.")
    offset: int = Field(description="Starting offset.")
    limit: int = Field(description="Maximum functions per page.")
    has_more: bool = Field(description="Whether more functions exist.")


class ExportedDisassembly(BaseModel):
    """Exported disassembly for a function."""

    name: str = Field(description="Function name.")
    address: str = Field(description="Function address (hex).")
    instruction_count: int = Field(description="Number of instructions.")
    disassembly: str = Field(description="Disassembly text.")


class ExportDisassemblyResult(BaseModel):
    """Result of batch disassembly export."""

    functions: list[ExportedDisassembly] = Field(description="Exported functions.")
    total: int = Field(description="Total matching functions.")
    offset: int = Field(description="Starting offset.")
    limit: int = Field(description="Maximum functions per page.")
    has_more: bool = Field(description="Whether more functions exist.")


def _matching_functions(program, pattern: re.Pattern | None) -> list[tuple[object, str]]:
    """Collect (Function, name) tuples for functions matching *pattern*."""
    func_mgr = program.getFunctionManager()
    results = []
    func_iter = func_mgr.getFunctions(True)
    while func_iter.hasNext():
        func = func_iter.next()
        name = func.getName()
        if pattern and not pattern.search(name):
            continue
        results.append((func, name))
    return results


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"export", "decompiler"})
    @session.require_open
    def export_all_pseudocode(
        filter_pattern: FilterPattern = "",
        offset: Offset = 0,
        limit: Limit = 50,
    ) -> ExportPseudocodeResult:
        """Decompile MANY functions in one call (expensive -- seconds each).

        Expensive: decompiles functions sequentially -- each may take seconds.
        A request for 50 functions can take minutes. Prefer using
        list_functions with filter_pattern to identify targets, then call
        decompile_function individually on functions of interest. Use
        filter_pattern here to restrict output to relevant functions (e.g.
        "crypto|decrypt") rather than decompiling everything.

        Args:
            filter_pattern: Optional regex to filter function names.
            offset: Pagination offset (by function index).
            limit: Maximum number of functions to decompile.
        """
        from ghidra.app.decompiler import DecompInterface  # noqa: PLC0415
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        program = session.program
        pattern = compile_filter(filter_pattern)
        candidates = _matching_functions(program, pattern)
        page = paginate(candidates, offset, limit)

        decomp = DecompInterface()
        decomp.openProgram(program)

        results = []
        errors = []
        try:
            for func, name in page["items"]:
                addr = func.getEntryPoint()
                try:
                    dr = decomp.decompileFunction(func, 60, TaskMonitor.DUMMY)
                    if not dr.decompileCompleted():
                        errors.append(
                            ExportError(
                                name=name,
                                address=format_address(addr.getOffset()),
                                error=dr.getErrorMessage() or "Decompilation failed",
                            )
                        )
                        continue

                    decomp_func = dr.getDecompiledFunction()
                    if decomp_func is None:
                        errors.append(
                            ExportError(
                                name=name,
                                address=format_address(addr.getOffset()),
                                error="Decompilation returned no result",
                            )
                        )
                        continue

                    results.append(
                        ExportedPseudocode(
                            name=name,
                            address=format_address(addr.getOffset()),
                            pseudocode=decomp_func.getC(),
                        )
                    )
                except Exception as e:
                    errors.append(
                        ExportError(
                            name=name,
                            address=format_address(addr.getOffset()),
                            error=str(e),
                        )
                    )
        finally:
            decomp.dispose()

        return ExportPseudocodeResult(
            functions=results,
            errors=errors,
            total=page["total"],
            offset=page["offset"],
            limit=page["limit"],
            has_more=page["has_more"],
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"export", "disassembly"})
    @session.require_open
    def export_all_disassembly(
        filter_pattern: FilterPattern = "",
        offset: Offset = 0,
        limit: Limit = 50,
    ) -> ExportDisassemblyResult:
        """Disassemble MANY functions in one call (paginated, regex-filterable).

        Much faster than export_all_pseudocode (no decompilation needed),
        but still processes multiple functions. Use filter_pattern to
        restrict output to relevant function groups.

        Args:
            filter_pattern: Optional regex to filter function names.
            offset: Pagination offset (by function index).
            limit: Maximum number of functions to export.
        """
        program = session.program
        listing = program.getListing()
        pattern = compile_filter(filter_pattern)
        candidates = _matching_functions(program, pattern)
        page = paginate(candidates, offset, limit)

        results = []
        for func, name in page["items"]:
            body = func.getBody()
            entry = func.getEntryPoint()
            lines = []
            insn_iter = listing.getInstructions(body, True)
            while insn_iter.hasNext():
                insn = insn_iter.next()
                addr = insn.getAddress()
                operands = []
                for i in range(insn.getNumOperands()):
                    op_str = insn.getDefaultOperandRepresentation(i)
                    if op_str:
                        operands.append(op_str)
                op_text = ", ".join(operands)
                mnemonic = insn.getMnemonicString()
                line = f"{format_address(addr.getOffset())}  {mnemonic}"
                if op_text:
                    line += f"  {op_text}"
                lines.append(line)

            results.append(
                ExportedDisassembly(
                    name=name,
                    address=format_address(entry.getOffset()),
                    instruction_count=len(lines),
                    disassembly="\n".join(lines),
                )
            )

        return ExportDisassemblyResult(
            functions=results,
            total=page["total"],
            offset=page["offset"],
            limit=page["limit"],
            has_more=page["has_more"],
        )
