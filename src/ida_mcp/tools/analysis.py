# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Auto-analysis control, problem tracking, and fixup tools."""

from __future__ import annotations

import ida_auto
import ida_entry
import ida_fixup
import ida_funcs
import ida_ida
import ida_problems
import ida_range
import ida_segment
import ida_strlist
import ida_tryblks
import idc
from fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

from ida_mcp.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    IDAError,
    Limit,
    Offset,
    check_cancelled,
    format_address,
    get_func_name,
    is_bad_addr,
    paginate_iter,
    resolve_address,
    resolve_function,
)
from ida_mcp.models import PaginatedResult
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class AnalysisCompleteResult(BaseModel):
    """Result of waiting for analysis to complete, with a database summary."""

    status: str = Field(description="Status message.")
    function_count: int = Field(description="Number of functions after analysis.")
    segment_count: int = Field(description="Number of segments.")
    entry_point_count: int = Field(description="Number of entry points.")
    string_count: int = Field(description="Number of strings in the binary.")
    min_address: str = Field(description="Minimum address (hex).")
    max_address: str = Field(description="Maximum address (hex).")


class ReanalyzeRangeResult(BaseModel):
    """Result of reanalyzing a range."""

    start: str = Field(description="Range start address (hex).")
    end: str = Field(description="Range end address (hex).")
    status: str = Field(description="Status message.")


class AnalysisProblem(BaseModel):
    """An analysis problem."""

    address: str = Field(description="Problem address (hex).")
    type: str = Field(description="Problem type.")
    function: str = Field(description="Containing function name.")


class AnalysisProblemListResult(PaginatedResult[AnalysisProblem]):
    """Paginated list of analysis problems."""

    items: list[AnalysisProblem] = Field(description="Page of analysis problems.")


class FixupItem(BaseModel):
    """A fixup entry."""

    address: str = Field(description="Fixup address (hex).")
    type: str = Field(description="Fixup type.")
    target: str = Field(description="Fixup target address (hex).")


class FixupListResult(PaginatedResult[FixupItem]):
    """Paginated list of fixups."""

    items: list[FixupItem] = Field(description="Page of fixups.")


class CatchBlock(BaseModel):
    """A catch block in an exception handler."""

    start: str = Field(description="Catch block start address (hex).")
    end: str = Field(description="Catch block end address (hex).")


class TryBlock(BaseModel):
    """A try block with its catch handlers."""

    try_start: str = Field(description="Try block start address (hex).")
    try_end: str = Field(description="Try block end address (hex).")
    catches: list[CatchBlock] = Field(description="Catch blocks.")


class GetExceptionHandlersResult(BaseModel):
    """Exception handlers for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    tryblock_count: int = Field(description="Number of try blocks.")
    tryblocks: list[TryBlock] = Field(description="Try blocks.")


class GetSegmentRegistersResult(BaseModel):
    """Segment register values at an address."""

    address: str = Field(description="Address (hex).")
    registers: dict[str, str] = Field(description="Register name to value mapping.")


class SetSegmentRegisterResult(BaseModel):
    """Result of setting a segment register."""

    model_config = ConfigDict(populate_by_name=True)

    address: str = Field(description="Address (hex).")
    register_: str = Field(alias="register", description="Register name.")
    old_value: str | None = Field(description="Previous value.")
    value: str = Field(description="New value.")


_PROBLEM_TYPES = [
    (ida_problems.PR_NOBASE, "no_base"),
    (ida_problems.PR_NONAME, "no_name"),
    (ida_problems.PR_NOCMT, "no_comment"),
    (ida_problems.PR_NOXREFS, "no_xrefs"),
    (ida_problems.PR_JUMP, "jump"),
    (ida_problems.PR_DISASM, "disasm"),
    (ida_problems.PR_HEAD, "head"),
    (ida_problems.PR_ILLADDR, "illegal_address"),
    (ida_problems.PR_MANYLINES, "many_lines"),
    (ida_problems.PR_BADSTACK, "bad_stack"),
    (ida_problems.PR_ATTN, "attention"),
    (ida_problems.PR_FINAL, "final"),
    (ida_problems.PR_ROLLED, "rolled"),
    (ida_problems.PR_COLLISION, "collision"),
]

_FIXUP_TYPES = {
    ida_fixup.FIXUP_OFF8: "off8",
    ida_fixup.FIXUP_OFF16: "off16",
    ida_fixup.FIXUP_SEG16: "seg16",
    ida_fixup.FIXUP_OFF32: "off32",
    ida_fixup.FIXUP_OFF64: "off64",
    ida_fixup.FIXUP_CUSTOM: "custom",
}


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"analysis"},
    )
    @session.require_open
    def reanalyze_range(
        start_address: Address,
        end_address: Address,
    ) -> ReanalyzeRangeResult:
        """Trigger IDA auto-analysis on an address range.

        Useful after patching bytes or changing types to update analysis.

        Args:
            start_address: Start of the range.
            end_address: End of the range (exclusive).
        """
        start = resolve_address(start_address)
        end = resolve_address(end_address)

        ida_auto.plan_and_wait(start, end)

        return ReanalyzeRangeResult(
            start=format_address(start),
            end=format_address(end),
            status="analysis_complete",
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"analysis"},
    )
    @session.require_open
    def wait_for_analysis() -> AnalysisCompleteResult:
        """Wait for IDA's auto-analysis to complete.

        Call this after making changes (patches, type applications) to ensure
        the database is fully analyzed before querying. Returns a summary of
        database statistics after analysis finishes so you can sanity-check
        results without extra round trips.
        """
        ida_auto.auto_wait()

        return AnalysisCompleteResult(
            status="analysis_complete",
            function_count=ida_funcs.get_func_qty(),
            segment_count=ida_segment.get_segm_qty(),
            entry_point_count=ida_entry.get_entry_qty(),
            string_count=ida_strlist.get_strlist_qty(),
            min_address=format_address(ida_ida.inf_get_min_ea()),
            max_address=format_address(ida_ida.inf_get_max_ea()),
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"analysis"},
    )
    @session.require_open
    def get_analysis_problems(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> AnalysisProblemListResult:
        """List analysis problems/conflicts found by IDA.

        These indicate areas where IDA's analysis is uncertain or incomplete.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """

        def _iter_problems():
            for ptype, pname in _PROBLEM_TYPES:
                check_cancelled()
                ea = ida_problems.get_problem(ptype, 0)
                while not is_bad_addr(ea):
                    check_cancelled()
                    yield {
                        "address": format_address(ea),
                        "type": pname,
                        "function": get_func_name(ea),
                    }
                    ea = ida_problems.get_problem(ptype, ea + 1)

        return AnalysisProblemListResult(**paginate_iter(_iter_problems(), offset, limit))

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"analysis"},
    )
    @session.require_open
    def get_fixups(
        start_address: Address = "",
        end_address: Address = "",
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> FixupListResult:
        """List relocation/fixup records in the binary.

        Fixups show where the loader adjusted addresses during loading.
        Useful for understanding PIE/PIC code and import resolution.

        Args:
            start_address: Start of range (default: database start).
            end_address: End of range (default: database end).
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        start = resolve_address(start_address) if start_address else ida_ida.inf_get_min_ea()
        end = resolve_address(end_address) if end_address else ida_ida.inf_get_max_ea()

        def _iter():
            ea = ida_fixup.get_first_fixup_ea()
            while not is_bad_addr(ea):
                check_cancelled()
                if ea < start:
                    ea = ida_fixup.get_next_fixup_ea(ea)
                    continue
                if ea >= end:
                    break

                fd = ida_fixup.fixup_data_t()
                if ida_fixup.get_fixup(fd, ea):
                    yield {
                        "address": format_address(ea),
                        "type": _FIXUP_TYPES.get(fd.get_type() & 0xF, f"type_{fd.get_type()}"),
                        "target": format_address(fd.off),
                    }

                ea = ida_fixup.get_next_fixup_ea(ea)

        return FixupListResult(**paginate_iter(_iter(), offset, limit))

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"analysis"},
    )
    @session.require_open
    def get_exception_handlers(
        address: Address,
    ) -> GetExceptionHandlersResult:
        """Get exception handling (try/catch) blocks for a function.

        Identifies protected regions, catch handlers, and exception types
        in C++ binaries.

        Args:
            address: Address or name of the function.
        """
        func = resolve_function(address)

        tryblks = ida_tryblks.tryblks_t()
        func_range = ida_range.range_t(func.start_ea, func.end_ea)
        count = ida_tryblks.get_tryblks(tryblks, func_range)

        blocks = []
        for i in range(count):
            tb = tryblks[i]
            catches = []
            for j in range(tb.size()):
                catch = tb[j]
                catches.append(
                    {
                        "start": format_address(catch.start_ea),
                        "end": format_address(catch.end_ea),
                    }
                )

            blocks.append(
                TryBlock(
                    try_start=format_address(tb.start_ea),
                    try_end=format_address(tb.end_ea),
                    catches=catches,
                )
            )

        return GetExceptionHandlersResult(
            function=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            tryblock_count=len(blocks),
            tryblocks=blocks,
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"analysis"},
    )
    @session.require_open
    def get_segment_registers(
        address: Address,
    ) -> GetSegmentRegistersResult:
        """Get segment register values at an address.

        Shows values of segment registers (CS, DS, ES, FS, GS, SS) at the
        given address. Useful for resolving TLS references and segmented
        addressing.

        Args:
            address: Address to query.
        """
        ea = resolve_address(address)

        regs = {}
        for reg_name in ["cs", "ds", "es", "fs", "gs", "ss"]:
            val = idc.get_sreg(ea, reg_name)
            if val is not None and val != -1:
                regs[reg_name] = format_address(val)

        return GetSegmentRegistersResult(
            address=format_address(ea),
            registers=regs,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"analysis"},
    )
    @session.require_open
    def set_segment_register(
        start_address: Address,
        register: str,
        value: int,
    ) -> SetSegmentRegisterResult:
        """Set a segment register value starting at an address.

        Creates a new segment register range. Useful for specifying TLS segment
        bases (e.g. fs, gs) or segment overrides in segmented code.

        Args:
            start_address: Address where the new register value starts.
            register: Register name (e.g. "fs", "gs", "ds").
            value: Value to set for the register.
        """
        start = resolve_address(start_address)

        old_sreg = idc.get_sreg(start, register)
        old_value = format_address(old_sreg) if old_sreg is not None and old_sreg != -1 else None
        success = idc.split_sreg_range(start, register, value, idc.SR_user)
        if not success:
            raise IDAError(
                f"Failed to set {register} = {value:#x} at {start_address}", error_type="SetFailed"
            )

        return SetSegmentRegisterResult(
            address=format_address(start),
            register_=register,
            old_value=old_value,
            value=format_address(value),
        )
