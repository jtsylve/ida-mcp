# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Auto-analysis control, problem tracking, and fixup tools."""

from __future__ import annotations

import ida_auto
import ida_fixup
import ida_ida
import ida_problems
import ida_range
import ida_tryblks
import idc
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import (
    check_cancelled,
    format_address,
    get_func_name,
    is_bad_addr,
    paginate_iter,
    resolve_address,
    resolve_function,
)
from ida_mcp.session import session

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
    @mcp.tool()
    @session.require_open
    def reanalyze_range(start_address: str, end_address: str) -> dict:
        """Trigger IDA auto-analysis on an address range.

        Useful after patching bytes or changing types to update analysis.

        Args:
            start_address: Start of the range.
            end_address: End of the range (exclusive).
        """
        start, err = resolve_address(start_address)
        if err:
            return err
        end, err = resolve_address(end_address)
        if err:
            return err

        ida_auto.plan_and_wait(start, end)

        return {
            "start": format_address(start),
            "end": format_address(end),
            "status": "analysis_complete",
        }

    @mcp.tool()
    @session.require_open
    def wait_for_analysis() -> dict:
        """Wait for IDA's auto-analysis to complete.

        Call this after making changes (patches, type applications) to ensure
        the database is fully analyzed before querying.
        """
        ida_auto.auto_wait()

        return {"status": "analysis_complete"}

    @mcp.tool()
    @session.require_open
    def get_analysis_problems(offset: int = 0, limit: int = 100) -> dict:
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

        return paginate_iter(_iter_problems(), offset, limit)

    @mcp.tool()
    @session.require_open
    def get_fixups(
        start_address: str = "", end_address: str = "", offset: int = 0, limit: int = 100
    ) -> dict:
        """List relocation/fixup records in the binary.

        Fixups show where the loader adjusted addresses during loading.
        Useful for understanding PIE/PIC code and import resolution.

        Args:
            start_address: Start of range (default: database start).
            end_address: End of range (default: database end).
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        if start_address:
            start, err = resolve_address(start_address)
            if err:
                return err
        else:
            start = ida_ida.inf_get_min_ea()

        if end_address:
            end, err = resolve_address(end_address)
            if err:
                return err
        else:
            end = ida_ida.inf_get_max_ea()

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

        return paginate_iter(_iter(), offset, limit)

    @mcp.tool()
    @session.require_open
    def get_exception_handlers(address: str) -> dict:
        """Get exception handling (try/catch) blocks for a function.

        Identifies protected regions, catch handlers, and exception types
        in C++ binaries.

        Args:
            address: Address or name of the function.
        """
        func, err = resolve_function(address)
        if err:
            return err

        tryblks = ida_tryblks.tryblks_t()
        func_range = ida_range.range_t(func.start_ea, func.end_ea)
        count = ida_tryblks.get_tryblks(tryblks, func_range)

        blocks = []
        for i in range(count):
            tb = tryblks[i]
            block = {
                "try_start": format_address(tb.start_ea),
                "try_end": format_address(tb.end_ea),
                "catches": [],
            }

            for j in range(tb.size()):
                catch = tb[j]
                block["catches"].append(
                    {
                        "start": format_address(catch.start_ea),
                        "end": format_address(catch.end_ea),
                    }
                )

            blocks.append(block)

        return {
            "function": format_address(func.start_ea),
            "name": get_func_name(func.start_ea),
            "tryblock_count": len(blocks),
            "tryblocks": blocks,
        }

    @mcp.tool()
    @session.require_open
    def get_segment_registers(address: str) -> dict:
        """Get segment register values at an address.

        Shows values of segment registers (CS, DS, ES, FS, GS, SS) at the
        given address. Useful for resolving TLS references and segmented
        addressing.

        Args:
            address: Address to query.
        """
        ea, err = resolve_address(address)
        if err:
            return err

        regs = {}
        for reg_name in ["cs", "ds", "es", "fs", "gs", "ss"]:
            val = idc.get_sreg(ea, reg_name)
            if val is not None and val != -1:
                regs[reg_name] = format_address(val)

        return {
            "address": format_address(ea),
            "registers": regs,
        }

    @mcp.tool()
    @session.require_open
    def set_segment_register(start_address: str, register: str, value: int) -> dict:
        """Set a segment register value starting at an address.

        Creates a new segment register range. Useful for specifying TLS segment
        bases (e.g. fs, gs) or segment overrides in segmented code.

        Args:
            start_address: Address where the new register value starts.
            register: Register name (e.g. "fs", "gs", "ds").
            value: Value to set for the register.
        """
        start, err = resolve_address(start_address)
        if err:
            return err

        old_sreg = idc.get_sreg(start, register)
        old_value = format_address(old_sreg) if old_sreg is not None and old_sreg != -1 else None
        success = idc.split_sreg_range(start, register, value, idc.SR_user)
        if not success:
            return {
                "error": f"Failed to set {register} = {value:#x} at {start_address}",
                "error_type": "SetFailed",
            }

        return {
            "address": format_address(start),
            "register": register,
            "old_value": old_value,
            "value": format_address(value),
        }
