# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Switch/jump table analysis tools."""

from __future__ import annotations

import ida_funcs
import ida_nalt
import idaapi
import idautils
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_READ_ONLY,
    Address,
    IDAError,
    Limit,
    Offset,
    async_paginate_iter,
    format_address,
    get_func_name,
    is_bad_addr,
    is_cancelled,
    resolve_address,
)
from ida_mcp.models import PaginatedResult
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class SwitchCase(BaseModel):
    """A switch case entry."""

    case_values: list[int] = Field(description="Case values mapping to this target.")
    target: str | None = Field(description="Target address (hex), or null.")


class GetSwitchInfoResult(BaseModel):
    """Switch table information."""

    address: str = Field(description="Switch instruction address (hex).")
    jump_table: str = Field(description="Jump table address (hex).")
    element_size: int = Field(description="Jump table element size in bytes.")
    num_cases: int = Field(description="Number of switch cases.")
    default_target: str | None = Field(description="Default case target (hex), or null.")
    start_value: int = Field(description="First case value.")
    cases: list[SwitchCase] = Field(description="Switch cases.")


class SwitchSummary(BaseModel):
    """Brief switch info."""

    address: str = Field(description="Switch instruction address (hex).")
    function: str = Field(description="Containing function name.")
    num_cases: int = Field(description="Number of switch cases.")


class SwitchListResult(PaginatedResult[SwitchSummary]):
    """Paginated list of switches."""

    items: list[SwitchSummary] = Field(description="Page of switches.")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"analysis"},
    )
    @session.require_open
    def get_switch_info(
        address: Address,
    ) -> GetSwitchInfoResult:
        """Get switch/jump table information at an indirect jump instruction.

        Resolves indirect jump targets and shows the jump table structure.

        Args:
            address: Address of the switch/indirect jump instruction.
        """
        ea = resolve_address(address)

        si = ida_nalt.get_switch_info(ea)
        if si is None:
            raise IDAError(f"No switch info at {format_address(ea)}", error_type="NotFound")

        cases = []
        results = idaapi.calc_switch_cases(ea, si)
        if results:
            for i in range(len(results.cases)):
                cur_case = results.cases[i]
                vals = [cur_case[j] for j in range(len(cur_case))]
                target = results.targets[i] if i < len(results.targets) else None
                if vals:
                    cases.append(
                        {
                            "case_values": vals,
                            "target": format_address(target) if target is not None else None,
                        }
                    )

        return GetSwitchInfoResult(
            address=format_address(ea),
            jump_table=format_address(si.jumps),
            element_size=si.get_jtable_element_size(),
            num_cases=si.get_jtable_size(),
            default_target=format_address(si.defjump) if not is_bad_addr(si.defjump) else None,
            start_value=si.lowcase,
            cases=cases,
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"analysis"},
    )
    @session.require_open
    async def list_switches(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> SwitchListResult:
        """Find all switch/jump tables in the database.

        Scans all instructions in all functions for indirect jumps with switch
        info. May be slow on large databases with many functions.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """

        def _iter():
            for i in range(ida_funcs.get_func_qty()):
                if is_cancelled():
                    return
                func = ida_funcs.getn_func(i)
                if func is None:
                    continue
                for head in idautils.FuncItems(func.start_ea):
                    si = ida_nalt.get_switch_info(head)
                    if si is not None:
                        yield {
                            "address": format_address(head),
                            "function": get_func_name(func.start_ea),
                            "num_cases": si.get_jtable_size(),
                        }

        return SwitchListResult(
            **await async_paginate_iter(_iter(), offset, limit, progress_label="Scanning switches")
        )
