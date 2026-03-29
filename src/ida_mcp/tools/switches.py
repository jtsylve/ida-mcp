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

from ida_mcp.helpers import (
    format_address,
    get_func_name,
    is_bad_addr,
    paginate_iter,
    resolve_address,
)
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def get_switch_info(address: str) -> dict:
        """Get switch/jump table information at an indirect jump instruction.

        Resolves indirect jump targets and shows the jump table structure.

        Args:
            address: Address of the switch/indirect jump instruction.
        """
        ea, err = resolve_address(address)
        if err:
            return err

        si = ida_nalt.get_switch_info(ea)
        if si is None:
            return {
                "error": f"No switch info at {format_address(ea)}",
                "error_type": "NotFound",
            }

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

        return {
            "address": format_address(ea),
            "jump_table": format_address(si.jumps),
            "element_size": si.get_jtable_element_size(),
            "num_cases": si.get_jtable_size(),
            "default_target": format_address(si.defjump) if not is_bad_addr(si.defjump) else None,
            "start_value": si.lowcase,
            "cases": cases,
        }

    @mcp.tool()
    @session.require_open
    def list_switches(offset: int = 0, limit: int = 100) -> dict:
        """Find all switch/jump tables in the database.

        Scans all instructions in all functions for indirect jumps with switch
        info. May be slow on large databases with many functions.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """

        def _iter():
            for i in range(ida_funcs.get_func_qty()):
                func = ida_funcs.getn_func(i)
                if func is None:
                    continue
                for head in idautils.FuncItems(func.start_ea):
                    si = ida_nalt.get_switch_info(head)
                    if si is not None:
                        yield {
                            "address": format_address(head),
                            "function": get_func_name(func.start_ea),
                            "jump_table": format_address(si.jumps),
                            "num_cases": si.get_jtable_size(),
                        }

        return paginate_iter(_iter(), offset, limit)
