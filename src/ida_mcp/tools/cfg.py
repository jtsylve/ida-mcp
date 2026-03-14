# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Control flow graph tools -- basic blocks, CFG, and flow analysis."""

from __future__ import annotations

import ida_gdl
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import format_address, get_func_name, resolve_function
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def get_basic_blocks(address: str) -> dict:
        """Get the basic blocks of a function (control flow graph nodes).

        Each block has a start/end address and lists of successor/predecessor
        block start addresses.

        Args:
            address: Address or name of the function.
        """
        func, err = resolve_function(address)
        if err:
            return err

        flowchart = ida_gdl.FlowChart(func)
        blocks = []
        for block in flowchart:
            succs = [format_address(s.start_ea) for s in block.succs()]
            preds = [format_address(p.start_ea) for p in block.preds()]
            blocks.append(
                {
                    "start": format_address(block.start_ea),
                    "end": format_address(block.end_ea),
                    "size": block.end_ea - block.start_ea,
                    "successors": succs,
                    "predecessors": preds,
                }
            )

        return {
            "function": format_address(func.start_ea),
            "name": get_func_name(func.start_ea),
            "block_count": len(blocks),
            "blocks": blocks,
        }

    @mcp.tool()
    @session.require_open
    def get_cfg_edges(address: str) -> dict:
        """Get the control flow graph edges of a function.

        Returns a list of (source, target) block address pairs representing
        control flow transitions. Useful for graph analysis tools.

        Args:
            address: Address or name of the function.
        """
        func, err = resolve_function(address)
        if err:
            return err

        flowchart = ida_gdl.FlowChart(func)
        edges = []
        for block in flowchart:
            src = format_address(block.start_ea)
            edges.extend(
                {"from": src, "to": format_address(succ.start_ea)} for succ in block.succs()
            )

        return {
            "function": format_address(func.start_ea),
            "name": get_func_name(func.start_ea),
            "edge_count": len(edges),
            "edges": edges,
        }
