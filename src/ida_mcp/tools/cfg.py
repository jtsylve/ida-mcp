# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Control flow graph tools — basic blocks, CFG, and flow analysis."""

from __future__ import annotations

import ida_gdl
from fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

from ida_mcp.helpers import (
    ANNO_READ_ONLY,
    Address,
    format_address,
    get_func_name,
    resolve_function,
)
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class BasicBlock(BaseModel):
    """A basic block in the control flow graph."""

    start: str = Field(description="Block start address (hex).")
    end: str = Field(description="Block end address (hex, exclusive).")
    size: int = Field(description="Block size in bytes.")
    successors: list[str] = Field(description="Successor block addresses (hex).")
    predecessors: list[str] = Field(description="Predecessor block addresses (hex).")


class GetBasicBlocksResult(BaseModel):
    """Basic blocks for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    block_count: int = Field(description="Number of basic blocks.")
    blocks: list[BasicBlock] = Field(description="Basic blocks.")


class CfgEdge(BaseModel):
    """An edge in the control flow graph."""

    model_config = ConfigDict(populate_by_name=True)

    from_: str = Field(alias="from", description="Source block address (hex).")
    to: str = Field(description="Target block address (hex).")


class GetCfgEdgesResult(BaseModel):
    """CFG edges for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    edge_count: int = Field(description="Number of edges.")
    edges: list[CfgEdge] = Field(description="CFG edges.")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"analysis"},
    )
    @session.require_open
    def get_basic_blocks(
        address: Address,
    ) -> GetBasicBlocksResult:
        """Get the basic blocks of a function (control flow graph nodes).

        Each block has a start/end address and lists of successor/predecessor
        block start addresses. Best for control flow analysis of functions
        with complex branching. For simple linear functions,
        disassemble_function may be more convenient. See also get_cfg_edges
        for a flat edge list suited to graph visualization.

        Args:
            address: Address or name of the function.
        """
        func = resolve_function(address)

        flowchart = ida_gdl.FlowChart(func)
        blocks = []
        for block in flowchart:
            succs = [format_address(s.start_ea) for s in block.succs()]
            preds = [format_address(p.start_ea) for p in block.preds()]
            blocks.append(
                BasicBlock(
                    start=format_address(block.start_ea),
                    end=format_address(block.end_ea),
                    size=block.end_ea - block.start_ea,
                    successors=succs,
                    predecessors=preds,
                )
            )

        return GetBasicBlocksResult(
            function=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            block_count=len(blocks),
            blocks=blocks,
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"analysis"},
    )
    @session.require_open
    def get_cfg_edges(
        address: Address,
    ) -> GetCfgEdgesResult:
        """Get the control flow graph edges of a function.

        Returns a list of (source, target) block address pairs representing
        control flow transitions. Useful for graph visualization tools.
        More compact than get_basic_blocks for large functions when you
        only need connectivity. For block-centric analysis with
        predecessor/successor lists, use get_basic_blocks instead.

        Args:
            address: Address or name of the function.
        """
        func = resolve_function(address)

        flowchart = ida_gdl.FlowChart(func)
        edges = []
        for block in flowchart:
            src = format_address(block.start_ea)
            edges.extend(
                CfgEdge(from_=src, to=format_address(succ.start_ea)) for succ in block.succs()
            )

        return GetCfgEdgesResult(
            function=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            edge_count=len(edges),
            edges=edges,
        )
