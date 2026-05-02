# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Control flow graph tools — basic blocks and CFG edges."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

from ghidra_mcp.helpers import (
    ANNO_READ_ONLY,
    Address,
    format_address,
    resolve_function,
)
from ghidra_mcp.session import session


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


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def get_basic_blocks(
        address: Address,
    ) -> GetBasicBlocksResult:
        """Get basic blocks of a function (CFG nodes with successor/predecessor lists).

        See get_cfg_edges for a compact edge list suited to graph visualization.

        Args:
            address: Address or name of the function.
        """
        from ghidra.program.model.block import BasicBlockModel  # noqa: PLC0415
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        func = resolve_function(address)
        program = session.program

        block_model = BasicBlockModel(program)
        body = func.getBody()

        # Collect all blocks in the function
        blocks = []
        block_iter = block_model.getCodeBlocksContaining(body, TaskMonitor.DUMMY)
        while block_iter.hasNext():
            block = block_iter.next()
            block_start = block.getMinAddress().getOffset()
            block_end = block.getMaxAddress().getOffset() + 1
            size = block_end - block_start

            # Get successors
            succs = []
            succ_iter = block.getDestinations(TaskMonitor.DUMMY)
            while succ_iter.hasNext():
                ref = succ_iter.next()
                dest = ref.getDestinationBlock()
                if dest is not None:
                    succs.append(format_address(dest.getMinAddress().getOffset()))

            # Get predecessors
            preds = []
            pred_iter = block.getSources(TaskMonitor.DUMMY)
            while pred_iter.hasNext():
                ref = pred_iter.next()
                src = ref.getSourceBlock()
                if src is not None:
                    preds.append(format_address(src.getMinAddress().getOffset()))

            blocks.append(
                BasicBlock(
                    start=format_address(block_start),
                    end=format_address(block_end),
                    size=size,
                    successors=succs,
                    predecessors=preds,
                )
            )

        entry = func.getEntryPoint().getOffset()
        return GetBasicBlocksResult(
            function=format_address(entry),
            name=func.getName(),
            block_count=len(blocks),
            blocks=blocks,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def get_cfg_edges(
        address: Address,
    ) -> GetCfgEdgesResult:
        """Get CFG edges as (source, target) pairs (compact, for graph visualization).

        For block-level detail with predecessor/successor lists, use get_basic_blocks.

        Args:
            address: Address or name of the function.
        """
        from ghidra.program.model.block import BasicBlockModel  # noqa: PLC0415
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        func = resolve_function(address)
        program = session.program

        block_model = BasicBlockModel(program)
        body = func.getBody()

        edges = []
        block_iter = block_model.getCodeBlocksContaining(body, TaskMonitor.DUMMY)
        while block_iter.hasNext():
            block = block_iter.next()
            src = format_address(block.getMinAddress().getOffset())

            succ_iter = block.getDestinations(TaskMonitor.DUMMY)
            while succ_iter.hasNext():
                ref = succ_iter.next()
                dest = ref.getDestinationBlock()
                if dest is not None:
                    edges.append(
                        CfgEdge(
                            from_=src,
                            to=format_address(dest.getMinAddress().getOffset()),
                        )
                    )

        entry = func.getEntryPoint().getOffset()
        return GetCfgEdgesResult(
            function=format_address(entry),
            name=func.getName(),
            edge_count=len(edges),
            edges=edges,
        )
