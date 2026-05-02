# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Naming and labeling tools."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ghidra_mcp.exceptions import GhidraError
from ghidra_mcp.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    FilterPattern,
    Limit,
    Offset,
    compile_filter,
    format_address,
    paginate_iter,
    resolve_address,
)
from ghidra_mcp.models import RenameResult
from ghidra_mcp.session import session


class NameItem(BaseModel):
    address: str = Field(description="Address (hex).")
    name: str = Field(description="Symbol name.")
    type: str = Field(description="Symbol type.")
    namespace: str = Field(default="", description="Namespace.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"names"})
    @session.require_open
    def list_names(
        offset: Offset = 0,
        limit: Limit = 100,
        filter_pattern: FilterPattern = "",
    ) -> dict:
        """List all named locations, paginated with optional regex filter."""
        program = session.program
        sym_table = program.getSymbolTable()
        filt = compile_filter(filter_pattern)

        def _gen():
            sym_iter = sym_table.getAllSymbols(True)
            for sym in sym_iter:
                if sym.isDynamic():
                    continue
                name = sym.getName()
                if filt and not filt.search(name):
                    continue
                ns = sym.getParentNamespace()
                yield NameItem(
                    address=format_address(sym.getAddress().getOffset()),
                    name=name,
                    type=str(sym.getSymbolType()),
                    namespace=ns.getName() if ns and not ns.isGlobal() else "",
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"names"})
    @session.require_open
    def rename_address(address: Address, new_name: str) -> RenameResult:
        """Rename a label/symbol at an address."""
        from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

        program = session.program
        addr = resolve_address(address)
        sym_table = program.getSymbolTable()

        sym = sym_table.getPrimarySymbol(addr)
        old_name = sym.getName() if sym else format_address(addr.getOffset())

        tx_id = program.startTransaction("Rename address")
        try:
            if sym:
                sym.setName(new_name, SourceType.USER_DEFINED)
            else:
                sym_table.createLabel(addr, new_name, SourceType.USER_DEFINED)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to rename: {e}", error_type="RenameFailed") from e

        return RenameResult(
            address=format_address(addr.getOffset()),
            old_name=old_name,
            new_name=new_name,
        )
