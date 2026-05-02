# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Cross-reference analysis tools."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ghidra_mcp.helpers import (
    ANNO_READ_ONLY,
    Address,
    Limit,
    Offset,
    format_address,
    paginate_iter,
    resolve_address,
)
from ghidra_mcp.session import session


class XrefTo(BaseModel):
    from_address: str = Field(description="Source address (hex).")
    from_function: str = Field(description="Containing function name, if any.")
    ref_type: str = Field(description="Reference type.")
    is_call: bool = Field(description="True if this is a call reference.")


class XrefFrom(BaseModel):
    to_address: str = Field(description="Target address (hex).")
    to_function: str = Field(description="Target function name, if any.")
    ref_type: str = Field(description="Reference type.")
    is_call: bool = Field(description="True if this is a call reference.")


class CallGraphEntry(BaseModel):
    name: str
    address: str
    callers: list[dict] = Field(default_factory=list)
    callees: list[dict] = Field(default_factory=list)


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"xrefs"})
    @session.require_open
    def get_xrefs_to(
        address: Address,
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """Get all cross-references pointing TO an address."""
        program = session.program
        ref_mgr = program.getReferenceManager()
        func_mgr = program.getFunctionManager()
        target = resolve_address(address)

        def _gen():
            refs = ref_mgr.getReferencesTo(target)
            for ref in refs:
                from_addr = ref.getFromAddress()
                func = func_mgr.getFunctionContaining(from_addr)
                ref_type = ref.getReferenceType()
                yield XrefTo(
                    from_address=format_address(from_addr.getOffset()),
                    from_function=func.getName() if func else "",
                    ref_type=str(ref_type),
                    is_call=ref_type.isCall(),
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"xrefs"})
    @session.require_open
    def get_xrefs_from(
        address: Address,
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """Get all cross-references FROM an address."""
        program = session.program
        ref_mgr = program.getReferenceManager()
        func_mgr = program.getFunctionManager()
        source = resolve_address(address)

        def _gen():
            refs = ref_mgr.getReferencesFrom(source)
            for ref in refs:
                to_addr = ref.getToAddress()
                func = func_mgr.getFunctionContaining(to_addr)
                ref_type = ref.getReferenceType()
                yield XrefFrom(
                    to_address=format_address(to_addr.getOffset()),
                    to_function=func.getName() if func else "",
                    ref_type=str(ref_type),
                    is_call=ref_type.isCall(),
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"xrefs"})
    @session.require_open
    def get_call_graph(
        address: Address,
        depth: int = 1,
    ) -> CallGraphEntry:
        """Get the call graph around a function (callers and callees).

        Args:
            address: Function address.
            depth: Recursion depth (1-3).
        """
        if depth < 1:
            depth = 1
        if depth > 3:
            depth = 3

        func = session.program.getFunctionManager().getFunctionContaining(resolve_address(address))
        if func is None:
            from ghidra_mcp.exceptions import GhidraError  # noqa: PLC0415

            raise GhidraError(f"No function at {address}", error_type="NotFound")

        return _build_call_graph(func, depth, set())

    def _build_call_graph(func, depth: int, visited: set) -> CallGraphEntry:
        addr = func.getEntryPoint()
        key = addr.getOffset()
        if key in visited or depth <= 0:
            return CallGraphEntry(
                name=func.getName(),
                address=format_address(key),
            )
        visited.add(key)

        program = session.program
        ref_mgr = program.getReferenceManager()
        func_mgr = program.getFunctionManager()

        # Callers
        callers = []
        for ref in ref_mgr.getReferencesTo(addr):
            if ref.getReferenceType().isCall():
                caller_func = func_mgr.getFunctionContaining(ref.getFromAddress())
                if caller_func and caller_func.getEntryPoint().getOffset() not in visited:
                    if depth > 1:
                        callers.append(
                            _build_call_graph(caller_func, depth - 1, visited).model_dump()
                        )
                    else:
                        callers.append(
                            {
                                "name": caller_func.getName(),
                                "address": format_address(caller_func.getEntryPoint().getOffset()),
                            }
                        )

        # Callees
        callees = []
        called = func.getCalledFunctions(None)
        if called:
            for callee in called:
                callee_key = callee.getEntryPoint().getOffset()
                if callee_key not in visited:
                    if depth > 1:
                        callees.append(_build_call_graph(callee, depth - 1, visited).model_dump())
                    else:
                        callees.append(
                            {
                                "name": callee.getName(),
                                "address": format_address(callee_key),
                            }
                        )

        return CallGraphEntry(
            name=func.getName(),
            address=format_address(key),
            callers=callers,
            callees=callees,
        )
