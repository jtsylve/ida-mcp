# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Advanced analysis tools — data flow tracing, complexity metrics, indirect calls."""

from __future__ import annotations

from collections import deque

import ida_funcs
import ida_gdl
import ida_idp
import ida_nalt
import ida_ua
import idautils
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import (
    clean_disasm_line,
    format_address,
    get_func_name,
    is_bad_addr,
    paginate_iter,
    resolve_address,
    resolve_function,
    xref_type_name,
)
from ida_mcp.session import session

# Operand types that indicate indirect references (not direct/immediate targets).
_INDIRECT_OPTYPES = frozenset(
    {
        ida_ua.o_reg,
        ida_ua.o_mem,
        ida_ua.o_phrase,
        ida_ua.o_displ,
    }
)


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def trace_data_flow(
        address: str,
        direction: str = "forward",
        max_depth: int = 3,
        max_results: int = 200,
        code_only: bool = False,
    ) -> dict:
        """BFS cross-reference traversal with direction and depth control.

        Traces the chain of cross-references starting from an address.
        "forward" follows XrefsFrom (what the address references),
        "backward" follows XrefsTo (what references the address),
        "both" follows both directions.

        Args:
            address: Starting address or symbol name.
            direction: Traversal direction — "forward", "backward", or "both".
            max_depth: Maximum traversal depth (1-10).
            max_results: Maximum total nodes to return.
            code_only: If true, only follow code cross-references.
        """
        ea, err = resolve_address(address)
        if err:
            return err

        direction = direction.lower()
        if direction not in ("forward", "backward", "both"):
            return {
                "error": f"Invalid direction: {direction!r}. Must be 'forward', 'backward', or 'both'.",
                "error_type": "InvalidArgument",
            }

        max_depth = max(1, min(max_depth, 10))
        max_results = max(1, min(max_results, 1000))

        visited: set[int] = {ea}
        # queue entries: (address, depth, from_addr, xref_type, xref_direction)
        queue: deque[tuple[int, int, int | None, int | None, str | None]] = deque()
        nodes: list[dict] = []

        def _enqueue_xrefs(src_ea: int, depth: int) -> None:
            if direction in ("forward", "both"):
                for xref in idautils.XrefsFrom(src_ea):
                    if code_only and not xref.iscode:
                        continue
                    if xref.to not in visited and not is_bad_addr(xref.to):
                        visited.add(xref.to)
                        queue.append((xref.to, depth, src_ea, xref.type, "forward"))
            if direction in ("backward", "both"):
                for xref in idautils.XrefsTo(src_ea):
                    if code_only and not xref.iscode:
                        continue
                    if xref.frm not in visited and not is_bad_addr(xref.frm):
                        visited.add(xref.frm)
                        queue.append((xref.frm, depth, src_ea, xref.type, "backward"))

        _enqueue_xrefs(ea, 1)

        while queue and len(nodes) < max_results:
            cur_ea, depth, from_ea, xtype, xdir = queue.popleft()
            node: dict = {
                "address": format_address(cur_ea),
                "name": get_func_name(cur_ea),
                "depth": depth,
            }
            if from_ea is not None:
                node["xref_from"] = format_address(from_ea)
            if xtype is not None:
                node["xref_type"] = xref_type_name(xtype)
            if xdir is not None:
                node["xref_direction"] = xdir
            nodes.append(node)

            if depth < max_depth:
                _enqueue_xrefs(cur_ea, depth + 1)

        return {
            "start": format_address(ea),
            "direction": direction,
            "max_depth": max_depth,
            "code_only": code_only,
            "node_count": len(nodes),
            "nodes": nodes,
        }

    @mcp.tool()
    @session.require_open
    def get_function_complexity(address: str) -> dict:
        """Compute control flow graph complexity metrics for a function.

        Returns basic block count, edge count, cyclomatic complexity,
        instruction count, and CFG nesting depth.

        Args:
            address: Address or name of the function.
        """
        func, err = resolve_function(address)
        if err:
            return err

        flowchart = ida_gdl.FlowChart(func)
        blocks = list(flowchart)
        block_count = len(blocks)

        edge_count = 0
        # Map block start_ea -> list of successor start_eas for BFS nesting depth
        succ_map: dict[int, list[int]] = {}
        entry_ea = func.start_ea

        for block in blocks:
            succs = list(block.succs())
            edge_count += len(succs)
            succ_map[block.start_ea] = [s.start_ea for s in succs]

        cyclomatic = edge_count - block_count + 2

        # Instruction count
        insn_count = sum(1 for _ in idautils.FuncItems(func.start_ea))

        # Nesting depth: longest path from entry block via BFS
        nesting_depth = 0
        if entry_ea in succ_map:
            depth_queue: deque[tuple[int, int]] = deque([(entry_ea, 0)])
            depth_visited: set[int] = {entry_ea}
            while depth_queue:
                bea, d = depth_queue.popleft()
                if d > nesting_depth:
                    nesting_depth = d
                for s in succ_map.get(bea, []):
                    if s not in depth_visited:
                        depth_visited.add(s)
                        depth_queue.append((s, d + 1))

        return {
            "function": format_address(func.start_ea),
            "name": get_func_name(func.start_ea),
            "block_count": block_count,
            "edge_count": edge_count,
            "cyclomatic_complexity": cyclomatic,
            "instruction_count": insn_count,
            "nesting_depth": nesting_depth,
        }

    @mcp.tool()
    @session.require_open
    def find_indirect_calls(
        address: str = "",
        offset: int = 0,
        limit: int = 100,
    ) -> dict:
        """Find indirect call and jump instructions (register/memory targets).

        Scans for call/jump instructions whose target is a register or memory
        operand rather than an immediate address. These represent virtual calls,
        function pointers, jump tables, and similar dynamic dispatch patterns.

        Args:
            address: Function address to scope the search (empty = all functions).
            offset: Pagination offset.
            limit: Maximum number of results (max 500).
        """
        if address:
            func, err = resolve_function(address)
            if err:
                return err
            func_eas = [func.start_ea]
        else:
            func_eas = [
                ida_funcs.getn_func(i).start_ea
                for i in range(ida_funcs.get_func_qty())
                if ida_funcs.getn_func(i) is not None
            ]

        def _iter():
            insn = ida_ua.insn_t()
            for fea in func_eas:
                for item_ea in idautils.FuncItems(fea):
                    if ida_ua.decode_insn(insn, item_ea) == 0:
                        continue

                    is_call = ida_idp.is_call_insn(insn)

                    # Check for indirect jump: operand type is register/memory
                    # and instruction is a jump (not a call).
                    is_indirect_jmp = False
                    if not is_call and insn.itype != 0:
                        mnem = ida_ua.print_insn_mnem(item_ea)
                        if mnem and "jmp" in mnem.lower():
                            is_indirect_jmp = True

                    if not is_call and not is_indirect_jmp:
                        continue

                    # Check if the first operand is indirect (not immediate/near/far)
                    op = insn.ops[0]
                    if op.type in _INDIRECT_OPTYPES:
                        yield {
                            "address": format_address(item_ea),
                            "disasm": clean_disasm_line(item_ea),
                            "function": get_func_name(fea),
                            "type": "call" if is_call else "jump",
                        }

        result = paginate_iter(_iter(), offset, limit)
        if address:
            result["scoped_to"] = format_address(func_eas[0])
        return result

    @mcp.tool()
    @session.require_open
    def func_profile(address: str) -> dict:
        """Compute per-function metrics without decompilation.

        Gathers instruction count, basic block count, caller/callee counts,
        string reference count, cyclomatic complexity, and function flags
        in a single call.

        Args:
            address: Address or name of the function.
        """
        func, err = resolve_function(address)
        if err:
            return err

        start = func.start_ea
        name = get_func_name(start)
        func_items = list(idautils.FuncItems(start))
        insn_count = len(func_items)

        # Basic blocks and complexity
        flowchart = ida_gdl.FlowChart(func)
        blocks = list(flowchart)
        block_count = len(blocks)
        edge_count = sum(len(list(b.succs())) for b in blocks)
        cyclomatic = edge_count - block_count + 2

        # Callers: unique functions that have code xrefs TO this function's entry
        caller_starts: set[int] = set()
        for xref in idautils.XrefsTo(start):
            if not xref.iscode:
                continue
            caller = ida_funcs.get_func(xref.frm)
            if caller and caller.start_ea != start:
                caller_starts.add(caller.start_ea)

        # Callees: unique functions called from this function
        callee_starts: set[int] = set()
        for item_ea in func_items:
            for ref in idautils.CodeRefsFrom(item_ea, False):
                callee = ida_funcs.get_func(ref)
                if callee and callee.start_ea != start:
                    callee_starts.add(callee.start_ea)

        # String references: data xrefs from function items to string addresses
        string_ref_count = 0
        for item_ea in func_items:
            for xref in idautils.XrefsFrom(item_ea):
                if xref.iscode:
                    continue
                str_type = ida_nalt.get_str_type(xref.to)
                if str_type is not None and str_type >= 0:
                    string_ref_count += 1

        # Function flags
        flags = func.flags
        is_thunk = bool(flags & ida_funcs.FUNC_THUNK)
        is_library = bool(flags & ida_funcs.FUNC_LIB)
        does_return = not bool(flags & ida_funcs.FUNC_NORET)

        return {
            "function": format_address(start),
            "name": name,
            "start": format_address(start),
            "end": format_address(func.end_ea),
            "size": func.size(),
            "instruction_count": insn_count,
            "block_count": block_count,
            "edge_count": edge_count,
            "cyclomatic_complexity": cyclomatic,
            "caller_count": len(caller_starts),
            "callee_count": len(callee_starts),
            "string_ref_count": string_ref_count,
            "is_thunk": is_thunk,
            "is_library": is_library,
            "does_return": does_return,
        }
