# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Hex-Rays ctree (decompiler AST) exploration tools."""

from __future__ import annotations

from typing import Annotated

import ida_hexrays
import ida_name
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_READ_ONLY,
    META_BATCH,
    META_DECOMPILER,
    Address,
    IDAError,
    decompile_at,
    format_address,
    get_func_name,
    is_bad_addr,
)
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class GetCtreeResult(BaseModel):
    """Ctree AST for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    ctree: dict | None = Field(description="Ctree AST as a nested dict, or null.")


class CtreeCallInfo(BaseModel):
    """A function call found in the ctree."""

    callee: str = Field(description="Callee name.")
    arg_count: int = Field(description="Number of arguments.")
    callee_address: str | None = Field(default=None, description="Callee address (hex).")
    call_address: str | None = Field(default=None, description="Call site address (hex).")


class FindCtreeCallsResult(BaseModel):
    """Function calls found in the ctree."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    call_count: int = Field(description="Number of calls found.")
    calls: list[CtreeCallInfo] = Field(description="Call list.")


class FindCtreePatternResult(BaseModel):
    """Pattern matches found in the ctree.

    When a single pattern_type is requested, ``pattern_type``, ``count``, and
    ``matches`` are populated.  When ``"all"`` is requested, ``summary`` and
    ``results`` are populated instead.
    """

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    pattern_type: str | None = Field(default=None, description="Pattern type searched (single).")
    count: int | None = Field(default=None, description="Number of matches (single).")
    matches: list[dict] | None = Field(default=None, description="Pattern matches (single).")
    summary: dict[str, int] | None = Field(
        default=None, description="Summary counts per pattern type (all)."
    )
    results: dict[str, list[dict]] | None = Field(
        default=None, description="Results per pattern type (all)."
    )


_VALID_PATTERN_TYPES = frozenset(
    {
        "calls",
        "string_refs",
        "comparisons",
        "assignments",
        "casts",
        "pointer_derefs",
        "all",
    }
)

_COMPARISON_OPS = frozenset(
    {
        ida_hexrays.cot_eq,
        ida_hexrays.cot_ne,
        ida_hexrays.cot_sge,
        ida_hexrays.cot_sgt,
        ida_hexrays.cot_sle,
        ida_hexrays.cot_slt,
        ida_hexrays.cot_uge,
        ida_hexrays.cot_ugt,
        ida_hexrays.cot_ule,
        ida_hexrays.cot_ult,
    }
)

_ASSIGNMENT_OPS = frozenset(
    {
        ida_hexrays.cot_asg,
        ida_hexrays.cot_asgadd,
        ida_hexrays.cot_asgsub,
        ida_hexrays.cot_asgmul,
        ida_hexrays.cot_asgband,
        ida_hexrays.cot_asgbor,
        ida_hexrays.cot_asgxor,
        ida_hexrays.cot_asgshl,
        ida_hexrays.cot_asgsshr,
        ida_hexrays.cot_asgushr,
    }
)


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"decompiler"},
        meta=META_DECOMPILER,
    )
    @session.require_open
    def get_ctree(
        function_address: Address,
        depth: Annotated[int, Field(description="Maximum tree depth (1-10).", ge=1, le=10)] = 3,
    ) -> GetCtreeResult:
        """Get the Hex-Rays decompiler AST (ctree) for a function.

        Returns a structured representation of the decompiled code's
        abstract syntax tree, useful for pattern matching and analysis.
        Output can be large for complex functions — keep depth low (2-3)
        for initial exploration. For targeted searches, find_ctree_calls
        and find_ctree_patterns are more efficient than walking the full
        tree.

        Args:
            function_address: Address or name of the function.
            depth: Maximum tree depth to return (1-10, default 3).
        """
        cfunc, func = decompile_at(function_address)

        depth = max(1, min(depth, 10))

        def _item_to_dict(item, current_depth):
            if item is None or current_depth <= 0:
                return None

            result = {
                "op": _op_name(item.op),
                "op_id": item.op,
            }

            if not is_bad_addr(item.ea):
                result["address"] = format_address(item.ea)

            if item.is_expr():
                expr = item.cexpr
                _type = expr.type
                if _type and not _type.empty():
                    result["type"] = str(_type)

                # Number literal
                if item.op == ida_hexrays.cot_num:
                    result["value"] = expr.numval()
                # String literal
                elif item.op == ida_hexrays.cot_str:
                    result["string"] = expr.string
                # Object (variable/global)
                elif item.op == ida_hexrays.cot_obj:
                    result["obj_ea"] = format_address(expr.obj_ea)
                # Variable reference
                elif item.op == ida_hexrays.cot_var:
                    v = expr.v
                    if v:
                        idx = v.idx
                        if 0 <= idx < len(cfunc.lvars):
                            result["var_name"] = cfunc.lvars[idx].name
                # Function call
                elif item.op == ida_hexrays.cot_call:
                    if expr.x:
                        call_target = _item_to_dict(expr.x, current_depth - 1)
                        if call_target:
                            result["call_target"] = call_target
                    if expr.a and current_depth > 1:
                        args = []
                        for i in range(len(expr.a)):
                            arg = _item_to_dict(expr.a[i], current_depth - 1)
                            if arg:
                                args.append(arg)
                        result["arguments"] = args

                # Binary/unary operands (skip for calls — already captured above)
                if current_depth > 1 and item.op != ida_hexrays.cot_call:
                    if expr.x:
                        x = _item_to_dict(expr.x, current_depth - 1)
                        if x:
                            result["x"] = x
                    if expr.y:
                        y = _item_to_dict(expr.y, current_depth - 1)
                        if y:
                            result["y"] = y

            else:
                insn = item.cinsn
                if current_depth > 1 and insn:
                    # if statement
                    if item.op == ida_hexrays.cit_if and insn.cif:
                        cif = insn.cif
                        if cif.expr:
                            result["condition"] = _item_to_dict(cif.expr, current_depth - 1)
                        if cif.ithen:
                            result["then"] = _item_to_dict(cif.ithen, current_depth - 1)
                        if cif.ielse:
                            result["else"] = _item_to_dict(cif.ielse, current_depth - 1)
                    # while/do/for
                    elif item.op == ida_hexrays.cit_while and insn.cwhile:
                        result["condition"] = _item_to_dict(insn.cwhile.expr, current_depth - 1)
                        result["body"] = _item_to_dict(insn.cwhile.body, current_depth - 1)
                    elif item.op == ida_hexrays.cit_do and insn.cdo:
                        result["condition"] = _item_to_dict(insn.cdo.expr, current_depth - 1)
                        result["body"] = _item_to_dict(insn.cdo.body, current_depth - 1)
                    elif item.op == ida_hexrays.cit_for and insn.cfor:
                        result["init"] = _item_to_dict(insn.cfor.init, current_depth - 1)
                        result["condition"] = _item_to_dict(insn.cfor.expr, current_depth - 1)
                        result["step"] = _item_to_dict(insn.cfor.step, current_depth - 1)
                        result["body"] = _item_to_dict(insn.cfor.body, current_depth - 1)
                    # return
                    elif item.op == ida_hexrays.cit_return and insn.creturn:
                        result["return_expr"] = _item_to_dict(insn.creturn.expr, current_depth - 1)
                    # block
                    elif item.op == ida_hexrays.cit_block and insn.cblock:
                        stmts = []
                        for stmt in insn.cblock:
                            s = _item_to_dict(stmt, current_depth - 1)
                            if s:
                                stmts.append(s)
                        result["statements"] = stmts
                    # expression statement
                    elif item.op == ida_hexrays.cit_expr and insn.cexpr:
                        result["expr"] = _item_to_dict(insn.cexpr, current_depth - 1)
                    # switch
                    elif item.op == ida_hexrays.cit_switch and insn.cswitch:
                        result["switch_expr"] = _item_to_dict(insn.cswitch.expr, current_depth - 1)

            return result

        body = _item_to_dict(cfunc.body, depth)

        return GetCtreeResult(
            function=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            ctree=body,
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"decompiler", "analysis"},
        meta={**META_DECOMPILER, **META_BATCH},
    )
    @session.require_open
    def find_ctree_calls(
        function_address: Address,
        callee_name: str = "",
    ) -> FindCtreeCallsResult:
        """Find all function calls in a decompiled function's AST.

        More targeted than get_ctree for finding call sites. Optionally
        filter by callee name (substring match). For cross-reference based
        call analysis without decompilation, use get_call_graph instead.

        Args:
            function_address: Address or name of the function to analyze.
            callee_name: Optional name to filter calls (empty = all calls).
        """
        cfunc, func = decompile_at(function_address)

        calls = []

        class CallFinder(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                super().__init__(ida_hexrays.CV_FAST)

            def visit_expr(self, expr):
                if expr.op == ida_hexrays.cot_call:
                    target = expr.x
                    target_name = ""
                    target_addr = None

                    if target and target.op == ida_hexrays.cot_obj:
                        target_addr = target.obj_ea
                        target_name = ida_name.get_name(target_addr) or ""

                    if callee_name and callee_name not in target_name:
                        return 0

                    call_info = CtreeCallInfo(
                        callee=target_name,
                        arg_count=len(expr.a) if expr.a else 0,
                        callee_address=format_address(target_addr)
                        if target_addr is not None
                        else None,
                        call_address=format_address(expr.ea) if not is_bad_addr(expr.ea) else None,
                    )

                    calls.append(call_info)
                return 0

        visitor = CallFinder()
        visitor.apply_to(cfunc.body, None)

        return FindCtreeCallsResult(
            function=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            call_count=len(calls),
            calls=calls,
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"decompiler"},
        meta={**META_DECOMPILER, **META_BATCH},
    )
    @session.require_open
    def find_ctree_patterns(
        function_address: Address,
        pattern_type: str = "all",
    ) -> FindCtreePatternResult:
        """Search for specific patterns in a function's decompiler AST.

        Finds common patterns like string comparisons, memory operations,
        arithmetic operations, casts, assignments, etc. Use a specific
        pattern_type to reduce output; "all" returns every pattern category,
        which can be verbose for large functions.

        Args:
            function_address: Address or name of the function.
            pattern_type: What to find — "calls", "string_refs", "comparisons",
                "assignments", "casts", "pointer_derefs", or "all".
        """
        cfunc, func = decompile_at(function_address)

        if pattern_type not in _VALID_PATTERN_TYPES:
            raise IDAError(
                f"Invalid pattern_type: {pattern_type!r}",
                error_type="InvalidArgument",
                valid_types=sorted(_VALID_PATTERN_TYPES),
            )

        results = {
            "calls": [],
            "string_refs": [],
            "comparisons": [],
            "assignments": [],
            "casts": [],
            "pointer_derefs": [],
        }

        class PatternFinder(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                super().__init__(ida_hexrays.CV_FAST)

            def visit_expr(self, expr):
                addr = format_address(expr.ea) if not is_bad_addr(expr.ea) else None

                if (pattern_type in ("all", "calls")) and expr.op == ida_hexrays.cot_call:
                    target = expr.x
                    name = ""
                    if target and target.op == ida_hexrays.cot_obj:
                        name = ida_name.get_name(target.obj_ea) or ""
                    results["calls"].append({"callee": name, "address": addr})

                if (pattern_type in ("all", "string_refs")) and expr.op == ida_hexrays.cot_str:
                    results["string_refs"].append({"string": expr.string, "address": addr})

                if (pattern_type in ("all", "comparisons")) and expr.op in _COMPARISON_OPS:
                    results["comparisons"].append({"op": _op_name(expr.op), "address": addr})

                if (pattern_type in ("all", "assignments")) and expr.op in _ASSIGNMENT_OPS:
                    results["assignments"].append({"op": _op_name(expr.op), "address": addr})

                if (pattern_type in ("all", "casts")) and expr.op == ida_hexrays.cot_cast:
                    target_type = (
                        str(expr.type) if expr.type and not expr.type.empty() else "unknown"
                    )
                    results["casts"].append({"target_type": target_type, "address": addr})

                if (pattern_type in ("all", "pointer_derefs")) and expr.op == ida_hexrays.cot_ptr:
                    results["pointer_derefs"].append({"address": addr})

                return 0

        visitor = PatternFinder()
        visitor.apply_to(cfunc.body, None)

        if pattern_type != "all":
            return FindCtreePatternResult(
                function=format_address(func.start_ea),
                name=get_func_name(func.start_ea),
                pattern_type=pattern_type,
                count=len(results[pattern_type]),
                matches=results[pattern_type],
            )

        summary = {k: len(v) for k, v in results.items()}
        return FindCtreePatternResult(
            function=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            summary=summary,
            results=results,
        )


# Map expression/statement op codes to names (built once at import time)
_OP_NAMES: dict[int, str] = {
    getattr(ida_hexrays, attr): attr
    for attr in dir(ida_hexrays)
    if attr.startswith(("cot_", "cit_"))
}


def _op_name(op: int) -> str:
    return _OP_NAMES.get(op, f"op_{op}")
