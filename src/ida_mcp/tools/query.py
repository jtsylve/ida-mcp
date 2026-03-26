# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Instruction and constant query tools."""

from __future__ import annotations

import ida_bytes
import ida_funcs
import ida_ida
import ida_search
import idautils
import idc
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import (
    clean_disasm_line,
    compile_filter,
    format_address,
    get_func_name,
    is_bad_addr,
    paginate_iter,
    resolve_address,
    resolve_function,
)
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def insn_query(
        mnemonic: str = "",
        operand_pattern: str = "",
        address: str = "",
        start_address: str = "",
        end_address: str = "",
        offset: int = 0,
        limit: int = 100,
    ) -> dict:
        """Search for instructions matching mnemonic and/or operand patterns.

        Finds instructions whose mnemonic matches a regex pattern and/or whose
        full disassembly line matches an operand pattern. At least one of
        mnemonic or operand_pattern must be provided.

        Scope can be narrowed to a single function (address), an address range
        (start_address/end_address), or the entire database (default).

        Args:
            mnemonic: Regex pattern to match against instruction mnemonics.
            operand_pattern: Regex pattern matched against the full disassembly line.
            address: Scope to a specific function (empty = use range or all).
            start_address: Start of address range (alternative to function scope).
            end_address: End of address range.
            offset: Pagination offset.
            limit: Maximum number of results (max 500).
        """
        if not mnemonic and not operand_pattern:
            return {
                "error": "At least one of mnemonic or operand_pattern must be provided.",
                "error_type": "InvalidArgument",
            }

        mnem_re, err = compile_filter(mnemonic)
        if err:
            return err
        op_re, err = compile_filter(operand_pattern)
        if err:
            return err

        # Determine instruction source
        if address:
            func, err = resolve_function(address)
            if err:
                return err

            def _items():
                yield from idautils.FuncItems(func.start_ea)

        elif start_address or end_address:
            if start_address:
                s_ea, err = resolve_address(start_address)
                if err:
                    return err
            else:
                s_ea = ida_ida.inf_get_min_ea()
            if end_address:
                e_ea, err = resolve_address(end_address)
                if err:
                    return err
            else:
                e_ea = ida_ida.inf_get_max_ea()

            def _items():
                ea = s_ea
                while ea < e_ea and not is_bad_addr(ea):
                    yield ea
                    ea = ida_bytes.next_head(ea, e_ea)

        else:
            min_ea = ida_ida.inf_get_min_ea()
            max_ea = ida_ida.inf_get_max_ea()

            def _items():
                ea = min_ea
                while ea < max_ea and not is_bad_addr(ea):
                    yield ea
                    ea = ida_bytes.next_head(ea, max_ea)

        def _match():
            for ea in _items():
                m = idc.print_insn_mnem(ea)
                if not m:
                    continue
                if mnem_re and not mnem_re.search(m):
                    continue
                if op_re:
                    line = clean_disasm_line(ea)
                    if not op_re.search(line):
                        continue
                else:
                    line = clean_disasm_line(ea)

                func_at = ida_funcs.get_func(ea)
                yield {
                    "address": format_address(ea),
                    "disasm": line,
                    "function": get_func_name(func_at.start_ea) if func_at else None,
                }

        result = paginate_iter(_match(), offset, limit)
        if mnemonic:
            result["mnemonic"] = mnemonic
        if operand_pattern:
            result["operand_pattern"] = operand_pattern
        return result

    @mcp.tool()
    @session.require_open
    def search_constants(
        value: int,
        filter_pattern: str = "",
        start_address: str = "",
        max_results: int = 100,
    ) -> dict:
        """Search for instructions containing a specific immediate constant value.

        Wraps IDA's find_immediate search with added function context and an
        optional function-name filter. Each match includes the containing
        function name and address for easier triage.

        Args:
            value: The constant value to search for.
            filter_pattern: Optional regex to filter by containing function name.
            start_address: Address to start searching from (default: beginning).
            max_results: Maximum results to return.
        """
        pattern, err = compile_filter(filter_pattern)
        if err:
            return err

        if start_address:
            start, err = resolve_address(start_address)
            if err:
                return err
        else:
            start = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()

        def _iter():
            ea = start
            flags = ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT
            found = 0
            while found < max_results:
                ea, _ = ida_search.find_imm(ea, flags, value)
                if is_bad_addr(ea):
                    break

                func = ida_funcs.get_func(ea)
                func_name = get_func_name(func.start_ea) if func else None

                # Apply function name filter if provided
                if pattern and (func_name is None or not pattern.search(func_name)):
                    next_ea = ida_bytes.next_head(ea, max_ea)
                    ea = next_ea if not is_bad_addr(next_ea) else ea + 1
                    continue

                yield {
                    "address": format_address(ea),
                    "disasm": clean_disasm_line(ea),
                    "function": func_name,
                    "function_address": format_address(func.start_ea) if func else None,
                }
                found += 1

                next_ea = ida_bytes.next_head(ea, max_ea)
                ea = next_ea if not is_bad_addr(next_ea) else ea + 1

        results = list(_iter())
        return {
            "value": f"{value:#x}",
            "match_count": len(results),
            "matches": results,
        }
