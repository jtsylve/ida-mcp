# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Search tools — strings, bytes, text, and function name patterns."""

from __future__ import annotations

import ida_bytes
import ida_funcs
import ida_ida
import ida_name
import ida_search
import ida_strlist
from fastmcp import FastMCP

from ida_mcp.helpers import (
    clean_disasm_line,
    compile_filter,
    decode_string,
    format_address,
    is_bad_addr,
    is_cancelled,
    paginate_iter,
    resolve_address,
)
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def get_strings(
        min_length: int = 4,
        offset: int = 0,
        limit: int = 100,
        filter_pattern: str = "",
    ) -> dict:
        """Extract strings from the binary.

        This is the recommended starting point for string-based analysis.
        Much faster than search_bytes or search_text for locating string
        literals. After finding a string of interest, use get_xrefs_to on
        its address to find all code that references it — this is far more
        efficient than scanning the entire binary for text.

        Args:
            min_length: Minimum string length to include.
            offset: Pagination offset.
            limit: Maximum number of results.
            filter_pattern: Optional regex to filter string values.
        """
        pattern, err = compile_filter(filter_pattern)
        if err:
            return err

        ida_strlist.build_strlist()
        qty = ida_strlist.get_strlist_qty()
        si = ida_strlist.string_info_t()

        limit = max(1, limit)
        offset = max(0, offset)
        strings = []
        matched = 0

        for i in range(qty):
            if is_cancelled():
                break
            if not ida_strlist.get_strlist_item(si, i):
                continue
            if si.length < min_length:
                continue

            value = decode_string(si.ea, si.length, si.type)
            if value is None:
                continue

            if pattern and not pattern.search(value):
                continue

            if matched < offset:
                matched += 1
                continue

            if len(strings) < limit:
                strings.append(
                    {
                        "address": format_address(si.ea),
                        "value": value,
                        "length": si.length,
                        "type": si.type,
                    }
                )
                matched += 1
            else:
                # Count a bounded number of remaining items to estimate total
                _COUNT_AHEAD = 10_000
                matched += 1
                scanned = 0
                for j in range(i + 1, qty):
                    if scanned >= _COUNT_AHEAD or is_cancelled():
                        break
                    if ida_strlist.get_strlist_item(si, j) and si.length >= min_length:
                        scanned += 1
                        if pattern:
                            val_j = decode_string(si.ea, si.length, si.type)
                            if val_j is None or not pattern.search(val_j):
                                continue
                        matched += 1
                break

        return {
            "items": strings,
            "total": matched,
            "offset": offset,
            "limit": limit,
            "has_more": offset + limit < matched,
        }

    @mcp.tool()
    @session.require_open
    def search_bytes(pattern: str, start_address: str = "", max_results: int = 50) -> dict:
        """Search for a byte pattern in the binary.

        Supports IDA-style hex patterns with wildcards:
        e.g. "48 8B ?? 90" or "488B??90"

        Performance: scans linearly from start_address through the binary.
        On large binaries, this can be slow when searching from the beginning.
        Prefer narrowing the search with start_address when possible, or use
        get_strings + get_xrefs_to for string-based lookups instead.

        Args:
            pattern: Hex byte pattern (spaces optional, ?? for wildcards).
            start_address: Address to start searching from (default: beginning).
            max_results: Maximum matches to return.
        """
        if start_address:
            start, err = resolve_address(start_address)
            if err:
                return err
        else:
            start = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()

        # Parse the pattern into IDA's binary search format
        binpat = ida_bytes.compiled_binpat_vec_t()

        # Normalize pattern: ensure spaces between byte pairs
        cleaned = pattern.replace(" ", "")
        if len(cleaned) % 2 != 0:
            return {
                "error": f"Byte pattern has odd length ({len(cleaned)} hex chars): {pattern!r}",
                "error_type": "InvalidArgument",
            }
        spaced = " ".join(cleaned[i : i + 2] for i in range(0, len(cleaned), 2))

        encoding = ida_bytes.parse_binpat_str(binpat, start, spaced, 16)
        if encoding:
            return {
                "error": f"Invalid byte pattern: {pattern!r}: {encoding}",
                "error_type": "InvalidArgument",
            }

        results = []
        ea = start
        for _ in range(max_results):
            if is_cancelled():
                break
            ea, _ = ida_bytes.bin_search(
                ea,
                max_ea,
                binpat,
                ida_bytes.BIN_SEARCH_FORWARD,
            )
            if is_bad_addr(ea):
                break
            context = ida_bytes.get_bytes(ea, min(16, max_ea - ea))
            results.append(
                {
                    "address": format_address(ea),
                    "bytes": context.hex() if context else "",
                }
            )
            ea += 1

        return {"pattern": pattern, "match_count": len(results), "matches": results}

    @mcp.tool()
    @session.require_open
    def search_text(text: str, max_results: int = 50) -> dict:
        """Search for text in disassembly mnemonics and operands.

        This searches the disassembly text representation, NOT string literals
        in the binary data. To find string constants (like "hello world"), use
        get_strings instead.

        Performance: scans linearly through all instructions from the start
        of the database. On large binaries, prefer get_strings + get_xrefs_to
        to locate code referencing known strings.

        Args:
            text: Text to search for in disassembly lines.
            max_results: Maximum matches to return.
        """
        results = []
        ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()

        for _ in range(max_results):
            if is_cancelled():
                break
            ea = ida_search.find_text(
                ea,
                0,
                0,
                text,
                ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT,
            )
            if is_bad_addr(ea):
                break
            results.append(
                {
                    "address": format_address(ea),
                    "disasm": clean_disasm_line(ea),
                }
            )
            next_ea = ida_bytes.next_head(ea, max_ea)
            ea = next_ea if not is_bad_addr(next_ea) else ea + 1

        return {"text": text, "match_count": len(results), "matches": results}

    @mcp.tool()
    @session.require_open
    def find_immediate(value: int, start_address: str = "", max_results: int = 50) -> dict:
        """Search for instructions containing a specific immediate operand value.

        Finds all instructions that use the given integer as an immediate
        operand. More precise than search_bytes (which matches raw bytes) —
        this matches the decoded operand value regardless of encoding.

        Performance: scans linearly like search_bytes. Common values (0, 1,
        alignment constants) will produce many matches. Use start_address to
        narrow the search range. Combine results with get_function to group
        matches by function.

        Args:
            value: The immediate value to search for.
            start_address: Address to start searching from (default: beginning).
            max_results: Maximum matches to return.
        """
        if start_address:
            start, err = resolve_address(start_address)
            if err:
                return err
        else:
            start = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()

        results = []
        ea = start
        flags = ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT

        for _ in range(max_results):
            if is_cancelled():
                break
            ea, _ = ida_search.find_imm(ea, flags, value)
            if is_bad_addr(ea):
                break
            results.append(
                {
                    "address": format_address(ea),
                    "disasm": clean_disasm_line(ea),
                }
            )
            next_ea = ida_bytes.next_head(ea, max_ea)
            ea = next_ea if not is_bad_addr(next_ea) else ea + 1

        return {
            "value": f"{value:#x}",
            "match_count": len(results),
            "matches": results,
        }

    @mcp.tool()
    @session.require_open
    def search_functions_by_pattern(pattern: str, offset: int = 0, limit: int = 100) -> dict:
        """Search for functions whose names match a regex pattern.

        Equivalent to list_functions with filter_pattern — both iterate all
        functions and apply a regex filter. Use either interchangeably.

        Args:
            pattern: Regular expression pattern to match against function names.
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        regex, err = compile_filter(pattern)
        if err:
            return err
        if regex is None:
            return {"error": "Pattern is required", "error_type": "InvalidArgument"}

        def _iter():
            for i in range(ida_funcs.get_func_qty()):
                if is_cancelled():
                    return
                func = ida_funcs.getn_func(i)
                if func is None:
                    continue
                name = ida_name.get_name(func.start_ea) or ""
                if regex.search(name):
                    yield {
                        "name": name,
                        "address": format_address(func.start_ea),
                        "size": func.size(),
                    }

        result = paginate_iter(_iter(), offset, limit)
        result["pattern"] = pattern
        return result
