# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Search tools — strings, bytes, text, and immediate values."""

from __future__ import annotations

import ida_bytes
import ida_ida
import ida_search
import ida_strlist
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    META_BATCH,
    Address,
    FilterPattern,
    IDAError,
    Limit,
    Offset,
    async_paginate_iter,
    clean_disasm_line,
    compile_filter,
    decode_string,
    format_address,
    is_bad_addr,
    is_cancelled,
    resolve_address,
    try_get_context,
)
from ida_mcp.models import PaginatedResult
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class StringItem(BaseModel):
    """A string found in the binary."""

    address: str = Field(description="String address (hex).")
    value: str = Field(description="String value.")
    length: int = Field(description="String length.")
    type: int = Field(description="String type ID.")


class StringListResult(PaginatedResult[StringItem]):
    """Paginated list of strings."""

    items: list[StringItem] = Field(description="Page of strings.")


class ByteSearchMatch(BaseModel):
    """A byte pattern match."""

    address: str = Field(description="Match address (hex).")
    bytes: str = Field(description="Matched bytes (hex).")


class SearchBytesResult(BaseModel):
    """Result of a byte pattern search."""

    pattern: str = Field(description="Search pattern.")
    match_count: int = Field(description="Number of matches found.")
    matches: list[ByteSearchMatch] = Field(description="List of matches.")


class TextSearchMatch(BaseModel):
    """A text search match."""

    address: str = Field(description="Match address (hex).")
    disasm: str = Field(description="Disassembly at the match.")


class SearchTextResult(BaseModel):
    """Result of a text search."""

    text: str = Field(description="Search text.")
    match_count: int = Field(description="Number of matches found.")
    matches: list[TextSearchMatch] = Field(description="List of matches.")


class FindImmediateResult(BaseModel):
    """Result of an immediate value search."""

    value: str = Field(description="Search value (hex).")
    match_count: int = Field(description="Number of matches found.")
    matches: list[TextSearchMatch] = Field(description="List of matches.")


class RebuildStringListResult(BaseModel):
    """Result of rebuilding the string list."""

    string_count: int = Field(description="Number of strings after rebuild.")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"analysis"},
    )
    @session.require_open
    def rebuild_string_list() -> RebuildStringListResult:
        """Rebuild the string list from scratch.

        Call this after patching bytes, defining new data, or any other
        modification that may create or destroy strings.  The string list
        is cached — read-only tools like get_strings use the cached
        version automatically, but the cache is NOT updated on mutation.
        """
        ida_strlist.build_strlist()
        return RebuildStringListResult(string_count=ida_strlist.get_strlist_qty())

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"navigation"},
        meta=META_BATCH,
    )
    @session.require_open
    async def get_strings(
        min_length: int = 4,
        offset: Offset = 0,
        limit: Limit = 100,
        filter_pattern: FilterPattern = "",
    ) -> StringListResult:
        """Extract strings from the binary.

        This is the recommended starting point for string-based analysis.
        Much faster than search_bytes or search_text for locating string
        literals. After finding a string of interest, use get_xrefs_to on
        its address to find all code that references it — this is far more
        efficient than scanning the entire binary for text.

        Results come from IDA's cached string list, which is built once
        during initial analysis (wait_for_analysis).  If you patch bytes,
        define new data, or otherwise create/destroy strings after that,
        call rebuild_string_list first to refresh the cache.

        Args:
            min_length: Minimum string length to include.
            offset: Pagination offset.
            limit: Maximum number of results.
            filter_pattern: Optional regex to filter string values.
        """
        pattern = compile_filter(filter_pattern)

        qty = ida_strlist.get_strlist_qty()
        si = ida_strlist.string_info_t()

        def _iter():
            for i in range(qty):
                if is_cancelled():
                    return
                if not ida_strlist.get_strlist_item(si, i):
                    continue
                if si.length < min_length:
                    continue
                value = decode_string(si.ea, si.length, si.type)
                if value is None:
                    continue
                if pattern and not pattern.search(value):
                    continue
                yield {
                    "address": format_address(si.ea),
                    "value": value,
                    "length": si.length,
                    "type": si.type,
                }

        return StringListResult(
            **await async_paginate_iter(_iter(), offset, limit, progress_label="Scanning strings")
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"navigation"},
        meta=META_BATCH,
    )
    @session.require_open
    async def search_bytes(
        pattern: str,
        start_address: Address = "",
        max_results: int = 50,
    ) -> SearchBytesResult:
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
        start = resolve_address(start_address) if start_address else ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()

        binpat = ida_bytes.compiled_binpat_vec_t()

        # Normalize pattern: ensure spaces between byte pairs
        cleaned = pattern.replace(" ", "")
        if len(cleaned) % 2 != 0:
            raise IDAError(
                f"Byte pattern has odd length ({len(cleaned)} hex chars): {pattern!r}",
                error_type="InvalidArgument",
            )
        spaced = " ".join(cleaned[i : i + 2] for i in range(0, len(cleaned), 2))

        encoding = ida_bytes.parse_binpat_str(binpat, start, spaced, 16)
        if encoding:
            raise IDAError(
                f"Invalid byte pattern: {pattern!r}: {encoding}", error_type="InvalidArgument"
            )

        ctx = try_get_context()
        results = []
        ea = start
        for i in range(max_results):
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
            context_bytes = ida_bytes.get_bytes(ea, min(16, max_ea - ea))
            results.append(
                {
                    "address": format_address(ea),
                    "bytes": context_bytes.hex() if context_bytes else "",
                }
            )
            if ctx and (i + 1) % 10 == 0:
                await ctx.report_progress(i + 1, max_results)
            ea += 1

        if ctx:
            await ctx.report_progress(len(results), len(results))
        return SearchBytesResult(pattern=pattern, match_count=len(results), matches=results)

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"navigation"},
        meta=META_BATCH,
    )
    @session.require_open
    async def search_text(text: str, max_results: int = 50) -> SearchTextResult:
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
        ctx = try_get_context()
        results = []
        ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()

        for i in range(max_results):
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
            if ctx and (i + 1) % 10 == 0:
                await ctx.report_progress(i + 1, max_results)
            next_ea = ida_bytes.next_head(ea, max_ea)
            ea = next_ea if not is_bad_addr(next_ea) else ea + 1

        if ctx:
            await ctx.report_progress(len(results), len(results))
        return SearchTextResult(text=text, match_count=len(results), matches=results)

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"navigation"},
        meta=META_BATCH,
    )
    @session.require_open
    async def find_immediate(
        value: int,
        start_address: Address = "",
        max_results: int = 50,
    ) -> FindImmediateResult:
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
        start = resolve_address(start_address) if start_address else ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()

        ctx = try_get_context()
        results = []
        ea = start
        flags = ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT

        for i in range(max_results):
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
            if ctx and (i + 1) % 10 == 0:
                await ctx.report_progress(i + 1, max_results)
            next_ea = ida_bytes.next_head(ea, max_ea)
            ea = next_ea if not is_bad_addr(next_ea) else ea + 1

        if ctx:
            await ctx.report_progress(len(results), len(results))
        return FindImmediateResult(
            value=f"{value:#x}",
            match_count=len(results),
            matches=results,
        )
