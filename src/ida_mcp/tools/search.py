# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Search tools — strings, bytes, text, and immediate values."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from typing import Annotated

import ida_bytes
import ida_funcs
import ida_ida
import ida_search
import ida_strlist
import idautils
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
    call_ida,
    clean_disasm_line,
    compile_filter,
    decode_string,
    format_address,
    get_func_name,
    is_bad_addr,
    is_cancelled,
    resolve_address,
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


class StringFilter(BaseModel):
    """A filter for batch string search."""

    pattern: str = Field(description="Regex pattern to match string values.")
    min_length: int = Field(default=4, description="Minimum string length.")
    limit: int = Field(default=100, ge=1, description="Max matches for this filter.")


class StringGroup(BaseModel):
    """Matches for one filter in a batch string search."""

    pattern: str = Field(description="The regex pattern used.")
    matches: list[StringItem] = Field(description="Matching strings.")
    total_scanned: int = Field(description="Total strings scanned.")


class BatchStringsResult(BaseModel):
    """Result of batch string search with multiple filters."""

    groups: list[StringGroup] = Field(description="Results grouped by filter.")
    cancelled: bool = Field(default=False, description="Whether search was cancelled early.")


class StringCodeRef(BaseModel):
    """A string and the function that references it."""

    string_address: str = Field(description="Address of the string (hex).")
    string_value: str = Field(description="The string value.")
    function_address: str = Field(description="Address of the referencing function (hex).")
    function_name: str = Field(description="Name of the referencing function.")


class FindCodeByStringResult(BaseModel):
    """Result of finding code that references matching strings."""

    results: list[StringCodeRef] = Field(description="String-to-function references found.")
    total_strings_scanned: int = Field(
        description="Number of matching strings scanned (may be less than total in binary)."
    )
    unique_functions: int = Field(description="Unique functions in the returned results.")


class RebuildStringListResult(BaseModel):
    """Result of rebuilding the string list."""

    string_count: int = Field(description="Number of strings after rebuild.")


def _iter_strings(min_length: int = 4, pattern: re.Pattern | None = None) -> Iterator[dict]:
    """Iterate IDA's string list, yielding dicts for matching entries.

    Each yielded dict contains ``ea`` (raw int), ``address`` (hex str),
    ``value``, ``length``, and ``type``.

    Assumes ``ida_strlist.build_strlist()`` has already been called.
    """
    qty = ida_strlist.get_strlist_qty()
    si = ida_strlist.string_info_t()
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
            "ea": si.ea,
            "address": format_address(si.ea),
            "value": value,
            "length": si.length,
            "type": si.type,
        }


def _batch_strings(filters: list[StringFilter]) -> BatchStringsResult:
    """Run batch string search (runs on main thread)."""
    compiled = [(compile_filter(f.pattern), f.min_length, f.limit, f.pattern) for f in filters]
    per_filter: list[list[dict]] = [[] for _ in compiled]
    qty = ida_strlist.get_strlist_qty()
    si = ida_strlist.string_info_t()
    cancelled = False
    remaining = len(compiled)
    for i in range(qty):
        if is_cancelled():
            cancelled = True
            break
        if not ida_strlist.get_strlist_item(si, i):
            continue
        value: str | None = None
        for fi, (pat, ml, lim, _) in enumerate(compiled):
            if len(per_filter[fi]) >= lim:
                continue
            if si.length < ml:
                continue
            if value is None:
                value = decode_string(si.ea, si.length, si.type)
                if value is None:
                    break
            if pat and not pat.search(value):
                continue
            per_filter[fi].append(
                {
                    "address": format_address(si.ea),
                    "value": value,
                    "length": si.length,
                    "type": si.type,
                }
            )
            if len(per_filter[fi]) >= lim:
                remaining -= 1
        if remaining <= 0:
            break

    groups = [
        StringGroup(pattern=raw_pattern, matches=per_filter[fi], total_scanned=qty)
        for fi, (_, _, _, raw_pattern) in enumerate(compiled)
    ]
    return BatchStringsResult(groups=groups, cancelled=cancelled)


def _search_bytes_sync(pattern: str, start_address: str, max_results: int) -> SearchBytesResult:
    """Run byte pattern search (runs on main thread)."""
    start = resolve_address(start_address) if start_address else ida_ida.inf_get_min_ea()
    max_ea = ida_ida.inf_get_max_ea()

    binpat = ida_bytes.compiled_binpat_vec_t()
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

    results = []
    ea = start
    for _i in range(max_results):
        if is_cancelled():
            break
        ea, _ = ida_bytes.bin_search(ea, max_ea, binpat, ida_bytes.BIN_SEARCH_FORWARD)
        if is_bad_addr(ea):
            break
        context_bytes = ida_bytes.get_bytes(ea, min(16, max_ea - ea))
        results.append(
            {"address": format_address(ea), "bytes": context_bytes.hex() if context_bytes else ""}
        )
        ea += 1
    return SearchBytesResult(pattern=pattern, match_count=len(results), matches=results)


def _linear_disasm_search(
    start: int, max_results: int, find_next: Callable[[int], int]
) -> list[dict]:
    """Shared loop for linear searches that collect {address, disasm} dicts.

    *find_next(ea)* returns the next match address, or BADADDR when done.
    """
    max_ea = ida_ida.inf_get_max_ea()
    results: list[dict] = []
    ea = start
    for _i in range(max_results):
        if is_cancelled():
            break
        ea = find_next(ea)
        if is_bad_addr(ea):
            break
        results.append({"address": format_address(ea), "disasm": clean_disasm_line(ea)})
        next_ea = ida_bytes.next_head(ea, max_ea)
        ea = next_ea if not is_bad_addr(next_ea) else ea + 1
    return results


def _search_text_sync(text: str, max_results: int) -> SearchTextResult:
    """Run text search in disassembly (runs on main thread)."""
    flags = ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT
    results = _linear_disasm_search(
        ida_ida.inf_get_min_ea(),
        max_results,
        lambda ea: ida_search.find_text(ea, 0, 0, text, flags),
    )
    return SearchTextResult(text=text, match_count=len(results), matches=results)


def _find_immediate_sync(value: int, start_address: str, max_results: int) -> FindImmediateResult:
    """Run immediate value search (runs on main thread)."""
    start = resolve_address(start_address) if start_address else ida_ida.inf_get_min_ea()
    flags = ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT
    results = _linear_disasm_search(
        start,
        max_results,
        lambda ea: ida_search.find_imm(ea, flags, value)[0],
    )
    return FindImmediateResult(value=f"{value:#x}", match_count=len(results), matches=results)


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
        filters: Annotated[
            list[StringFilter],
            Field(
                description=(
                    "Batch mode: list of filters to search for multiple "
                    "patterns in one pass (max 10). Mutually exclusive with "
                    "filter_pattern."
                ),
                max_length=10,
            ),
        ] = [],  # noqa: B006
    ) -> StringListResult | BatchStringsResult:
        """Extract strings from the binary.

        **Single mode** — use filter_pattern (or no filter) to get a
        paginated list of strings.  **Batch mode** — pass filters (a list
        of ``{pattern, min_length, limit}``) to search for multiple
        patterns in a single pass over the string list.

        This is the recommended starting point for string-based analysis.
        After finding a string of interest, use get_xrefs_to on its
        address to find all code that references it, or use
        find_code_by_string to do both steps at once.

        Results come from IDA's cached string list, which is built once
        during initial analysis (wait_for_analysis).  If you patch bytes,
        define new data, or otherwise create/destroy strings after that,
        call rebuild_string_list first to refresh the cache.

        Args:
            min_length: Minimum string length to include.
            offset: Pagination offset.
            limit: Maximum number of results.
            filter_pattern: Optional regex to filter string values.
            filters: Batch mode — list of filters for multi-pattern search.
        """
        # Batch mode
        if filters:
            if filter_pattern:
                raise IDAError(
                    "Provide either filters (batch) or filter_pattern (single), not both",
                    error_type="InvalidArgument",
                )
            return await call_ida(_batch_strings, filters)

        # Single mode (compile_filter is pure Python — no IDA API)
        pattern = compile_filter(filter_pattern)
        return StringListResult(
            **await async_paginate_iter(
                _iter_strings(min_length, pattern),
                offset,
                limit,
                progress_label="Scanning strings",
            )
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"navigation", "xrefs", "strings"},
        meta=META_BATCH,
    )
    @session.require_open
    def find_code_by_string(
        pattern: str,
        min_length: int = 4,
        offset: Offset = 0,
        limit: Limit = 20,
    ) -> FindCodeByStringResult:
        """Find functions that reference strings matching a regex.

        Combines get_strings + get_xrefs_to + function resolution into a
        single call.  Returns a list of (string, function) pairs —
        does NOT auto-decompile.  Use the returned function addresses
        with decompile_function to inspect the code.

        Uses IDA's cached string list (built during wait_for_analysis).
        If you patch bytes or define new data, call rebuild_string_list
        first to refresh the cache.

        Args:
            pattern: Regex pattern to match string values.
            min_length: Minimum string length.
            offset: Number of results to skip (for pagination).
            limit: Maximum number of string-to-function refs to return.
        """
        compiled = compile_filter(pattern)
        if compiled is None:
            raise IDAError("pattern is required", error_type="InvalidArgument")

        results: list[StringCodeRef] = []
        strings_scanned = 0
        seen_funcs: set[int] = set()
        skipped = 0

        for s in _iter_strings(min_length, compiled):
            if is_cancelled():
                break
            strings_scanned += 1
            for xref in idautils.XrefsTo(s["ea"]):
                if is_cancelled():
                    break
                func = ida_funcs.get_func(xref.frm)
                if func is None:
                    continue
                if skipped < offset:
                    skipped += 1
                    continue
                seen_funcs.add(func.start_ea)
                results.append(
                    StringCodeRef(
                        string_address=s["address"],
                        string_value=s["value"],
                        function_address=format_address(func.start_ea),
                        function_name=get_func_name(func.start_ea),
                    )
                )
                if len(results) >= limit:
                    break
            if len(results) >= limit:
                break

        return FindCodeByStringResult(
            results=results,
            total_strings_scanned=strings_scanned,
            unique_functions=len(seen_funcs),
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
        return await call_ida(_search_bytes_sync, pattern, start_address, max_results)

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
        return await call_ida(_search_text_sync, text, max_results)

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
        return await call_ida(_find_immediate_sync, value, start_address, max_results)
