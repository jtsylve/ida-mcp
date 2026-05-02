# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Search tools — strings, bytes, text."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ghidra_mcp.exceptions import GhidraError
from ghidra_mcp.helpers import (
    ANNO_READ_ONLY,
    Address,
    FilterPattern,
    HexBytes,
    Limit,
    Offset,
    compile_filter,
    format_address,
    paginate_iter,
    resolve_address,
)
from ghidra_mcp.session import session


class StringItem(BaseModel):
    address: str = Field(description="String address (hex).")
    value: str = Field(description="String content.")
    length: int = Field(description="String length.")
    type: str = Field(description="String encoding type.")


class SearchBytesMatch(BaseModel):
    address: str = Field(description="Match address (hex).")
    function: str = Field(description="Containing function name, if any.")


class SearchTextMatch(BaseModel):
    address: str = Field(description="Instruction address (hex).")
    text: str = Field(description="Disassembly text.")
    function: str = Field(description="Containing function name, if any.")


class StringCodeRef(BaseModel):
    string_address: str
    string_value: str
    code_address: str
    function_name: str
    function_address: str


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"search", "strings"})
    @session.require_open
    def get_strings(
        offset: Offset = 0,
        limit: Limit = 100,
        filter_pattern: FilterPattern = "",
        min_length: int = 4,
    ) -> dict:
        """Get defined strings from the database with optional regex filter."""
        program = session.program
        filt = compile_filter(filter_pattern)

        def _gen():
            listing = program.getListing()
            data_iter = listing.getDefinedData(True)
            while data_iter.hasNext():
                data = data_iter.next()
                dt = data.getDataType()
                if dt is None or "string" not in dt.getName().lower():
                    continue
                val = data.getDefaultValueRepresentation()
                if val is None:
                    continue
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                if len(val) < min_length:
                    continue
                if filt and not filt.search(val):
                    continue
                yield StringItem(
                    address=format_address(data.getAddress().getOffset()),
                    value=val,
                    length=len(val),
                    type=dt.getName() if dt else "unknown",
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"search", "strings"})
    @session.require_open
    def find_code_by_string(
        pattern: str,
        offset: Offset = 0,
        limit: Limit = 50,
    ) -> dict:
        """Find code references to strings matching a regex pattern.

        Combines string search + xref resolution + function lookup.
        """
        program = session.program
        filt = compile_filter(pattern)
        if filt is None:
            raise GhidraError("pattern is required", error_type="InvalidArgument")

        def _gen():
            listing = program.getListing()
            func_mgr = program.getFunctionManager()
            ref_mgr = program.getReferenceManager()

            data_iter = listing.getDefinedData(True)
            while data_iter.hasNext():
                data = data_iter.next()
                dt = data.getDataType()
                if dt is None or "string" not in dt.getName().lower():
                    continue
                val = data.getDefaultValueRepresentation()
                if val is None:
                    continue
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                if not filt.search(val):
                    continue

                str_addr = data.getAddress()
                refs = ref_mgr.getReferencesTo(str_addr)
                for ref in refs:
                    from_addr = ref.getFromAddress()
                    func = func_mgr.getFunctionContaining(from_addr)
                    yield StringCodeRef(
                        string_address=format_address(str_addr.getOffset()),
                        string_value=val,
                        code_address=format_address(from_addr.getOffset()),
                        function_name=func.getName() if func else "",
                        function_address=format_address(func.getEntryPoint().getOffset())
                        if func
                        else "",
                    ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"search"})
    @session.require_open
    def search_bytes(
        pattern: HexBytes,
        start_address: Address = "",
        limit: Limit = 20,
    ) -> list[SearchBytesMatch]:
        """Search for a byte pattern in the database.

        Pattern is a hex string, e.g. "48 8B" or "488B". Wildcards not supported.
        """
        program = session.program
        mem = program.getMemory()
        func_mgr = program.getFunctionManager()

        clean = pattern.replace(" ", "")
        if len(clean) % 2 != 0:
            raise GhidraError(
                "Hex pattern must have even number of hex digits", error_type="InvalidArgument"
            )
        try:
            search_bytes = bytes.fromhex(clean)
        except ValueError as e:
            raise GhidraError(f"Invalid hex pattern: {e}", error_type="InvalidArgument") from e

        addr = resolve_address(start_address) if start_address else mem.getMinAddress()

        results = []
        for _ in range(limit):
            found = mem.findBytes(addr, search_bytes, None, True, None)
            if found is None:
                break
            func = func_mgr.getFunctionContaining(found)
            results.append(
                SearchBytesMatch(
                    address=format_address(found.getOffset()),
                    function=func.getName() if func else "",
                )
            )
            addr = found.add(1)

        return results

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"search"})
    @session.require_open
    def search_text(
        pattern: str,
        offset: Offset = 0,
        limit: Limit = 50,
    ) -> dict:
        """Search disassembly text (mnemonics + operands) for a regex pattern."""
        program = session.program
        listing = program.getListing()
        func_mgr = program.getFunctionManager()
        filt = compile_filter(pattern)
        if filt is None:
            raise GhidraError("pattern is required", error_type="InvalidArgument")

        def _gen():
            insn_iter = listing.getInstructions(True)
            while insn_iter.hasNext():
                insn = insn_iter.next()
                text = str(insn)
                if not filt.search(text):
                    continue
                addr = insn.getAddress()
                func = func_mgr.getFunctionContaining(addr)
                yield SearchTextMatch(
                    address=format_address(addr.getOffset()),
                    text=text,
                    function=func.getName() if func else "",
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)
