# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Address metadata tools -- code/data classification, xref presence, naming info."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.helpers import (
    ANNO_READ_ONLY,
    Address,
    format_address,
    resolve_address,
)
from re_mcp_ghidra.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class AddressInfoResult(BaseModel):
    """Address metadata and classification."""

    address: str = Field(description="Address (hex).")
    is_code: bool = Field(description="Address contains an instruction.")
    is_data: bool = Field(description="Address contains defined data.")
    is_undefined: bool = Field(description="Address has no code or data definition.")
    has_name: bool = Field(description="Address has an assigned name/symbol.")
    name: str = Field(default="", description="Symbol name, if any.")
    has_references_to: bool = Field(description="Other addresses reference this address.")
    has_references_from: bool = Field(description="This address references other addresses.")
    reference_to_count: int = Field(description="Number of references pointing to this address.")
    reference_from_count: int = Field(description="Number of references from this address.")
    is_function_entry: bool = Field(description="Address is a function entry point.")
    function_name: str = Field(default="", description="Containing function name, if any.")
    in_function: bool = Field(description="Address is inside a function.")
    is_external: bool = Field(description="Address is in an external block.")
    code_unit_size: int = Field(description="Size of the code unit at this address (bytes).")
    data_type: str = Field(
        default="", description="Data type name if address contains defined data."
    )


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"metadata"})
    @session.require_open
    def get_address_info(
        address: Address,
    ) -> AddressInfoResult:
        """Get classification and metadata for an address.

        Reports whether the address contains code, data, or is undefined,
        whether it has a name, cross-references, and function membership.

        Args:
            address: Address to query.
        """
        from ghidra.program.model.listing import Instruction  # noqa: PLC0415

        program = session.program
        listing = program.getListing()
        sym_table = program.getSymbolTable()
        ref_mgr = program.getReferenceManager()
        func_mgr = program.getFunctionManager()
        addr = resolve_address(address)

        cu = listing.getCodeUnitAt(addr)

        # Classification
        is_code = False
        is_data = False
        is_undefined = True
        code_unit_size = 1
        data_type_name = ""

        if cu is not None:
            code_unit_size = cu.getLength()
            if isinstance(cu, Instruction):
                is_code = True
                is_undefined = False
            else:
                # Data or undefined
                from ghidra.program.model.listing import Data  # noqa: PLC0415

                if isinstance(cu, Data) and cu.isDefined():
                    is_data = True
                    is_undefined = False
                    dt = cu.getDataType()
                    data_type_name = dt.getName() if dt else ""
                else:
                    is_undefined = True

        # Name / symbol
        sym = sym_table.getPrimarySymbol(addr)
        has_name = sym is not None and not sym.isDynamic()
        name = sym.getName() if has_name else ""

        # References
        refs_to = list(ref_mgr.getReferencesTo(addr))
        ref_to_count = len(refs_to)

        refs_from = ref_mgr.getReferencesFrom(addr)
        ref_from_count = len(refs_from) if refs_from else 0

        # Function
        func = func_mgr.getFunctionContaining(addr)
        func_at = func_mgr.getFunctionAt(addr)
        is_function_entry = func_at is not None
        in_function = func is not None
        function_name = func.getName() if func else ""

        # External
        mem = program.getMemory()
        block = mem.getBlock(addr)
        is_external = block is not None and block.isExternalBlock() if block else False

        return AddressInfoResult(
            address=format_address(addr.getOffset()),
            is_code=is_code,
            is_data=is_data,
            is_undefined=is_undefined,
            has_name=has_name,
            name=name,
            has_references_to=ref_to_count > 0,
            has_references_from=ref_from_count > 0,
            reference_to_count=ref_to_count,
            reference_from_count=ref_from_count,
            is_function_entry=is_function_entry,
            function_name=function_name,
            in_function=in_function,
            is_external=is_external,
            code_unit_size=code_unit_size,
            data_type=data_type_name,
        )
