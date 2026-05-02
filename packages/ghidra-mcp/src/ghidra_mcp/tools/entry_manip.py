# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Entry point manipulation tools."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ghidra_mcp.exceptions import GhidraError
from ghidra_mcp.helpers import (
    ANNO_MUTATE,
    Address,
    format_address,
    resolve_address,
)
from ghidra_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class AddEntryPointResult(BaseModel):
    """Result of adding an entry point."""

    address: str = Field(description="Entry point address (hex).")
    name: str = Field(description="Entry point name.")
    status: str = Field(description="Status.")


class RenameEntryPointResult(BaseModel):
    """Result of renaming an entry point."""

    address: str = Field(description="Entry point address (hex).")
    old_name: str = Field(description="Previous name.")
    new_name: str = Field(description="New name.")
    status: str = Field(description="Status.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"metadata"})
    @session.require_open
    def add_entry_point(
        address: Address,
        name: str,
    ) -> AddEntryPointResult:
        """Register a new entry point at an address.

        Adds the address as an external entry point and creates a label
        with the given name.

        Args:
            address: Address of the entry point.
            name: Name for the entry point.
        """
        from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

        program = session.program
        addr = resolve_address(address)

        tx_id = program.startTransaction("Add entry point")
        try:
            sym_table = program.getSymbolTable()
            sym_table.addExternalEntryPoint(addr)

            # Create or update a label at the entry point
            existing_sym = sym_table.getPrimarySymbol(addr)
            if existing_sym is not None:
                existing_sym.setName(name, SourceType.USER_DEFINED)
            else:
                sym_table.createLabel(addr, name, SourceType.USER_DEFINED)

            program.endTransaction(tx_id, True)
        except GhidraError:
            program.endTransaction(tx_id, False)
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to add entry point: {e}", error_type="AddFailed") from e

        return AddEntryPointResult(
            address=format_address(addr.getOffset()),
            name=name,
            status="added",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"metadata"})
    @session.require_open
    def rename_entry_point(
        address: Address,
        name: str,
    ) -> RenameEntryPointResult:
        """Rename an entry point's symbol at an address.

        Args:
            address: Address of the entry point.
            name: New name for the entry point.
        """
        from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

        program = session.program
        addr = resolve_address(address)

        sym_table = program.getSymbolTable()

        # Verify this is an entry point
        if not sym_table.isExternalEntryPoint(addr):
            raise GhidraError(
                f"Address {format_address(addr.getOffset())} is not an entry point",
                error_type="NotFound",
            )

        existing_sym = sym_table.getPrimarySymbol(addr)
        old_name = existing_sym.getName() if existing_sym else format_address(addr.getOffset())

        tx_id = program.startTransaction("Rename entry point")
        try:
            if existing_sym is not None:
                existing_sym.setName(name, SourceType.USER_DEFINED)
            else:
                sym_table.createLabel(addr, name, SourceType.USER_DEFINED)
            program.endTransaction(tx_id, True)
        except GhidraError:
            program.endTransaction(tx_id, False)
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to rename entry point: {e}", error_type="RenameFailed"
            ) from e

        return RenameEntryPointResult(
            address=format_address(addr.getOffset()),
            old_name=old_name,
            new_name=name,
            status="renamed",
        )
