# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Name demangling tools for C++ symbol analysis."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ghidra_mcp.helpers import (
    ANNO_READ_ONLY,
    Address,
    FilterPattern,
    Limit,
    Offset,
    compile_filter,
    format_address,
    paginate_iter,
    resolve_address,
)
from ghidra_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class DemangleResult(BaseModel):
    """Result of demangling a name."""

    name: str = Field(description="Original mangled name.")
    demangled: str | None = Field(description="Demangled name, or null if not mangled.")
    is_mangled: bool = Field(description="Whether the name was mangled.")


class DemangleAtAddressResult(BaseModel):
    """Result of demangling the name at an address."""

    address: str = Field(description="Address (hex).")
    name: str | None = Field(description="Name at the address.")
    demangled: str | None = Field(description="Demangled name, or null if not mangled.")
    is_mangled: bool = Field(description="Whether the name was mangled.")


class DemangledNameItem(BaseModel):
    """A demangled name entry."""

    address: str = Field(description="Address (hex).")
    mangled: str = Field(description="Mangled name.")
    demangled: str = Field(description="Demangled name.")


def _try_demangle(name: str) -> str | None:
    """Attempt to demangle a name using Ghidra's DemanglerUtil.

    Returns the demangled string or ``None`` if the name is not mangled.
    """
    from ghidra.app.util.demangler import DemanglerUtil  # noqa: PLC0415

    try:
        result = DemanglerUtil.demangle(name)
        if result is not None:
            return str(result)
    except Exception:
        pass
    return None


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"utility", "symbols"})
    @session.require_open
    def demangle_name(name: str) -> DemangleResult:
        """Demangle a C++ symbol name to readable form.

        Example: ``_ZN3FooC1Ev`` -> ``Foo::Foo(void)``.

        Args:
            name: The mangled symbol name.
        """
        demangled = _try_demangle(name)
        return DemangleResult(
            name=name,
            demangled=demangled,
            is_mangled=demangled is not None,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"utility", "symbols"})
    @session.require_open
    def demangle_at_address(
        address: Address,
    ) -> DemangleAtAddressResult:
        """Demangle the symbol name at a given address.

        Args:
            address: Address or symbol name to demangle.
        """
        program = session.program
        addr = resolve_address(address)
        sym_table = program.getSymbolTable()
        sym = sym_table.getPrimarySymbol(addr)

        if sym is None:
            return DemangleAtAddressResult(
                address=format_address(addr.getOffset()),
                name=None,
                demangled=None,
                is_mangled=False,
            )

        name = sym.getName()
        demangled = _try_demangle(name)
        return DemangleAtAddressResult(
            address=format_address(addr.getOffset()),
            name=name,
            demangled=demangled,
            is_mangled=demangled is not None,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"utility", "symbols"})
    @session.require_open
    def list_demangled_names(
        offset: Offset = 0,
        limit: Limit = 100,
        filter_pattern: FilterPattern = "",
    ) -> dict:
        """List named addresses with demangled forms (C++ only; paginated, regex-filterable).

        For a single symbol, use demangle_name or demangle_at_address instead.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
            filter_pattern: Optional regex to filter demangled names.
        """
        program = session.program
        sym_table = program.getSymbolTable()
        filt = compile_filter(filter_pattern)

        def _gen():
            sym_iter = sym_table.getAllSymbols(True)
            for sym in sym_iter:
                if sym.isDynamic():
                    continue
                name = sym.getName()
                demangled = _try_demangle(name)
                if demangled is None:
                    continue
                if filt and not filt.search(demangled):
                    continue
                yield DemangledNameItem(
                    address=format_address(sym.getAddress().getOffset()),
                    mangled=name,
                    demangled=demangled,
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)
