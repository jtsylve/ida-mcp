# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""FLIRT signature and type library tools."""

from __future__ import annotations

import ida_funcs
import ida_loader
import ida_typeinf
import idc
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ida.helpers import ANNO_MUTATE, ANNO_READ_ONLY, META_READS_FILES, IDAError
from re_mcp_ida.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class FlirtSignatureInfo(BaseModel):
    """FLIRT signature information."""

    index: int = Field(description="Signature index.")
    name: str = Field(description="Signature name.")
    optional_libs: str = Field(description="Optional library modules.")


class ApplyFlirtResult(BaseModel):
    """Result of applying a FLIRT signature."""

    signature: str = Field(description="Signature name.")
    status: str = Field(description="Status message.")


class FlirtSignatureListResult(BaseModel):
    """List of available FLIRT signatures."""

    count: int = Field(description="Number of signatures.")
    signatures: list[FlirtSignatureInfo] = Field(description="Available signatures.")


class TypeLibraryInfo(BaseModel):
    """Type library information."""

    index: int = Field(description="Library index.")
    name: str = Field(description="Library name.")
    description: str = Field(description="Library description.")


class LoadTypeLibraryResult(BaseModel):
    """Result of loading a type library."""

    library: str = Field(description="Library name.")
    status: str = Field(description="Status message.")


class TypeLibraryListResult(BaseModel):
    """List of available type libraries."""

    count: int = Field(description="Number of libraries.")
    libraries: list[TypeLibraryInfo] = Field(description="Available libraries.")


class LoadIdsModuleResult(BaseModel):
    """Result of loading an IDS module."""

    filename: str = Field(description="Module filename.")
    status: str = Field(description="Status message.")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"signatures"},
    )
    @session.require_open
    def apply_flirt_signature(sig_name: str) -> ApplyFlirtResult:
        """Apply a FLIRT signature library to auto-identify and name library functions.

        Essential for statically linked binaries.

        Args:
            sig_name: Name of the signature file (without extension), e.g. "libc".
        """
        # plan_to_apply_idasgn applies the signature
        result = idc.plan_to_apply_idasgn(sig_name)
        if result == 0:
            raise IDAError(
                f"Failed to apply signature: {sig_name!r}. File may not exist.",
                error_type="ApplyFailed",
            )

        return ApplyFlirtResult(
            signature=sig_name,
            status="applied",
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"signatures"},
    )
    @session.require_open
    def list_flirt_signatures() -> FlirtSignatureListResult:
        """List FLIRT signature files currently applied to the database."""
        sigs = []
        n = ida_funcs.get_idasgn_qty()
        for i in range(n):
            desc = ida_funcs.get_idasgn_desc(i)
            if desc:
                name, optlibs = desc
                sigs.append(
                    {
                        "index": i,
                        "name": name,
                        "optional_libs": optlibs,
                    }
                )

        return FlirtSignatureListResult(count=len(sigs), signatures=sigs)

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"signatures"},
        meta=META_READS_FILES,
    )
    @session.require_open
    def load_type_library(til_name: str) -> LoadTypeLibraryResult:
        """Load a TIL (type library) for OS/SDK types (e.g., gnulnx_x64, mssdk_win10).

        Args:
            til_name: Name of the type library (without extension).
        """
        result = ida_typeinf.add_til(til_name, ida_typeinf.ADDTIL_DEFAULT)
        if result == 0:
            raise IDAError(f"Failed to load type library: {til_name!r}", error_type="LoadFailed")

        return LoadTypeLibraryResult(library=til_name, status="loaded")

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"signatures"},
    )
    @session.require_open
    def list_type_libraries() -> TypeLibraryListResult:
        """List all loaded type information libraries (TILs)."""
        til = ida_typeinf.get_idati()
        libs = []
        for i in range(til.nbases):
            base = til.base(i)
            if base:
                libs.append(
                    {
                        "index": i,
                        "name": base.name,
                        "description": base.desc or "",
                    }
                )

        return TypeLibraryListResult(count=len(libs), libraries=libs)

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"signatures"},
        meta=META_READS_FILES,
    )
    @session.require_open
    def load_ids_module(filename: str) -> LoadIdsModuleResult:
        """Load and apply an IDS (ID Signature) file.

        IDS files contain type information for known library functions.
        If the program imports from a module matching the IDS filename,
        only those imports are affected. Otherwise any function may be updated.

        Args:
            filename: Name of the IDS file to apply.
        """
        result = ida_loader.load_ids_module(filename)
        if result == 0:
            raise IDAError(f"Failed to load IDS module: {filename!r}", error_type="LoadFailed")
        return LoadIdsModuleResult(filename=filename, status="applied")
