# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""FLIRT signature and type library tools."""

from __future__ import annotations

import ida_funcs
import ida_loader
import ida_typeinf
import idc
from fastmcp import FastMCP

from ida_mcp.helpers import ANNO_MUTATE, ANNO_READ_ONLY, IDAError
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"signatures"},
    )
    @session.require_open
    def apply_flirt_signature(sig_name: str) -> dict:
        """Apply a FLIRT signature library to identify library functions.

        FLIRT signatures match byte patterns to known library functions,
        automatically naming them. Essential for statically linked binaries.

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

        return {
            "signature": sig_name,
            "status": "applied",
        }

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"signatures"},
    )
    @session.require_open
    def list_flirt_signatures() -> dict:
        """List available FLIRT signature files that have been applied to the database."""
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

        return {"count": len(sigs), "signatures": sigs}

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"signatures"},
    )
    @session.require_open
    def load_type_library(til_name: str) -> dict:
        """Load a type information library (TIL) to make its types available.

        Type libraries provide struct/enum/typedef definitions for OS APIs,
        SDKs, and common libraries (e.g. "gnulnx_x64", "mssdk_win10", "ntapi").

        Args:
            til_name: Name of the type library (without extension).
        """
        result = ida_typeinf.add_til(til_name, ida_typeinf.ADDTIL_DEFAULT)
        if result == 0:
            raise IDAError(f"Failed to load type library: {til_name!r}", error_type="LoadFailed")

        return {"library": til_name, "status": "loaded"}

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"signatures"},
    )
    @session.require_open
    def list_type_libraries() -> dict:
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

        return {"count": len(libs), "libraries": libs}

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"signatures"},
    )
    @session.require_open
    def load_ids_module(filename: str) -> dict:
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
        return {"filename": filename, "status": "applied"}
