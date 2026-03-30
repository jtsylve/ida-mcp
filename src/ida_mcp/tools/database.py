# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Database/session management tools."""

from __future__ import annotations

import os

import ida_entry
import ida_funcs
import ida_ida
import ida_idp
import ida_loader
import ida_segment
from fastmcp import FastMCP

from ida_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    IDAError,
    format_address,
    is_bad_addr,
    resolve_address,
    tool_timeout,
)
from ida_mcp.session import session

_DBFL_MAP = {
    "kill": ida_loader.DBFL_KILL,
    "compress": ida_loader.DBFL_COMP,
    "backup": ida_loader.DBFL_BAK,
    "temporary": ida_loader.DBFL_TEMP,
}


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"database"},
        timeout=tool_timeout("open_database"),
    )
    def open_database(file_path: str, run_auto_analysis: bool = False) -> dict:
        """Open a binary file for analysis with IDA Pro.

        This must be called before using any other analysis tools.
        If a database is already open, it will be saved and closed first.

        Set run_auto_analysis=True only for first-time analysis of a new binary
        (no existing .i64). For existing databases, analysis is already stored —
        leave this False to avoid blocking. Call wait_for_analysis separately if needed.

        Args:
            file_path: Path to the binary file to analyze.
            run_auto_analysis: Wait for auto-analysis to complete before returning.
                               Default False — safe for existing .i64 databases.
        """
        session.open(file_path, run_auto_analysis)

        return {
            "status": "ok",
            "file_path": session.current_path,
            "pid": os.getpid(),
            "processor": ida_idp.get_idp_name(),
            "bitness": ida_ida.inf_get_app_bitness(),
            "file_type": ida_loader.get_file_type_name(),
            "function_count": ida_funcs.get_func_qty(),
            "segment_count": ida_segment.get_segm_qty(),
        }

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"database"},
    )
    def close_database(save: bool = True) -> dict:
        """Close the currently open database.

        Args:
            save: Whether to save changes to the IDB file.
        """
        return session.close(save)

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"database"},
    )
    @session.require_open
    def get_database_info() -> dict:
        """Get metadata about the currently open database.

        Returns architecture, bitness, file type, address range,
        function count, segment count, and more.
        """
        return {
            "file_path": session.current_path,
            "processor": ida_idp.get_idp_name(),
            "bitness": ida_ida.inf_get_app_bitness(),
            "file_type": ida_loader.get_file_type_name(),
            "min_address": format_address(ida_ida.inf_get_min_ea()),
            "max_address": format_address(ida_ida.inf_get_max_ea()),
            "entry_point": format_address(ida_ida.inf_get_start_ea()),
            "function_count": ida_funcs.get_func_qty(),
            "segment_count": ida_segment.get_segm_qty(),
            "entry_point_count": ida_entry.get_entry_qty(),
            "trusted": bool(ida_loader.is_trusted_idb()),
        }

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"database"},
        timeout=tool_timeout("save_database"),
    )
    @session.require_open
    def save_database(outfile: str = "", flags: int = -1) -> dict:
        """Save the currently open database without closing it.

        Args:
            outfile: Output file path. Empty string saves to the current path.
            flags: Database flags (-1 keeps current flags).
        """
        if flags >= 0:
            result = ida_loader.save_database(outfile or "", flags)
        elif outfile:
            result = ida_loader.save_database(outfile)
        else:
            result = ida_loader.save_database()
        if not result:
            raise IDAError("Failed to save database", error_type="SaveFailed")
        return {"status": "saved", "path": outfile or session.current_path}

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"database"},
    )
    @session.require_open
    def flush_buffers() -> dict:
        """Flush IDA's internal buffers to disk.

        Ensures all pending changes are written to the database file.
        """
        result = ida_loader.flush_buffers()
        return {"status": "flushed", "result": result}

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"database"},
    )
    @session.require_open
    def get_database_paths() -> dict:
        """Get file paths associated with the current database.

        Returns the original input file path, the IDB database path,
        and the ID0 component path.
        """
        return {
            "input_file": ida_loader.get_path(ida_loader.PATH_TYPE_CMD),
            "idb_path": ida_loader.get_path(ida_loader.PATH_TYPE_IDB),
            "id0_path": ida_loader.get_path(ida_loader.PATH_TYPE_ID0),
        }

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"database"},
    )
    @session.require_open
    def get_fileregion_ea(file_offset: int) -> dict:
        """Get the linear address corresponding to a file offset.

        Maps a byte offset in the original input file to its loaded
        virtual address in the database.

        Args:
            file_offset: Byte offset in the input file.
        """
        ea = ida_loader.get_fileregion_ea(file_offset)
        if is_bad_addr(ea):
            raise IDAError(
                f"No address mapped for file offset {file_offset}", error_type="NotFound"
            )
        return {"file_offset": file_offset, "address": format_address(ea)}

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"database"},
    )
    @session.require_open
    def get_fileregion_offset(
        address: Address,
    ) -> dict:
        """Get the input file offset corresponding to a database address.

        Maps a virtual address back to its byte offset in the original input file.

        Args:
            address: Address in the database.
        """
        ea = resolve_address(address)
        offset = ida_loader.get_fileregion_offset(ea)
        if offset == -1:
            raise IDAError(
                f"No file offset for address {format_address(ea)}", error_type="NotFound"
            )
        return {"address": format_address(ea), "file_offset": offset}

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"database"},
    )
    @session.require_open
    def get_database_flags() -> dict:
        """Get the current database flags.

        Returns the state of each database flag: kill (delete unpacked DB),
        compress, backup, and temporary.
        """
        return {
            "kill": bool(ida_loader.is_database_flag(ida_loader.DBFL_KILL)),
            "compress": bool(ida_loader.is_database_flag(ida_loader.DBFL_COMP)),
            "backup": bool(ida_loader.is_database_flag(ida_loader.DBFL_BAK)),
            "temporary": bool(ida_loader.is_database_flag(ida_loader.DBFL_TEMP)),
        }

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"database"},
    )
    @session.require_open
    def set_database_flag(flag: str, value: bool = True) -> dict:
        """Set or clear a database flag.

        Args:
            flag: Flag name — one of "kill", "compress", "backup", "temporary".
            value: True to set, False to clear.
        """
        dbfl = _DBFL_MAP.get(flag.lower())
        if dbfl is None:
            raise IDAError(
                f"Unknown flag: {flag!r}. Valid: {', '.join(_DBFL_MAP)}",
                error_type="InvalidArgument",
            )
        ida_loader.set_database_flag(dbfl, value)
        return {"flag": flag, "value": value}

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"database"},
    )
    @session.require_open
    def get_elf_debug_file_directory() -> dict:
        """Get the ELF debug file directory path.

        Returns the value of the ELF_DEBUG_FILE_DIRECTORY configuration
        directive, used for locating separate debug info files.
        """
        return {"directory": ida_loader.get_elf_debug_file_directory()}

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"database"},
    )
    @session.require_open
    def reload_file(is_remote: bool = False) -> dict:
        """Reload byte values from the input file.

        Re-reads the original input file and updates byte values in the
        database. Does not modify segmentation, names, or comments.
        Useful after the original binary has been modified externally.

        Args:
            is_remote: Whether the file is on a remote debugger server.
        """
        path = ida_loader.get_path(ida_loader.PATH_TYPE_CMD)
        result = ida_loader.reload_file(path, is_remote)
        if not result:
            raise IDAError("Failed to reload file", error_type="ReloadFailed")
        return {"status": "reloaded", "path": path}
