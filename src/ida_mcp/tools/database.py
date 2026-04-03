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
import ida_nalt
import ida_segment
import ida_strlist
import idautils
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    META_WRITES_FILES,
    Address,
    IDAError,
    decode_string,
    format_address,
    get_func_name,
    is_bad_addr,
    is_cancelled,
    resolve_address,
)
from ida_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class OpenDatabaseResult(BaseModel):
    """Result of opening a database."""

    status: str = Field(description="Status message.")
    file_path: str = Field(description="Path to the opened database file.")
    pid: int = Field(description="Worker process ID.")
    processor: str = Field(description="Processor architecture name.")
    bitness: int = Field(description="Address size in bits (16, 32, or 64).")
    file_type: str = Field(description="Input file type description.")
    function_count: int = Field(description="Number of functions.")
    segment_count: int = Field(description="Number of segments.")
    capabilities: dict[str, bool] = Field(
        description="Available features for this database (e.g. decompiler, assembler)."
    )


class CloseDatabaseResult(BaseModel):
    """Result of closing a database."""

    status: str = Field(description="Status message.")
    path: str | None = Field(default=None, description="Path of closed database.")
    saved: bool | None = Field(default=None, description="Whether changes were saved.")


class DatabaseInfoResult(BaseModel):
    """Database metadata."""

    file_path: str = Field(description="Path to the database file.")
    processor: str = Field(description="Processor architecture name.")
    bitness: int = Field(description="Address size in bits.")
    file_type: str = Field(description="Input file type description.")
    min_address: str = Field(description="Minimum address (hex).")
    max_address: str = Field(description="Maximum address (hex).")
    entry_point: str = Field(description="Entry point address (hex).")
    function_count: int = Field(description="Number of functions.")
    segment_count: int = Field(description="Number of segments.")
    entry_point_count: int = Field(description="Number of entry points.")
    trusted: bool = Field(description="Whether the database is trusted.")


class SaveDatabaseResult(BaseModel):
    """Result of saving a database."""

    status: str = Field(description="Status message.")
    path: str = Field(description="Path to the saved database file.")


class FlushBuffersResult(BaseModel):
    """Result of flushing buffers."""

    status: str = Field(description="Status message.")


class DatabasePathsResult(BaseModel):
    """File paths associated with the database."""

    input_file: str = Field(description="Original input file path.")
    idb_path: str = Field(description="IDB database path.")
    id0_path: str = Field(description="ID0 component path.")


class FileRegionEaResult(BaseModel):
    """File offset to address mapping."""

    file_offset: int = Field(description="Byte offset in the input file.")
    address: str = Field(description="Mapped linear address (hex).")


class FileRegionOffsetResult(BaseModel):
    """Address to file offset mapping."""

    address: str = Field(description="Database address (hex).")
    file_offset: int = Field(description="Byte offset in the input file.")


class DatabaseFlagsResult(BaseModel):
    """Database flags state."""

    kill: bool = Field(description="Delete unpacked DB on close.")
    compress: bool = Field(description="Compress the database.")
    backup: bool = Field(description="Create backup on save.")
    temporary: bool = Field(description="Database is temporary.")


class SetDatabaseFlagResult(BaseModel):
    """Result of setting a database flag."""

    flag: str = Field(description="Flag name.")
    value: bool = Field(description="New flag value.")


class ElfDebugDirResult(BaseModel):
    """ELF debug file directory."""

    directory: str = Field(description="Debug file directory path.")


class ReloadFileResult(BaseModel):
    """Result of reloading a file."""

    status: str = Field(description="Status message.")
    path: str = Field(description="Path of reloaded file.")


class DatabaseOverviewResult(BaseModel):
    """Combined database overview — metadata plus first page of key collections.

    Saves 4-5 round trips by combining get_database_info, list_functions,
    get_strings, get_imports, get_exports, and list_names in one call.
    """

    # Database metadata
    file_path: str = Field(description="Path to the database file.")
    processor: str = Field(description="Processor architecture name.")
    bitness: int = Field(description="Address size in bits.")
    file_type: str = Field(description="Input file type description.")
    min_address: str = Field(description="Minimum address (hex).")
    max_address: str = Field(description="Maximum address (hex).")
    entry_point: str = Field(description="Entry point address (hex).")
    capabilities: dict[str, bool] = Field(description="Available features (decompiler, assembler).")

    # Collection counts
    function_count: int = Field(description="Total number of functions.")
    segment_count: int = Field(description="Number of segments.")
    entry_point_count: int = Field(description="Number of entry points.")
    string_count: int = Field(description="Total number of strings.")
    import_count: int = Field(description="Total number of imports.")
    export_count: int = Field(description="Total number of exports.")
    name_count: int = Field(description="Total number of named addresses.")

    # First page of each collection
    functions: list[dict] = Field(description="First page of functions (name, start, end, size).")
    strings: list[dict] = Field(description="First page of strings (address, value, length, type).")
    imports: list[dict] = Field(
        description="First page of imports (module, address, name, ordinal)."
    )
    exports: list[dict] = Field(
        description="First page of exports (index, ordinal, address, name)."
    )
    names: list[dict] = Field(description="First page of named addresses (address, name).")


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
    )
    def open_database(
        file_path: str,
        run_auto_analysis: bool = False,
        force_new: bool = False,
    ) -> OpenDatabaseResult:
        """Open a binary or existing IDA database for analysis.

        This must be called before using any other analysis tools.
        If a database is already open, it will be saved and closed first.

        file_path can be a raw binary or an existing .i64/.idb database.
        When a database is passed, the original binary does not need to be present.

        Set run_auto_analysis=True only for first-time analysis of a new binary
        (no existing .i64). For existing databases, analysis is already stored —
        leave this False to avoid blocking. Call wait_for_analysis separately if needed.

        Args:
            file_path: Path to the binary file or IDA database (.i64/.idb).
            run_auto_analysis: Wait for auto-analysis to complete before returning.
                               Default False — safe for existing .i64 databases.
            force_new: Delete any existing database files (.i64, .idb, etc.) and
                       start fresh from the raw binary. Useful when IDA returns
                       error code 4 due to a stale or incompatible database.
        """
        session.open(file_path, run_auto_analysis, force_new=force_new)

        return OpenDatabaseResult(
            status="ok",
            file_path=session.current_path,
            pid=os.getpid(),
            processor=ida_idp.get_idp_name(),
            bitness=ida_ida.inf_get_app_bitness(),
            file_type=ida_loader.get_file_type_name(),
            function_count=ida_funcs.get_func_qty(),
            segment_count=ida_segment.get_segm_qty(),
            capabilities=session.capabilities,
        )

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"database"},
    )
    def close_database(save: bool = True) -> CloseDatabaseResult:
        """Close the currently open database.

        Args:
            save: Whether to save changes to the IDB file.
        """
        return CloseDatabaseResult(**session.close(save))

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"database"},
    )
    @session.require_open
    def get_database_info() -> DatabaseInfoResult:
        """Get metadata about the currently open database.

        Returns architecture, bitness, file type, address range,
        function count, segment count, and more.
        """
        return DatabaseInfoResult(
            file_path=session.current_path,
            processor=ida_idp.get_idp_name(),
            bitness=ida_ida.inf_get_app_bitness(),
            file_type=ida_loader.get_file_type_name(),
            min_address=format_address(ida_ida.inf_get_min_ea()),
            max_address=format_address(ida_ida.inf_get_max_ea()),
            entry_point=format_address(ida_ida.inf_get_start_ea()),
            function_count=ida_funcs.get_func_qty(),
            segment_count=ida_segment.get_segm_qty(),
            entry_point_count=ida_entry.get_entry_qty(),
            trusted=bool(ida_loader.is_trusted_idb()),
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"database"},
    )
    @session.require_open
    def get_database_overview(page_size: int = 50) -> DatabaseOverviewResult:
        """Get a full overview of the database in a single call.

        Returns database metadata plus the first page of functions, strings,
        imports, exports, and named addresses.  Use this after open_database
        or wait_for_analysis instead of calling get_database_info,
        list_functions, get_strings, get_imports, get_exports, and
        list_names separately — saves 4-5 round trips.

        Args:
            page_size: Number of items per collection (default 50, max 200).
        """
        page_size = max(1, min(page_size, 200))

        # Functions
        func_total = ida_funcs.get_func_qty()
        func_items = []
        for i in range(min(page_size, func_total)):
            func = ida_funcs.getn_func(i)
            if func is None:
                continue
            func_items.append(
                {
                    "name": get_func_name(func.start_ea),
                    "start": format_address(func.start_ea),
                    "end": format_address(func.end_ea),
                    "size": func.size(),
                }
            )

        # Strings (first page)
        string_total = ida_strlist.get_strlist_qty()
        si = ida_strlist.string_info_t()
        string_items: list[dict] = []
        for i in range(string_total):
            if is_cancelled() or len(string_items) >= page_size:
                break
            if not ida_strlist.get_strlist_item(si, i):
                continue
            value = decode_string(si.ea, si.length, si.type)
            if value is None:
                continue
            string_items.append(
                {
                    "address": format_address(si.ea),
                    "value": value,
                    "length": si.length,
                    "type": si.type,
                }
            )

        # Imports — collect up to page_size dicts, count the rest cheaply.
        import_items: list[dict] = []
        import_count = 0
        current_module = ""

        def _import_cb(ea, name, ordinal):
            nonlocal import_count
            import_count += 1
            if len(import_items) < page_size:
                import_items.append(
                    {
                        "module": current_module,
                        "address": format_address(ea),
                        "name": name or "",
                        "ordinal": ordinal,
                    }
                )
            return True

        for i in range(ida_nalt.get_import_module_qty()):
            current_module = ida_nalt.get_import_module_name(i) or ""
            ida_nalt.enum_import_names(i, _import_cb)

        # Exports
        export_items = []
        export_total = 0
        for index, ordinal, ea, name in idautils.Entries():
            export_total += 1
            if len(export_items) < page_size:
                export_items.append(
                    {
                        "index": index,
                        "ordinal": ordinal,
                        "address": format_address(ea),
                        "name": name or "",
                    }
                )

        # Names
        name_items = []
        name_total = 0
        for ea, name in idautils.Names():
            name_total += 1
            if len(name_items) < page_size:
                name_items.append({"address": format_address(ea), "name": name})

        return DatabaseOverviewResult(
            file_path=session.current_path,
            processor=ida_idp.get_idp_name(),
            bitness=ida_ida.inf_get_app_bitness(),
            file_type=ida_loader.get_file_type_name(),
            min_address=format_address(ida_ida.inf_get_min_ea()),
            max_address=format_address(ida_ida.inf_get_max_ea()),
            entry_point=format_address(ida_ida.inf_get_start_ea()),
            capabilities=session.capabilities,
            function_count=func_total,
            segment_count=ida_segment.get_segm_qty(),
            entry_point_count=ida_entry.get_entry_qty(),
            string_count=string_total,
            import_count=import_count,
            export_count=export_total,
            name_count=name_total,
            functions=func_items,
            strings=string_items,
            imports=import_items,
            exports=export_items,
            names=name_items,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"database"},
        meta=META_WRITES_FILES,
    )
    @session.require_open
    def save_database(outfile: str = "", flags: int = -1) -> SaveDatabaseResult:
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
        return SaveDatabaseResult(status="saved", path=outfile or session.current_path)

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"database"},
    )
    @session.require_open
    def flush_buffers() -> FlushBuffersResult:
        """Flush IDA's internal buffers to disk.

        Ensures all pending changes are written to the database file.
        """
        ida_loader.flush_buffers()
        return FlushBuffersResult(status="flushed")

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"database"},
    )
    @session.require_open
    def get_database_paths() -> DatabasePathsResult:
        """Get file paths associated with the current database.

        Returns the original input file path, the IDB database path,
        and the ID0 component path.
        """
        return DatabasePathsResult(
            input_file=ida_loader.get_path(ida_loader.PATH_TYPE_CMD),
            idb_path=ida_loader.get_path(ida_loader.PATH_TYPE_IDB),
            id0_path=ida_loader.get_path(ida_loader.PATH_TYPE_ID0),
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"database"},
    )
    @session.require_open
    def get_fileregion_ea(file_offset: int) -> FileRegionEaResult:
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
        return FileRegionEaResult(file_offset=file_offset, address=format_address(ea))

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"database"},
    )
    @session.require_open
    def get_fileregion_offset(
        address: Address,
    ) -> FileRegionOffsetResult:
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
        return FileRegionOffsetResult(address=format_address(ea), file_offset=offset)

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"database"},
    )
    @session.require_open
    def get_database_flags() -> DatabaseFlagsResult:
        """Get the current database flags.

        Returns the state of each database flag: kill (delete unpacked DB),
        compress, backup, and temporary.
        """
        return DatabaseFlagsResult(
            kill=bool(ida_loader.is_database_flag(ida_loader.DBFL_KILL)),
            compress=bool(ida_loader.is_database_flag(ida_loader.DBFL_COMP)),
            backup=bool(ida_loader.is_database_flag(ida_loader.DBFL_BAK)),
            temporary=bool(ida_loader.is_database_flag(ida_loader.DBFL_TEMP)),
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"database"},
    )
    @session.require_open
    def set_database_flag(flag: str, value: bool = True) -> SetDatabaseFlagResult:
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
        return SetDatabaseFlagResult(flag=flag, value=value)

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"database"},
    )
    @session.require_open
    def get_elf_debug_file_directory() -> ElfDebugDirResult:
        """Get the ELF debug file directory path.

        Returns the value of the ELF_DEBUG_FILE_DIRECTORY configuration
        directive, used for locating separate debug info files.
        """
        return ElfDebugDirResult(directory=ida_loader.get_elf_debug_file_directory())

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"database"},
    )
    @session.require_open
    def reload_file(is_remote: bool = False) -> ReloadFileResult:
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
        return ReloadFileResult(status="reloaded", path=path)
