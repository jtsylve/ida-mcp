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
from pydantic import BaseModel, Field

from ida_mcp.exceptions import build_ida_args, check_fat_binary, check_processor_ambiguity
from ida_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    META_WRITES_FILES,
    Address,
    IDAError,
    format_address,
    is_bad_addr,
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
    warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal warnings raised while opening (e.g. loader options dropped).",
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
        processor: str = "",
        loader: str = "",
        base_address: str = "",
        fat_arch: str = "",
        options: str = "",
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
            force_new: **Destructive** — permanently delete any existing database
                       files (.i64, .idb, etc.) and start fresh from the raw
                       binary, discarding all prior analysis.  Useful when IDA
                       returns error code 4 due to a stale or incompatible database.
            processor: Optional.  IDA processor module, optionally with a
                       variant after a colon.  IDA auto-detects from file
                       headers when omitted, but may guess wrong for raw
                       binaries.  **ARM gotcha:** the ``arm`` module
                       defaults to AArch64 (64-bit) for raw binaries —
                       use ``arm:ARMv7-M`` for Cortex-M firmware,
                       ``arm:ARMv7-A`` for 32-bit A-profile, or
                       ``arm:ARMv7-R`` for R-profile.  Other examples:
                       ``metapc`` (x86/x64), ``ppc``, ``mips``, ``mipsl``.
            loader: Optional.  IDA loader to use instead of auto-detection
                    (e.g. "ELF", "PE", "Mach-O", "Binary file").
            base_address: Optional.  Base loading address for the binary
                          (hex or decimal).  Must be 16-byte aligned.
                          Primarily useful for raw binary files; structured
                          formats (ELF, PE, Mach-O) contain their own base
                          addresses.
            fat_arch: Optional.  Architecture slice name (``x86_64``,
                      ``arm64``, ``arm64e``, ...) to extract from a
                      Mach-O fat (universal) binary.  Required when
                      opening a fat binary — the error on a missing
                      slice lists the available names.  Must be
                      omitted for thin / non-Mach-O files **and** for
                      explicit ``.i64``/``.idb`` database paths
                      (stored analysis already pins the slice);
                      either combination raises ``InvalidArgument``.
            options: Optional.  Additional IDA command-line arguments.
                     Processor, loader, and base address flags are added
                     automatically from the other parameters — do not
                     duplicate them here.
        """
        # The supervisor also runs these fail-fast checks before spawning
        # the worker.  We repeat them here so the worker's own open_database
        # tool is safe when used standalone (e.g. direct worker connections
        # or tests).  check_fat_binary returns the 1-based slice index
        # (or None when no -T flag is needed) which feeds into build_ida_args.
        check_processor_ambiguity(processor, file_path, force_new, fat_arch)
        fat_slice_index = check_fat_binary(file_path, fat_arch, force_new)
        ida_args = build_ida_args(
            processor=processor,
            loader=loader,
            base_address=base_address,
            fat_slice_index=fat_slice_index,
            options=options,
        )

        open_result = session.open(
            file_path,
            run_auto_analysis,
            force_new=force_new,
            options=ida_args,
            fat_arch=fat_arch,
        )

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
            warnings=open_result.get("warnings", []),
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
        """Flush IDA's internal buffers to disk without saving the full database.

        Writes any buffered but uncommitted byte changes to disk. Faster than
        save_database when you only need to ensure recent byte-level changes are
        persisted, not a full IDB snapshot.
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
