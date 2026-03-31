# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Tools for loading additional data into the database."""

from __future__ import annotations

import os

import ida_bytes
import ida_diskio
import ida_loader
from fastmcp import FastMCP

from ida_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    META_READS_FILES,
    Address,
    HexBytes,
    IDAError,
    format_address,
    resolve_address,
)
from ida_mcp.models import LoadBytesFromFileResult, LoadBytesFromMemoryResult
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"modification"},
        meta=META_READS_FILES,
    )
    @session.require_open
    def load_bytes_from_file(
        file_path: str,
        target_address: Address,
        file_offset: int = 0,
        size: int = 0,
    ) -> LoadBytesFromFileResult:
        """Load bytes from a file into the database at a given address.

        The target address range must already exist in a segment.
        The file path has the same access as the server process — this tool
        trusts the MCP client to supply appropriate paths.

        Args:
            file_path: Absolute path to the file to load bytes from.
            target_address: Address in the database to load bytes to.
            file_offset: Offset within the file to start reading from.
            size: Number of bytes to load (0 = rest of file from offset).
        """
        ea = resolve_address(target_address)

        path = os.path.expanduser(file_path)
        if not os.path.isfile(path):
            raise IDAError(f"File not found: {path}", error_type="FileNotFound")

        file_size = os.path.getsize(path)
        if file_offset >= file_size:
            raise IDAError("File offset beyond file size", error_type="InvalidArgument")

        if size == 0:
            size = file_size - file_offset

        li = ida_diskio.open_linput(path, False)
        if li is None:
            raise IDAError(f"Failed to open file: {path}", error_type="OpenFailed")

        # Read old bytes before overwriting (cap preview at 256 bytes)
        preview_size = min(size, 256)
        old_bytes_data = ida_bytes.get_bytes(ea, preview_size)

        try:
            result = ida_loader.file2base(li, file_offset, ea, ea + size, 1)
        finally:
            ida_diskio.close_linput(li)

        if not result:
            raise IDAError("Failed to load bytes into database", error_type="LoadFailed")

        return LoadBytesFromFileResult(
            file=path,
            target_address=format_address(ea),
            file_offset=file_offset,
            size=size,
            old_bytes=old_bytes_data.hex() if old_bytes_data else "",
        )

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"modification"},
    )
    @session.require_open
    def load_bytes_from_memory(
        target_address: Address,
        data: HexBytes,
    ) -> LoadBytesFromMemoryResult:
        """Load hex-encoded bytes directly into the database.

        The target address range must already exist in a segment. For
        single-instruction patches, patch_bytes is usually more
        convenient (creates an undo point automatically).

        Args:
            target_address: Address in the database to load bytes to.
            data: Hex-encoded bytes to load (e.g. "90909090" for NOPs).
        """
        ea = resolve_address(target_address)

        _MAX_HEX_LEN = 2 * 1024 * 1024  # 1 MB of data = 2M hex chars
        data = data.strip().replace(" ", "")
        if len(data) > _MAX_HEX_LEN:
            raise IDAError(
                f"Hex data too large ({len(data)} chars, max {_MAX_HEX_LEN})",
                error_type="InvalidArgument",
            )
        try:
            raw = bytes.fromhex(data)
        except ValueError:
            raise IDAError("Invalid hex data", error_type="InvalidArgument") from None

        old_bytes_data = ida_bytes.get_bytes(ea, len(raw))

        result = ida_loader.mem2base(raw, ea, -1)
        if result != 1:
            raise IDAError("Failed to load bytes into database", error_type="LoadFailed")

        return LoadBytesFromMemoryResult(
            target_address=format_address(ea),
            size=len(raw),
            old_bytes=old_bytes_data.hex() if old_bytes_data else "",
        )
