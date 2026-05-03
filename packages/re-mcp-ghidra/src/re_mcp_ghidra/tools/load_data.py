# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tools for loading bytes into the database."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_DESTRUCTIVE,
    Address,
    HexBytes,
    format_address,
    resolve_address,
)
from re_mcp_ghidra.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class LoadBytesFromMemoryResult(BaseModel):
    """Result of loading bytes from memory."""

    target_address: str = Field(description="Target address (hex).")
    size: int = Field(description="Number of bytes written.")
    old_bytes: str = Field(description="Previous bytes at target (hex).")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"modification", "patching"})
    @session.require_open
    def load_bytes_from_memory(
        target_address: Address,
        data: HexBytes,
    ) -> LoadBytesFromMemoryResult:
        """Write hex-encoded bytes directly into an existing memory block.

        Args:
            target_address: Address in the database to write bytes to.
            data: Hex-encoded bytes to write (e.g. "90909090" for NOPs,
                or "90 90 90 90" with spaces).
        """
        program = session.program
        mem = program.getMemory()
        addr = resolve_address(target_address)

        _MAX_HEX_LEN = 2 * 1024 * 1024  # 1 MB of data = 2M hex chars
        data = data.strip().replace(" ", "")
        if len(data) > _MAX_HEX_LEN:
            raise GhidraError(
                f"Hex data too large ({len(data)} chars, max {_MAX_HEX_LEN})",
                error_type="InvalidArgument",
            )
        try:
            raw = bytes.fromhex(data)
        except ValueError:
            raise GhidraError("Invalid hex data", error_type="InvalidArgument") from None

        if not raw:
            raise GhidraError("Empty data", error_type="InvalidArgument")

        # Read old bytes before overwriting (cap preview at 256 bytes)
        preview_size = min(len(raw), 256)
        old_bytes_data = bytearray(preview_size)
        try:
            mem.getBytes(addr, old_bytes_data)
        except Exception:
            old_bytes_data = bytearray()

        tx_id = program.startTransaction("Load bytes from memory")
        try:
            mem.setBytes(addr, raw)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to write bytes at {format_address(addr.getOffset())}: {e}",
                error_type="LoadFailed",
            ) from e

        return LoadBytesFromMemoryResult(
            target_address=format_address(addr.getOffset()),
            size=len(raw),
            old_bytes=old_bytes_data.hex() if old_bytes_data else "",
        )
