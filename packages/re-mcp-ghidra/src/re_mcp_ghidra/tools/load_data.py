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
    read_memory,
    resolve_address,
    write_memory,
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
        try:
            old_bytes_data = read_memory(mem, addr, preview_size)
        except Exception:
            old_bytes_data = b""

        write_memory(program, addr, raw, label="Load bytes from memory")

        return LoadBytesFromMemoryResult(
            target_address=format_address(addr.getOffset()),
            size=len(raw),
            old_bytes=old_bytes_data.hex() if old_bytes_data else "",
        )
