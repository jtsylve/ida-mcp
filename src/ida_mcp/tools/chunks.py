# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Function chunk/tail management tools."""

from __future__ import annotations

import ida_funcs
import idautils
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import format_address, resolve_address, resolve_function
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def list_function_chunks(address: str) -> dict:
        """List all chunks (contiguous regions) of a function.

        Non-contiguous functions have multiple chunks due to compiler optimizations
        like basic block reordering or hot/cold splitting.

        Args:
            address: Address or symbol name of the function.
        """
        func, err = resolve_function(address)
        if err:
            return err

        chunks = []
        for start, end in idautils.Chunks(func.start_ea):
            chunks.append(
                {
                    "start": format_address(start),
                    "end": format_address(end),
                    "size": end - start,
                }
            )

        return {
            "function": format_address(func.start_ea),
            "chunk_count": len(chunks),
            "chunks": chunks,
        }

    @mcp.tool()
    @session.require_open
    def append_function_tail(function_address: str, start: str, end: str) -> dict:
        """Append a tail (non-contiguous chunk) to a function.

        Use this when a function has code at a separate address range that
        belongs to it but isn't contiguous with the main body.

        Args:
            function_address: Address or name of the owning function.
            start: Start address of the tail region.
            end: End address of the tail region (exclusive).
        """
        func, err = resolve_function(function_address)
        if err:
            return err
        ea1, err = resolve_address(start)
        if err:
            return err
        ea2, err = resolve_address(end)
        if err:
            return err

        success = ida_funcs.append_func_tail(func, ea1, ea2)
        if not success:
            return {
                "error": f"Failed to append tail [{format_address(ea1)}, {format_address(ea2)}) "
                f"to function at {format_address(func.start_ea)}",
                "error_type": "AppendFailed",
            }

        return {
            "function": format_address(func.start_ea),
            "tail_start": format_address(ea1),
            "tail_end": format_address(ea2),
        }

    @mcp.tool()
    @session.require_open
    def remove_function_tail(function_address: str, tail_address: str) -> dict:
        """Remove a tail (non-contiguous chunk) from a function.

        Args:
            function_address: Address or name of the owning function.
            tail_address: Any address within the tail chunk to remove.
        """
        func, err = resolve_function(function_address)
        if err:
            return err
        tail_ea, err = resolve_address(tail_address)
        if err:
            return err

        success = ida_funcs.remove_func_tail(func, tail_ea)
        if not success:
            return {
                "error": f"Failed to remove tail at {format_address(tail_ea)} "
                f"from function at {format_address(func.start_ea)}",
                "error_type": "RemoveFailed",
            }

        return {
            "function": format_address(func.start_ea),
            "removed_tail_at": format_address(tail_ea),
        }

    @mcp.tool()
    @session.require_open
    def set_tail_owner(tail_address: str, new_owner_address: str) -> dict:
        """Change the owner of a function tail chunk.

        Reassigns a tail chunk from its current owning function to a different one.

        Args:
            tail_address: Any address within the tail chunk.
            new_owner_address: Address or name of the new owning function.
        """
        tail_ea, err = resolve_address(tail_address)
        if err:
            return err
        owner_ea, err = resolve_address(new_owner_address)
        if err:
            return err

        fnt = ida_funcs.get_fchunk(tail_ea)
        if fnt is None:
            return {
                "error": f"No function chunk at {format_address(tail_ea)}",
                "error_type": "NotFound",
            }

        success = ida_funcs.set_tail_owner(fnt, owner_ea)
        if not success:
            return {
                "error": f"Failed to set tail owner at {format_address(tail_ea)} "
                f"to {format_address(owner_ea)}",
                "error_type": "SetOwnerFailed",
            }

        return {
            "tail_address": format_address(tail_ea),
            "new_owner": format_address(owner_ea),
        }
