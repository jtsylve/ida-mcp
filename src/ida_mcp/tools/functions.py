# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Function analysis tools — listing, querying, decompilation, and disassembly."""

from __future__ import annotations

import ida_funcs
import ida_lines
import ida_name
import idautils
import idc
from mcp.server.fastmcp import FastMCP

from ida_mcp.helpers import (
    clean_disasm_line,
    compile_filter,
    decompile_at,
    format_address,
    get_func_name,
    is_bad_addr,
    paginate_iter,
    resolve_address,
    resolve_function,
)
from ida_mcp.session import session

_VALID_FILTER_TYPES = {"thunk", "library", "noreturn", "user", ""}


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def list_functions(
        offset: int = 0,
        limit: int = 100,
        filter_pattern: str = "",
        filter_type: str = "",
    ) -> dict:
        """List functions in the binary with optional filtering.

        Use filter_pattern with a regex to find functions by name (equivalent
        to search_functions_by_pattern). Combine filter_type="user" to exclude
        library stubs and thunks for more targeted results.

        Args:
            offset: Starting index for pagination.
            limit: Maximum number of results (max 500).
            filter_pattern: Optional regex pattern to filter function names.
            filter_type: Optional filter by function type — "thunk" (thunks only),
                "library" (library functions), "noreturn" (non-returning),
                "user" (exclude library and thunk functions).
        """
        pattern, err = compile_filter(filter_pattern)
        if err:
            return err

        if filter_type not in _VALID_FILTER_TYPES:
            return {
                "error": f"Invalid filter_type: {filter_type!r}",
                "error_type": "InvalidArgument",
                "valid_types": sorted(_VALID_FILTER_TYPES - {""}),
            }

        def _iter():
            for i in range(ida_funcs.get_func_qty()):
                func = ida_funcs.getn_func(i)
                if func is None:
                    continue

                if filter_type:
                    is_thunk = bool(func.flags & ida_funcs.FUNC_THUNK)
                    is_lib = bool(func.flags & ida_funcs.FUNC_LIB)
                    is_noret = bool(func.flags & ida_funcs.FUNC_NORET)
                    if (
                        (filter_type == "thunk" and not is_thunk)
                        or (filter_type == "library" and not is_lib)
                        or (filter_type == "noreturn" and not is_noret)
                        or (filter_type == "user" and (is_thunk or is_lib))
                    ):
                        continue

                name = get_func_name(func.start_ea)
                if pattern and not pattern.search(name):
                    continue
                yield {
                    "name": name,
                    "start": format_address(func.start_ea),
                    "end": format_address(func.end_ea),
                    "size": func.size(),
                }

        return paginate_iter(_iter(), offset, limit)

    @mcp.tool()
    @session.require_open
    def get_function(address: str) -> dict:
        """Get detailed information about a function at the given address.

        Args:
            address: Address or symbol name of the function.
        """
        func, err = resolve_function(address)
        if err:
            return err

        name = get_func_name(func.start_ea)
        regular_cmt = ida_funcs.get_func_cmt(func, False) or ""
        repeatable_cmt = ida_funcs.get_func_cmt(func, True) or ""

        chunks = list(idautils.Chunks(func.start_ea))
        result = {
            "name": name,
            "start": format_address(func.start_ea),
            "end": format_address(func.end_ea),
            "size": func.size(),
            "flags": func.flags,
            "does_return": not (func.flags & ida_funcs.FUNC_NORET),
            "is_library": bool(func.flags & ida_funcs.FUNC_LIB),
            "is_thunk": bool(func.flags & ida_funcs.FUNC_THUNK),
            "comment": regular_cmt,
            "repeatable_comment": repeatable_cmt,
        }
        if len(chunks) > 1:
            result["chunks"] = [
                {"start": format_address(s), "end": format_address(e), "size": e - s}
                for s, e in chunks
            ]
        return result

    @mcp.tool()
    @session.require_open
    def get_function_by_name(name: str) -> dict:
        """Find a function by its name.

        Args:
            name: The function name to search for.
        """
        ea = idc.get_name_ea_simple(name)
        if is_bad_addr(ea):
            return {"error": f"Function not found: {name}", "error_type": "NotFound"}
        return get_function(format_address(ea))

    @mcp.tool()
    @session.require_open
    def decompile_function(address: str = "", name: str = "") -> dict:
        """Decompile a function to pseudocode using Hex-Rays.

        Requires a Hex-Rays decompiler license. For quick inspection without
        decompilation, use disassemble_function instead (faster, no license
        needed). For batch decompilation, prefer calling this in a loop on
        filtered results from list_functions rather than export_all_pseudocode.

        Provide either address or name (not both).

        Args:
            address: Address of the function (hex string or symbol).
            name: Name of the function to decompile.
        """
        if not address and not name:
            return {
                "error": "Provide either address or name",
                "error_type": "InvalidArgument",
            }

        target = address or name
        cfunc, func, err = decompile_at(target)
        if err:
            return err

        lines = []
        sv = cfunc.get_pseudocode()
        for i in range(sv.size()):
            line = ida_lines.tag_remove(sv[i].line)
            lines.append(line)

        func_name = get_func_name(func.start_ea)
        return {
            "address": format_address(func.start_ea),
            "name": func_name,
            "pseudocode": "\n".join(lines),
        }

    @mcp.tool()
    @session.require_open
    def disassemble_function(address: str) -> dict:
        """Get the disassembly listing of a function.

        Faster than decompile_function and does not require Hex-Rays.
        Use this for quick inspection of function logic or when only
        assembly-level detail is needed. For readable C-like output,
        use decompile_function instead.

        Args:
            address: Address or symbol name of the function.
        """
        func, err = resolve_function(address)
        if err:
            return err

        instructions = [
            {
                "address": format_address(item_ea),
                "disasm": clean_disasm_line(item_ea),
            }
            for item_ea in idautils.FuncItems(func.start_ea)
        ]

        func_name = get_func_name(func.start_ea)
        return {
            "address": format_address(func.start_ea),
            "name": func_name,
            "instruction_count": len(instructions),
            "instructions": instructions,
        }

    @mcp.tool()
    @session.require_open
    def rename_function(address: str, new_name: str) -> dict:
        """Rename a function.

        Args:
            address: Address or current name of the function.
            new_name: The new name to assign.
        """
        func, err = resolve_function(address)
        if err:
            return err

        old_name = get_func_name(func.start_ea)
        success = ida_name.set_name(func.start_ea, new_name, ida_name.SN_CHECK)
        if not success:
            return {
                "error": f"Failed to rename function to {new_name!r}",
                "error_type": "RenameFailed",
            }

        return {
            "address": format_address(func.start_ea),
            "old_name": old_name,
            "new_name": new_name,
        }

    @mcp.tool()
    @session.require_open
    def delete_function(address: str) -> dict:
        """Delete a function definition (does not delete the code).

        The instructions remain but are no longer grouped as a function.

        Args:
            address: Address or name of the function to delete.
        """
        func, err = resolve_function(address)
        if err:
            return err

        start_ea = func.start_ea
        name = get_func_name(start_ea)
        success = ida_funcs.del_func(start_ea)
        if not success:
            return {
                "error": f"Failed to delete function {name} at {format_address(start_ea)}",
                "error_type": "DeleteFailed",
            }
        return {
            "address": format_address(start_ea),
            "name": name,
        }

    @mcp.tool()
    @session.require_open
    def set_function_bounds(address: str, new_end: str) -> dict:
        """Change the end address of a function.

        Useful for fixing function boundaries when IDA guesses wrong.

        Args:
            address: Address or name of the function.
            new_end: New end address (exclusive).
        """
        func, err = resolve_function(address)
        if err:
            return err
        end_ea, err = resolve_address(new_end)
        if err:
            return err

        old_end = func.end_ea
        success = ida_funcs.set_func_end(func.start_ea, end_ea)
        if not success:
            return {
                "error": f"Failed to set function end to {format_address(end_ea)}",
                "error_type": "SetBoundsFailed",
            }
        return {
            "address": format_address(func.start_ea),
            "name": get_func_name(func.start_ea),
            "old_end": format_address(old_end),
            "new_end": format_address(end_ea),
        }
