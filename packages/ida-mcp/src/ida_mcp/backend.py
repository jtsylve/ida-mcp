# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""IDA Pro backend for re-mcp."""

from __future__ import annotations

import os
import platform as plat
from typing import TYPE_CHECKING

from re_mcp.backend import BackendInfo, build_instructions

from ida_mcp import find_ida_dir
from ida_mcp.exceptions import (
    IDAError,
    build_ida_args,
    check_fat_binary,
    check_processor_ambiguity,
    slice_sidecar_stem,
)
from ida_mcp.transforms import MANAGEMENT_TOOLS, PINNED_TOOLS

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from re_mcp.transforms import ToolTransform
    from re_mcp.worker_provider import WorkerPoolProvider

_DYLIB_EXT = {"Darwin": ".dylib", "Windows": ".dll"}.get(plat.system(), ".so")


def _list_module_names(directory: str) -> list[str]:
    """List IDA plugin module names (stem of .dylib/.so/.dll and .py files)."""
    if not os.path.isdir(directory):
        return []
    names: set[str] = set()
    for entry in os.listdir(directory):
        stem, ext = os.path.splitext(entry)
        if ext in (_DYLIB_EXT, ".py"):
            names.add(stem)
    return sorted(names)


class IDABackend:
    """IDA Pro backend implementation."""

    @staticmethod
    def info() -> BackendInfo:
        return BackendInfo(
            name="ida",
            display_name="IDA Pro",
            uri_scheme="ida",
            worker_module="ida_mcp.server",
            pinned_tools=PINNED_TOOLS,
            management_tools=MANAGEMENT_TOOLS,
            env_prefix="IDA_MCP_",
            state_dir_name="ida-mcp",
        )

    @staticmethod
    def build_instructions(transform: ToolTransform) -> str:
        return build_instructions(
            transform=transform,
            intro="IDA Pro binary analysis server with multi-database support.",
            file_path_detail=(
                "file_path accepts raw binaries or existing .i64/.idb databases. "
                "The binary must be in a writable directory. "
                "Fat Mach-O binaries require explicit fat_arch=."
            ),
            uri_scheme="ida",
            resource_prefix="idb",
            workflows=(
                "- **Triage:** get_database_info → list_functions + get_strings.\n"
                "- **String search:** find_code_by_string(pattern) combines "
                "string search + xref + function resolution.\n"
                "- **Function analysis:** decompile_function, "
                "disassemble_function, get_call_graph(depth=1).\n"
                "- **Name search:** list_functions/list_names accept "
                "filter_pattern. Use search_bytes/search_text/"
                "find_immediate for binary content.\n"
                "- **Types:** parse_type_declaration → apply_type_at_address "
                "for named types; set_type for inline; "
                "set_function_type for prototypes.\n"
                "- **Multi-pattern search:** get_strings, list_functions, "
                "list_names, list_demangled_names accept filters=[...] "
                "for single-pass multi-pattern search.\n"
                "- **Pointer tables:** read_pointer_table for vtables, "
                "dispatch tables (auto-dereferences + string detection).\n"
                "- **Firmware:** set processor/loader explicitly. "
                'ARM defaults to AArch64 — use "arm:ARMv7-M" for Cortex-M. '
                "Use rebase_program (delta, not absolute) + create_segment + "
                "reanalyze_range after setup."
            ),
        )

    @staticmethod
    def register_management_tools(mcp: FastMCP, pool: WorkerPoolProvider) -> None:
        @mcp.tool(annotations={"title": "Open Database"})
        async def open_database(
            file_path: str,
            run_auto_analysis: bool = False,
            keep_open: bool = True,
            database_id: str = "",
            force_new: bool = False,
            processor: str = "",
            loader: str = "",
            base_address: str = "",
            fat_arch: str = "",
            options: str = "",
        ) -> dict:
            """Open a binary or existing IDA database (.i64/.idb) for analysis.

            Returns immediately with ``"opening": true`` — call
            wait_for_analysis before using other tools on this database.
            Re-opening an already-open database returns the existing worker.

            **Multiple binaries:** use a separate subagent per binary.
            Each agent calls open_database then wait_for_analysis. Do NOT
            serialize open+wait calls — that blocks parallel loading.

            **force_new=True** is destructive: deletes existing .i64/.idb
            and all prior analysis. Use only for stale/incompatible DBs.

            **Fat Mach-O:** requires explicit *fat_arch* (e.g. ``arm64``).
            Error lists available slices. Use distinct *database_id* per
            slice for concurrent analysis. *fat_arch* must be omitted for
            non-fat files and existing databases.

            Args:
                file_path: Path to the binary file or IDA database.
                run_auto_analysis: Run IDA auto-analysis after opening.
                keep_open: Keep other open databases (default True).
                database_id: Custom ID (must match [a-z][a-z0-9_]{0,31}).
                force_new: Delete existing DB files and start fresh.
                processor: IDA processor module (e.g. ``metapc``, ``arm``,
                           ``mips``). Auto-detected when omitted.
                           **ARM:** defaults to AArch64 — use
                           ``arm:ARMv7-M`` for Cortex-M, ``arm:ARMv7-A``
                           for 32-bit. Use list_targets to see options.
                loader: IDA loader (e.g. "ELF", "PE", "Binary file").
                        Auto-detected when omitted. See list_targets.
                base_address: Base address for raw binaries (hex/decimal,
                              16-byte aligned). Ignored for structured formats.
                fat_arch: Mach-O fat slice (``x86_64``, ``arm64``, etc.).
                          Required for fat binaries; must be omitted for
                          thin files and existing databases.
                options: Extra IDA CLI arguments. Do not duplicate
                         processor/loader/base_address flags here.
            """
            check_processor_ambiguity(processor, file_path, force_new, fat_arch)
            fat_slice_index = check_fat_binary(file_path, fat_arch, force_new)
            build_ida_args(
                processor=processor,
                loader=loader,
                base_address=base_address,
                fat_slice_index=fat_slice_index,
                options=options,
            )

            extra = {
                k: v
                for k, v in {
                    "processor": processor,
                    "loader": loader,
                    "base_address": base_address,
                    "fat_arch": fat_arch,
                    "options": options,
                }.items()
                if v is not None and v != ""
            }

            return await pool.open_database(
                file_path,
                run_auto_analysis,
                database_id,
                keep_open,
                force_new,
                **extra,
            )

    @staticmethod
    def register_prompts(mcp: FastMCP) -> None:
        from ida_mcp.prompts import register_all  # noqa: PLC0415

        register_all(mcp)

    @staticmethod
    def canonical_path(file_path: str, **kwargs: object) -> str:
        fat_arch = str(kwargs.get("fat_arch", ""))
        return slice_sidecar_stem(file_path, fat_arch)

    @staticmethod
    def list_targets() -> dict:
        ida_dir = find_ida_dir()
        if ida_dir is None:
            raise IDAError("IDA Pro installation not found", error_type="NotFound")
        return {
            "processors": _list_module_names(os.path.join(ida_dir, "procs")),
            "loaders": _list_module_names(os.path.join(ida_dir, "loaders")),
        }
