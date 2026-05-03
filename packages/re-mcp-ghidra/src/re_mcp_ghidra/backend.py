# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Ghidra backend for re-mcp."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from re_mcp.backend import BackendInfo, build_instructions

from re_mcp_ghidra import find_ghidra_dir
from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.transforms import MANAGEMENT_TOOLS, PINNED_TOOLS

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from re_mcp.transforms import ToolTransform
    from re_mcp.worker_provider import WorkerPoolProvider


class GhidraBackend:
    """Ghidra backend implementation."""

    @staticmethod
    def info() -> BackendInfo:
        return BackendInfo(
            name="ghidra",
            display_name="Ghidra",
            uri_scheme="ghidra",
            worker_module="re_mcp_ghidra.server",
            pinned_tools=PINNED_TOOLS,
            management_tools=MANAGEMENT_TOOLS,
            env_prefix="GHIDRA_MCP_",
            state_dir_name="re-mcp-ghidra",
        )

    @staticmethod
    def build_instructions(transform: ToolTransform) -> str:
        return build_instructions(
            transform=transform,
            intro="Ghidra binary analysis server with multi-database support.",
            file_path_detail=(
                "file_path accepts raw binaries or existing Ghidra project files. "
                "The binary must be in a writable directory."
            ),
            uri_scheme="ghidra",
            resource_prefix="db",
            workflows=(
                "- **Triage:** get_database_info → list_functions + get_strings.\n"
                "- **String search:** find_code_by_string(pattern) combines "
                "string search + xref + function resolution.\n"
                "- **Function analysis:** decompile_function, "
                "disassemble_function, get_call_graph(depth=1).\n"
                "- **Name search:** list_functions/list_names accept "
                "filter_pattern.\n"
                "- **Types:** parse_type_declaration → apply_type_at_address "
                "for named types; set_type for inline.\n"
                "- **Language:** set language/compiler_spec explicitly when "
                "auto-detection fails. Use list_targets to see options."
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
            language: str = "",
            compiler_spec: str = "",
        ) -> dict:
            """Open a binary for analysis with Ghidra.

            Returns immediately with ``"opening": true`` — call
            wait_for_analysis before using other tools on this database.
            Re-opening an already-open database returns the existing worker.

            **Multiple binaries:** use a separate subagent per binary.

            **force_new=True** is destructive: deletes existing Ghidra
            project and all prior analysis.

            Args:
                file_path: Path to the binary file.
                run_auto_analysis: Run Ghidra auto-analysis after opening.
                keep_open: Keep other open databases (default True).
                database_id: Custom ID (must match [a-z][a-z0-9_]{0,31}).
                force_new: Delete existing project and start fresh.
                language: Ghidra language ID (e.g. ``x86:LE:64:default``,
                          ``ARM:LE:32:v8``). Auto-detected when omitted.
                          Use list_targets to see options.
                compiler_spec: Ghidra compiler spec (e.g. ``gcc``,
                               ``windows``). Auto-detected when omitted.
            """
            extra = {
                k: v
                for k, v in {"language": language, "compiler_spec": compiler_spec}.items()
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
        from re_mcp_ghidra.prompts import register_all  # noqa: PLC0415

        register_all(mcp)

    @staticmethod
    def canonical_path(file_path: str, **kwargs: object) -> str:
        return os.path.realpath(os.path.expanduser(file_path))

    @staticmethod
    def list_targets() -> dict:
        ghidra_dir = find_ghidra_dir()
        if ghidra_dir is None:
            raise GhidraError("Ghidra installation not found", error_type="NotFound")
        return _list_ghidra_targets(ghidra_dir)


def _list_ghidra_targets(ghidra_dir: str) -> dict:
    """List available Ghidra languages and compiler specs from .ldefs files."""
    import xml.etree.ElementTree as ET  # noqa: PLC0415

    languages: list[dict[str, str]] = []
    processors_dir = os.path.join(ghidra_dir, "Ghidra", "Processors")

    if not os.path.isdir(processors_dir):
        return {"languages": [], "processors_dir": processors_dir}

    for proc_name in sorted(os.listdir(processors_dir)):
        ldefs_dir = os.path.join(processors_dir, proc_name, "data", "languages")
        if not os.path.isdir(ldefs_dir):
            continue
        for fname in sorted(os.listdir(ldefs_dir)):
            if not fname.endswith(".ldefs"):
                continue
            try:
                tree = ET.parse(os.path.join(ldefs_dir, fname))
                for lang_elem in tree.findall(".//language"):
                    lang_id = lang_elem.get("id", "")
                    lang_desc = ""
                    desc_elem = lang_elem.find("description")
                    if desc_elem is not None and desc_elem.text:
                        lang_desc = desc_elem.text.strip()
                    compiler_specs = []
                    for cspec in lang_elem.findall("compiler"):
                        cs_id = cspec.get("id", "")
                        cs_name = cspec.get("name", "")
                        if cs_id:
                            compiler_specs.append({"id": cs_id, "name": cs_name})
                    if lang_id:
                        entry: dict[str, Any] = {
                            "id": lang_id,
                            "processor": lang_elem.get("processor", ""),
                            "endian": lang_elem.get("endian", ""),
                            "size": lang_elem.get("size", ""),
                            "variant": lang_elem.get("variant", ""),
                            "description": lang_desc,
                        }
                        if compiler_specs:
                            entry["compiler_specs"] = compiler_specs
                        languages.append(entry)
            except ET.ParseError:
                continue

    return {"languages": languages}
