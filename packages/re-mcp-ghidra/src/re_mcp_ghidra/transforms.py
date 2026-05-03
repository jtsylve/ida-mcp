# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Ghidra-specific tool visibility constants."""

from re_mcp.transforms import MANAGEMENT_TOOLS, META_TOOLS

PINNED_TOOLS = frozenset(
    {
        *MANAGEMENT_TOOLS,
        *META_TOOLS,
        # Exploration
        "get_database_info",
        "list_functions",
        "get_strings",
        "decompile_function",
        "disassemble_function",
        "list_names",
        "find_code_by_string",
        "get_xrefs_to",
        "get_xrefs_from",
        # Mutation
        "rename_function",
        "set_comment",
        "set_decompiler_comment",
        # Structs
        "list_structures",
        "get_structure",
        "create_structure",
        "add_struct_member",
        "retype_struct_member",
        # Types
        "list_local_types",
        "parse_type_declaration",
        "apply_type_at_address",
        "get_type_info",
        "set_type",
    }
)
