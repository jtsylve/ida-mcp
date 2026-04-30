# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Workflow prompts — renaming, ABI application, script export."""

from __future__ import annotations

from fastmcp import FastMCP


def register(mcp: FastMCP):
    @mcp.prompt(
        description=(
            "Suggest function renames based on unique string references. "
            "Does not apply changes — presents suggestions for review."
        ),
    )
    async def auto_rename_strings(filter_pattern: str = "") -> str:
        func_source = "list_functions"
        if filter_pattern:
            func_source = f'list_functions with filter_pattern="{filter_pattern}"'
        return f"""\
Find functions that can be meaningfully renamed based on their string references:

1. {func_source} — get all functions; note which have default names (sub_*, fn_*)
2. find_code_by_string with pattern "." and limit=500 — this returns \
(string, function) pairs for the whole binary in one call. Group by function \
address and keep only entries where the function has a default name.
3. For each such function, if it references exactly 1-3 unique strings, \
propose a name derived from the most descriptive string
4. Present a table: current name | proposed name | referenced strings | confidence

Rules:
- Only suggest renames for functions with default/auto-generated names
- Derive names from the string content (e.g. "invalid password" -> check_password)
- Use snake_case, keep names under 40 characters
- Mark confidence: HIGH (single unique string), MEDIUM (2-3 strings with clear theme), \
LOW (ambiguous)
- Do NOT apply any renames — this is suggestions only"""

    @mcp.prompt(
        description=(
            "Apply known ABI type information to identified functions "
            "(e.g. syscalls, Windows API wrappers, libc stubs)."
        ),
    )
    async def apply_abi(abi: str) -> str:
        instructions = f"""\
Apply {abi} type information to matching functions:

1. get_processor_info — confirm architecture compatibility
2. get_imports — find imported functions matching the ABI
3. list_functions to identify candidate functions (use filter_pattern to
   narrow by name, or filter_type="library" to find library stubs)
4. For each matched function:
   a. Use get_function_type to see the current prototype
   b. Use set_function_type to apply the correct prototype
   c. Use list_decompiler_variables then rename_decompiler_variable if
      parameter names need updating

"""
        if abi == "linux_syscall":
            instructions += """\
ABI-specific guidance:
Look for functions that use syscall/svc/int 0x80. Apply prototypes based on \
the syscall number (found in the appropriate register: rax on x86_64, r7 on ARM)."""
        elif abi == "libc":
            instructions += """\
ABI-specific guidance:
Match imported function names against standard libc prototypes. Apply full \
prototypes including parameter names \
(e.g. `void *memcpy(void *dest, const void *src, size_t n)`)."""
        elif abi == "windows_api":
            instructions += """\
ABI-specific guidance:
Match imported function names against Windows API prototypes. Apply full \
prototypes including HANDLE, DWORD, LPVOID parameter types. Pay attention to \
A/W suffixes for ANSI/Unicode variants."""
        elif abi == "posix":
            instructions += """\
ABI-specific guidance:
Match imported function names against POSIX prototypes (open, read, write, \
ioctl, mmap, etc.). Apply full prototypes including parameter names."""

        instructions += "\n\nReport what was applied and any functions that couldn't be matched."
        return instructions

    @mcp.prompt(
        description=(
            "Generate an IDAPython script that reproduces all user annotations "
            "(renames, types, comments) for portability to another IDB."
        ),
    )
    async def export_idc_script(scope: str = "all") -> str:
        return f"""\
Generate an IDAPython script that reproduces user annotations.

Scope: {scope}

1. Gather annotations:
   - list_names — find named addresses; filter out auto-generated names \
(sub_*, loc_*, off_*, byte_*, word_*, dword_*, qword_*, unk_*, etc.) to keep only user renames
   - list_local_types — find all user-defined types
   - For renamed functions: get_function_comment, get_comment for each
   - list_structures / list_enums — user-created type definitions
2. Generate a Python script with:
   - `idc.set_name(ea, name)` for renames
   - `idc.SetType(ea, type)` for type applications
   - `idc.set_cmt(ea, comment, repeatable)` for comments
   - Type declarations via `idc.parse_decls()`
3. Include a header comment with source IDB path, date, and scope

Output the script as a fenced code block."""
