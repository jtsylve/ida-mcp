# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Analysis prompts — binary triage, function analysis, diffing, classification."""

from __future__ import annotations

from fastmcp import FastMCP


def register(mcp: FastMCP):
    @mcp.prompt(
        description=(
            "One-call binary triage. Produces an executive summary of the binary: "
            "what it is, what it does, key areas of interest, and recommended next steps."
        ),
    )
    async def survey_binary(focus: str = "") -> str:
        instructions = """\
Perform a triage survey of the currently open binary. Use these tools in order:

1. get_database_info — file type, architecture, bitness, entry point
2. get_segments — memory layout and permissions
3. get_entry_points — all entry points
4. get_imports with limit=200 — imported functions
5. get_exports — exported symbols
6. get_strings with limit=200 — strings (results are in address order, not sorted by length)
7. list_functions with limit=200 — function list

Then synthesize a triage report with these sections:
- **Overview**: file type, architecture, compiler (if detectable), binary purpose
- **Segments**: memory layout, notable permission patterns (e.g. RWX segments)
- **Imports by category**: group imports into categories (file I/O, network, crypto, \
memory, string ops, UI, registry, process/thread, etc.) and note which categories \
are most prominent
- **Interesting strings**: strings that reveal functionality, paths, URLs, error \
messages, format strings, embedded credentials
- **Key functions**: entry points, large functions, functions with many xrefs, \
functions with suspicious names
- **Recommended next steps**: specific functions or areas to investigate first"""
        if focus:
            instructions += f"\n\nFocus the analysis on: {focus}"
        return instructions

    @mcp.prompt(
        description=(
            "Full single-function analysis. Decompiles, maps data flow, "
            "identifies strings and constants, and summarizes behavior."
        ),
    )
    async def analyze_function(address: str) -> str:
        return f"""\
Perform a deep analysis of the function at {address}:

1. get_function — metadata (address, size, flags)
2. decompile_function — pseudocode (also reveals signature)
3. get_function_type — return type, parameters, calling convention
4. get_function_vars — typed local variables and parameters from decompilation
5. get_call_graph with depth=1 — direct callers and callees
6. get_xrefs_to — who references this function
7. get_basic_blocks — control flow structure

Synthesize a report:
- **Purpose**: one-line summary of what the function does
- **Signature**: parameters, return type, calling convention
- **Control flow**: complexity (linear, branching, looping), notable patterns
- **Data flow**: what data it reads, transforms, and writes
- **Callees**: what it calls and why (classify each call's role)
- **Callers**: who calls it and in what context
- **Strings & constants**: embedded literals and magic numbers
- **Security notes**: potential issues (buffer handling, unchecked returns, etc.)"""

    @mcp.prompt(
        description=(
            "Preview the effect of renaming or retyping on decompiler output. "
            "Decompiles before and after, then shows what changed."
        ),
    )
    async def diff_before_after(address: str, modifications: str) -> str:
        return f"""\
Show the before/after effect of modifications on {address}:

1. decompile_function at {address} — capture "BEFORE" output
2. Apply the requested modifications: {modifications}
   Use rename_function, rename_decompiler_variable, retype_decompiler_variable, \
set_function_type, or set_type as appropriate.
3. decompile_function at {address} again — capture "AFTER" output
4. Present both versions side by side, highlighting what changed.

If the modifications look wrong or would fail, explain why and suggest alternatives \
instead of applying them."""

    @mcp.prompt(
        description=("Classify functions by behavioral patterns to prioritize analysis effort."),
    )
    async def classify_functions(filter_pattern: str = "", limit: str = "50") -> str:
        instructions = f"""\
Classify functions in the binary by behavioral pattern:

1. list_functions (limit {limit})
2. For each function, gather metadata using the batch meta-tool or execute \
to parallelize: get_function (size, flags), get_call_graph depth=1 \
(caller/callee counts), get_basic_blocks (block count)
3. Classify into categories:
   - **Thunks/wrappers**: very small (< 10 instructions), single callee
   - **Library/runtime**: flagged as library, or matches known patterns
   - **Leaf functions**: no callees (utility/helper functions)
   - **Hub functions**: high caller AND callee count (dispatchers, managers)
   - **Complex logic**: high block count relative to size (many branches)
   - **Data processors**: high ratio of memory operations
   - **Entry points / handlers**: few callers, called from dispatch tables

Present results as a table sorted by likely analysis value (complex and hub \
functions first, thunks last)."""
        if filter_pattern:
            instructions = instructions.replace(
                f"list_functions (limit {limit})",
                f'list_functions (filter_pattern="{filter_pattern}", limit {limit})',
            )
        return instructions
