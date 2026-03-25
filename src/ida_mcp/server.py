# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""IDA Pro MCP worker process.

Each worker manages a single idalib database and exposes IDA's analysis
capabilities as MCP tools.  The supervisor (``supervisor.py``) spawns
workers and routes tool calls to the correct one.  This module can also
run standalone via the ``ida-mcp-worker`` entry point.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

# bootstrap() loads idalib — must be called before any ida_* imports.
import ida_mcp

ida_mcp.bootstrap()
from ida_mcp import resources as ida_resources  # noqa: E402
from ida_mcp.tools import (  # noqa: E402
    analysis,
    assemble,
    bookmarks,
    cfg,
    chunks,
    colors,
    comments,
    ctree,
    data,
    database,
    decompiler,
    demangle,
    dirtree,
    entry_manip,
    enums,
    export,
    frames,
    func_flags,
    function_type,
    functions,
    imports_exports,
    load_data,
    makedata,
    nalt,
    names,
    operand_repr,
    operands,
    patching,
    processor,
    rebase,
    regfinder,
    regvars,
    search,
    segments,
    sig_gen,
    signatures,
    snapshots,
    srclang,
    structs,
    switches,
    typeinf,
    types,
    undo,
    utility,
    xref_manip,
    xrefs,
)

mcp = FastMCP(
    "IDA Pro",
    instructions=(
        "IDA Pro binary analysis server. Use open_database to load a binary "
        "before calling other tools. Addresses can be specified as hex strings "
        '(e.g. "0x401000"), bare hex ("4010a0"), decimal, or symbol names '
        '(e.g. "main"). Use convert_number for base conversions instead of '
        "computing them yourself."
    ),
)

ida_resources.register(mcp)
database.register(mcp)
functions.register(mcp)
function_type.register(mcp)
xrefs.register(mcp)
xref_manip.register(mcp)
search.register(mcp)
data.register(mcp)
makedata.register(mcp)
imports_exports.register(mcp)
entry_manip.register(mcp)
comments.register(mcp)
names.register(mcp)
demangle.register(mcp)
types.register(mcp)
patching.register(mcp)
utility.register(mcp)
cfg.register(mcp)
operands.register(mcp)
operand_repr.register(mcp)
frames.register(mcp)
typeinf.register(mcp)
signatures.register(mcp)
sig_gen.register(mcp)
structs.register(mcp)
enums.register(mcp)
segments.register(mcp)
rebase.register(mcp)
switches.register(mcp)
bookmarks.register(mcp)
decompiler.register(mcp)
ctree.register(mcp)
processor.register(mcp)
colors.register(mcp)
regfinder.register(mcp)
undo.register(mcp)
dirtree.register(mcp)
load_data.register(mcp)
analysis.register(mcp)
export.register(mcp)
func_flags.register(mcp)
regvars.register(mcp)
srclang.register(mcp)
nalt.register(mcp)
chunks.register(mcp)
assemble.register(mcp)
snapshots.register(mcp)


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
