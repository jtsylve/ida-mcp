# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""IDA Pro MCP worker process.

Each worker manages a single idalib database and exposes IDA's analysis
capabilities as MCP tools.  The supervisor (``supervisor.py``) spawns
workers and routes tool calls to the correct one.  This module can also
run standalone via the ``ida-mcp-worker`` entry point.

idalib is thread-affine: the ``idapro`` import and all subsequent IDA API
calls must happen on the **main OS thread** (idalib also registers signal
handlers, which Python restricts to the main thread).  FastMCP v3
dispatches sync tool functions via ``anyio.to_thread.run_sync`` (a pool
of 40 threads), so a plain ``def`` tool would land on an arbitrary
thread each time.

To fix this we subclass ``FastMCP`` so that every sync tool registered
via ``@mcp.tool()`` is automatically wrapped into an ``async def`` that
calls the original function **directly** (i.e. on the event-loop thread,
which *is* the main thread).  Because FastMCP sees an async function it
skips its own threadpool entirely.  Blocking the event loop is acceptable
here — the worker handles one database and the supervisor serializes
requests per worker, so there is no concurrency to protect.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP
from fastmcp.tools.function_tool import FunctionTool


def _wrap_sync_tool(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a sync function into an async def that runs on the main thread.

    FastMCP only threadpools ``def`` tools.  By presenting an ``async def``
    we keep execution on the event-loop thread (== main thread) where
    idalib was initialized.
    """
    if inspect.iscoroutinefunction(fn):
        return fn

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        return fn(*args, **kwargs)

    return wrapper


_UPPERCASE_WORDS = frozenset(
    {
        "abi",
        "asm",
        "cfg",
        "elf",
        "exe",
        "flirt",
        "ida",
        "idc",
        "ids",
        "io",
        "mcp",
        "pat",
    }
)


def _auto_title(name: str) -> str:
    """Convert a snake_case tool name to a human-friendly title.

    ``get_xrefs_to`` -> ``"Get Xrefs To"``
    ``get_cfg_edges`` -> ``"Get CFG Edges"``
    """
    words = [w for w in name.split("_") if w]
    return " ".join(w.upper() if w in _UPPERCASE_WORDS else w.title() for w in words)


def _inject_title(kwargs: dict[str, Any], name: str | None, fn: Callable[..., Any] | None) -> None:
    """Add a ``title`` to annotations if not already present.

    Always copies the annotations dict to avoid mutating shared presets
    like ``ANNO_READ_ONLY``.
    """
    tool_name = name or (fn.__name__ if fn else None)
    if not tool_name:
        return
    annotations = kwargs.get("annotations")
    if annotations is None:
        annotations = {}
    elif isinstance(annotations, dict):
        annotations = {**annotations}  # avoid mutating shared ANNO_* presets
    else:
        return
    if "title" not in annotations:
        annotations["title"] = _auto_title(tool_name)
    kwargs["annotations"] = annotations


class IDAServer(FastMCP):
    """FastMCP subclass that keeps all sync tool execution on the main thread."""

    def tool(
        self, name_or_fn: str | Callable[..., Any] | None = None, **kwargs: Any
    ) -> Callable[[Callable[..., Any]], FunctionTool] | FunctionTool:
        if callable(name_or_fn):
            # @mcp.tool  (no parentheses)
            _inject_title(kwargs, None, name_or_fn)
            return super().tool(_wrap_sync_tool(name_or_fn), **kwargs)

        # @mcp.tool()  or  @mcp.tool("name")  — returns a decorator.
        # When name is given we can inject the title now; otherwise we
        # defer until the decorated function is known.
        has_name = isinstance(name_or_fn, str)
        if has_name:
            _inject_title(kwargs, name_or_fn, None)
            dec = super().tool(name_or_fn, **kwargs)
        else:
            # Copy kwargs so the closure owns its own dict — _inject_title
            # mutates it when the decorated function is finally known.
            kwargs = {**kwargs}
            dec = None

        def wrapping_decorator(fn: Callable[..., Any]) -> FunctionTool:
            d = dec
            if d is None:
                _inject_title(kwargs, None, fn)
                d = super(IDAServer, self).tool(None, **kwargs)
            return d(_wrap_sync_tool(fn))

        return wrapping_decorator


# ---------------------------------------------------------------------------
# Bootstrap idalib on the main thread, then import ida_* modules.
# ---------------------------------------------------------------------------

import ida_mcp  # noqa: E402

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

mcp = IDAServer(
    "IDA Pro",
    instructions=(
        "IDA Pro binary analysis server. Use open_database to load a binary "
        "before calling other tools. Addresses can be specified as hex strings "
        '(e.g. "0x401000"), bare hex ("4010a0"), decimal, or symbol names '
        '(e.g. "main"). Use convert_number for base conversions instead of '
        "computing them yourself."
    ),
    on_duplicate="error",
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
