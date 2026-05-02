# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Backend protocol and discovery for re-mcp.

Each backend (IDA, Ghidra, ...) implements the :class:`Backend` protocol
and registers itself via a ``re_mcp.backends`` entry point.  The core
infrastructure discovers installed backends at runtime and loads one
based on user selection or auto-detection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from re_mcp.transforms import ToolTransform
    from re_mcp.worker_provider import WorkerPoolProvider


# ---------------------------------------------------------------------------
# Instruction builder
# ---------------------------------------------------------------------------


def build_instructions(
    *,
    transform: ToolTransform,
    intro: str,
    file_path_detail: str,
    uri_scheme: str,
    resource_prefix: str,
    workflows: str,
) -> str:
    """Build the LLM instruction text from shared template and backend-specific parts.

    Args:
        transform: The tool transform with feature flags.
        intro: Opening line (e.g. "IDA Pro binary analysis server ...").
        file_path_detail: The ``file_path accepts ...`` sentence(s) for the
            "Opening databases" section.
        uri_scheme: URI scheme for resources (e.g. ``"ida"``).
        resource_prefix: Path prefix for resources (e.g. ``"idb"`` or ``"db"``).
        workflows: Full "Workflows" section body (backend-specific).
    """
    has_tool_search = transform.has_tool_search
    has_batch = transform.has_batch
    has_execute = transform.has_execute

    sections: list[str] = [intro]

    sections.append(
        "## Opening databases\n"
        "open_database returns immediately — call wait_for_analysis "
        "before using other tools. Multiple databases load concurrently; "
        "pass databases=[...] to wait_for_analysis to wait for several "
        "at once (returns when at least one is ready).\n\n" + file_path_detail
    )

    sections.append(
        "## Addressing\n"
        "All tools except management tools require the database "
        "parameter (stem ID from open_database/list_databases). "
        'Addresses accept hex ("0x401000"), bare hex ("4010a0"), '
        'decimal, or symbol names ("main").'
    )

    sections.append(
        "## Resources\n"
        "Paginated read-only access via URIs: "
        f"{uri_scheme}://<database>/{resource_prefix}/imports, "
        ".../exports, .../entrypoints. "
        "Each has a /search/{pattern} variant for regex filtering."
    )

    call_lines = ["## Call patterns"]
    if has_tool_search:
        call_lines.append("ONE pinned tool → call the tool directly.")
        call_lines.append("ONE hidden tool → **call**(tool, arguments, database).")
    else:
        call_lines.append("ONE tool → call the tool directly.")
    if has_batch:
        call_lines.append("N independent calls → **batch** (per-item errors).")
    if has_execute:
        call_lines.append("Chaining/filtering → **execute** with invoke().")
        call_lines.append("Cross-database parallel → execute with asyncio.gather.")
    sections.append("\n".join(call_lines))

    if has_tool_search:
        callable_via = ["**call**"]
        if has_batch:
            callable_via.append("**batch**")
        if has_execute:
            callable_via.append("**execute**")
        sections.append(
            "## Tool discovery\n"
            "Common tools are pinned (always visible). Use "
            "search_tools(pattern) to find hidden tools, then "
            "get_schema(tools=[...]) for parameter details. "
            "Hidden tools are callable via "
            + ", ".join(callable_via)
            + " (they are not in the client tool list, so "
            "direct calls will fail with 'No such tool')."
        )

    sections.append(
        "## Session trust\n"
        "If your prompt states a database is already open by ID, "
        "trust it — do not re-verify with open/list/wait calls."
    )

    sections.append("## Workflows\n" + workflows)

    return "\n\n".join(sections)


@dataclass(frozen=True)
class BackendInfo:
    """Static metadata about a backend."""

    name: str
    """Short identifier (e.g. ``"ida"``, ``"ghidra"``)."""

    display_name: str
    """Human-readable name (e.g. ``"IDA Pro"``, ``"Ghidra"``)."""

    uri_scheme: str
    """URI scheme for MCP resources (e.g. ``"ida"``, ``"ghidra"``)."""

    worker_module: str
    """Python module to run as ``python -m <module>`` for workers."""

    pinned_tools: frozenset[str]
    """Tools that are always visible in the tool listing."""

    management_tools: frozenset[str]
    """Tools registered on the supervisor (not proxied to workers)."""

    env_prefix: str
    """Environment variable prefix (e.g. ``"IDA_MCP_"``)."""

    state_dir_name: str = "re-mcp"
    """Subdirectory name for daemon state files."""


@runtime_checkable
class Backend(Protocol):
    """Contract between core infrastructure and a backend implementation."""

    @staticmethod
    def info() -> BackendInfo:
        """Return static backend metadata."""
        ...

    @staticmethod
    def build_instructions(transform: ToolTransform) -> str:
        """Build the LLM instruction text for this backend."""
        ...

    @staticmethod
    def register_management_tools(mcp: FastMCP, pool: WorkerPoolProvider) -> None:
        """Register backend-specific management tools on the supervisor.

        The core registers generic management tools (``close_database``,
        ``list_databases``, ``wait_for_analysis``, ``save_database``).
        The backend registers tools with backend-specific parameters
        (e.g. IDA's ``open_database`` with ``processor``/``fat_arch``,
        or Ghidra's with ``language``/``compiler_spec``).
        """
        ...

    @staticmethod
    def register_prompts(mcp: FastMCP) -> None:
        """Register backend-specific MCP prompts on the supervisor."""
        ...

    @staticmethod
    def canonical_path(file_path: str, **kwargs: object) -> str:
        """Compute the canonical dedup key for a database path.

        Used by :class:`WorkerPoolProvider` for worker deduplication.
        Two calls with paths that resolve to the same underlying
        database must return the same string.
        """
        ...

    @staticmethod
    def list_targets() -> dict:
        """List available analysis targets (processors, languages, etc.).

        Backend-specific return shape.
        """
        ...


def discover_backends() -> dict[str, type[Backend]]:
    """Discover installed backends via ``re_mcp.backends`` entry points."""
    from importlib.metadata import entry_points  # noqa: PLC0415

    eps = entry_points(group="re_mcp.backends")
    return {ep.name: ep.load() for ep in eps}


def get_backend(name: str | None = None) -> type[Backend]:
    """Get a backend by name, or auto-select if only one is installed.

    Raises :class:`RuntimeError` when no backends are found, when
    multiple backends are installed and *name* is not specified, or
    when the requested *name* is not installed.
    """
    backends = discover_backends()
    if not backends:
        raise RuntimeError(
            "No re-mcp backends installed.  Install a backend package "
            "(e.g. ida-mcp, ghidra-mcp) to use this tool."
        )
    if name is None:
        if len(backends) == 1:
            return next(iter(backends.values()))
        raise RuntimeError(
            f"Multiple backends installed ({', '.join(sorted(backends))}); "
            "specify one with --backend or RE_MCP_BACKEND."
        )
    if name not in backends:
        raise RuntimeError(f"Backend {name!r} not found.  Installed: {', '.join(sorted(backends))}")
    return backends[name]
