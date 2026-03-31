# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Shared Pydantic models used across multiple tool modules.

Tool-specific models live in their respective tool modules.  Only models
that are referenced by two or more tool modules are kept here.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Pagination envelope — shared by all paginated endpoints
# ---------------------------------------------------------------------------


class PaginatedResult[T](BaseModel):
    """Paginated result set."""

    items: list[T] = Field(description="Page of result items.")
    total: int = Field(
        description="Total number of matching items (may be approximate for large sets)."
    )
    offset: int = Field(description="Starting offset of this page.")
    limit: int = Field(description="Maximum items per page.")
    has_more: bool = Field(description="Whether more items exist beyond this page.")


# ---------------------------------------------------------------------------
# Shared function helpers — used by functions.py, chunks.py, search.py
# ---------------------------------------------------------------------------


class FunctionChunk(BaseModel):
    """A non-contiguous chunk of a function."""

    start: str = Field(description="Chunk start address (hex).")
    end: str = Field(description="Chunk end address (hex, exclusive).")
    size: int = Field(description="Chunk size in bytes.")


class FunctionSummary(BaseModel):
    """Brief function info returned by list_functions."""

    name: str = Field(description="Function name.")
    start: str = Field(description="Start address (hex).")
    end: str = Field(description="End address (hex, exclusive).")
    size: int = Field(description="Function size in bytes.")


# ---------------------------------------------------------------------------
# Shared result — used by functions.py and names.py
# ---------------------------------------------------------------------------


class RenameResult(BaseModel):
    """Result of a rename operation."""

    address: str = Field(description="Address of the renamed item (hex).")
    old_name: str = Field(description="Previous name.")
    new_name: str = Field(description="New name.")
