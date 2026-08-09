# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Shared Pydantic models used across multiple tool modules.

Tool-specific models live in their respective tool modules.  Only models
that are referenced by two or more tool modules are kept here.

Models common to all backends live in :mod:`re_mcp.models` and are
re-exported here for convenient single-source imports.
"""

from __future__ import annotations

from pydantic import BaseModel, Field
from re_mcp.models import (
    FunctionChunk,
    FunctionSummary,
    PaginatedResult,
    RenameResult,
)

__all__ = [
    "DecompilerWarning",
    "FunctionChunk",
    "FunctionSummary",
    "PaginatedResult",
    "RenameResult",
]


class DecompilerWarning(BaseModel):
    """A non-fatal Hex-Rays warning raised while decompiling."""

    address: str = Field(description="Address the warning refers to (hex).")
    id: str = Field(description="Warning id name (e.g. WARN_BAD_SP).")
    text: str = Field(description="Formatted warning text.")
