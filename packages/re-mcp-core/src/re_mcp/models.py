# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Shared Pydantic models used across backends."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PaginatedResult[T](BaseModel):
    """Paginated result set."""

    items: list[T] = Field(description="Page of result items.")
    total: int = Field(
        description="Total number of matching items (may be approximate for large sets)."
    )
    offset: int = Field(description="Starting offset of this page.")
    limit: int = Field(description="Maximum items per page.")
    has_more: bool = Field(description="Whether more items exist beyond this page.")
