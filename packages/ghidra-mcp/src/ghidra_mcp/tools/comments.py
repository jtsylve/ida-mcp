# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Comment management tools."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ghidra_mcp.exceptions import GhidraError
from ghidra_mcp.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    format_address,
    resolve_address,
)
from ghidra_mcp.session import session


class GetCommentResult(BaseModel):
    address: str
    eol_comment: str = Field(default="", description="End-of-line comment.")
    pre_comment: str = Field(default="", description="Pre-instruction comment.")
    post_comment: str = Field(default="", description="Post-instruction comment.")
    plate_comment: str = Field(default="", description="Plate (block) comment.")
    repeatable_comment: str = Field(default="", description="Repeatable comment.")


class SetCommentResult(BaseModel):
    address: str
    comment_type: str
    comment: str
    status: str


class GetFunctionCommentResult(BaseModel):
    address: str
    function_name: str
    comment: str
    repeatable_comment: str


class SetFunctionCommentResult(BaseModel):
    address: str
    function_name: str
    comment: str
    status: str


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"comments"})
    @session.require_open
    def get_comment(address: Address) -> GetCommentResult:
        """Get all comments at an address."""
        from ghidra.program.model.listing import CodeUnit  # noqa: PLC0415

        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)
        cu = listing.getCodeUnitAt(addr)

        if cu is None:
            return GetCommentResult(address=format_address(addr.getOffset()))

        return GetCommentResult(
            address=format_address(addr.getOffset()),
            eol_comment=cu.getComment(CodeUnit.EOL_COMMENT) or "",
            pre_comment=cu.getComment(CodeUnit.PRE_COMMENT) or "",
            post_comment=cu.getComment(CodeUnit.POST_COMMENT) or "",
            plate_comment=cu.getComment(CodeUnit.PLATE_COMMENT) or "",
            repeatable_comment=cu.getComment(CodeUnit.REPEATABLE_COMMENT) or "",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"comments"})
    @session.require_open
    def set_comment(
        address: Address,
        comment: str,
        comment_type: str = "eol",
    ) -> SetCommentResult:
        """Set a comment at an address.

        Args:
            address: Target address.
            comment: Comment text (empty string to clear).
            comment_type: One of "eol", "pre", "post", "plate", "repeatable".
        """
        from ghidra.program.model.listing import CodeUnit  # noqa: PLC0415

        type_map = {
            "eol": CodeUnit.EOL_COMMENT,
            "pre": CodeUnit.PRE_COMMENT,
            "post": CodeUnit.POST_COMMENT,
            "plate": CodeUnit.PLATE_COMMENT,
            "repeatable": CodeUnit.REPEATABLE_COMMENT,
        }
        ct = type_map.get(comment_type.lower())
        if ct is None:
            raise GhidraError(
                f"Invalid comment_type: {comment_type!r}. Must be one of: {', '.join(type_map)}",
                error_type="InvalidArgument",
            )

        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)
        cu = listing.getCodeUnitAt(addr)
        if cu is None:
            raise GhidraError(
                f"No code unit at {format_address(addr.getOffset())}",
                error_type="NotFound",
            )

        tx_id = program.startTransaction("Set comment")
        try:
            cu.setComment(ct, comment or None)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to set comment: {e}", error_type="CommentFailed") from e

        return SetCommentResult(
            address=format_address(addr.getOffset()),
            comment_type=comment_type,
            comment=comment,
            status="ok",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"comments", "decompiler"})
    @session.require_open
    def set_decompiler_comment(
        address: Address,
        comment: str,
    ) -> SetCommentResult:
        """Set a pre-comment at an address (visible in decompiler output).

        This sets a PRE comment, which Ghidra's decompiler renders
        above the corresponding line in the pseudocode.
        """
        from ghidra.program.model.listing import CodeUnit  # noqa: PLC0415

        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)
        cu = listing.getCodeUnitAt(addr)
        if cu is None:
            raise GhidraError(
                f"No code unit at {format_address(addr.getOffset())}",
                error_type="NotFound",
            )

        tx_id = program.startTransaction("Set decompiler comment")
        try:
            cu.setComment(CodeUnit.PRE_COMMENT, comment or None)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to set comment: {e}", error_type="CommentFailed") from e

        return SetCommentResult(
            address=format_address(addr.getOffset()),
            comment_type="pre",
            comment=comment,
            status="ok",
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"comments", "functions"})
    @session.require_open
    def get_function_comment(address: Address) -> GetFunctionCommentResult:
        """Get the comment on a function."""
        from ghidra_mcp.helpers import resolve_function  # noqa: PLC0415

        func = resolve_function(address)
        return GetFunctionCommentResult(
            address=format_address(func.getEntryPoint().getOffset()),
            function_name=func.getName(),
            comment=func.getComment() or "",
            repeatable_comment=func.getRepeatableComment() or "",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"comments", "functions"})
    @session.require_open
    def set_function_comment(
        address: Address,
        comment: str,
        repeatable: bool = True,
    ) -> SetFunctionCommentResult:
        """Set a comment on a function header."""
        from ghidra_mcp.helpers import resolve_function  # noqa: PLC0415

        func = resolve_function(address)

        tx_id = session.program.startTransaction("Set function comment")
        try:
            if repeatable:
                func.setRepeatableComment(comment or None)
            else:
                func.setComment(comment or None)
            session.program.endTransaction(tx_id, True)
        except Exception as e:
            session.program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to set function comment: {e}", error_type="CommentFailed"
            ) from e

        return SetFunctionCommentResult(
            address=format_address(func.getEntryPoint().getOffset()),
            function_name=func.getName(),
            comment=comment,
            status="ok",
        )
