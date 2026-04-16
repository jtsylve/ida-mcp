# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""IDA directory tree (folder) tools for organizing functions, names, etc."""

from __future__ import annotations

import ida_dirtree
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ida_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    IDAError,
)
from ida_mcp.session import session


class DirEntry(BaseModel):
    """A directory tree entry."""

    name: str = Field(description="Entry name.")
    is_folder: bool = Field(description="Whether this is a folder.")
    path: str = Field(description="Full path.")


class ListFoldersResult(BaseModel):
    """Directory tree listing."""

    tree: str = Field(description="Tree type.")
    path: str = Field(description="Listed path.")
    count: int = Field(description="Number of entries.")
    entries: list[DirEntry] = Field(description="Directory entries.")


class FolderActionResult(BaseModel):
    """Result of a folder create/rename/delete operation."""

    tree: str = Field(description="Tree type.")
    path: str = Field(description="Folder path.")
    old_path: str | None = Field(default=None, description="Previous path (for rename).")
    new_path: str | None = Field(default=None, description="New path (for rename).")


_TREE_MAP = {
    "funcs": ida_dirtree.DIRTREE_FUNCS,
    "names": ida_dirtree.DIRTREE_NAMES,
    "local_types": ida_dirtree.DIRTREE_LOCAL_TYPES,
    "imports": ida_dirtree.DIRTREE_IMPORTS,
}


def _get_dirtree(tree: str):
    """Resolve a tree name to its dirtree object.  Raises :class:`IDAError` on failure."""
    tree_id = _TREE_MAP.get(tree)
    if tree_id is None:
        raise IDAError(
            f"Invalid tree: {tree!r}",
            error_type="InvalidArgument",
            valid_trees=list(_TREE_MAP),
        )

    dt = ida_dirtree.get_std_dirtree(tree_id)
    if dt is None:
        raise IDAError("Failed to get directory tree", error_type="NotAvailable")

    return dt


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"metadata"},
    )
    @session.require_open
    def list_folders(tree: str = "funcs", path: str = "/") -> ListFoldersResult:
        """List folders and items in IDA's directory tree (funcs/names/local_types/imports).

        Args:
            tree: Which tree — "funcs", "names", "local_types", or "imports".
            path: Directory path to list (default "/" for root).
        """
        dt = _get_dirtree(tree)

        entries = []
        it = ida_dirtree.dirtree_iterator_t()
        ok = dt.findfirst(it, path + "*" if path.endswith("/") else path + "/*")
        while ok:
            de = dt.resolve_cursor(it.cursor)
            name = dt.get_entry_name(de)
            abspath = dt.get_abspath(it.cursor)
            is_dir = dt.isdir(abspath)
            entries.append(
                DirEntry(
                    name=name,
                    is_folder=bool(is_dir),
                    path=abspath,
                )
            )
            ok = dt.findnext(it)

        return ListFoldersResult(
            tree=tree,
            path=path,
            count=len(entries),
            entries=entries,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"metadata"},
    )
    @session.require_open
    def create_folder(tree: str, path: str) -> FolderActionResult:
        """Create a new folder in IDA's directory tree.

        Args:
            tree: Which tree — "funcs", "names", "local_types", or "imports".
            path: Full path of the folder to create (e.g. "/crypto/aes").
        """
        dt = _get_dirtree(tree)

        code = dt.mkdir(path)
        if code != 0:
            raise IDAError(f"Failed to create folder: error {code}", error_type="CreateFailed")

        return FolderActionResult(tree=tree, path=path)

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"metadata"},
    )
    @session.require_open
    def rename_folder(tree: str, old_path: str, new_path: str) -> FolderActionResult:
        """Rename or move a folder in IDA's directory tree.

        Args:
            tree: Which tree — "funcs", "names", "local_types", or "imports".
            old_path: Current path of the folder/item.
            new_path: New path for the folder/item.
        """
        dt = _get_dirtree(tree)

        code = dt.rename(old_path, new_path)
        if code != 0:
            raise IDAError(f"Failed to rename: error {code}", error_type="RenameFailed")

        return FolderActionResult(tree=tree, old_path=old_path, new_path=new_path, path=new_path)

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"metadata"},
    )
    @session.require_open
    def delete_folder(tree: str, path: str) -> FolderActionResult:
        """Delete an empty folder from IDA's directory tree.

        Args:
            tree: Which tree — "funcs", "names", "local_types", or "imports".
            path: Path of the folder to delete.
        """
        dt = _get_dirtree(tree)

        code = dt.rmdir(path)
        if code != 0:
            raise IDAError(f"Failed to delete folder: error {code}", error_type="DeleteFailed")

        return FolderActionResult(tree=tree, path=path)
