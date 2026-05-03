# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Program tree / folder management tools.

Ghidra organizes code into a Program Tree with modules and fragments.
This is the equivalent of IDA's directory tree (dirtree) for organizing
functions and code into folders.
"""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
)
from re_mcp_ghidra.session import session


class DirEntry(BaseModel):
    """A program tree entry."""

    name: str = Field(description="Entry name.")
    is_folder: bool = Field(description="Whether this is a module (folder).")
    path: str = Field(description="Full path.")


class ListFoldersResult(BaseModel):
    """Program tree listing."""

    tree: str = Field(description="Tree name.")
    path: str = Field(description="Listed path.")
    count: int = Field(description="Number of entries.")
    entries: list[DirEntry] = Field(description="Directory entries.")


class FolderActionResult(BaseModel):
    """Result of a folder create/rename/delete operation."""

    tree: str = Field(description="Tree name.")
    path: str = Field(description="Folder path.")
    old_path: str | None = Field(default=None, description="Previous path (for rename).")
    new_path: str | None = Field(default=None, description="New path (for rename).")


def _get_tree_root(tree_name: str):
    """Get the root module for the named program tree."""
    program = session.program
    listing = program.getListing()

    tree_names = listing.getTreeNames()
    if tree_name not in list(tree_names):
        available = list(tree_names)
        raise GhidraError(
            f"Tree {tree_name!r} not found. Available: {available}",
            error_type="NotFound",
        )

    root = listing.getRootModule(tree_name)
    if root is None:
        raise GhidraError(
            f"Cannot get root module for tree {tree_name!r}",
            error_type="NotFound",
        )
    return root


def _resolve_module(root, path: str):
    """Walk the path from root to find a ProgramModule."""
    parts = [p for p in path.strip("/").split("/") if p]
    current = root
    for part in parts:
        found = False
        for i in range(current.getNumChildren()):
            child = current.getChildAt(i)
            if child.getName() == part:
                # Check if it's a module (folder)
                from ghidra.program.model.listing import ProgramModule  # noqa: PLC0415

                if isinstance(child, ProgramModule):
                    current = child
                    found = True
                    break
                raise GhidraError(
                    f"{part!r} is a fragment, not a folder",
                    error_type="InvalidArgument",
                )
        if not found:
            raise GhidraError(
                f"Path component {part!r} not found in {path!r}",
                error_type="NotFound",
            )
    return current


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"metadata"})
    @session.require_open
    def list_folders(tree: str = "Program Tree", path: str = "/") -> ListFoldersResult:
        """List folders and fragments in Ghidra's program tree.

        Args:
            tree: Program tree name (use default "Program Tree" or check
                the listing for available trees).
            path: Directory path to list (default "/" for root).
        """
        from ghidra.program.model.listing import ProgramModule  # noqa: PLC0415

        root = _get_tree_root(tree)

        # Navigate to the requested path
        module = root if path in ("/", "") else _resolve_module(root, path)

        entries = []
        for i in range(module.getNumChildren()):
            child = module.getChildAt(i)
            child_name = child.getName()
            is_module = isinstance(child, ProgramModule)
            child_path = f"{path.rstrip('/')}/{child_name}"
            entries.append(
                DirEntry(
                    name=child_name,
                    is_folder=is_module,
                    path=child_path,
                )
            )

        return ListFoldersResult(
            tree=tree,
            path=path,
            count=len(entries),
            entries=entries,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"metadata"})
    @session.require_open
    def create_folder(tree: str, path: str) -> FolderActionResult:
        """Create a new folder (module) in the program tree.

        Args:
            tree: Program tree name.
            path: Full path of the folder to create (e.g. "/crypto/aes").
        """
        root = _get_tree_root(tree)
        parts = [p for p in path.strip("/").split("/") if p]
        if not parts:
            raise GhidraError("Empty path", error_type="InvalidArgument")

        parent_path = "/".join(parts[:-1])
        new_name = parts[-1]

        parent = _resolve_module(root, parent_path) if parent_path else root

        program = session.program
        tx_id = program.startTransaction("Create folder")
        try:
            parent.createModule(new_name)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to create folder: {e}", error_type="CreateFailed") from e

        return FolderActionResult(tree=tree, path=path)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"metadata"})
    @session.require_open
    def rename_folder(tree: str, old_path: str, new_path: str) -> FolderActionResult:
        """Rename a folder (module) in the program tree.

        The new_path should have the same parent; only the leaf name
        is changed.

        Args:
            tree: Program tree name.
            old_path: Current path of the folder.
            new_path: New path for the folder.
        """
        root = _get_tree_root(tree)
        module = _resolve_module(root, old_path)

        new_parts = [p for p in new_path.strip("/").split("/") if p]
        if not new_parts:
            raise GhidraError("Empty new path", error_type="InvalidArgument")
        new_name = new_parts[-1]

        program = session.program
        tx_id = program.startTransaction("Rename folder")
        try:
            module.setName(new_name)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to rename folder: {e}", error_type="RenameFailed") from e

        return FolderActionResult(tree=tree, old_path=old_path, new_path=new_path, path=new_path)

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"metadata"})
    @session.require_open
    def delete_folder(tree: str, path: str) -> FolderActionResult:
        """Delete a folder (module) from the program tree.

        The folder must be empty (no children) to be deleted.

        Args:
            tree: Program tree name.
            path: Path of the folder to delete.
        """
        root = _get_tree_root(tree)

        parts = [p for p in path.strip("/").split("/") if p]
        if not parts:
            raise GhidraError("Cannot delete root", error_type="InvalidArgument")

        folder_name = parts[-1]
        parent = _resolve_module(root, "/".join(parts[:-1])) if len(parts) > 1 else root

        # Find and verify the child exists
        found = False
        for i in range(parent.getNumChildren()):
            child = parent.getChildAt(i)
            if child.getName() == folder_name:
                found = True
                break

        if not found:
            raise GhidraError(
                f"Folder {folder_name!r} not found at path {path!r}",
                error_type="NotFound",
            )

        program = session.program
        tx_id = program.startTransaction("Delete folder")
        try:
            parent.removeChild(folder_name)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to delete folder: {e}", error_type="DeleteFailed") from e

        return FolderActionResult(tree=tree, path=path)
