# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""IDA directory tree (folder) tools for organizing functions, names, etc."""

from __future__ import annotations

import ida_dirtree
from mcp.server.fastmcp import FastMCP

from ida_mcp.session import session

_TREE_MAP = {
    "funcs": ida_dirtree.DIRTREE_FUNCS,
    "names": ida_dirtree.DIRTREE_NAMES,
    "local_types": ida_dirtree.DIRTREE_LOCAL_TYPES,
    "imports": ida_dirtree.DIRTREE_IMPORTS,
}


def _get_dirtree(tree: str):
    """Resolve a tree name to its dirtree object, or return an error dict."""
    tree_id = _TREE_MAP.get(tree)
    if tree_id is None:
        return None, {
            "error": f"Invalid tree: {tree!r}",
            "error_type": "InvalidArgument",
            "valid_trees": list(_TREE_MAP),
        }

    dt = ida_dirtree.get_std_dirtree(tree_id)
    if dt is None:
        return None, {"error": "Failed to get directory tree", "error_type": "NotAvailable"}

    return dt, None


def register(mcp: FastMCP):
    @mcp.tool()
    @session.require_open
    def list_folders(tree: str = "funcs", path: str = "/") -> dict:
        """List folders and items in IDA's directory tree.

        IDA 9 organizes functions, names, local types, and imports into
        a folder hierarchy. This tool lets you browse that hierarchy.

        Args:
            tree: Which tree — "funcs", "names", "local_types", or "imports".
            path: Directory path to list (default "/" for root).
        """
        dt, err = _get_dirtree(tree)
        if err:
            return err

        entries = []
        it = ida_dirtree.dirtree_iterator_t()
        ok = dt.findfirst(it, path + "*" if path.endswith("/") else path + "/*")
        while ok:
            de = dt.resolve_cursor(it.cursor)
            name = dt.get_entry_name(de)
            abspath = dt.get_abspath(it.cursor)
            is_dir = dt.isdir(abspath)
            entries.append(
                {
                    "name": name,
                    "is_folder": bool(is_dir),
                    "path": abspath,
                }
            )
            ok = dt.findnext(it)

        return {
            "tree": tree,
            "path": path,
            "count": len(entries),
            "entries": entries,
        }

    @mcp.tool()
    @session.require_open
    def create_folder(tree: str, path: str) -> dict:
        """Create a new folder in IDA's directory tree.

        Args:
            tree: Which tree — "funcs", "names", "local_types", or "imports".
            path: Full path of the folder to create (e.g. "/crypto/aes").
        """
        dt, err = _get_dirtree(tree)
        if err:
            return err

        code = dt.mkdir(path)
        if code != 0:
            return {
                "error": f"Failed to create folder: error {code}",
                "error_type": "CreateFailed",
            }

        return {"tree": tree, "path": path}

    @mcp.tool()
    @session.require_open
    def rename_folder(tree: str, old_path: str, new_path: str) -> dict:
        """Rename or move a folder in IDA's directory tree.

        Args:
            tree: Which tree — "funcs", "names", "local_types", or "imports".
            old_path: Current path of the folder/item.
            new_path: New path for the folder/item.
        """
        dt, err = _get_dirtree(tree)
        if err:
            return err

        code = dt.rename(old_path, new_path)
        if code != 0:
            return {
                "error": f"Failed to rename: error {code}",
                "error_type": "RenameFailed",
            }

        return {"tree": tree, "old_path": old_path, "new_path": new_path}

    @mcp.tool()
    @session.require_open
    def delete_folder(tree: str, path: str) -> dict:
        """Delete a folder from IDA's directory tree.

        The folder must be empty.

        Args:
            tree: Which tree — "funcs", "names", "local_types", or "imports".
            path: Path of the folder to delete.
        """
        dt, err = _get_dirtree(tree)
        if err:
            return err

        code = dt.rmdir(path)
        if code != 0:
            return {
                "error": f"Failed to delete folder: error {code}",
                "error_type": "DeleteFailed",
            }

        return {"tree": tree, "path": path}
