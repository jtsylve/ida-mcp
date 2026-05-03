#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

# Bump version across all workspace packages.
# Usage: scripts/bump-version.sh 3.1.0
#        scripts/bump-version.sh --bump patch

set -euo pipefail

if [ $# -eq 0 ]; then
    echo "Usage: $0 <version>  or  $0 --bump <major|minor|patch|...>"
    echo ""
    echo "Current versions:"
    uv version
    uv version --package re-mcp-core
    uv version --package re-mcp-ida
    uv version --package re-mcp-ghidra
    uv version --package ida-mcp
    exit 1
fi

uv version "$@"
uv version --package re-mcp-core "$@"
uv version --package re-mcp-ida "$@"
uv version --package re-mcp-ghidra "$@"
uv version --package ida-mcp "$@"
