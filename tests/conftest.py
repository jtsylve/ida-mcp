# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Shared test fixtures — IDA module stubs for tests that run without idalib."""

from __future__ import annotations

import importlib.util
import sys
from types import ModuleType
from unittest.mock import MagicMock

# All IDA modules that may be transitively imported by the code under test.
# Stubbed once here so individual test files don't need to duplicate the list.
# Only stub modules that are genuinely unavailable — if a real idalib is
# installed, let the real modules load so tests can run against them too.
_IDA_MODULES = [
    "idapro",
    "idaapi",
    "idc",
    "idautils",
    "ida_auto",
    "ida_bytes",
    "ida_dirtree",
    "ida_diskio",
    "ida_entry",
    "ida_enum",
    "ida_fixup",
    "ida_fpro",
    "ida_frame",
    "ida_funcs",
    "ida_gdl",
    "ida_hexrays",
    "ida_ida",
    "ida_idaapi",
    "ida_idp",
    "ida_kernwin",
    "ida_lines",
    "ida_loader",
    "ida_nalt",
    "ida_name",
    "ida_problems",
    "ida_range",
    "ida_regfinder",
    "ida_search",
    "ida_segment",
    "ida_srclang",
    "ida_strlist",
    "ida_struct",
    "ida_tryblks",
    "ida_typeinf",
    "ida_ua",
    "ida_undo",
    "ida_xref",
]

_stubs: dict[str, ModuleType] = {}
for _mod_name in _IDA_MODULES:
    if _mod_name not in sys.modules and importlib.util.find_spec(_mod_name) is None:
        _stubs[_mod_name] = MagicMock()
        sys.modules[_mod_name] = _stubs[_mod_name]
