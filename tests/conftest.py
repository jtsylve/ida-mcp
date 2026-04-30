# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

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

# Set real constant values on stubs so that module-level expressions in
# production code (e.g. ``_ALL_STR_TYPES`` in helpers.py) capture integers
# instead of MagicMock objects.  Values come from the IDA 9.3 .pyi stubs.
_STUB_CONSTANTS: dict[str, dict[str, int]] = {
    "ida_nalt": {
        "STRTYPE_C": 0,
        "STRTYPE_C_16": 1,
        "STRTYPE_C_32": 2,
        "STRTYPE_PASCAL": 4,
        "STRTYPE_PASCAL_16": 5,
        "STRTYPE_PASCAL_32": 6,
        "STRTYPE_LEN2": 8,
        "STRTYPE_LEN2_16": 9,
        "STRTYPE_LEN2_32": 10,
        "STRTYPE_LEN4": 12,
        "STRTYPE_LEN4_16": 13,
        "STRTYPE_LEN4_32": 14,
        "STRWIDTH_1B": 0,
        "STRWIDTH_2B": 1,
        "STRWIDTH_4B": 2,
        "STRWIDTH_MASK": 3,
    },
    "ida_segment": {
        "SEGPERM_READ": 4,
        "SEGPERM_WRITE": 2,
        "SEGPERM_EXEC": 1,
    },
}
for _mod_name, _constants in _STUB_CONSTANTS.items():
    if _mod_name in _stubs:
        for _attr, _val in _constants.items():
            setattr(_stubs[_mod_name], _attr, _val)
