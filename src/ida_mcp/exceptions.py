# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""IDA MCP error types and idalib-safe validation.

Separated from ``helpers`` so that modules which cannot load idalib (e.g.
the supervisor process) can still raise structured errors and validate
parameters before spawning worker processes.
"""

from __future__ import annotations

import json
import os

# ToolError is not re-exported from the top-level fastmcp package as of v3.1;
# if FastMCP reorganizes its internals this import path may need updating.
from fastmcp.exceptions import ToolError


class IDAError(ToolError):
    """Raised when an IDA operation fails.

    Subclasses ``ToolError`` so fastmcp automatically returns ``isError=True``
    with the message as text content.  The *error_type* attribute preserves the
    existing error taxonomy (e.g. ``InvalidAddress``, ``NotFound``).

    Optional *details* carry structured context (valid values, available names,
    etc.).  ``__str__`` returns a JSON object so the MCP error text is
    machine-parseable — the supervisor's ``parse_result`` decodes it
    transparently.
    """

    def __init__(self, message: str, error_type: str = "Error", **details: object):
        super().__init__(message)
        self.error_type = error_type
        self.details = details

    def __str__(self) -> str:
        d: dict[str, object] = {"error": self.args[0], "error_type": self.error_type}
        if self.details:
            d.update(self.details)
        return json.dumps(d, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Primary IDA database extensions
# ---------------------------------------------------------------------------

PRIMARY_IDB_EXTENSIONS: frozenset[str] = frozenset((".i64", ".idb"))


# ---------------------------------------------------------------------------
# Processor ambiguity detection
# ---------------------------------------------------------------------------


def _bitness_ambiguity_hint(name: str, description: str) -> str:
    """Build a standard hint for processors with ambiguous bitness on raw binaries."""
    return (
        f'"{name}" {description} that cannot be auto-detected for raw binaries.  '
        "In IDA's GUI a dialog prompts for the mode; headless mode picks a "
        "default that may be wrong.  Use list_targets and pass a specific "
        "variant via the processor parameter (processor:variant) or set "
        "bitness after opening."
    )


_X86_VARIANTS = (
    "  metapc:8086     — 16-bit real mode\n"
    "  metapc:80386p   — 32-bit protected mode\n"
    "  metapc:80386r   — 32-bit real mode\n"
    "  metapc:80486p   — 32-bit protected (486+)"
)


AMBIGUOUS_PROCESSORS: dict[str, str] = {
    "arm": (
        '"arm" is ambiguous for raw binaries — it defaults to AArch64 '
        "(64-bit) in headless mode.  Use a specific variant:\n"
        "  arm:ARMv7-M    — Cortex-M (32-bit Thumb-2)\n"
        "  arm:ARMv7-A    — 32-bit A-profile\n"
        "  arm:ARMv7-R    — 32-bit R-profile\n"
        "  arm:ARMv8-M    — ARMv8-M (32-bit)\n"
        "  arm:ARMv8-A    — ARMv8 A-profile (32-bit)\n"
        "  arm:ARMv9-A    — ARMv9 A-profile (32-bit)\n"
        'For 64-bit ARM, use "aarch64" as the processor.'
    ),
    "metapc": (
        '"metapc" supports 16-bit, 32-bit, and 64-bit x86 modes.  '
        "For raw binaries IDA cannot auto-detect the mode.  "
        f"Use a variant to select:\n{_X86_VARIANTS}\n"
        'For 64-bit x86, the default may work or try "metapc:Pentium 4".'
    ),
    "pc": (
        '"pc" supports 16-bit, 32-bit, and 64-bit x86 modes.  '
        "For raw binaries IDA cannot auto-detect the mode.  "
        f"Use a variant to select:\n{_X86_VARIANTS}\n"
        'The canonical processor name is "metapc", not "pc".'
    ),
    "mips": _bitness_ambiguity_hint("mips", "has 32-bit and 64-bit modes"),
    "mipsl": _bitness_ambiguity_hint("mipsl", "(MIPS little-endian) has 32-bit and 64-bit modes"),
    "ppc": _bitness_ambiguity_hint("ppc", "has 32-bit and 64-bit modes"),
    "riscv": _bitness_ambiguity_hint("riscv", "has 32-bit (RV32) and 64-bit (RV64) modes"),
}


def check_processor_ambiguity(processor: str, file_path: str, force_new: bool) -> None:
    """Raise :class:`IDAError` if *processor* is ambiguous for a raw binary.

    Processors like ``arm`` and ``metapc`` support multiple bitness modes.
    For structured formats (ELF, PE, ...) IDA reads the bitness from file
    headers, but for raw binaries it shows an interactive dialog — which
    is suppressed in headless mode, silently picking a (often wrong) default.
    """
    if not processor or ":" in processor:
        return  # Auto-detect or variant already specified.

    # Opening an existing IDA database — bitness is stored in the DB.
    _, ext = os.path.splitext(file_path)
    if ext.lower() in PRIMARY_IDB_EXTENSIONS:
        return

    # If not forcing a fresh analysis, an existing database sidecar means
    # IDA will reuse stored analysis (including bitness).
    if not force_new:
        resolved = os.path.abspath(os.path.expanduser(file_path))
        for db_ext in PRIMARY_IDB_EXTENSIONS:
            if os.path.isfile(resolved + db_ext):
                return

    hint = AMBIGUOUS_PROCESSORS.get(processor.lower())
    if hint:
        raise IDAError(hint, error_type="AmbiguousProcessor")


# ---------------------------------------------------------------------------
# IDA command-line args builder (idalib-safe)
# ---------------------------------------------------------------------------


def build_ida_args(
    *,
    processor: str = "",
    loader: str = "",
    base_address: str = "",
    options: str = "",
) -> str | None:
    """Build an IDA command-line args string from structured parameters.

    Returns ``None`` when no arguments are needed.  Raises :class:`IDAError`
    on invalid *base_address* or when *options* duplicates a flag that is
    already provided by a structured parameter.
    """
    # Reject options that duplicate a structured parameter already in use.
    if options:
        for flag, value, param_name in (
            ("-p", processor, "processor"),
            ("-T", loader, "loader"),
            ("-b", base_address, "base_address"),
        ):
            if value and flag in options:
                raise IDAError(
                    f"options contains '{flag}' — use the {param_name} parameter instead "
                    f"of passing '{flag}' in options to avoid duplicate flags.",
                    error_type="InvalidArgument",
                )

    args_parts: list[str] = []
    if processor:
        args_parts.append(f"-p{processor}")
    if loader:
        # Values containing spaces must be quoted so IDA's C-level arg parser
        # doesn't split them into separate positional arguments.
        val = f'"{loader}"' if " " in loader else loader
        args_parts.append(f"-T{val}")
    if base_address:
        try:
            addr = int(base_address, 0)
        except ValueError:
            raise IDAError(
                f"Invalid base_address: {base_address!r}. "
                "Provide a hex (0x...) or decimal integer.",
                error_type="InvalidArgument",
            ) from None
        if addr & 0xF:
            raise IDAError(
                f"base_address {base_address} is not 16-byte aligned. "
                "IDA requires paragraph alignment (multiple of 0x10).",
                error_type="InvalidArgument",
            )
        args_parts.append(f"-b{addr >> 4:#x}")
    if options:
        args_parts.append(options)
    return " ".join(args_parts) or None
