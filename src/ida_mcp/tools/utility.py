# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Utility tools — number conversion, expression evaluation, script execution."""

from __future__ import annotations

import contextlib
import io
import os

import idc
from fastmcp import FastMCP

from ida_mcp.helpers import IDAError, format_address
from ida_mcp.session import session


def register(mcp: FastMCP):
    @mcp.tool()
    def convert_number(value: str) -> dict:
        """Convert a number between hex, decimal, octal, and binary representations.

        This is useful because LLMs frequently make errors with base conversions.
        Also returns signed 32-bit and 64-bit interpretations when the value fits,
        useful for understanding sign-extended values in disassembly.

        Args:
            value: Number to convert (prefix with 0x for hex, 0o for octal, 0b for binary).
        """
        value = value.strip()
        try:
            if value.lower().startswith("0x"):
                n = int(value, 16)
            elif value.lower().startswith("0o"):
                n = int(value, 8)
            elif value.lower().startswith("0b"):
                n = int(value, 2)
            else:
                n = int(value, 0)
        except ValueError:
            raise IDAError(
                f"Cannot parse number: {value!r}", error_type="InvalidArgument"
            ) from None

        # Compute signed value for common widths
        signed_32 = n if n < 0x80000000 else n - 0x100000000
        signed_64 = n if n < 0x8000000000000000 else n - 0x10000000000000000

        return {
            "decimal": str(n),
            "hex": hex(n),
            "octal": oct(n),
            "binary": bin(n),
            "signed_32": signed_32 if 0 <= n <= 0xFFFFFFFF else None,
            "signed_64": signed_64 if 0 <= n <= 0xFFFFFFFFFFFFFFFF else None,
        }

    @mcp.tool()
    @session.require_open
    def evaluate_expression(expression: str) -> dict:
        """Evaluate an IDC expression and return the result.

        Args:
            expression: IDC expression to evaluate (e.g. "MinEA()", "0x1000+0x20").
        """
        result = idc.eval_idc(expression)
        if isinstance(result, int):
            return {"expression": expression, "result": result, "hex": format_address(result)}
        return {"expression": expression, "result": str(result)}

    if os.environ.get("IDA_MCP_ALLOW_SCRIPTS", "").lower() in ("1", "true", "yes"):

        @mcp.tool()
        @session.require_open
        def run_script(code: str) -> dict:
            """Execute arbitrary IDAPython code and capture the output.

            SECURITY WARNING: This runs arbitrary Python with FULL access to the
            filesystem, network, and IDA internals. Only use with trusted input.
            Prefer the dedicated tools when possible — this is a last resort for
            operations not covered by other tools.

            This tool is only available when the IDA_MCP_ALLOW_SCRIPTS
            environment variable is set to "1", "true", or "yes".

            Args:
                code: Python code to execute. Use print() for output.
            """
            stdout_capture = io.StringIO()
            stderr_capture = io.StringIO()
            exec_globals = {"__builtins__": __builtins__}

            try:
                with (
                    contextlib.redirect_stdout(stdout_capture),
                    contextlib.redirect_stderr(stderr_capture),
                ):
                    exec(code, exec_globals)
            except Exception as e:
                raise IDAError(
                    f"{type(e).__name__}: {e}",
                    error_type="ScriptError",
                    stdout=stdout_capture.getvalue(),
                    stderr=stderr_capture.getvalue(),
                ) from e

            return {
                "stdout": stdout_capture.getvalue(),
                "stderr": stderr_capture.getvalue(),
            }
