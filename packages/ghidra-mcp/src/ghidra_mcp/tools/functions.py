# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Function analysis tools — list, decompile, disassemble, rename."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel

from ghidra_mcp.exceptions import GhidraError
from ghidra_mcp.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    FilterPattern,
    Limit,
    Offset,
    compile_filter,
    format_address,
    paginate_iter,
    resolve_function,
)
from ghidra_mcp.models import FunctionSummary, RenameResult
from ghidra_mcp.session import session


class FunctionDetail(BaseModel):
    name: str
    start: str
    end: str
    size: int
    calling_convention: str = ""
    signature: str = ""
    is_thunk: bool = False
    is_external: bool = False
    comment: str = ""
    entry_point: str = ""


class DecompilationResult(BaseModel):
    function_name: str
    address: str
    decompiled_code: str


class Instruction(BaseModel):
    address: str
    bytes: str
    mnemonic: str
    operands: str


class DisassemblyResult(BaseModel):
    function_name: str
    start: str
    end: str
    instruction_count: int
    instructions: list[Instruction]


class DeleteFunctionResult(BaseModel):
    address: str
    name: str
    status: str


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions"})
    @session.require_open
    def list_functions(
        offset: Offset = 0,
        limit: Limit = 100,
        filter_pattern: FilterPattern = "",
    ) -> dict:
        """List all functions in the database, paginated with optional regex filter."""
        program = session.program
        func_mgr = program.getFunctionManager()
        filt = compile_filter(filter_pattern)

        def _gen():
            func_iter = func_mgr.getFunctions(True)
            while func_iter.hasNext():
                func = func_iter.next()
                name = func.getName()
                if filt and not filt.search(name):
                    continue
                body = func.getBody()
                start = func.getEntryPoint().getOffset()
                end = body.getMaxAddress().getOffset() + 1 if body.getNumAddresses() > 0 else start
                yield FunctionSummary(
                    name=name,
                    start=format_address(start),
                    end=format_address(end),
                    size=int(body.getNumAddresses()),
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions"})
    @session.require_open
    def get_function(address: Address) -> FunctionDetail:
        """Get detailed information about a function."""
        func = resolve_function(address)
        body = func.getBody()
        entry = func.getEntryPoint()
        start = entry.getOffset()
        end = body.getMaxAddress().getOffset() + 1 if body.getNumAddresses() > 0 else start

        return FunctionDetail(
            name=func.getName(),
            start=format_address(start),
            end=format_address(end),
            size=int(body.getNumAddresses()),
            calling_convention=func.getCallingConventionName() or "",
            signature=func.getPrototypeString(False, False) or "",
            is_thunk=func.isThunk(),
            is_external=func.isExternal(),
            comment=func.getComment() or "",
            entry_point=format_address(start),
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions", "decompiler"})
    @session.require_open
    def decompile_function(address: Address) -> DecompilationResult:
        """Decompile a function to C pseudocode using Ghidra's decompiler."""
        from ghidra.app.decompiler import DecompInterface  # noqa: PLC0415
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        func = resolve_function(address)
        program = session.program

        decomp = DecompInterface()
        decomp.openProgram(program)

        try:
            results = decomp.decompileFunction(func, 60, TaskMonitor.DUMMY)
            if not results.decompileCompleted():
                error_msg = results.getErrorMessage() or "Decompilation failed"
                raise GhidraError(error_msg, error_type="DecompilationFailed")

            decomp_func = results.getDecompiledFunction()
            if decomp_func is None:
                raise GhidraError(
                    "Decompilation returned no result", error_type="DecompilationFailed"
                )

            code = decomp_func.getC()
            return DecompilationResult(
                function_name=func.getName(),
                address=format_address(func.getEntryPoint().getOffset()),
                decompiled_code=code,
            )
        finally:
            decomp.dispose()

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions"})
    @session.require_open
    def disassemble_function(address: Address) -> DisassemblyResult:
        """Disassemble a function into individual instructions."""
        func = resolve_function(address)
        program = session.program
        listing = program.getListing()
        body = func.getBody()

        instructions = []
        insn_iter = listing.getInstructions(body, True)
        while insn_iter.hasNext():
            insn = insn_iter.next()
            addr = insn.getAddress()
            raw_bytes = []
            for i in range(insn.getLength()):
                b = insn.getByte(i)
                raw_bytes.append(f"{b & 0xFF:02X}")

            operands = []
            for i in range(insn.getNumOperands()):
                op_str = insn.getDefaultOperandRepresentation(i)
                if op_str:
                    operands.append(op_str)

            instructions.append(
                Instruction(
                    address=format_address(addr.getOffset()),
                    bytes=" ".join(raw_bytes),
                    mnemonic=insn.getMnemonicString(),
                    operands=", ".join(operands),
                )
            )

        entry = func.getEntryPoint().getOffset()
        end_addr = body.getMaxAddress().getOffset() + 1 if body.getNumAddresses() > 0 else entry

        return DisassemblyResult(
            function_name=func.getName(),
            start=format_address(entry),
            end=format_address(end_addr),
            instruction_count=len(instructions),
            instructions=instructions,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"functions"})
    @session.require_open
    def rename_function(address: Address, new_name: str) -> RenameResult:
        """Rename a function."""
        from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

        func = resolve_function(address)
        old_name = func.getName()

        tx_id = session.program.startTransaction("Rename function")
        try:
            func.setName(new_name, SourceType.USER_DEFINED)
            session.program.endTransaction(tx_id, True)
        except Exception as e:
            session.program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to rename function: {e}", error_type="RenameFailed") from e

        return RenameResult(
            address=format_address(func.getEntryPoint().getOffset()),
            old_name=old_name,
            new_name=new_name,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"functions"})
    @session.require_open
    def delete_function(address: Address) -> DeleteFunctionResult:
        """Delete a function definition (does not delete the bytes)."""
        func = resolve_function(address)
        name = func.getName()
        entry = func.getEntryPoint()

        tx_id = session.program.startTransaction("Delete function")
        try:
            success = session.program.getFunctionManager().removeFunction(entry)
            session.program.endTransaction(tx_id, success)
            if not success:
                raise GhidraError("Failed to delete function", error_type="DeleteFailed")
        except GhidraError:
            raise
        except Exception as e:
            session.program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to delete function: {e}", error_type="DeleteFailed") from e

        return DeleteFunctionResult(
            address=format_address(entry.getOffset()),
            name=name,
            status="deleted",
        )
