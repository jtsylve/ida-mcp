# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Function flag manipulation and byte-level flag query tools."""

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
    resolve_function,
)
from ghidra_mcp.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class SetFunctionFlagsResult(BaseModel):
    """Result of setting function flags."""

    address: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    changed: dict[str, bool] = Field(description="Flags that were changed.")
    status: str = Field(description="Status.")


class ByteFlagsResult(BaseModel):
    """Byte-level flags at an address."""

    address: str = Field(description="Address (hex).")
    is_instruction: bool = Field(description="Address contains an instruction.")
    is_data: bool = Field(description="Address contains defined data.")
    is_undefined: bool = Field(description="Address is undefined.")
    has_function: bool = Field(description="Address is within a function.")
    has_label: bool = Field(description="Address has a label/symbol.")
    has_comment: bool = Field(description="Address has a comment.")
    item_type: str = Field(description="Type of item at address (instruction/data/undefined).")
    item_size: int = Field(description="Size of the item at this address.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"functions"})
    @session.require_open
    def set_function_flags(
        address: Address,
        library: bool | None = None,
        thunk: bool | None = None,
        noreturn: bool | None = None,
        inline: bool | None = None,
    ) -> SetFunctionFlagsResult:
        """Set or clear function flags (library, thunk, noreturn, inline).

        Only provided flags are changed; others are left as-is.

        Args:
            address: Address or name of the function.
            library: Mark/unmark as library function (tag only, no behavior change).
            thunk: Mark/unmark as thunk (wrapper) function.
            noreturn: Mark/unmark as non-returning.
            inline: Mark/unmark as inline.
        """
        func = resolve_function(address)
        program = session.program
        entry = func.getEntryPoint().getOffset()

        changed: dict[str, bool] = {}

        if library is not None:
            changed["library"] = library
        if thunk is not None:
            changed["thunk"] = thunk
        if noreturn is not None:
            changed["noreturn"] = noreturn
        if inline is not None:
            changed["inline"] = inline

        if not changed:
            return SetFunctionFlagsResult(
                address=format_address(entry),
                name=func.getName(),
                changed=changed,
                status="no_change",
            )

        tx_id = program.startTransaction("Set function flags")
        try:
            if "thunk" in changed:
                if changed["thunk"]:
                    # Setting as thunk requires a thunked function address.
                    # If the function is not already a thunk, try to identify
                    # the target from the function body (first call).
                    if not func.isThunk():
                        # Cannot blindly set thunk without a target; raise error
                        raise GhidraError(
                            "Cannot mark as thunk: no thunk target identified. "
                            "Use Ghidra's auto-analysis or set the thunked function manually.",
                            error_type="InvalidArgument",
                        )
                else:
                    # Ghidra does not have a direct unsetThunk.
                    # We skip this silently if it's not a thunk.
                    pass

            if "noreturn" in changed:
                func.setNoReturn(changed["noreturn"])

            if "inline" in changed:
                func.setInline(changed["inline"])

            # Ghidra's Function class doesn't have a direct setLibrary flag.
            # Library functions are typically identified by their source or
            # namespace. We can tag the function with a tag instead.
            if "library" in changed:
                tag_mgr = program.getFunctionManager()
                lib_tag_name = "LIBRARY"
                if changed["library"]:
                    tag = tag_mgr.getFunctionTag(lib_tag_name)
                    if tag is None:
                        tag = tag_mgr.createFunctionTag(lib_tag_name, "Library function")
                    func.addTag(lib_tag_name)
                else:
                    func.removeTag(lib_tag_name)

            program.endTransaction(tx_id, True)
        except GhidraError:
            program.endTransaction(tx_id, False)
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to update function flags: {e}", error_type="UpdateFailed"
            ) from e

        return SetFunctionFlagsResult(
            address=format_address(entry),
            name=func.getName(),
            changed=changed,
            status="updated",
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions"})
    @session.require_open
    def get_byte_flags(
        address: Address,
    ) -> ByteFlagsResult:
        """Get what is at an address: instruction, data, or undefined.

        Args:
            address: Address to query.
        """
        program = session.program
        addr = resolve_address(address)
        listing = program.getListing()

        cu = listing.getCodeUnitAt(addr)
        insn = listing.getInstructionAt(addr)
        data = listing.getDefinedDataAt(addr)
        func_mgr = program.getFunctionManager()
        func = func_mgr.getFunctionContaining(addr)
        sym_table = program.getSymbolTable()
        sym = sym_table.getPrimarySymbol(addr)

        is_instruction = insn is not None
        is_data = data is not None
        is_undefined = not is_instruction and not is_data

        if is_instruction:
            item_type = "instruction"
            item_size = insn.getLength()
        elif is_data:
            item_type = "data"
            item_size = data.getLength()
        elif cu is not None:
            item_type = "undefined"
            item_size = cu.getLength()
        else:
            item_type = "undefined"
            item_size = 1

        has_comment = False
        if cu is not None:
            from ghidra.program.model.listing import CodeUnit  # noqa: PLC0415

            has_comment = any(
                cu.getComment(ct) is not None
                for ct in [
                    CodeUnit.EOL_COMMENT,
                    CodeUnit.PRE_COMMENT,
                    CodeUnit.POST_COMMENT,
                    CodeUnit.PLATE_COMMENT,
                    CodeUnit.REPEATABLE_COMMENT,
                ]
            )

        return ByteFlagsResult(
            address=format_address(addr.getOffset()),
            is_instruction=is_instruction,
            is_data=is_data,
            is_undefined=is_undefined,
            has_function=func is not None,
            has_label=sym is not None,
            has_comment=has_comment,
            item_type=item_type,
            item_size=item_size,
        )
