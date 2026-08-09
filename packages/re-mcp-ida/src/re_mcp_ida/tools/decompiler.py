# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Hex-Rays decompiler interaction tools — rename/retype variables, microcode, comments."""

from __future__ import annotations

import ida_hexrays
import ida_idp
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ida.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    META_DECOMPILER,
    Address,
    IDAError,
    decompile_at,
    format_address,
    get_func_name,
    is_bad_addr,
    parse_type,
    resolve_address,
    resolve_function,
)
from re_mcp_ida.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class RenameDecompilerVarResult(BaseModel):
    """Result of renaming a decompiler variable."""

    function: str = Field(description="Function address (hex).")
    old_name: str = Field(description="Previous variable name.")
    new_name: str = Field(description="New variable name.")


class RetypeDecompilerVarResult(BaseModel):
    """Result of retyping a decompiler variable."""

    function: str = Field(description="Function address (hex).")
    variable: str = Field(description="Variable name.")
    old_type: str = Field(description="Previous variable type.")
    new_type: str = Field(description="New variable type.")


class MicrocodeBlock(BaseModel):
    """A microcode basic block."""

    block_index: int = Field(description="Block index.")
    start: str = Field(description="Block start address (hex).")
    end: str = Field(description="Block end address (hex).")
    instruction_count: int = Field(description="Number of micro-instructions.")
    instructions: list[str] = Field(description="Micro-instruction text.")


class GetMicrocodeResult(BaseModel):
    """Microcode for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    maturity: str = Field(description="Microcode maturity level.")
    block_count: int = Field(description="Number of basic blocks.")
    blocks: list[MicrocodeBlock] = Field(description="Microcode basic blocks.")


class SetDecompilerCommentResult(BaseModel):
    """Result of setting a decompiler comment."""

    address: str = Field(description="Comment address (hex).")
    function: str = Field(description="Function address (hex).")
    old_comment: str = Field(description="Previous comment.")
    comment: str = Field(description="New comment.")


class DecompilerCommentItem(BaseModel):
    """A decompiler comment."""

    address: str = Field(description="Comment address (hex).")
    comment: str = Field(description="Comment text.")


class GetDecompilerCommentsResult(BaseModel):
    """Decompiler comments for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    comments: list[DecompilerCommentItem] = Field(description="Comments.")


class DecompilerVariable(BaseModel):
    """A decompiler local variable."""

    name: str = Field(description="Variable name.")
    type: str = Field(description="Variable type.")
    is_arg: bool = Field(description="Whether this is an argument.")
    is_stk_var: bool = Field(description="Whether this is a stack variable.")
    is_reg_var: bool = Field(description="Whether this is a register variable.")
    register_name: str | None = Field(default=None, description="Register name (if reg var).")
    stack_offset: int | None = Field(default=None, description="Stack offset (if stack var).")
    flags: list[str] = Field(
        default_factory=list,
        description="Hex-Rays attributes (BYREF, OVERLAPPED, MAPDST, SPLIT, ...).",
    )


class ListDecompilerVarsResult(BaseModel):
    """Decompiler variables for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    variable_count: int = Field(description="Number of variables.")
    variables: list[DecompilerVariable] = Field(description="Variable list.")


class PseudocodeLine(BaseModel):
    """A pseudocode line and the address it came from."""

    line: int = Field(description="Line number (0-based, matches decompile_function output).")
    address: str = Field(description="Lowest address contributing to this line (hex).")


class PseudocodeLineMapResult(BaseModel):
    """Line-to-address mapping for a function's pseudocode."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    line_count: int = Field(description="Total number of pseudocode lines.")
    lines: list[PseudocodeLine] = Field(description="Lines that map to an address.")


class RefreshDecompilationResult(BaseModel):
    """Result of invalidating a cached decompilation."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    was_cached: bool = Field(description="Whether a cached decompilation was discarded.")


class MapDecompilerVarResult(BaseModel):
    """Result of mapping one decompiler variable onto another."""

    function: str = Field(description="Function address (hex).")
    source: str = Field(description="Source variable name.")
    target: str = Field(description="Target variable name.")


class ClearVarMapsResult(BaseModel):
    """Result of clearing a function's variable mappings."""

    function: str = Field(description="Function address (hex).")
    cleared: int = Field(description="Number of mappings removed.")


_MATURITY_MAP = {
    "MMAT_GENERATED": ida_hexrays.MMAT_GENERATED,
    "MMAT_PREOPTIMIZED": ida_hexrays.MMAT_PREOPTIMIZED,
    "MMAT_LOCOPT": ida_hexrays.MMAT_LOCOPT,
    "MMAT_CALLS": ida_hexrays.MMAT_CALLS,
    "MMAT_GLBOPT1": ida_hexrays.MMAT_GLBOPT1,
    "MMAT_GLBOPT2": ida_hexrays.MMAT_GLBOPT2,
    "MMAT_GLBOPT3": ida_hexrays.MMAT_GLBOPT3,
    "MMAT_LVARS": ida_hexrays.MMAT_LVARS,
}

# There are no CVAR_* constants in the Python bindings, only these predicates.
# Names match the keywords Hex-Rays prints in the pseudocode where one exists.
_LVAR_FLAG_PREDICATES: tuple[tuple[str, str], ...] = (
    ("BYREF", "is_used_byref"),
    ("OVERLAPPED", "is_overlapped_var"),
    ("MAPDST", "is_mapdst_var"),
    ("SPLIT", "is_split_var"),
    ("THISARG", "is_thisarg"),
    ("INASM", "in_asm"),
    ("FAKE", "is_fake_var"),
    ("AUTOMAP", "is_automapped"),
    ("DUMMY", "is_dummy_arg"),
    ("NOTARG", "is_notarg"),
    ("UNUSED", "is_decl_unused"),
)


def _lvar_flags(lvar) -> list[str]:
    # SWIG exposes some of these as methods and some as plain bool properties
    flags = []
    for name, pred in _LVAR_FLAG_PREDICATES:
        attr = getattr(lvar, pred)
        if attr() if callable(attr) else attr:
            flags.append(name)
    return flags


def _find_lvar(cfunc, name: str):
    """Look up an lvar by name, raising the usual NotFound with the valid choices."""
    for lvar in cfunc.lvars:
        if lvar.name == name:
            return lvar
    raise IDAError(
        f"Variable not found: {name!r}",
        error_type="NotFound",
        available_variables=[lvar.name for lvar in cfunc.lvars],
    )


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"decompiler", "modification"},
        meta=META_DECOMPILER,
    )
    @session.require_open
    def rename_decompiler_variable(
        function_address: Address,
        old_name: str,
        new_name: str,
    ) -> RenameDecompilerVarResult:
        """Rename ONE Hex-Rays local or parameter (pseudocode scope; not globals or regvars).

        Args:
            function_address: Address or name of the function.
            old_name: Current variable name in the pseudocode.
            new_name: New name to assign to the variable.
        """
        cfunc, func = decompile_at(function_address)

        available = [lvar.name for lvar in cfunc.lvars]
        if old_name not in available:
            raise IDAError(
                f"Variable not found: {old_name!r}",
                error_type="NotFound",
                available_variables=available,
            )

        # IDA 9.x: rename_lvar(func_ea, old_name, new_name) — all strings
        success = ida_hexrays.rename_lvar(cfunc.entry_ea, old_name, new_name)
        if not success:
            raise IDAError(
                f"Failed to rename variable {old_name!r} to {new_name!r}", error_type="RenameFailed"
            )
        return RenameDecompilerVarResult(
            function=format_address(func.start_ea),
            old_name=old_name,
            new_name=new_name,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"decompiler", "modification"},
        meta=META_DECOMPILER,
    )
    @session.require_open
    def retype_decompiler_variable(
        function_address: Address,
        variable_name: str,
        new_type: str,
    ) -> RetypeDecompilerVarResult:
        """Retype ONE Hex-Rays local or parameter; for the function prototype use set_function_type.

        Args:
            function_address: Address or name of the function.
            variable_name: Name of the variable to retype.
            new_type: C type string to apply (e.g. "int *", "struct foo *").
        """
        cfunc, func = decompile_at(function_address)

        tinfo = parse_type(new_type)

        # IDA 9.x: use modify_user_lvar_info() — cfuncptr_t has no set_lvar_type().
        for lvar in cfunc.lvars:
            if lvar.name == variable_name:
                old_type = str(lvar.type())
                info = ida_hexrays.lvar_saved_info_t()
                info.ll = lvar
                info.type = tinfo
                success = ida_hexrays.modify_user_lvar_info(
                    cfunc.entry_ea, ida_hexrays.MLI_TYPE, info
                )
                if not success:
                    raise IDAError(
                        f"Failed to set type on {variable_name!r}", error_type="RetypeFailed"
                    )
                return RetypeDecompilerVarResult(
                    function=format_address(func.start_ea),
                    variable=variable_name,
                    old_type=old_type,
                    new_type=str(tinfo),
                )

        available = [lvar.name for lvar in cfunc.lvars]
        raise IDAError(
            f"Variable not found: {variable_name!r}",
            error_type="NotFound",
            available_variables=available,
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"decompiler"},
        meta=META_DECOMPILER,
    )
    @session.require_open
    def get_microcode(
        function_address: Address,
        maturity: str = "MMAT_LVARS",
    ) -> GetMicrocodeResult:
        """Get Hex-Rays microcode for a function at a specified maturity level.

        Microcode is the intermediate representation used by the decompiler.
        Lower levels are closer to assembly, higher levels closer to C.
        Use MMAT_GENERATED for speed (closest to assembly), MMAT_LVARS for
        closest-to-C analysis. Complex functions may hit internal limits
        (50,000 insns/block) — try a lower maturity level if that happens.

        Args:
            function_address: Address or name of the function.
            maturity: Maturity level — one of MMAT_GENERATED, MMAT_PREOPTIMIZED,
                MMAT_LOCOPT, MMAT_CALLS, MMAT_GLBOPT1, MMAT_GLBOPT2,
                MMAT_GLBOPT3, MMAT_LVARS.
        """
        func = resolve_function(function_address)

        mat_val = _MATURITY_MAP.get(maturity)
        if mat_val is None:
            raise IDAError(
                f"Invalid maturity level: {maturity!r}",
                error_type="InvalidArgument",
                valid_levels=list(_MATURITY_MAP),
            )

        try:
            mbr = ida_hexrays.mba_ranges_t(func)
            mba = ida_hexrays.gen_microcode(
                mbr,
                None,  # hf
                None,  # retlist
                0,  # decomp_flags
                mat_val,
            )
        except Exception as e:
            raise IDAError(f"Microcode generation failed: {e}", error_type="MicrocodeFailed") from e

        if mba is None:
            raise IDAError("Microcode generation returned no result", error_type="MicrocodeFailed")

        _MAX_INSNS_PER_BLOCK = 50_000
        blocks = []
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            lines = []
            insn = blk.head
            safety = 0
            while insn is not None and safety < _MAX_INSNS_PER_BLOCK:
                lines.append(insn.dstr())
                insn = insn.next if insn.next != insn else None
                safety += 1
            blocks.append(
                MicrocodeBlock(
                    block_index=i,
                    start=format_address(blk.start),
                    end=format_address(blk.end),
                    instruction_count=len(lines),
                    instructions=lines,
                )
            )

        return GetMicrocodeResult(
            function=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            maturity=maturity,
            block_count=len(blocks),
            blocks=blocks,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"decompiler", "modification", "comments"},
        meta=META_DECOMPILER,
    )
    @session.require_open
    def set_decompiler_comment(
        address: Address,
        comment: str,
        function_address: Address = "",
    ) -> SetDecompilerCommentResult:
        """Attach a comment to a pseudocode line (Hex-Rays view only).

        Appears in decompilation output only, not in the disassembly view.
        To annotate the disassembly instead, use set_comment. Pass empty
        string to delete an existing comment.

        Args:
            address: Instruction address where the comment should appear.
            function_address: Address or name of the containing function (auto-detected if empty).
            comment: Comment text to set (empty string to delete).
        """
        ea = resolve_address(address)

        cfunc, func = decompile_at(function_address or address)
        func_ea = func.start_ea

        # Find the treeloc for the address
        tl = ida_hexrays.treeloc_t()
        tl.ea = ea
        tl.itp = ida_hexrays.ITP_SEMI

        old_comment = cfunc.get_user_cmt(tl, ida_hexrays.RETRIEVE_ALWAYS) or ""

        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()

        return SetDecompilerCommentResult(
            address=format_address(ea),
            function=format_address(func_ea),
            old_comment=old_comment,
            comment=comment,
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"decompiler"},
        meta=META_DECOMPILER,
    )
    @session.require_open
    def get_decompiler_comments(
        function_address: Address,
    ) -> GetDecompilerCommentsResult:
        """List Hex-Rays pseudocode comments for ONE function (pseudocode scope only).

        Returns only pseudocode-view comments (set via set_decompiler_comment), not
        disassembly comments. Use get_comment or get_function_comment for those.

        Args:
            function_address: Address or name of the function.
        """
        cfunc, func = decompile_at(function_address)

        comments = []
        cmts = cfunc.user_cmts
        if cmts is not None:
            it = ida_hexrays.user_cmts_begin(cmts)
            while it != ida_hexrays.user_cmts_end(cmts):
                tl = ida_hexrays.user_cmts_first(it)
                cmt = ida_hexrays.user_cmts_second(it)
                comments.append(
                    DecompilerCommentItem(
                        address=format_address(tl.ea),
                        comment=str(cmt),
                    )
                )
                it = ida_hexrays.user_cmts_next(it)

        return GetDecompilerCommentsResult(
            function=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            comments=comments,
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"decompiler"},
        meta=META_DECOMPILER,
    )
    @session.require_open
    def list_decompiler_variables(
        function_address: Address,
    ) -> ListDecompilerVarsResult:
        """List Hex-Rays locals/params for ONE function (for stack layout use get_stack_frame).

        Returns each variable's name, type, storage (stack/register), whether it is
        a parameter, and its Hex-Rays attributes (BYREF, OVERLAPPED, MAPDST, ...) so
        they need not be parsed out of the pseudocode text. Use this before
        rename_decompiler_variable or retype_decompiler_variable to get the exact
        current names.

        Args:
            function_address: Address or name of the function.
        """
        cfunc, func = decompile_at(function_address)

        variables = []
        for lvar in cfunc.lvars:
            var = DecompilerVariable(
                name=lvar.name,
                type=str(lvar.type()),
                is_arg=lvar.is_arg_var,
                is_stk_var=lvar.is_stk_var(),
                is_reg_var=lvar.is_reg_var(),
                register_name=ida_idp.get_reg_name(lvar.get_reg1(), lvar.width)
                if lvar.is_reg_var()
                else None,
                stack_offset=lvar.get_stkoff() if lvar.is_stk_var() else None,
                flags=_lvar_flags(lvar),
            )
            variables.append(var)

        return ListDecompilerVarsResult(
            function=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            variable_count=len(variables),
            variables=variables,
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"decompiler"},
        meta=META_DECOMPILER,
    )
    @session.require_open
    def get_pseudocode_line_map(
        function_address: Address,
    ) -> PseudocodeLineMapResult:
        """Map decompile_function's pseudocode line numbers to addresses.

        Line numbers are 0-based and line up with splitting decompile_function's
        pseudocode on newlines. Only lines carrying at least one addressable ctree
        item appear; the address reported is the lowest one on that line. Use it to
        hand a pseudocode line off to an address-taking tool.

        Args:
            function_address: Address or name of the function.
        """
        cfunc, func = decompile_at(function_address)

        # treeitems is only populated once the pseudocode has been printed
        sv = cfunc.get_pseudocode()

        lowest: dict[int, int] = {}
        for item in cfunc.treeitems:
            ea = item.ea
            if is_bad_addr(ea):
                continue
            coords = cfunc.find_item_coords(item)
            # returns (None, None) for items that never made it into the listing
            if not coords or coords[1] is None or coords[1] < 0:
                continue
            line = coords[1]
            if line not in lowest or ea < lowest[line]:
                lowest[line] = ea

        return PseudocodeLineMapResult(
            function=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            line_count=sv.size(),
            lines=[
                PseudocodeLine(line=line, address=format_address(ea))
                for line, ea in sorted(lowest.items())
            ],
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"decompiler"},
        meta=META_DECOMPILER,
    )
    @session.require_open
    def refresh_decompilation(
        function_address: Address,
    ) -> RefreshDecompilationResult:
        """Drop the cached decompilation of a function so the next decompile is fresh.

        Needed after changing something the pseudocode depends on but that Hex-Rays
        does not notice on its own — a callee's prototype, a struct layout, a stack
        delta, a forced call type. Without it decompile_function keeps returning the
        stale text.

        Args:
            function_address: Address or name of the function.
        """
        func = resolve_function(function_address)
        was_cached = ida_hexrays.mark_cfunc_dirty(func.start_ea, False)
        return RefreshDecompilationResult(
            function=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            was_cached=was_cached,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"decompiler", "modification"},
        meta=META_DECOMPILER,
    )
    @session.require_open
    def map_decompiler_variable(
        function_address: Address,
        source_name: str,
        target_name: str,
    ) -> MapDecompilerVarResult:
        """Merge one Hex-Rays local into another, so both locations read as one variable.

        The documented fix for a variable the decompiler split into pieces (a 64-bit
        value living as two 32-bit halves, say): map the fragment onto the variable
        you want to keep. The target then carries the MAPDST attribute. If Hex-Rays
        rejects the pairing the next decompilation warns with WARN_BAD_MAPDST.

        The source loses its own identity once mapped, so there is no way to name it
        again afterwards — undo with clear_decompiler_variable_maps.

        Args:
            function_address: Address or name of the function.
            source_name: Variable to merge away.
            target_name: Variable to merge it into.
        """
        cfunc, func = decompile_at(function_address)

        source = _find_lvar(cfunc, source_name)
        target = _find_lvar(cfunc, target_name)
        if source_name == target_name:
            raise IDAError("Cannot map a variable onto itself", error_type="InvalidArgument")

        lvinf = ida_hexrays.lvar_uservec_t()
        ida_hexrays.restore_user_lvar_settings(lvinf, func.start_ea)
        ida_hexrays.lvar_mapping_insert(lvinf.lmaps, source, target)
        ida_hexrays.save_user_lvar_settings(func.start_ea, lvinf)
        ida_hexrays.mark_cfunc_dirty(func.start_ea, False)

        return MapDecompilerVarResult(
            function=format_address(func.start_ea),
            source=source_name,
            target=target_name,
        )

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"decompiler", "modification"},
        meta=META_DECOMPILER,
    )
    @session.require_open
    def clear_decompiler_variable_maps(
        function_address: Address,
    ) -> ClearVarMapsResult:
        """Drop every map_decompiler_variable merge in a function, splitting the vars back apart.

        This is the undo for map_decompiler_variable. It is all-or-nothing: a merged
        variable stops existing under its old name, so individual merges cannot be
        addressed afterwards.

        Args:
            function_address: Address or name of the function.
        """
        func = resolve_function(function_address)

        lvinf = ida_hexrays.lvar_uservec_t()
        ida_hexrays.restore_user_lvar_settings(lvinf, func.start_ea)
        cleared = ida_hexrays.lvar_mapping_size(lvinf.lmaps)
        if cleared:
            ida_hexrays.lvar_mapping_clear(lvinf.lmaps)
            ida_hexrays.save_user_lvar_settings(func.start_ea, lvinf)
            ida_hexrays.mark_cfunc_dirty(func.start_ea, False)

        return ClearVarMapsResult(function=format_address(func.start_ea), cleared=cleared)
