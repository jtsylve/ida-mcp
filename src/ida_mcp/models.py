# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Pydantic models for structured tool output schemas.

Tools use these as return type annotations (e.g. ``-> FunctionDetail:``).
FastMCP auto-generates the ``output_schema`` from the annotation and
serializes the returned model instance into ``structuredContent``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Pagination envelope — shared by all paginated endpoints
# ---------------------------------------------------------------------------


class PaginatedResult(BaseModel):
    """Paginated result set."""

    items: list[dict] = Field(description="Page of result items.")
    total: int = Field(
        description="Total number of matching items (may be approximate for large sets)."
    )
    offset: int = Field(description="Starting offset of this page.")
    limit: int = Field(description="Maximum items per page.")
    has_more: bool = Field(description="Whether more items exist beyond this page.")


# ---------------------------------------------------------------------------
# Database schemas
# ---------------------------------------------------------------------------


class OpenDatabaseResult(BaseModel):
    """Result of opening a database."""

    status: str = Field(description="Status message.")
    file_path: str = Field(description="Path to the opened database file.")
    pid: int = Field(description="Worker process ID.")
    processor: str = Field(description="Processor architecture name.")
    bitness: int = Field(description="Address size in bits (16, 32, or 64).")
    file_type: str = Field(description="Input file type description.")
    function_count: int = Field(description="Number of functions.")
    segment_count: int = Field(description="Number of segments.")


class CloseDatabaseResult(BaseModel):
    """Result of closing a database."""

    status: str = Field(description="Status message.")
    path: str | None = Field(default=None, description="Path of closed database.")
    saved: bool | None = Field(default=None, description="Whether changes were saved.")


class DatabaseInfoResult(BaseModel):
    """Database metadata."""

    file_path: str = Field(description="Path to the database file.")
    processor: str = Field(description="Processor architecture name.")
    bitness: int = Field(description="Address size in bits.")
    file_type: str = Field(description="Input file type description.")
    min_address: str = Field(description="Minimum address (hex).")
    max_address: str = Field(description="Maximum address (hex).")
    entry_point: str = Field(description="Entry point address (hex).")
    function_count: int = Field(description="Number of functions.")
    segment_count: int = Field(description="Number of segments.")
    entry_point_count: int = Field(description="Number of entry points.")
    trusted: bool = Field(description="Whether the database is trusted.")


class SaveDatabaseResult(BaseModel):
    """Result of saving a database."""

    status: str = Field(description="Status message.")
    path: str = Field(description="Path to the saved database file.")


class FlushBuffersResult(BaseModel):
    """Result of flushing buffers."""

    status: str = Field(description="Status message.")
    result: Any = Field(description="Flush result code.")


class DatabasePathsResult(BaseModel):
    """File paths associated with the database."""

    input_file: str = Field(description="Original input file path.")
    idb_path: str = Field(description="IDB database path.")
    id0_path: str = Field(description="ID0 component path.")


class FileRegionEaResult(BaseModel):
    """File offset to address mapping."""

    file_offset: int = Field(description="Byte offset in the input file.")
    address: str = Field(description="Mapped linear address (hex).")


class FileRegionOffsetResult(BaseModel):
    """Address to file offset mapping."""

    address: str = Field(description="Database address (hex).")
    file_offset: int = Field(description="Byte offset in the input file.")


class DatabaseFlagsResult(BaseModel):
    """Database flags state."""

    kill: bool = Field(description="Delete unpacked DB on close.")
    compress: bool = Field(description="Compress the database.")
    backup: bool = Field(description="Create backup on save.")
    temporary: bool = Field(description="Database is temporary.")


class SetDatabaseFlagResult(BaseModel):
    """Result of setting a database flag."""

    flag: str = Field(description="Flag name.")
    value: bool = Field(description="New flag value.")


class ElfDebugDirResult(BaseModel):
    """ELF debug file directory."""

    directory: str = Field(description="Debug file directory path.")


class ReloadFileResult(BaseModel):
    """Result of reloading a file."""

    status: str = Field(description="Status message.")
    path: str = Field(description="Path of reloaded file.")


# ---------------------------------------------------------------------------
# Function-related schemas
# ---------------------------------------------------------------------------


class FunctionChunk(BaseModel):
    """A non-contiguous chunk of a function."""

    start: str = Field(description="Chunk start address (hex).")
    end: str = Field(description="Chunk end address (hex, exclusive).")
    size: int = Field(description="Chunk size in bytes.")


class FunctionSummary(BaseModel):
    """Brief function info returned by list_functions."""

    name: str = Field(description="Function name.")
    start: str = Field(description="Start address (hex).")
    end: str = Field(description="End address (hex, exclusive).")
    size: int = Field(description="Function size in bytes.")


class FunctionListResult(PaginatedResult):
    """Paginated list of functions."""

    items: list[FunctionSummary] = Field(description="Page of function summaries.")  # type: ignore[assignment]


class FunctionDetail(BaseModel):
    """Detailed function information."""

    name: str = Field(description="Function name.")
    start: str = Field(description="Start address (hex).")
    end: str = Field(description="End address (hex, exclusive).")
    size: int = Field(description="Function size in bytes.")
    flags: int = Field(description="IDA function flags bitmask.")
    does_return: bool = Field(description="Whether the function returns.")
    is_library: bool = Field(description="Whether this is a library function.")
    is_thunk: bool = Field(description="Whether this is a thunk function.")
    comment: str = Field(description="Regular comment.")
    repeatable_comment: str = Field(description="Repeatable comment.")
    chunks: list[FunctionChunk] | None = Field(
        default=None,
        description="Non-contiguous chunks if function has multiple ranges.",
    )


class DecompilationResult(BaseModel):
    """Decompiled function pseudocode."""

    address: str = Field(description="Function start address (hex).")
    name: str = Field(description="Function name.")
    pseudocode: str = Field(description="Decompiled C pseudocode.")


class DisassemblyInstruction(BaseModel):
    """Single disassembled instruction."""

    address: str = Field(description="Instruction address (hex).")
    disasm: str = Field(description="Disassembly text.")


class DisassemblyResult(BaseModel):
    """Disassembled function listing."""

    address: str = Field(description="Function start address (hex).")
    name: str = Field(description="Function name.")
    instruction_count: int = Field(description="Number of instructions.")
    instructions: list[DisassemblyInstruction] = Field(description="Instruction listing.")


class RenameResult(BaseModel):
    """Result of a rename operation."""

    address: str = Field(description="Address of the renamed item (hex).")
    old_name: str = Field(description="Previous name.")
    new_name: str = Field(description="New name.")


class CreateFunctionResult(BaseModel):
    """Result of creating a function."""

    address: str = Field(description="Function start address (hex).")
    name: str = Field(description="Function name.")
    end: str = Field(description="Function end address (hex, exclusive).")
    size: int = Field(description="Function size in bytes.")


class DeleteFunctionResult(BaseModel):
    """Result of deleting a function."""

    address: str = Field(description="Deleted function start address (hex).")
    name: str = Field(description="Deleted function name.")
    old_end: str = Field(description="Previous end address of the deleted function (hex).")


class SetFunctionBoundsResult(BaseModel):
    """Result of setting function bounds."""

    address: str = Field(description="Function start address (hex).")
    name: str = Field(description="Function name.")
    old_end: str = Field(description="Previous end address (hex).")
    end: str = Field(description="New end address (hex).")


# ---------------------------------------------------------------------------
# Cross-reference schemas
# ---------------------------------------------------------------------------


class XrefTo(BaseModel):
    """A cross-reference TO an address."""

    model_config = ConfigDict(populate_by_name=True)

    from_: str = Field(alias="from", description="Source address of the reference (hex).")
    from_name: str = Field(description="Function name containing the source address.")
    type: str = Field(description="Cross-reference type (e.g. 'Code_Near_Call', 'Data_Read').")
    is_code: bool = Field(description="Whether this is a code (vs data) reference.")


class XrefToResult(PaginatedResult):
    """Paginated cross-references TO an address."""

    address: str = Field(description="Target address queried (hex).")
    items: list[XrefTo] = Field(description="Page of cross-references.")  # type: ignore[assignment]


class XrefFrom(BaseModel):
    """A cross-reference FROM an address."""

    to: str = Field(description="Target address of the reference (hex).")
    to_name: str = Field(description="Function name containing the target address.")
    type: str = Field(description="Cross-reference type.")
    is_code: bool = Field(description="Whether this is a code (vs data) reference.")


class XrefFromResult(PaginatedResult):
    """Paginated cross-references FROM an address."""

    address: str = Field(description="Source address queried (hex).")
    items: list[XrefFrom] = Field(description="Page of cross-references.")  # type: ignore[assignment]


class CallGraphEntry(BaseModel):
    """A node in a call graph."""

    address: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")


class CallGraphResult(BaseModel):
    """Call graph showing callers and callees of a function.

    ``callers`` and ``callees`` are recursive trees: each entry contains
    ``address``, ``name``, and (when depth > 1) a nested ``callers`` or
    ``callees`` list.  Typed as ``list[dict]`` because Pydantic's JSON Schema
    output doesn't support recursive ``$ref`` cycles cleanly.
    """

    function: CallGraphEntry = Field(description="The queried function.")
    callers: list[dict] = Field(
        description="Functions that call this function (recursive with depth)."
    )
    callees: list[dict] = Field(
        description="Functions called by this function (recursive with depth)."
    )


class XrefManipResult(BaseModel):
    """Result of adding or deleting a cross-reference."""

    model_config = ConfigDict(populate_by_name=True)

    from_: str = Field(alias="from", description="Source address (hex).")
    to: str = Field(description="Target address (hex).")
    type: str | None = Field(default=None, description="Cross-reference type (for add).")


class DeleteXrefResult(BaseModel):
    """Result of deleting a cross-reference."""

    model_config = ConfigDict(populate_by_name=True)

    from_: str = Field(alias="from", description="Source address (hex).")
    to: str = Field(description="Target address (hex).")


# ---------------------------------------------------------------------------
# Search schemas
# ---------------------------------------------------------------------------


class StringItem(BaseModel):
    """A string found in the binary."""

    address: str = Field(description="String address (hex).")
    value: str = Field(description="String value.")
    length: int = Field(description="String length.")
    type: int = Field(description="String type ID.")


class StringListResult(PaginatedResult):
    """Paginated list of strings."""

    items: list[StringItem] = Field(description="Page of strings.")  # type: ignore[assignment]


class ByteSearchMatch(BaseModel):
    """A byte pattern match."""

    address: str = Field(description="Match address (hex).")
    bytes: str = Field(description="Matched bytes (hex).")


class SearchBytesResult(BaseModel):
    """Result of a byte pattern search."""

    pattern: str = Field(description="Search pattern.")
    match_count: int = Field(description="Number of matches found.")
    matches: list[ByteSearchMatch] = Field(description="List of matches.")


class TextSearchMatch(BaseModel):
    """A text search match."""

    address: str = Field(description="Match address (hex).")
    disasm: str = Field(description="Disassembly at the match.")


class SearchTextResult(BaseModel):
    """Result of a text search."""

    text: str = Field(description="Search text.")
    match_count: int = Field(description="Number of matches found.")
    matches: list[TextSearchMatch] = Field(description="List of matches.")


class FindImmediateResult(BaseModel):
    """Result of an immediate value search."""

    value: str = Field(description="Search value (hex).")
    match_count: int = Field(description="Number of matches found.")
    matches: list[TextSearchMatch] = Field(description="List of matches.")


class FunctionSearchResult(PaginatedResult):
    """Paginated function search results."""

    pattern: str = Field(description="Search pattern.")
    items: list[FunctionSummary] = Field(description="Page of matching functions.")  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Data / segments schemas
# ---------------------------------------------------------------------------


class ReadBytesResult(BaseModel):
    """Raw bytes read from the database."""

    address: str = Field(description="Start address (hex).")
    size: int = Field(description="Number of bytes read.")
    hex: str = Field(description="Hex string of bytes.")
    dump: str = Field(description="Hex dump with ASCII.")


class SegmentSummary(BaseModel):
    """Brief segment information."""

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(description="Segment name.")
    start: str = Field(description="Start address (hex).")
    end: str = Field(description="End address (hex, exclusive).")
    size: int = Field(description="Segment size in bytes.")
    class_: str | None = Field(alias="class", description="Segment class.")
    permissions: str = Field(description="Permissions string (e.g. 'RWX').")
    bitness: int = Field(description="Segment bitness (16, 32, or 64).")


class SegmentListResult(PaginatedResult):
    """Paginated list of segments."""

    items: list[SegmentSummary] = Field(description="Page of segments.")  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Makedata schemas
# ---------------------------------------------------------------------------


class MakeDataResult(BaseModel):
    """Result of a make-data operation (byte/word/dword/qword/float/double)."""

    address: str = Field(description="Target address (hex).")
    old_item_type: str = Field(description="Previous item type at address.")
    old_item_size: int = Field(description="Previous item size in bytes.")
    size: int = Field(description="New data item size in bytes.")


class MakeStringResult(BaseModel):
    """Result of creating a string."""

    address: str = Field(description="String address (hex).")
    old_item_type: str = Field(description="Previous item type at address.")
    old_item_size: int = Field(description="Previous item size in bytes.")
    length: int = Field(description="String length.")
    string_type: str = Field(description="String encoding type.")


class MakeArrayResult(BaseModel):
    """Result of creating an array."""

    address: str = Field(description="Array address (hex).")
    old_item_type: str = Field(description="Previous item type at address.")
    old_item_size: int = Field(description="Previous item size in bytes.")
    element_size: int = Field(description="Size of each element in bytes.")
    count: int = Field(description="Number of elements.")
    total_size: int = Field(description="Total array size in bytes.")


class MakeCodeResult(BaseModel):
    """Result of converting to code."""

    address: str = Field(description="Target address (hex).")
    old_item_type: str = Field(description="Previous item type at address.")
    old_item_size: int = Field(description="Previous item size in bytes.")
    size: int = Field(description="Instruction size in bytes.")


class UndefineResult(BaseModel):
    """Result of undefining an item."""

    address: str = Field(description="Target address (hex).")
    old_item_type: str = Field(description="Previous item type at address.")
    old_item_size: int = Field(description="Previous item size in bytes.")
    size: int = Field(description="Number of bytes undefined.")


# ---------------------------------------------------------------------------
# Comment schemas
# ---------------------------------------------------------------------------


class GetCommentResult(BaseModel):
    """Comments at an address."""

    address: str = Field(description="Address (hex).")
    comment: str = Field(description="Regular comment.")
    repeatable_comment: str = Field(description="Repeatable comment.")


class SetCommentResult(BaseModel):
    """Result of setting a comment."""

    address: str = Field(description="Address (hex).")
    old_comment: str = Field(description="Previous comment.")
    comment: str = Field(description="New comment.")
    repeatable: bool = Field(description="Whether the comment is repeatable.")


class AppendCommentResult(BaseModel):
    """Result of appending to a comment."""

    address: str = Field(description="Address (hex).")
    old_comment: str = Field(description="Previous comment.")
    comment: str = Field(description="New combined comment.")
    repeatable: bool = Field(description="Whether the comment is repeatable.")
    appended: bool = Field(description="Whether text was appended (vs set fresh).")


class GetFunctionCommentResult(BaseModel):
    """Function comments."""

    address: str = Field(description="Function address (hex).")
    comment: str = Field(description="Regular function comment.")
    repeatable_comment: str = Field(description="Repeatable function comment.")


class SetFunctionCommentResult(BaseModel):
    """Result of setting a function comment."""

    address: str = Field(description="Function address (hex).")
    old_comment: str = Field(description="Previous comment.")
    comment: str = Field(description="New comment.")
    repeatable: bool = Field(description="Whether the comment is repeatable.")


# ---------------------------------------------------------------------------
# Names schemas
# ---------------------------------------------------------------------------


class NameItem(BaseModel):
    """A named address."""

    address: str = Field(description="Address (hex).")
    name: str = Field(description="Name at address.")


class NameListResult(PaginatedResult):
    """Paginated list of names."""

    items: list[NameItem] = Field(description="Page of names.")  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Demangle schemas
# ---------------------------------------------------------------------------


class DemangleResult(BaseModel):
    """Result of demangling a name."""

    name: str = Field(description="Original mangled name.")
    demangled: str | None = Field(description="Demangled name, or null if not mangled.")
    is_mangled: bool = Field(description="Whether the name was mangled.")


class DemangleAtAddressResult(BaseModel):
    """Result of demangling the name at an address."""

    address: str = Field(description="Address (hex).")
    name: str | None = Field(description="Name at the address.")
    demangled: str | None = Field(description="Demangled name, or null if not mangled.")
    is_mangled: bool = Field(description="Whether the name was mangled.")


class DemangledNameItem(BaseModel):
    """A demangled name entry."""

    address: str = Field(description="Address (hex).")
    mangled: str = Field(description="Mangled name.")
    demangled: str = Field(description="Demangled name.")


class DemangledNameListResult(PaginatedResult):
    """Paginated list of demangled names."""

    items: list[DemangledNameItem] = Field(description="Page of demangled names.")  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Type schemas
# ---------------------------------------------------------------------------


class GetTypeInfoResult(BaseModel):
    """Type information at an address."""

    address: str = Field(description="Address (hex).")
    name: str = Field(description="Name at address.")
    type: str = Field(description="Type string.")


class SetTypeResult(BaseModel):
    """Result of setting a type at an address."""

    address: str = Field(description="Address (hex).")
    old_type: str = Field(description="Previous type.")
    type: str = Field(description="New type.")


# ---------------------------------------------------------------------------
# Patching schemas
# ---------------------------------------------------------------------------


class PatchBytesResult(BaseModel):
    """Result of patching bytes."""

    address: str = Field(description="Patch address (hex).")
    size: int = Field(description="Number of bytes patched.")
    old_bytes: str = Field(description="Previous bytes (hex).")
    new_bytes: str = Field(description="New bytes (hex).")


# ---------------------------------------------------------------------------
# Utility schemas
# ---------------------------------------------------------------------------


class ConvertNumberResult(BaseModel):
    """Number in multiple bases."""

    decimal: str = Field(description="Decimal representation.")
    hex: str = Field(description="Hexadecimal representation.")
    octal: str = Field(description="Octal representation.")
    binary: str = Field(description="Binary representation.")
    signed_32: int | None = Field(description="Signed 32-bit interpretation.")
    signed_64: int | None = Field(description="Signed 64-bit interpretation.")


class EvaluateExpressionResult(BaseModel):
    """Result of evaluating an IDC expression."""

    expression: str = Field(description="Evaluated expression.")
    result: int | str = Field(description="Expression result.")
    hex: str | None = Field(default=None, description="Hex representation (for int results).")


class RunScriptResult(BaseModel):
    """Result of executing an IDAPython script."""

    stdout: str = Field(description="Captured standard output.")
    stderr: str = Field(description="Captured standard error.")


# ---------------------------------------------------------------------------
# Operand schemas
# ---------------------------------------------------------------------------


class OperandDetail(BaseModel):
    """Decoded operand information."""

    index: int = Field(description="Operand index.")
    type: str = Field(description="Operand type name.")
    type_id: int = Field(description="Operand type ID.")
    register_name: str | None = Field(default=None, description="Register name.")
    value: str | None = Field(default=None, description="Immediate value (hex).")
    address: str | None = Field(default=None, description="Address reference (hex).")
    displacement: int | None = Field(default=None, description="Displacement value.")


class DecodeInstructionResult(BaseModel):
    """Decoded instruction with operand details."""

    address: str = Field(description="Instruction address (hex).")
    disasm: str = Field(description="Disassembly text.")
    mnemonic: str = Field(description="Instruction mnemonic.")
    size: int = Field(description="Instruction size in bytes.")
    operand_count: int = Field(description="Number of operands.")
    operands: list[OperandDetail] = Field(description="Operand details.")


class DecodedInstructionBrief(BaseModel):
    """Brief decoded instruction info."""

    address: str = Field(description="Instruction address (hex).")
    disasm: str = Field(description="Disassembly text.")
    mnemonic: str = Field(description="Instruction mnemonic.")
    size: int = Field(description="Instruction size in bytes.")


class DecodeInstructionsResult(BaseModel):
    """Multiple decoded instructions."""

    start: str = Field(description="Start address (hex).")
    instruction_count: int = Field(description="Number of instructions decoded.")
    instructions: list[DecodedInstructionBrief] = Field(description="Decoded instructions.")


class GetOperandValueResult(BaseModel):
    """Operand value at an address."""

    address: str = Field(description="Instruction address (hex).")
    operand_index: int = Field(description="Operand index.")
    type: str = Field(description="Operand type.")
    value: str | None = Field(description="Operand value (hex) or null.")


class SetOperandReprResult(BaseModel):
    """Result of changing operand representation."""

    address: str = Field(description="Instruction address (hex).")
    operand: int = Field(description="Operand index.")
    old_format: str = Field(description="Previous format.")
    format: str = Field(description="New format.")


class SetOperandOffsetResult(BaseModel):
    """Result of setting operand as offset."""

    address: str = Field(description="Instruction address (hex).")
    operand: int = Field(description="Operand index.")
    old_format: str = Field(description="Previous format.")
    format: str = Field(description="New format.")
    base: str = Field(description="Offset base address (hex).")


class SetOperandEnumResult(BaseModel):
    """Result of setting operand as enum."""

    address: str = Field(description="Instruction address (hex).")
    operand: int = Field(description="Operand index.")
    old_format: str = Field(description="Previous format.")
    enum: str = Field(description="Enum name.")


class SetOperandStructOffsetResult(BaseModel):
    """Result of setting operand as struct offset."""

    address: str = Field(description="Instruction address (hex).")
    operand: int = Field(description="Operand index.")
    old_format: str = Field(description="Previous format.")
    struct: str = Field(description="Struct name.")


# ---------------------------------------------------------------------------
# Stack frame / variable schemas
# ---------------------------------------------------------------------------


class FrameMember(BaseModel):
    """Stack frame member."""

    offset: int = Field(description="Frame offset.")
    name: str = Field(description="Member name.")
    size: int = Field(description="Member size in bytes.")


class FrameDetail(BaseModel):
    """Stack frame details."""

    frame_size: int = Field(description="Total frame size.")
    local_size: int = Field(description="Local variable area size.")
    saved_regs_size: int = Field(description="Saved registers area size.")
    args_size: int = Field(description="Arguments area size.")
    member_count: int = Field(description="Number of frame members.")
    members: list[FrameMember] = Field(description="Frame members.")


class GetStackFrameResult(BaseModel):
    """Stack frame for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    frame: FrameDetail | None = Field(description="Frame details, or null if no frame.")


class FunctionVariable(BaseModel):
    """A decompiler variable."""

    name: str = Field(description="Variable name.")
    type: str = Field(description="Variable type.")
    is_arg: bool = Field(description="Whether this is a function argument.")
    is_result: bool = Field(description="Whether this is the return value.")
    width: int = Field(description="Variable width in bytes.")


class GetFunctionVarsResult(BaseModel):
    """Function variables from the decompiler."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    variable_count: int = Field(description="Number of variables.")
    variables: list[FunctionVariable] = Field(description="Variable list.")


# ---------------------------------------------------------------------------
# Type info (local types) schemas
# ---------------------------------------------------------------------------


class LocalTypeSummary(BaseModel):
    """Brief local type info."""

    ordinal: int = Field(description="Type ordinal.")
    name: str = Field(description="Type name.")
    type: str = Field(description="Type string.")
    size: int = Field(description="Type size in bytes.")
    is_struct: bool = Field(description="Whether type is a struct.")
    is_union: bool = Field(description="Whether type is a union.")
    is_enum: bool = Field(description="Whether type is an enum.")
    is_typedef: bool = Field(description="Whether type is a typedef.")


class LocalTypeListResult(PaginatedResult):
    """Paginated list of local types."""

    items: list[LocalTypeSummary] = Field(description="Page of local types.")  # type: ignore[assignment]


class TypeMember(BaseModel):
    """A member of a struct/union type."""

    name: str = Field(description="Member name.")
    type: str = Field(description="Member type.")
    offset_bits: int = Field(description="Member offset in bits.")
    size_bits: int = Field(description="Member size in bits.")


class GetLocalTypeResult(BaseModel):
    """Detailed local type information."""

    name: str = Field(description="Type name.")
    ordinal: int = Field(description="Type ordinal.")
    declaration: str = Field(description="Full type declaration.")
    size: int = Field(description="Type size in bytes.")
    is_struct: bool = Field(description="Whether type is a struct.")
    is_union: bool = Field(description="Whether type is a union.")
    is_enum: bool = Field(description="Whether type is an enum.")
    members: list[TypeMember] | None = Field(
        default=None, description="Members for struct/union/enum types."
    )


class ParsedTypeResult(BaseModel):
    """Result of parsing a type declaration."""

    name: str | None = Field(default=None, description="Type name.")
    ordinal: int | None = Field(default=None, description="Type ordinal.")
    declaration: str | None = Field(default=None, description="Parsed declaration.")
    size: int | None = Field(default=None, description="Type size in bytes.")
    saved: bool = Field(description="Whether the type was saved to local types.")
    message: str | None = Field(default=None, description="Additional info message.")
    types: list[dict] | None = Field(
        default=None, description="Multiple parsed types (for multi-type declarations)."
    )


class DeleteLocalTypeResult(BaseModel):
    """Result of deleting a local type."""

    name: str = Field(description="Deleted type name.")
    ordinal: int = Field(description="Deleted type ordinal.")
    old_declaration: str = Field(description="Previous type declaration.")


class ApplyTypeResult(BaseModel):
    """Result of applying a type at an address."""

    address: str = Field(description="Target address (hex).")
    old_type: str = Field(description="Previous type.")
    type_name: str = Field(description="Applied type name.")


# ---------------------------------------------------------------------------
# Signature schemas
# ---------------------------------------------------------------------------


class FlirtSignatureInfo(BaseModel):
    """FLIRT signature information."""

    index: int = Field(description="Signature index.")
    name: str = Field(description="Signature name.")
    optional_libs: str = Field(description="Optional library modules.")


class ApplyFlirtResult(BaseModel):
    """Result of applying a FLIRT signature."""

    signature: str = Field(description="Signature name.")
    status: str = Field(description="Status message.")


class FlirtSignatureListResult(BaseModel):
    """List of available FLIRT signatures."""

    count: int = Field(description="Number of signatures.")
    signatures: list[FlirtSignatureInfo] = Field(description="Available signatures.")


class TypeLibraryInfo(BaseModel):
    """Type library information."""

    index: int = Field(description="Library index.")
    name: str = Field(description="Library name.")
    description: str = Field(description="Library description.")


class LoadTypeLibraryResult(BaseModel):
    """Result of loading a type library."""

    library: str = Field(description="Library name.")
    status: str = Field(description="Status message.")


class TypeLibraryListResult(BaseModel):
    """List of available type libraries."""

    count: int = Field(description="Number of libraries.")
    libraries: list[TypeLibraryInfo] = Field(description="Available libraries.")


class LoadIdsModuleResult(BaseModel):
    """Result of loading an IDS module."""

    filename: str = Field(description="Module filename.")
    status: str = Field(description="Status message.")


# ---------------------------------------------------------------------------
# Structure schemas
# ---------------------------------------------------------------------------


class StructSummary(BaseModel):
    """Brief structure info."""

    name: str = Field(description="Structure name.")
    id: int = Field(description="Structure ID.")
    size: int = Field(description="Structure size in bytes.")
    member_count: int = Field(description="Number of members.")
    is_union: bool = Field(description="Whether this is a union.")


class StructListResult(PaginatedResult):
    """Paginated list of structures."""

    items: list[StructSummary] = Field(description="Page of structures.")  # type: ignore[assignment]


class StructMember(BaseModel):
    """Structure member details."""

    offset: int = Field(description="Member offset in bytes.")
    name: str = Field(description="Member name.")
    size: int = Field(description="Member size in bytes.")


class StructDetailResult(BaseModel):
    """Detailed structure information."""

    name: str = Field(description="Structure name.")
    id: int = Field(description="Structure ID.")
    size: int = Field(description="Structure size in bytes.")
    member_count: int = Field(description="Number of members.")
    members: list[StructMember] = Field(description="Structure members.")


class CreateStructResult(BaseModel):
    """Result of creating a structure."""

    name: str = Field(description="Structure name.")
    id: int = Field(description="Structure ID.")
    is_union: bool = Field(description="Whether this is a union.")


class DeleteStructResult(BaseModel):
    """Result of deleting a structure."""

    name: str = Field(description="Structure name.")
    old_size: int = Field(description="Previous structure size.")
    old_member_count: int = Field(description="Previous member count.")


class AddStructMemberResult(BaseModel):
    """Result of adding a structure member."""

    struct: str = Field(description="Structure name.")
    member: str = Field(description="Member name.")
    offset: int = Field(description="Member offset.")
    size: int = Field(description="Member size.")


class RenameStructMemberResult(BaseModel):
    """Result of renaming a structure member."""

    struct: str = Field(description="Structure name.")
    old_name: str = Field(description="Previous member name.")
    new_name: str = Field(description="New member name.")


class DeleteStructMemberResult(BaseModel):
    """Result of deleting a structure member."""

    struct: str = Field(description="Structure name.")
    member: str = Field(description="Deleted member name.")
    old_size: int = Field(description="Previous member size.")


class RetypeStructMemberResult(BaseModel):
    """Result of retyping a structure member."""

    struct: str = Field(description="Structure name.")
    member: str = Field(description="Member name.")
    old_type: str = Field(description="Previous type.")
    type: str = Field(description="New type.")


class SetStructMemberCommentResult(BaseModel):
    """Result of setting a structure member comment."""

    struct: str = Field(description="Structure name.")
    member: str = Field(description="Member name.")
    old_comment: str = Field(description="Previous comment.")
    comment: str = Field(description="New comment.")
    repeatable: bool = Field(description="Whether the comment is repeatable.")


# ---------------------------------------------------------------------------
# Enum schemas
# ---------------------------------------------------------------------------


class EnumSummary(BaseModel):
    """Brief enum info."""

    name: str = Field(description="Enum name.")
    member_count: int = Field(description="Number of members.")
    bitfield: bool = Field(description="Whether this is a bitfield.")


class EnumListResult(PaginatedResult):
    """Paginated list of enums."""

    items: list[EnumSummary] = Field(description="Page of enums.")  # type: ignore[assignment]


class CreateEnumResult(BaseModel):
    """Result of creating an enum."""

    name: str = Field(description="Enum name.")
    bitfield: bool = Field(description="Whether this is a bitfield.")


class DeleteEnumResult(BaseModel):
    """Result of deleting an enum."""

    name: str = Field(description="Enum name.")
    old_member_count: int = Field(description="Previous member count.")


class AddEnumMemberResult(BaseModel):
    """Result of adding an enum member."""

    enum: str = Field(description="Enum name.")
    member: str = Field(description="Member name.")
    value: int = Field(description="Member value.")


class EnumMemberItem(BaseModel):
    """Enum member info."""

    name: str = Field(description="Member name.")
    value: int = Field(description="Member value.")


class EnumMemberListResult(PaginatedResult):
    """Paginated list of enum members."""

    items: list[EnumMemberItem] = Field(description="Page of enum members.")  # type: ignore[assignment]


class RenameEnumResult(BaseModel):
    """Result of renaming an enum."""

    old_name: str = Field(description="Previous enum name.")
    new_name: str = Field(description="New enum name.")


class DeleteEnumMemberResult(BaseModel):
    """Result of deleting an enum member."""

    enum: str = Field(description="Enum name.")
    member: str = Field(description="Deleted member name.")
    value: int = Field(description="Member value.")


class RenameEnumMemberResult(BaseModel):
    """Result of renaming an enum member."""

    enum: str = Field(description="Enum name.")
    old_name: str = Field(description="Previous member name.")
    new_name: str = Field(description="New member name.")
    value: int = Field(description="Member value.")


class SetEnumMemberCommentResult(BaseModel):
    """Result of setting an enum member comment."""

    enum: str = Field(description="Enum name.")
    value: int = Field(description="Member value.")
    old_comment: str = Field(description="Previous comment.")
    comment: str = Field(description="New comment.")


# ---------------------------------------------------------------------------
# Segment schemas
# ---------------------------------------------------------------------------


class CreateSegmentResult(BaseModel):
    """Result of creating a segment."""

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(description="Segment name.")
    start: str = Field(description="Start address (hex).")
    end: str = Field(description="End address (hex).")
    class_: str = Field(alias="class", description="Segment class.")
    bitness: int = Field(description="Segment bitness.")
    permissions: str = Field(description="Permissions string.")


class DeleteSegmentResult(BaseModel):
    """Result of deleting a segment."""

    name: str = Field(description="Segment name.")
    start: str = Field(description="Start address (hex).")
    old_end: str = Field(description="Previous end address (hex).")
    old_permissions: str = Field(description="Previous permissions.")
    old_class: str = Field(description="Previous segment class.")


class SetSegmentNameResult(BaseModel):
    """Result of renaming a segment."""

    old_name: str = Field(description="Previous segment name.")
    new_name: str = Field(description="New segment name.")


class SetSegmentPermissionsResult(BaseModel):
    """Result of changing segment permissions."""

    segment: str = Field(description="Segment name or address.")
    old_permissions: str = Field(description="Previous permissions.")
    permissions: str = Field(description="New permissions.")


class SetSegmentBitnessResult(BaseModel):
    """Result of changing segment bitness."""

    segment: str = Field(description="Segment name or address.")
    old_bitness: int = Field(description="Previous bitness.")
    bitness: int = Field(description="New bitness.")


class SetSegmentClassResult(BaseModel):
    """Result of changing segment class."""

    model_config = ConfigDict(populate_by_name=True)

    segment: str = Field(description="Segment name or address.")
    old_class: str = Field(description="Previous class.")
    class_: str = Field(alias="class", description="New class.")


# ---------------------------------------------------------------------------
# Switch schemas
# ---------------------------------------------------------------------------


class SwitchCase(BaseModel):
    """A switch case entry."""

    case_values: list[int] = Field(description="Case values mapping to this target.")
    target: str | None = Field(description="Target address (hex), or null.")


class GetSwitchInfoResult(BaseModel):
    """Switch table information."""

    address: str = Field(description="Switch instruction address (hex).")
    jump_table: str = Field(description="Jump table address (hex).")
    element_size: int = Field(description="Jump table element size in bytes.")
    num_cases: int = Field(description="Number of switch cases.")
    default_target: str | None = Field(description="Default case target (hex), or null.")
    start_value: int = Field(description="First case value.")
    cases: list[SwitchCase] = Field(description="Switch cases.")


class SwitchSummary(BaseModel):
    """Brief switch info."""

    address: str = Field(description="Switch instruction address (hex).")
    function: str = Field(description="Containing function name.")
    num_cases: int = Field(description="Number of switch cases.")


class SwitchListResult(PaginatedResult):
    """Paginated list of switches."""

    items: list[SwitchSummary] = Field(description="Page of switches.")  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Bookmark schemas
# ---------------------------------------------------------------------------


class SetBookmarkResult(BaseModel):
    """Result of setting a bookmark."""

    address: str = Field(description="Bookmark address (hex).")
    slot: int = Field(description="Bookmark slot number.")
    old_description: str = Field(description="Previous description.")
    description: str = Field(description="New description.")


class BookmarkItem(BaseModel):
    """A bookmark entry."""

    address: str = Field(description="Bookmark address (hex).")
    slot: int = Field(description="Bookmark slot number.")
    description: str = Field(description="Bookmark description.")


class BookmarkListResult(PaginatedResult):
    """Paginated list of bookmarks."""

    items: list[BookmarkItem] = Field(description="Page of bookmarks.")  # type: ignore[assignment]


class DeleteBookmarkResult(BaseModel):
    """Result of deleting a bookmark."""

    slot: int = Field(description="Bookmark slot number.")
    address: str = Field(description="Bookmark address (hex).")
    old_description: str = Field(description="Previous description.")


# ---------------------------------------------------------------------------
# Decompiler schemas
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


class ListDecompilerVarsResult(BaseModel):
    """Decompiler variables for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    variable_count: int = Field(description="Number of variables.")
    variables: list[DecompilerVariable] = Field(description="Variable list.")


# ---------------------------------------------------------------------------
# Ctree schemas
# ---------------------------------------------------------------------------


class GetCtreeResult(BaseModel):
    """Ctree AST for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    ctree: dict | None = Field(description="Ctree AST as a nested dict, or null.")


class CtreeCallInfo(BaseModel):
    """A function call found in the ctree."""

    callee: str = Field(description="Callee name.")
    arg_count: int = Field(description="Number of arguments.")
    callee_address: str | None = Field(default=None, description="Callee address (hex).")
    call_address: str | None = Field(default=None, description="Call site address (hex).")


class FindCtreeCallsResult(BaseModel):
    """Function calls found in the ctree."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    call_count: int = Field(description="Number of calls found.")
    calls: list[CtreeCallInfo] = Field(description="Call list.")


class FindCtreePatternResult(BaseModel):
    """Pattern matches found in the ctree (single pattern type)."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    pattern_type: str | None = Field(default=None, description="Pattern type searched.")
    count: int | None = Field(default=None, description="Number of matches.")
    matches: list[dict] | None = Field(default=None, description="Pattern matches.")
    summary: dict | None = Field(
        default=None, description="Summary counts per pattern type (for 'all')."
    )
    results: dict | None = Field(default=None, description="Results per pattern type (for 'all').")


# ---------------------------------------------------------------------------
# CFG schemas
# ---------------------------------------------------------------------------


class BasicBlock(BaseModel):
    """A basic block in the control flow graph."""

    start: str = Field(description="Block start address (hex).")
    end: str = Field(description="Block end address (hex, exclusive).")
    size: int = Field(description="Block size in bytes.")
    successors: list[str] = Field(description="Successor block addresses (hex).")
    predecessors: list[str] = Field(description="Predecessor block addresses (hex).")


class GetBasicBlocksResult(BaseModel):
    """Basic blocks for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    block_count: int = Field(description="Number of basic blocks.")
    blocks: list[BasicBlock] = Field(description="Basic blocks.")


class CfgEdge(BaseModel):
    """An edge in the control flow graph."""

    model_config = ConfigDict(populate_by_name=True)

    from_: str = Field(alias="from", description="Source block address (hex).")
    to: str = Field(description="Target block address (hex).")


class GetCfgEdgesResult(BaseModel):
    """CFG edges for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    edge_count: int = Field(description="Number of edges.")
    edges: list[CfgEdge] = Field(description="CFG edges.")


# ---------------------------------------------------------------------------
# Processor schemas
# ---------------------------------------------------------------------------


class ProcessorInfoResult(BaseModel):
    """Processor information."""

    processor: str = Field(description="Processor name.")
    bitness: int = Field(description="Default address size in bits.")
    is_64bit: bool = Field(description="Whether the processor is 64-bit.")
    register_names: list[str] = Field(description="Available register names.")


class GetRegisterNameResult(BaseModel):
    """Register name lookup result."""

    register_number: int = Field(description="Register number.")
    width: int = Field(description="Register width.")
    name: str = Field(description="Register name.")


class InstructionCheckResult(BaseModel):
    """Result of checking instruction type."""

    address: str = Field(description="Instruction address (hex).")
    is_call: bool | None = Field(default=None, description="Whether this is a call instruction.")
    is_return: bool | None = Field(
        default=None, description="Whether this is a return instruction."
    )
    is_alignment: bool | None = Field(
        default=None, description="Whether this is an alignment instruction."
    )
    alignment_size: int | None = Field(
        default=None, description="Alignment size (if alignment instruction)."
    )


class InstructionListResult(BaseModel):
    """List of processor instructions."""

    processor: str = Field(description="Processor name.")
    count: int = Field(description="Number of instructions.")
    instructions: list[str] = Field(description="Instruction mnemonics.")


# ---------------------------------------------------------------------------
# Color schemas
# ---------------------------------------------------------------------------


class SetColorResult(BaseModel):
    """Result of setting a color."""

    address: str = Field(description="Address (hex).")
    old_color: str | None = Field(description="Previous color.")
    color: str = Field(description="New color.")
    what: str = Field(description="Color target type.")


class GetColorResult(BaseModel):
    """Color at an address."""

    address: str = Field(description="Address (hex).")
    what: str = Field(description="Color target type.")
    color: str | None = Field(description="Color value, or null if unset.")
    has_color: bool = Field(description="Whether a color is set.")


# ---------------------------------------------------------------------------
# Register finder schemas
# ---------------------------------------------------------------------------


class FindRegisterValueResult(BaseModel):
    """Result of finding a register value."""

    address: str = Field(description="Address (hex).")
    register_name: str = Field(description="Register name.")
    found: bool = Field(description="Whether the value was determined.")
    reason: str | None = Field(default=None, description="Reason value could not be determined.")
    value: str | None = Field(default=None, description="Register value (hex).")


class FindStackPointerResult(BaseModel):
    """Stack pointer value at an address."""

    address: str = Field(description="Address (hex).")
    sp_value: int = Field(description="Stack pointer delta value.")


# ---------------------------------------------------------------------------
# Undo schemas
# ---------------------------------------------------------------------------


class UndoRedoResult(BaseModel):
    """Result of an undo/redo operation."""

    action: str = Field(description="Action performed.")


# ---------------------------------------------------------------------------
# Directory tree schemas
# ---------------------------------------------------------------------------


class DirEntry(BaseModel):
    """A directory tree entry."""

    name: str = Field(description="Entry name.")
    is_folder: bool = Field(description="Whether this is a folder.")
    path: str = Field(description="Full path.")


class ListFoldersResult(BaseModel):
    """Directory tree listing."""

    tree: str = Field(description="Tree type.")
    path: str = Field(description="Listed path.")
    count: int = Field(description="Number of entries.")
    entries: list[DirEntry] = Field(description="Directory entries.")


class FolderActionResult(BaseModel):
    """Result of a folder create/rename/delete operation."""

    tree: str = Field(description="Tree type.")
    path: str = Field(description="Folder path.")
    old_path: str | None = Field(default=None, description="Previous path (for rename).")
    new_path: str | None = Field(default=None, description="New path (for rename).")


# ---------------------------------------------------------------------------
# Load data schemas
# ---------------------------------------------------------------------------


class LoadBytesFromFileResult(BaseModel):
    """Result of loading bytes from a file."""

    file: str = Field(description="Source file path.")
    target_address: str = Field(description="Target address (hex).")
    file_offset: int = Field(description="File offset.")
    size: int = Field(description="Number of bytes loaded.")
    old_bytes: str = Field(description="Previous bytes at target (hex).")


class LoadBytesFromMemoryResult(BaseModel):
    """Result of loading bytes from memory."""

    target_address: str = Field(description="Target address (hex).")
    size: int = Field(description="Number of bytes loaded.")
    old_bytes: str = Field(description="Previous bytes at target (hex).")


# ---------------------------------------------------------------------------
# Analysis schemas
# ---------------------------------------------------------------------------


class StatusResult(BaseModel):
    """Simple status result."""

    status: str = Field(description="Status message.")


class ReanalyzeRangeResult(BaseModel):
    """Result of reanalyzing a range."""

    start: str = Field(description="Range start address (hex).")
    end: str = Field(description="Range end address (hex).")
    status: str = Field(description="Status message.")


class AnalysisProblem(BaseModel):
    """An analysis problem."""

    address: str = Field(description="Problem address (hex).")
    type: str = Field(description="Problem type.")
    function: str = Field(description="Containing function name.")


class AnalysisProblemListResult(PaginatedResult):
    """Paginated list of analysis problems."""

    items: list[AnalysisProblem] = Field(description="Page of analysis problems.")  # type: ignore[assignment]


class FixupItem(BaseModel):
    """A fixup entry."""

    address: str = Field(description="Fixup address (hex).")
    type: str = Field(description="Fixup type.")
    target: str = Field(description="Fixup target address (hex).")


class FixupListResult(PaginatedResult):
    """Paginated list of fixups."""

    items: list[FixupItem] = Field(description="Page of fixups.")  # type: ignore[assignment]


class CatchBlock(BaseModel):
    """A catch block in an exception handler."""

    start: str = Field(description="Catch block start address (hex).")
    end: str = Field(description="Catch block end address (hex).")


class TryBlock(BaseModel):
    """A try block with its catch handlers."""

    try_start: str = Field(description="Try block start address (hex).")
    try_end: str = Field(description="Try block end address (hex).")
    catches: list[CatchBlock] = Field(description="Catch blocks.")


class GetExceptionHandlersResult(BaseModel):
    """Exception handlers for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    tryblock_count: int = Field(description="Number of try blocks.")
    tryblocks: list[TryBlock] = Field(description="Try blocks.")


class GetSegmentRegistersResult(BaseModel):
    """Segment register values at an address."""

    address: str = Field(description="Address (hex).")
    registers: dict[str, str] = Field(description="Register name to value mapping.")


class SetSegmentRegisterResult(BaseModel):
    """Result of setting a segment register."""

    address: str = Field(description="Address (hex).")
    register_name: str = Field(description="Register name.")
    old_value: str | None = Field(description="Previous value.")
    value: str = Field(description="New value.")


# ---------------------------------------------------------------------------
# Export schemas
# ---------------------------------------------------------------------------


class ExportedPseudocode(BaseModel):
    """Exported pseudocode for a function."""

    name: str = Field(description="Function name.")
    address: str = Field(description="Function address (hex).")
    pseudocode: str = Field(description="Decompiled pseudocode.")


class ExportError(BaseModel):
    """An error during batch export."""

    name: str = Field(description="Function name.")
    address: str = Field(description="Function address (hex).")
    error: str = Field(description="Error message.")


class ExportPseudocodeResult(BaseModel):
    """Result of batch pseudocode export."""

    functions: list[ExportedPseudocode] = Field(description="Exported functions.")
    errors: list[ExportError] = Field(description="Functions that failed.")
    total: int = Field(description="Total matching functions.")
    offset: int = Field(description="Starting offset.")
    limit: int = Field(description="Maximum functions per page.")
    has_more: bool = Field(description="Whether more functions exist.")


class ExportedDisassembly(BaseModel):
    """Exported disassembly for a function."""

    name: str = Field(description="Function name.")
    address: str = Field(description="Function address (hex).")
    instruction_count: int = Field(description="Number of instructions.")
    disassembly: str = Field(description="Disassembly text.")


class ExportDisassemblyResult(BaseModel):
    """Result of batch disassembly export."""

    functions: list[ExportedDisassembly] = Field(description="Exported functions.")
    total: int = Field(description="Total matching functions.")
    offset: int = Field(description="Starting offset.")
    limit: int = Field(description="Maximum functions per page.")
    has_more: bool = Field(description="Whether more functions exist.")


class GenerateOutputFileResult(BaseModel):
    """Result of generating an output file."""

    output_path: str = Field(description="Output file path.")
    output_type: str = Field(description="Output file type.")
    start_address: str = Field(description="Start address (hex).")
    end_address: str = Field(description="End address (hex).")
    lines_generated: int = Field(description="Number of lines generated.")


class GenerateExeFileResult(BaseModel):
    """Result of generating an executable file."""

    output_path: str = Field(description="Output file path.")
    status: str = Field(description="Status message.")


# ---------------------------------------------------------------------------
# Function flags schemas
# ---------------------------------------------------------------------------


class SetFunctionFlagsResult(BaseModel):
    """Result of setting function flags."""

    address: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    changed: dict[str, bool] = Field(description="Flags that were changed.")
    old_flags: int = Field(description="Previous flags bitmask.")
    flags: int = Field(description="New flags bitmask.")


class ByteFlagsResult(BaseModel):
    """Byte-level flags at an address."""

    address: str = Field(description="Address (hex).")
    raw_flags: str = Field(description="Raw flags value (hex).")
    is_code: bool = Field(description="Address contains code.")
    is_data: bool = Field(description="Address contains data.")
    is_tail: bool = Field(description="Address is a tail byte.")
    is_head: bool = Field(description="Address is a head byte.")
    is_loaded: bool = Field(description="Address is loaded.")
    has_value: bool = Field(description="Address has a value.")
    has_xref: bool = Field(description="Address has cross-references.")
    has_name: bool = Field(description="Address has a name.")
    has_dummy_name: bool = Field(description="Address has a dummy name.")
    has_auto_name: bool = Field(description="Address has an auto-generated name.")
    has_user_name: bool = Field(description="Address has a user-defined name.")
    has_comment: bool = Field(description="Address has a comment.")
    has_extra_comment: bool = Field(description="Address has extra comments.")
    item_size: int = Field(description="Size of the item at this address.")


class AddHiddenRangeResult(BaseModel):
    """Result of adding a hidden range."""

    start: str = Field(description="Range start address (hex).")
    end: str = Field(description="Range end address (hex).")
    description: str = Field(description="Range description.")


class DeleteHiddenRangeResult(BaseModel):
    """Result of deleting a hidden range."""

    address: str = Field(description="Address in the hidden range (hex).")
    old_start: str | None = Field(description="Previous start address (hex).")
    old_end: str | None = Field(description="Previous end address (hex).")
    old_description: str = Field(description="Previous description.")


class HiddenRangeItem(BaseModel):
    """A hidden range."""

    start: str = Field(description="Range start address (hex).")
    end: str = Field(description="Range end address (hex).")
    description: str = Field(description="Range description.")
    size: int = Field(description="Range size in bytes.")


class HiddenRangeListResult(PaginatedResult):
    """Paginated list of hidden ranges."""

    items: list[HiddenRangeItem] = Field(description="Page of hidden ranges.")  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Regvar schemas
# ---------------------------------------------------------------------------


class RegvarResult(BaseModel):
    """Result of a regvar operation."""

    function: str = Field(description="Function address (hex).")
    start: str | None = Field(default=None, description="Range start address (hex).")
    end: str | None = Field(default=None, description="Range end address (hex).")
    register_name: str = Field(description="Register name.")
    name: str | None = Field(default=None, description="Regvar name.")
    comment: str | None = Field(default=None, description="Regvar comment.")
    old_name: str | None = Field(default=None, description="Previous name (for rename).")
    old_comment: str | None = Field(default=None, description="Previous comment (for set_comment).")


class RegvarInfo(BaseModel):
    """Register variable details."""

    start: str = Field(description="Range start address (hex).")
    end: str = Field(description="Range end address (hex).")
    register_name: str = Field(description="Register name.")
    name: str = Field(description="Regvar name.")
    comment: str = Field(description="Regvar comment.")


class ListRegvarsResult(BaseModel):
    """Register variables for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    count: int = Field(description="Number of regvars.")
    regvars: list[RegvarInfo] = Field(description="Register variables.")


# ---------------------------------------------------------------------------
# Source language schemas
# ---------------------------------------------------------------------------


class GetSourceParserResult(BaseModel):
    """Source language parser info."""

    parser: str = Field(description="Active source parser name.")


class ParseSourceResult(BaseModel):
    """Result of parsing source declarations."""

    error_count: int = Field(description="Number of parse errors.")
    status: str = Field(description="Status message.")


# ---------------------------------------------------------------------------
# Nalt schemas
# ---------------------------------------------------------------------------


class SourceLineResult(BaseModel):
    """Source line number at an address."""

    address: str = Field(description="Address (hex).")
    line_number: int | None = Field(description="Source line number, or null.")


class SetSourceLineResult(BaseModel):
    """Result of setting a source line number."""

    address: str = Field(description="Address (hex).")
    old_line_number: int | None = Field(description="Previous line number.")
    line_number: int = Field(description="New line number.")


class AddressInfoResult(BaseModel):
    """Address analysis flags."""

    address: str = Field(description="Address (hex).")
    no_return: bool = Field(description="Function does not return.")
    is_library_item: bool = Field(description="Item is from a library.")
    is_hidden: bool = Field(description="Item is hidden.")
    type_guessed_by_ida: bool = Field(description="Type was guessed by IDA.")
    type_guessed_by_hexrays: bool = Field(description="Type was guessed by Hex-Rays.")
    type_determined_by_hexrays: bool = Field(description="Type was determined by Hex-Rays.")
    func_guessed_by_hexrays: bool = Field(description="Function was guessed by Hex-Rays.")
    fixed_sp_delta: bool = Field(description="SP delta is fixed.")
    source_line_number: int | None = Field(description="Source line number, or null.")
    raw_aflags: int = Field(description="Raw analysis flags bitmask.")


class SetLibraryItemResult(BaseModel):
    """Result of setting library item flag."""

    address: str = Field(description="Address (hex).")
    old_is_library_item: bool = Field(description="Previous flag value.")
    is_library_item: bool = Field(description="New flag value.")


# ---------------------------------------------------------------------------
# Chunk schemas
# ---------------------------------------------------------------------------


class ListFunctionChunksResult(BaseModel):
    """Function chunks."""

    function: str = Field(description="Function address (hex).")
    chunk_count: int = Field(description="Number of chunks.")
    chunks: list[FunctionChunk] = Field(description="Function chunks.")


class AppendFunctionTailResult(BaseModel):
    """Result of appending a function tail."""

    function: str = Field(description="Function address (hex).")
    tail_start: str = Field(description="Tail start address (hex).")
    tail_end: str = Field(description="Tail end address (hex).")


class RemoveFunctionTailResult(BaseModel):
    """Result of removing a function tail."""

    function: str = Field(description="Function address (hex).")
    removed_tail_at: str = Field(description="Removed tail address (hex).")


class SetTailOwnerResult(BaseModel):
    """Result of setting a tail owner."""

    tail_address: str = Field(description="Tail address (hex).")
    old_owner: str | None = Field(description="Previous owner (hex).")
    new_owner: str = Field(description="New owner (hex).")


# ---------------------------------------------------------------------------
# Assemble schemas
# ---------------------------------------------------------------------------


class AssembleResult(BaseModel):
    """Result of assembling an instruction."""

    address: str = Field(description="Target address (hex).")
    instruction: str = Field(description="Assembly instruction.")
    old_bytes: str = Field(description="Previous bytes (hex).")
    bytes: str = Field(description="Assembled bytes (hex).")
    length: int = Field(description="Instruction length in bytes.")


class PatchAsmResult(BaseModel):
    """Result of patching with assembly."""

    address: str = Field(description="Target address (hex).")
    instruction: str = Field(description="Assembly instruction.")
    old_bytes: str = Field(description="Previous bytes (hex).")
    new_bytes: str = Field(description="New bytes (hex).")
    length: int = Field(description="Instruction length in bytes.")
    patched: bool = Field(description="Whether bytes were patched.")


# ---------------------------------------------------------------------------
# Snapshot schemas
# ---------------------------------------------------------------------------


class TakeSnapshotResult(BaseModel):
    """Result of taking a snapshot."""

    id: str = Field(description="Snapshot ID.")
    description: str = Field(description="Snapshot description.")
    filename: str = Field(description="Snapshot filename.")


class SnapshotInfo(BaseModel):
    """Snapshot information."""

    id: str = Field(description="Snapshot ID.")
    description: str = Field(description="Snapshot description.")
    filename: str = Field(description="Snapshot filename.")
    depth: int = Field(description="Snapshot depth.")


class ListSnapshotsResult(BaseModel):
    """List of database snapshots."""

    snapshots: list[SnapshotInfo] = Field(description="Available snapshots.")
    count: int = Field(description="Number of snapshots.")


class RestoreSnapshotResult(BaseModel):
    """Result of restoring a snapshot."""

    action: str = Field(description="Action performed.")
    snapshot_id: str = Field(description="Restored snapshot ID.")
    description: str = Field(description="Snapshot description.")
    file: str = Field(description="Snapshot filename.")


# ---------------------------------------------------------------------------
# Entry point schemas
# ---------------------------------------------------------------------------


class AddEntryPointResult(BaseModel):
    """Result of adding an entry point."""

    address: str = Field(description="Entry point address (hex).")
    name: str = Field(description="Entry point name.")
    ordinal: int = Field(description="Entry point ordinal.")


class RenameEntryPointResult(BaseModel):
    """Result of renaming an entry point."""

    ordinal: int = Field(description="Entry point ordinal.")
    address: str = Field(description="Entry point address (hex).")
    old_name: str = Field(description="Previous name.")
    new_name: str = Field(description="New name.")


class SetEntryForwarderResult(BaseModel):
    """Result of setting an entry forwarder."""

    ordinal: int = Field(description="Entry point ordinal.")
    address: str = Field(description="Entry point address (hex).")
    old_forwarder: str = Field(description="Previous forwarder.")
    forwarder: str = Field(description="New forwarder.")


class GetEntryForwarderResult(BaseModel):
    """Entry point forwarder info."""

    ordinal: int = Field(description="Entry point ordinal.")
    address: str = Field(description="Entry point address (hex).")
    name: str = Field(description="Entry point name.")
    forwarder: str = Field(description="Forwarder string.")


# ---------------------------------------------------------------------------
# Rebase schemas
# ---------------------------------------------------------------------------


class MoveSegmentResult(BaseModel):
    """Result of moving a segment."""

    segment: str = Field(description="Segment name.")
    old_start: str = Field(description="Previous start address (hex).")
    new_start: str = Field(description="New start address (hex).")


class RebaseProgramResult(BaseModel):
    """Result of rebasing the program."""

    old_base: str = Field(description="Previous base address (hex).")
    delta: str = Field(description="Rebase delta (hex).")


# ---------------------------------------------------------------------------
# Import/export schemas
# ---------------------------------------------------------------------------


class ImportItem(BaseModel):
    """An imported symbol."""

    module: str = Field(description="Module name.")
    address: str = Field(description="Import address (hex).")
    name: str = Field(description="Import name.")
    ordinal: int = Field(description="Import ordinal.")


class ImportListResult(PaginatedResult):
    """Paginated list of imports."""

    items: list[ImportItem] = Field(description="Page of imports.")  # type: ignore[assignment]


class ExportItem(BaseModel):
    """An exported symbol."""

    index: int = Field(description="Export index.")
    ordinal: int = Field(description="Export ordinal.")
    address: str = Field(description="Export address (hex).")
    name: str = Field(description="Export name.")


class ExportListResult(PaginatedResult):
    """Paginated list of exports."""

    items: list[ExportItem] = Field(description="Page of exports.")  # type: ignore[assignment]


class EntryPointItem(BaseModel):
    """An entry point."""

    ordinal: int = Field(description="Entry point ordinal.")
    address: str = Field(description="Entry point address (hex).")
    name: str = Field(description="Entry point name.")


class EntryPointListResult(PaginatedResult):
    """Paginated list of entry points."""

    items: list[EntryPointItem] = Field(description="Page of entry points.")  # type: ignore[assignment]


class SetImportNameResult(BaseModel):
    """Result of setting an import name."""

    modnode: int = Field(description="Module node index.")
    address: str = Field(description="Import address (hex).")
    name: str = Field(description="New import name.")


class SetImportOrdinalResult(BaseModel):
    """Result of setting an import ordinal."""

    modnode: int = Field(description="Module node index.")
    address: str = Field(description="Import address (hex).")
    ordinal: int = Field(description="New import ordinal.")


# ---------------------------------------------------------------------------
# Function type schemas
# ---------------------------------------------------------------------------


class FunctionTypeParameter(BaseModel):
    """A function type parameter."""

    name: str = Field(description="Parameter name.")
    type: str = Field(description="Parameter type.")


class FunctionTypeDetail(BaseModel):
    """Detailed function type information."""

    return_type: str = Field(description="Return type.")
    calling_convention: str = Field(description="Calling convention.")
    parameters: list[FunctionTypeParameter] = Field(description="Function parameters.")


class GetFunctionTypeResult(BaseModel):
    """Function type information."""

    address: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    type: str = Field(description="Function type string.")
    details: FunctionTypeDetail | None = Field(
        description="Parsed type details, or null if parsing failed."
    )


class SetFunctionTypeResult(BaseModel):
    """Result of setting a function type."""

    address: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    old_type: str = Field(description="Previous type.")
    type: str = Field(description="New type.")


class SetCallingConventionResult(BaseModel):
    """Result of setting a function's calling convention."""

    address: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    old_convention: str = Field(description="Previous calling convention.")
    convention: str = Field(description="New calling convention.")


# ---------------------------------------------------------------------------
# Signature generation schemas
# ---------------------------------------------------------------------------


class GenerateSignaturesResult(BaseModel):
    """Result of generating signatures."""

    status: str = Field(description="Status message.")
    only_pat: bool = Field(description="Whether only .pat file was generated.")
