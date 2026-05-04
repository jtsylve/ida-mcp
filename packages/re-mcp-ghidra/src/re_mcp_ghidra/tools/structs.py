# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Structure (struct/union) management tools."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_MUTATE_NON_IDEMPOTENT,
    ANNO_READ_ONLY,
    FilterPattern,
    Limit,
    Offset,
    compile_filter,
    paginate_iter,
)
from re_mcp_ghidra.session import session


class StructSummary(BaseModel):
    name: str
    size: int
    member_count: int
    is_union: bool = False
    category: str = ""


class StructMember(BaseModel):
    offset: int
    name: str
    type: str
    size: int
    comment: str = ""


class StructDetailResult(BaseModel):
    name: str
    size: int
    is_union: bool
    category: str
    members: list[StructMember]


class CreateStructResult(BaseModel):
    name: str
    is_union: bool
    status: str


class AddStructMemberResult(BaseModel):
    struct_name: str
    member_name: str
    offset: int
    type: str
    status: str


class RetypeStructMemberResult(BaseModel):
    struct_name: str
    member_name: str
    old_type: str
    new_type: str
    status: str


class RenameStructMemberResult(BaseModel):
    struct_name: str
    old_name: str
    new_name: str


class DeleteStructMemberResult(BaseModel):
    struct_name: str
    member_name: str
    old_size: int


class DeleteStructureResult(BaseModel):
    name: str
    old_size: int
    old_member_count: int


def _resolve_struct(name: str):
    """Resolve a structure by name from the data type manager."""

    program = session.program
    dtm = program.getDataTypeManager()

    # Search all categories
    for dt in dtm.getAllDataTypes():
        if dt.getName() == name:
            from ghidra.program.model.data import Structure, Union  # noqa: PLC0415

            if isinstance(dt, (Structure, Union)):
                return dt

    raise GhidraError(f"Structure not found: {name}", error_type="NotFound")


def _find_member(dt, member_name: str) -> tuple[int, object]:
    """Find a struct/union component by name.

    Returns ``(index, component)``.
    Raises :class:`GhidraError` if not found.
    """
    for i in range(dt.getNumComponents()):
        comp = dt.getComponent(i)
        if (comp.getFieldName() or f"field_{i}") == member_name:
            return i, comp

    raise GhidraError(
        f"Member {member_name!r} not found in {dt.getName()}",
        error_type="NotFound",
    )


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"structs"})
    @session.require_open
    def list_structures(
        offset: Offset = 0,
        limit: Limit = 100,
        filter_pattern: FilterPattern = "",
    ) -> dict:
        """List all structures and unions in the database."""
        from ghidra.program.model.data import Structure, Union  # noqa: PLC0415

        program = session.program
        dtm = program.getDataTypeManager()
        filt = compile_filter(filter_pattern)

        def _gen():
            for dt in dtm.getAllDataTypes():
                if not isinstance(dt, (Structure, Union)):
                    continue
                name = dt.getName()
                if filt and not filt.search(name):
                    continue
                cat = dt.getCategoryPath()
                yield StructSummary(
                    name=name,
                    size=dt.getLength(),
                    member_count=dt.getNumComponents(),
                    is_union=isinstance(dt, Union),
                    category=str(cat) if cat else "",
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"structs"})
    @session.require_open
    def get_structure(name: str) -> StructDetailResult:
        """Get detailed structure info including all members."""
        dt = _resolve_struct(name)
        from ghidra.program.model.data import Union  # noqa: PLC0415

        members = []
        for i in range(dt.getNumComponents()):
            comp = dt.getComponent(i)
            members.append(
                StructMember(
                    offset=comp.getOffset(),
                    name=comp.getFieldName() or f"field_{i}",
                    type=str(comp.getDataType().getName()),
                    size=comp.getLength(),
                    comment=comp.getComment() or "",
                )
            )

        cat = dt.getCategoryPath()
        return StructDetailResult(
            name=dt.getName(),
            size=dt.getLength(),
            is_union=isinstance(dt, Union),
            category=str(cat) if cat else "",
            members=members,
        )

    @mcp.tool(annotations=ANNO_MUTATE_NON_IDEMPOTENT, tags={"structs"})
    @session.require_open
    def create_structure(
        name: str,
        is_union: bool = False,
        size: int = 0,
    ) -> CreateStructResult:
        """Create a new structure or union."""
        from ghidra.program.model.data import (  # noqa: PLC0415
            CategoryPath,
            StructureDataType,
            UnionDataType,
        )

        program = session.program
        dtm = program.getDataTypeManager()

        tx_id = program.startTransaction("Create structure")
        try:
            if is_union:
                dt = UnionDataType(CategoryPath.ROOT, name)
            else:
                dt = StructureDataType(CategoryPath.ROOT, name, size)
            dtm.addDataType(dt, None)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to create structure: {e}", error_type="CreateFailed") from e

        return CreateStructResult(
            name=name,
            is_union=is_union,
            status="created",
        )

    @mcp.tool(annotations=ANNO_MUTATE_NON_IDEMPOTENT, tags={"structs"})
    @session.require_open
    def add_struct_member(
        struct_name: str,
        member_name: str,
        member_type: str = "byte",
        offset: int = -1,
        size: int = 0,
    ) -> AddStructMemberResult:
        """Add a member to a structure.

        Args:
            struct_name: Name of the structure.
            member_name: Name for the new member.
            member_type: C type of the member (e.g. "int", "char *").
            offset: Byte offset (-1 to append at end).
            size: Size in bytes (0 to auto-detect from type).
        """

        dt = _resolve_struct(struct_name)
        program = session.program

        member_dt = _parse_data_type(member_type)

        tx_id = program.startTransaction("Add struct member")
        try:
            if offset < 0:
                dt.add(member_dt, size or member_dt.getLength(), member_name, None)
                actual_offset = dt.getLength() - (size or member_dt.getLength())
            else:
                dt.replaceAtOffset(
                    offset, member_dt, size or member_dt.getLength(), member_name, None
                )
                actual_offset = offset
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to add member: {e}", error_type="AddMemberFailed") from e

        return AddStructMemberResult(
            struct_name=struct_name,
            member_name=member_name,
            offset=actual_offset,
            type=member_type,
            status="added",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"structs"})
    @session.require_open
    def retype_struct_member(
        struct_name: str,
        member_name: str,
        new_type: str,
    ) -> RetypeStructMemberResult:
        """Change the type of a structure member."""
        dt = _resolve_struct(struct_name)
        program = session.program

        _, member = _find_member(dt, member_name)
        old_type = str(member.getDataType().getName())
        new_dt = _parse_data_type(new_type)

        tx_id = program.startTransaction("Retype struct member")
        try:
            member.setDataType(new_dt)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to retype member: {e}", error_type="RetypeFailed") from e

        return RetypeStructMemberResult(
            struct_name=struct_name,
            member_name=member_name,
            old_type=old_type,
            new_type=new_type,
            status="retyped",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"structs"})
    @session.require_open
    def rename_struct_member(
        struct_name: str,
        old_name: str,
        new_name: str,
    ) -> RenameStructMemberResult:
        """Rename a member of a structure.

        Args:
            struct_name: Name of the structure.
            old_name: Current member name.
            new_name: New member name.
        """
        dt = _resolve_struct(struct_name)
        program = session.program

        _, member = _find_member(dt, old_name)

        tx_id = program.startTransaction("Rename struct member")
        try:
            member.setFieldName(new_name)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to rename member: {e}", error_type="RenameFailed") from e

        return RenameStructMemberResult(
            struct_name=struct_name,
            old_name=old_name,
            new_name=new_name,
        )

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"structs"})
    @session.require_open
    def delete_struct_member(
        struct_name: str,
        member_name: str,
    ) -> DeleteStructMemberResult:
        """Delete a member from a structure.

        Args:
            struct_name: Name of the structure.
            member_name: Name of the member to delete.
        """
        from ghidra.program.model.data import Union  # noqa: PLC0415

        dt = _resolve_struct(struct_name)
        program = session.program

        member_idx, comp = _find_member(dt, member_name)
        member_size = comp.getLength()

        tx_id = program.startTransaction("Delete struct member")
        try:
            if isinstance(dt, Union):
                dt.delete(member_idx)
            else:
                dt.clearComponent(member_idx)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to delete member: {e}", error_type="DeleteFailed") from e

        return DeleteStructMemberResult(
            struct_name=struct_name,
            member_name=member_name,
            old_size=member_size,
        )

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"structs"})
    @session.require_open
    def delete_structure(name: str) -> DeleteStructureResult:
        """Delete ONE struct/union by name.

        Args:
            name: Name of the structure to delete.
        """
        dt = _resolve_struct(name)
        program = session.program
        dtm = program.getDataTypeManager()

        old_size = dt.getLength()
        old_member_count = dt.getNumComponents()

        tx_id = program.startTransaction("Delete structure")
        try:
            dtm.remove(dt, None)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to delete structure: {e}", error_type="DeleteFailed") from e

        return DeleteStructureResult(
            name=name,
            old_size=old_size,
            old_member_count=old_member_count,
        )


def _parse_data_type(type_str: str):
    """Parse a C type string into a Ghidra DataType."""
    from ghidra.program.model.data import (  # noqa: PLC0415
        BooleanDataType,
        ByteDataType,
        CharDataType,
        DoubleDataType,
        FloatDataType,
        IntegerDataType,
        LongDataType,
        LongLongDataType,
        PointerDataType,
        ShortDataType,
        Undefined1DataType,
        Undefined2DataType,
        Undefined4DataType,
        Undefined8DataType,
        UnsignedIntegerDataType,
        UnsignedLongDataType,
        UnsignedLongLongDataType,
        UnsignedShortDataType,
        VoidDataType,
    )

    type_map = {
        "byte": ByteDataType.dataType,
        "char": CharDataType.dataType,
        "short": ShortDataType.dataType,
        "int": IntegerDataType.dataType,
        "long": LongDataType.dataType,
        "long long": LongLongDataType.dataType,
        "unsigned byte": ByteDataType.dataType,  # Ghidra has no UnsignedByteDataType
        "unsigned char": ByteDataType.dataType,
        "unsigned short": UnsignedShortDataType.dataType,
        "unsigned int": UnsignedIntegerDataType.dataType,
        "uint": UnsignedIntegerDataType.dataType,
        "unsigned long": UnsignedLongDataType.dataType,
        "unsigned long long": UnsignedLongLongDataType.dataType,
        "float": FloatDataType.dataType,
        "double": DoubleDataType.dataType,
        "void": VoidDataType.dataType,
        "bool": BooleanDataType.dataType,
        "undefined1": Undefined1DataType.dataType,
        "undefined2": Undefined2DataType.dataType,
        "undefined4": Undefined4DataType.dataType,
        "undefined8": Undefined8DataType.dataType,
    }

    clean = type_str.strip().lower()

    # Check for pointer types
    if clean.endswith("*"):
        base = clean[:-1].strip()
        if base:
            base_dt = _parse_data_type(base)
            return PointerDataType(base_dt)
        return PointerDataType(VoidDataType.dataType)

    dt = type_map.get(clean)
    if dt is not None:
        return dt

    # Try looking up in the program's data type manager
    program = session.program
    if program:
        dtm = program.getDataTypeManager()
        for existing_dt in dtm.getAllDataTypes():
            if existing_dt.getName().lower() == clean:
                return existing_dt

    raise GhidraError(f"Unknown data type: {type_str!r}", error_type="InvalidArgument")
