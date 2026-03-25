# Tools Reference

Complete reference for all tools provided by the IDA MCP Server.

## Conventions

**Addresses** can be specified as hex strings (`"0x401000"`), bare hex (`"4010a0"`), decimal (`"4198400"`), or symbol names (`"main"`).

**Pagination** — tools that return lists accept `offset` (default 0) and `limit` (default 100, max 500) parameters, and return `items`, `total`, `offset`, `limit`, and `has_more` fields.

**Multi-database** — when multiple databases are open, every tool accepts an optional `database` parameter (database ID or file path) to specify the target database. Omit it when only one database is open.

**Errors** are returned as `{"error": "message", "error_type": "Category"}` — never as exceptions.

**Old values** — mutation tools return the previous state of modified items (e.g., `old_comment`, `old_type`, `old_bytes`, `old_flags`) alongside the new values, enabling undo tracking and change verification.

---

## Database

Core database lifecycle management.

| Tool | Description |
|------|-------------|
| `open_database` | Open a binary file for analysis. Must be called before any other tool. Set `keep_open=True` to keep existing databases open (multi-database mode). Use `database_id` to assign a custom identifier. |
| `close_database` | Close a database, optionally saving changes. Use `database` to specify which when multiple are open. |
| `save_database` | Save a database without closing it. Use `database` to specify which when multiple are open. |
| `list_databases` | List all currently open databases with metadata (file path, processor, bitness, etc.). |
| `get_database_info` | Get metadata: file path, processor, bitness, file type, address range, counts. |
| `get_database_paths` | Get file paths associated with current database (input file, IDB, ID0). |
| `get_database_flags` | Get database flags (kill, compress, backup, temporary). |
| `set_database_flag` | Set or clear a database flag. |
| `flush_buffers` | Flush IDA's internal buffers to disk. |
| `get_fileregion_ea` | Map a file offset to a virtual address. |
| `get_fileregion_offset` | Map a virtual address to a file offset. |
| `get_elf_debug_file_directory` | Get the ELF debug file directory path. |
| `reload_file` | Reload byte values from the input file. |

## Functions

Function analysis — listing, querying, decompilation, and disassembly.

| Tool | Description |
|------|-------------|
| `list_functions` | List functions with optional regex filter and type filtering (thunk, library, noreturn, user). Paginated. |
| `get_function` | Get detailed info for a function at an address: name, bounds, size, flags, chunks. |
| `get_function_by_name` | Find a function by its name. |
| `decompile_function` | Decompile a function to pseudocode using Hex-Rays. Accepts address or name. |
| `disassemble_function` | Get the full disassembly listing of a function. |
| `rename_function` | Rename a function. |
| `delete_function` | Delete a function definition (underlying code remains). |
| `set_function_bounds` | Change a function's end address. |

## Function Types

Function prototypes and calling conventions.

| Tool | Description |
|------|-------------|
| `get_function_type` | Get function signature, return type, calling convention, and parameters. |
| `set_function_type` | Set a function's prototype from a C declaration string. |
| `set_function_calling_convention` | Change calling convention (cdecl, stdcall, fastcall, thiscall, pascal). |

## Function Flags

Function flags, byte flags, and hidden ranges.

| Tool | Description |
|------|-------------|
| `set_function_flags` | Set function flags: library, thunk, noreturn, hidden. Only provided flags are changed. |
| `get_byte_flags` | Get IDA byte flags at an address: code/data/tail/head status, xrefs, names, comments, item size. |
| `add_hidden_range` | Create a hidden (collapsed) range with a description. |
| `delete_hidden_range` | Delete a hidden range. |
| `get_hidden_ranges` | List all hidden ranges. Paginated. |

## Function Chunks

Function chunks (non-contiguous tail regions).

| Tool | Description |
|------|-------------|
| `list_function_chunks` | List all chunks of a function. |
| `append_function_tail` | Append a tail region to a function. |
| `remove_function_tail` | Remove a tail from a function. |
| `set_tail_owner` | Change which function owns a tail chunk. |

## Stack Frames

Stack frame and local variable analysis.

| Tool | Description |
|------|-------------|
| `get_stack_frame` | Get the stack frame layout: members with offsets, sizes, and names. |
| `get_function_vars` | Get local variables via decompilation: names, types, widths, arg/result flags. |

## Cross-References

Cross-reference queries and call graph analysis.

| Tool | Description |
|------|-------------|
| `get_xrefs_to` | Get all references TO an address (what references it). Paginated. |
| `get_xrefs_from` | Get all references FROM an address (what it references). Paginated. |
| `get_call_graph` | Get the call graph for a function — callers and callees, up to 3 levels deep. |

## Cross-Reference Manipulation

Add and delete cross-references.

| Tool | Description |
|------|-------------|
| `add_code_xref` | Add a code cross-reference (fl_CF, fl_CN, fl_JF, fl_JN, fl_F). |
| `add_data_xref` | Add a data cross-reference (dr_R, dr_W, dr_O, dr_I, dr_T, dr_S). |
| `delete_code_xref` | Delete a code cross-reference. |
| `delete_data_xref` | Delete a data cross-reference. |

## Search

String extraction and pattern searching.

| Tool | Description |
|------|-------------|
| `get_strings` | Extract strings from the binary with optional minimum length and regex filter. Paginated. |
| `search_bytes` | Search for a hex byte pattern (spaces and wildcards supported). |
| `search_text` | Search for text in disassembly output. |
| `find_immediate` | Find instructions with a specific immediate operand value. |
| `search_functions_by_pattern` | Search function names by regex. Paginated. |

## Data

Read raw bytes and list segments.

| Tool | Description |
|------|-------------|
| `read_bytes` | Read raw bytes at an address (max 4096). Returns hex and formatted hex dump. |
| `get_segments` | List all segments with name, bounds, class, permissions, and bitness. Paginated. |

## Make Data

Define data types at addresses.

| Tool | Description |
|------|-------------|
| `make_byte` | Define byte(s) at an address. |
| `make_word` | Define 16-bit word(s) at an address. |
| `make_dword` | Define 32-bit dword(s) at an address. |
| `make_qword` | Define 64-bit qword(s) at an address. |
| `make_float` | Define 32-bit float(s) at an address. |
| `make_double` | Define 64-bit double(s) at an address. |
| `make_string` | Define a string at an address (C, UTF-16, or UTF-32; 0 = auto-detect length). |
| `make_array` | Create an array at an address with a given element size and count. |

## Imports and Exports

Imported functions, exported symbols, and entry points.

| Tool | Description |
|------|-------------|
| `get_imports` | List imported functions, optionally filtered by module name. Paginated. |
| `get_exports` | List exported symbols. Paginated. |
| `get_entry_points` | List entry points. Paginated. |
| `set_import_name` | Set the name of an import entry. |
| `set_import_ordinal` | Set the ordinal of an import entry. |

## Entry Point Manipulation

Add, rename, and manage entry points.

| Tool | Description |
|------|-------------|
| `add_entry_point` | Add an entry point with a name and ordinal. |
| `rename_entry_point` | Rename an entry point by ordinal. |
| `set_entry_forwarder` | Set a forwarder name for an entry point (e.g., "NTDLL.RtlAllocateHeap"). |
| `get_entry_forwarder` | Get the forwarder name for an entry point. |

## Comments

Address and function comments.

| Tool | Description |
|------|-------------|
| `get_comment` | Get regular and repeatable comments at an address. |
| `set_comment` | Set a comment at an address (regular or repeatable). |
| `append_comment` | Append text to an existing comment without overwriting. Skips if text already present. |
| `get_function_comment` | Get regular and repeatable comments for a function. |
| `set_function_comment` | Set a function comment (repeatable by default). |

## Names

Global naming and labeling.

| Tool | Description |
|------|-------------|
| `rename_address` | Rename any address (globals, labels, etc.). |
| `list_names` | List all named locations with optional regex filter. Paginated. |

## Demangling

C++ symbol name demangling.

| Tool | Description |
|------|-------------|
| `demangle_name` | Demangle a C++ symbol name. |
| `demangle_at_address` | Demangle the symbol at a given address. |
| `list_demangled_names` | List demangled C++ names with optional regex filter. Paginated. |

## Instructions and Operands

Instruction decoding and operand value resolution.

| Tool | Description |
|------|-------------|
| `decode_instruction` | Decode a single instruction with full operand details. |
| `decode_instructions` | Decode multiple consecutive instructions (max 200). |
| `get_operand_value` | Get the resolved value of an instruction operand. |

## Operand Display

Change how operands are displayed in the disassembly.

| Tool | Description |
|------|-------------|
| `set_operand_hex` | Display an operand as hexadecimal. |
| `set_operand_decimal` | Display an operand as decimal. |
| `set_operand_binary` | Display an operand as binary. |
| `set_operand_octal` | Display an operand as octal. |
| `set_operand_char` | Display an operand as a character. |
| `set_operand_offset` | Convert an operand to an offset/pointer with a given base. |
| `set_operand_enum` | Apply an enum type to an operand. |
| `set_operand_struct_offset` | Apply a struct member offset to an operand. |

## Control Flow

Basic blocks and control flow graph edges.

| Tool | Description |
|------|-------------|
| `get_basic_blocks` | Get all basic blocks of a function with successors and predecessors. |
| `get_cfg_edges` | Get CFG edges as (from, to) address pairs. |

## Decompiler

Hex-Rays decompiler interaction — variable management, microcode, and comments.

| Tool | Description |
|------|-------------|
| `rename_decompiler_variable` | Rename a local variable in pseudocode. |
| `retype_decompiler_variable` | Change the type of a local variable in pseudocode. |
| `list_decompiler_variables` | List all variables in a function's pseudocode. |
| `get_microcode` | Get microcode at a given maturity level. |
| `set_decompiler_comment` | Set a comment in pseudocode at a specific address. |
| `get_decompiler_comments` | Get all user comments in a function's pseudocode. |

## Ctree

Hex-Rays AST (ctree) exploration and pattern matching.

| Tool | Description |
|------|-------------|
| `get_ctree` | Get the decompiler AST for a function (configurable depth, max 10). |
| `find_ctree_calls` | Find function calls in the AST, optionally filtered by callee name. |
| `find_ctree_patterns` | Find patterns in the AST: calls, string_refs, comparisons, assignments, casts, pointer_derefs, or all. |

## Types

Type query and application.

| Tool | Description |
|------|-------------|
| `get_type_info` | Get the type applied at an address. |
| `set_type` | Apply a C type declaration at an address. |

## Type Information

Local type management and type library operations.

| Tool | Description |
|------|-------------|
| `list_local_types` | List all local types with ordinal, name, size, and classification. Paginated. |
| `get_local_type` | Get full type details by name, including struct/union members. |
| `parse_type_declaration` | Parse a C type declaration into the type library. |
| `delete_local_type` | Delete a local type by name. |
| `delete_local_type_by_ordinal` | Delete a local type by ordinal number. |
| `apply_type_at_address` | Apply a named local type at an address. |

## Structures

Structure and union creation and modification.

| Tool | Description |
|------|-------------|
| `list_structures` | List all structures with index, ID, name, and size. Paginated. |
| `get_structure` | Get structure details: members with offsets, names, and sizes. |
| `create_structure` | Create a new structure or union. |
| `delete_structure` | Delete a structure by name. |
| `add_struct_member` | Add a member to a structure (offset -1 appends). |
| `rename_struct_member` | Rename a structure member. |
| `delete_struct_member` | Delete a structure member. |
| `retype_struct_member` | Change a structure member's type. |
| `set_struct_member_comment` | Set a comment on a structure member. |

## Enums

Enum creation and management.

| Tool | Description |
|------|-------------|
| `list_enums` | List all enums with ordinal, name, and member count. Paginated. |
| `create_enum` | Create a new enum or bitfield. |
| `delete_enum` | Delete an enum by name. |
| `add_enum_member` | Add a member to an enum with a value. |
| `get_enum_members` | List enum members with names and values. Paginated. |
| `rename_enum` | Rename an enum. |
| `delete_enum_member` | Delete an enum member by value. |
| `rename_enum_member` | Rename an enum member. |
| `set_enum_member_comment` | Set a comment on an enum member. |

## Segments

Segment creation and modification.

| Tool | Description |
|------|-------------|
| `create_segment` | Create a new segment with name, bounds, class, bitness, and permissions. |
| `delete_segment` | Delete a segment. |
| `set_segment_name` | Rename a segment. |
| `set_segment_permissions` | Change segment permissions (RWX format). |
| `set_segment_bitness` | Change segment bitness (0=16-bit, 1=32-bit, 2=64-bit). |
| `set_segment_class` | Change the segment class string. |

## Rebase

Segment moving and program rebasing.

| Tool | Description |
|------|-------------|
| `move_segment` | Move a segment to a new start address. |
| `rebase_program` | Rebase the entire program by a delta. |

## Patching

Binary modification — byte patching, function/code creation, undefine.

| Tool | Description |
|------|-------------|
| `patch_bytes` | Patch bytes at an address (creates an undo point). Returns old and new bytes. |
| `create_function` | Create a function at an address with auto-detected boundaries. |
| `make_code` | Mark bytes as a code instruction (without creating a function). |
| `undefine` | Undefine items at an address, converting them back to raw bytes. |

## Assembly

Instruction assembly and patching.

| Tool | Description |
|------|-------------|
| `assemble_instruction` | Assemble a mnemonic string into bytes at an address (does not modify the database). |
| `patch_asm` | Assemble an instruction and patch it into the database in one step (creates an undo point). |

## Signatures

FLIRT signatures, type libraries, and IDS modules.

| Tool | Description |
|------|-------------|
| `apply_flirt_signature` | Apply a FLIRT signature library by name. |
| `list_flirt_signatures` | List all applied FLIRT signatures. |
| `generate_signatures` | Generate FLIRT signatures (.sig and .pat files). |
| `load_type_library` | Load a type library (e.g., gnulnx_x64, mssdk_win10). |
| `list_type_libraries` | List all loaded type libraries. |
| `load_ids_module` | Load and apply an IDS file. |

## Source Language

Source language parsing — import C/C++ declarations.

| Tool | Description |
|------|-------------|
| `get_source_parser` | Get the current source parser name. |
| `parse_source_declarations` | Parse C/C++ source into types using the compiler parser. |

## Analysis

Auto-analysis control, problems, fixups, exception handlers, and segment registers.

| Tool | Description |
|------|-------------|
| `reanalyze_range` | Trigger auto-analysis on an address range. |
| `wait_for_analysis` | Wait for auto-analysis to complete. |
| `get_analysis_problems` | List analysis problems and conflicts. Paginated. |
| `get_fixups` | List relocation/fixup records in an address range. Paginated. |
| `get_exception_handlers` | Get exception try/catch blocks for a function. |
| `get_segment_registers` | Get segment register values (CS, DS, ES, FS, GS, SS) at an address. |
| `set_segment_register` | Set a segment register value at an address. |

## Address Metadata

Source line numbers, analysis flags, and library item marking.

| Tool | Description |
|------|-------------|
| `get_source_line_number` | Get the source line mapping at an address. |
| `set_source_line_number` | Set a source line mapping at an address. |
| `get_address_info` | Get all analysis flags for an address: noreturn, library, hidden, type guess source, SP delta. |
| `set_library_item` | Mark an address as library code. |

## Register Tracking

Register and stack pointer value tracking.

| Tool | Description |
|------|-------------|
| `find_register_value` | Track a register value backward from an address. |
| `find_stack_pointer_value` | Track the stack pointer value at an address. |

## Register Variables

Register-to-name mappings within functions.

| Tool | Description |
|------|-------------|
| `add_regvar` | Map a register to a user-defined name within an address range. |
| `delete_regvar` | Remove a register variable mapping. |
| `get_regvar` | Get a register variable at a specific address. |
| `list_regvars` | List all register variables in a function. |
| `rename_regvar` | Rename a register variable. |
| `set_regvar_comment` | Set a comment on a register variable. |

## Switches

Switch/jump table analysis.

| Tool | Description |
|------|-------------|
| `get_switch_info` | Get switch table info at an indirect jump: cases, targets, element size. |
| `list_switches` | Find all switches in the database. Paginated. |

## Bookmarks

Bookmark (marked position) management.

| Tool | Description |
|------|-------------|
| `set_bookmark` | Set a bookmark at an address with a description (slot -1 auto-assigns). |
| `get_bookmarks` | List all bookmarks. Paginated. |
| `delete_bookmark` | Delete a bookmark by slot number. |

## Colors

Address and function coloring.

| Tool | Description |
|------|-------------|
| `set_color` | Set the background color of an address, function, or segment (RRGGBB hex or empty to remove). |
| `get_color` | Get the background color at an address. |

## Load Data

Load additional data into the database.

| Tool | Description |
|------|-------------|
| `load_bytes_from_file` | Load bytes from an external file into the database at a target address. |
| `load_bytes_from_memory` | Load hex-encoded bytes directly into the database at a target address. |

## Export

Batch export tools, output file generation, and executable rebuilding.

| Tool | Description |
|------|-------------|
| `export_all_pseudocode` | Batch decompile functions (max 100 per call). Optional regex filter. Paginated. |
| `export_all_disassembly` | Batch export disassembly for functions (max 100 per call). Optional regex filter. Paginated. |
| `generate_output_file` | Generate an IDA output file (asm, lst, map, dif, idc). |
| `generate_exe_file` | Rebuild an executable from the database. |

## Directory Tree

IDA directory tree (folder organization).

| Tool | Description |
|------|-------------|
| `list_folders` | List folders and items in a tree (funcs, names, local_types, imports). |
| `create_folder` | Create a folder in a tree. |
| `rename_folder` | Rename or move a folder. |
| `delete_folder` | Delete an empty folder. |

## Undo

Undo and redo operations.

| Tool | Description |
|------|-------------|
| `undo` | Undo the last modification. |
| `redo` | Redo the last undone change. |

## Snapshots

Database snapshot management — persistent point-in-time captures that survive across sessions.

| Tool | Description |
|------|-------------|
| `take_snapshot` | Take a snapshot of the current database state with an optional description. |
| `list_snapshots` | List all snapshots as a flattened tree with depth information. |
| `restore_snapshot` | Restore a previously taken snapshot (replaces current database state). |

## Utility

Number conversion, expression evaluation, and scripting.

| Tool | Description |
|------|-------------|
| `convert_number` | Convert between hex, decimal, octal, and binary representations. |
| `evaluate_expression` | Evaluate an IDC expression. |
| `run_script` | Execute arbitrary IDAPython code (only available when `IDA_MCP_ALLOW_SCRIPTS` is set to `1`, `true`, or `yes`). |

## Processor

Architecture and instruction set information.

| Tool | Description |
|------|-------------|
| `get_processor_info` | Get processor/architecture info: name, bitness, register names. |
| `get_register_name` | Get a register name by number and width. |
| `is_call_instruction` | Check if an instruction is a call. |
| `is_return_instruction` | Check if an instruction is a return. |
| `is_alignment_instruction` | Check if an instruction is a NOP/alignment padding. |
| `get_instruction_list` | Get all mnemonics supported by the current processor. |
