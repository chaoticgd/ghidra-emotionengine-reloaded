# Changelog

## v2.1.11

- stabs: Built-ins and typedefs are now imported and used instead of their underlying type.
- stabs: Anonymous return types, parameter types, local variable types and global variable types are now given more useful names.

## v2.1.10

- Added support for Ghidra 10.4.
- The pmultw instruction is now correctly disassembled.

## v2.1.9

- Improve the disassembly of certain VU macro mode instructions.

## v2.1.8

- stabs: Add support for recovering vtables from binaries built with compiler versions where `__vtbl_ptr_type` is 8 bytes instead of 4.

## v2.1.7

- stabs: Fixed a number of severe issues relating to inheritance, such as base classes being embedded in sub classes at the wrong offset, and types being misnamed.
- stabs: Anonymous types defined as part of a global variable, function, or local variable declaration are now named appropriately.

## v2.1.6

- Added support for Ghidra 10.3.3.
- The PCSX2 save state importer will no longer crash when encountering certain overlay sections.
- stabs: Embed fields from base classes in sub classes by default.
- stabs: When base classes are embedded, the vtable pointer is now given the type of the sub class. This improves decompilation.
- stabs: When base classes are not embedded, the field generated for the base class is now given a name.
- stabs: Dummy structs will now be created for types that are forward declared in a translation unit with symbols, but not defined in one.

## v2.1.5

- Added support for Ghidra 10.3.
- stabs: Prevent erroneous inlining-related comments from being generated.
- stabs: Bumped stdump version.

## v2.1.4

- stabs: Silence the error that gets thrown when a function name is already applied.

## v2.1.3

- stabs: Fixed an issue where Ghidra would mix up types in some cases for structures defined inline inside unions.
- stabs: Remove junk labels such as `gcc2_compiled.` during analysis so that Ghidra doesn't confuse them for the real function names.

## v2.1.2

- Improved type deduplication algorithm (stdump v1.1 is included).
- Improved logic for handling nested types and type conflicts.
- The STABS analyzer will now only run once by default to prevent accidental corruption of files.

## v2.1.1

- Added support for Ghidra 10.2.3.

## v2.1.0

- A STABS symbol table analyzer is included which makes use a bundled copy of [stdump](https://github.com/chaoticgd/ccc) to extract information about data types, functions and global variables from ELF files with a .mdebug section.
- Simplified the pcode implementation of the plzcw instruction.

## v2.0.0

- Support for Ghidra 10.2.2.
- The VU macro and MMI instruction implementations have	been replaced with pcodeop stubs, improving decompilation.
- Support for disassembling VU microcode has been removed. If you want to reverse a VU microprogram may I suggest having a look at [vutrace](https://github.com/chaoticgd/vutrace).
