# Changelog

## v2.1.31

- Added support for Ghidra 12.0.1.

## v2.1.30

- Disabled the DvpOverlayTable class as a temporary measure to fix the symbol tree.

## v2.1.29

- Added support for Ghidra 12.0.

## v2.1.28

- Added vector unit overlay importer.
- Added support for Ghidra 11.4.3.

## v2.1.27

- Added support for Ghidra 11.4.2.

## v2.1.26

- Added support for Ghidra 11.4.1.

## v2.1.25

- Updated the system call patterns to better match those found in commercial games (because the SDKs patch the kernel, the system call numbers differ between the official SDK and the homebrew SDK).
- Added support for Ghidra 11.4.

## v2.1.24

- Added support for Ghidra 11.3.2.

## v2.1.23

- Added support for Ghidra 11.3.1.

## v2.1.22

- Fixed an issue where the STABS importer would creating conflicting built-in types.
- Fixed disassembly of interlock bit in cfc2/ctc2/qmfc2/qmtc2 instructions.
- Added support for Ghidra 11.3.

## v2.1.21

- Added support for Ghidra 11.2.1.

## v2.1.20

- Added support for Ghidra 11.2.

## v2.1.19

- Fixed a relocation regression introduced in v2.1.17 where Ghidra's built-in MIPS relocation handler would take priority over the one included with the extension.

## v2.1.18

- Added support for Ghidra 11.1.2.

## v2.1.17

- Added support for Ghidra 11.1.1.

## v2.1.16

- Improved the decompilation of unaligned loads/stores with the new MipsR5900PreAnalyzer. [abelbriggs1](https://github.com/abelbriggs1)
- The argument shown in decompilation output for the syscall instruction is now the syscall number instead of the break code (which is now shown in the disassembly).

## v2.1.15

- Added support for Ghidra 11.0.3.

## v2.1.14

- Added support for Ghidra 11.0.2.

## v2.1.13

- Added support for Ghidra 11.0.1.
- Prevent relocations from being applied incorrectly for statically linked executable files that still have a relocation table.

## v2.1.12

- Added support for Ghidra 11.0.
- Fixed parsing of HI16, LO16 and MIPS_26 relocations. [abelbriggs1](https://github.com/abelbriggs1)

## v2.1.11

- stabs: Built-ins and typedefs are now imported and used instead of their underlying type.
- stabs: Bitfields are now imported instead of being replaced with `undefined` bytes. [abelbriggs1](https://github.com/abelbriggs1)
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
