# Changelog

# v2.1.5

- Added support for Ghidra 10.3.
- stabs: Prevent erroneous inlining-related comments from being generated.
- stabs: Bumped stdump version.

# v2.1.4

- stabs: Silence the error that gets thrown when a function name is already applied.

# v2.1.3

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
