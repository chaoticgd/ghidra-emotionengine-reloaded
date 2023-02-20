# Changelog

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
