# Ghidra Emotion Engine: Reloaded [![run tests](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/actions/workflows/test.yml)
An extension for Ghidra that adds support for the PlayStation 2.

The core MIPS/FPU/COP0 instruction are based off the MIPS32/64 processor included in Ghidra, with superfluous instructions stripped out and some instructions modified.

The following instuction sets are currently supported:

 1. The core MIPS instruction set
 2. The EE core instruction set (MMI, etc)
 3. COP0 (System control processor) instruction set
 4. COP1 (FPU) instruction set
 5. COP2 (VU0) macro instruction set

This extension is based on the original [ghidra-emotionengine](https://github.com/beardypig/ghidra-emotionengine) project, with a number or changes:
- Support for Ghidra 10.2.3.
- The VU macro and MMI instruction implementations have	been replaced with pcodeop stubs. This is a bit subjective, but I think it helps a lot.
- Support for disassembling VU microcode has been removed. If you want to reverse a VU microprogram may I suggest having a look at [vutrace](https://github.com/chaoticgd/vutrace).

## Installation

Release builds are available on the [releases](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/releases) page. Unstable builds, generated whenever there is a push to the main branch, are available [here](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/releases/tag/unstable). To install the package, follow the instructions in the [Ghidra documentation](https://ghidra-sre.org/InstallationGuide.html#Extensions).


## Building

If you want to build the extension yourself, install `gradle` and run:
 
```
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra buildExtension
```

Only Ghidra versions 9.2 and above are supported.
