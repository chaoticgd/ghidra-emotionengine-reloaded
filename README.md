# Ghidra Emotion Engine: Reloaded [![run tests](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/actions/workflows/test.yml)
An extension for Ghidra that adds support for the PlayStation 2. Based on the original [ghidra-emotionengine](https://github.com/beardypig/ghidra-emotionengine) project, with a number or changes:
- Support for Ghidra 10.2.2.
- The VU macro and MMI instruction implementations have	been replaced with pcodeop stubs, improving decompilation.
- Support for disassembling VU microcode has been removed. If you want to reverse a VU microprogram may I suggest having a look at [vutrace](https://github.com/chaoticgd/vutrace).

The core MIPS/FPU/COP0 instruction are based off the MIPS32/64 processor included in Ghidra, with superfluous instructions stripped out and some instructions modified.

The following instuction sets are currently supported:

 1. The core MIPS instruction set
 1. The EE core instruction set
 1. COP0 (System control processor) instruction set
 1. COP1 (FPU) instruction set
 1. COP2 (VU0) macro instruction set

## Building

If you want to build the extension yourself, install `gradle` and run:
 
```
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra buildExtension
```

Only Ghidra versions 9.2 and above are supported.

## Installation

Precompiled packages for each version of Ghidra are available in the [releases](https://github.com/beardypig/ghidra-emotionengine/releases) tab. To install the package, follow the instructions in the [Ghidra docs](https://ghidra-sre.org/InstallationGuide.html#Extensions).
