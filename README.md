# Ghidra Emotion Engine: Reloaded [![run tests](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/actions/workflows/test.yml)
An extension for Ghidra that adds support for the PlayStation 2.

This extension is based on the original [ghidra-emotionengine](https://github.com/beardypig/ghidra-emotionengine) project, with a number of changes.

## Features

- Disassemble and decompile EE-specific instruction sets (MMI, VU0 macro mode, etc).
- Recover data types, functions and global variables from ELF files with `.mdebug` sections with the included STABS Analyzer.
- Import PCSX2 save states.
- Fix references to global variables with the MIPS-R5900 Constant Reference Analyzer.
- Support for Ghidra 11.0.3.

## Installation

Release builds are available on the [releases](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/releases) page. Unstable builds, generated whenever there is a push to the main branch, are available [here](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/releases/tag/unstable). To install the package, follow the instructions in the [Ghidra documentation](https://ghidra-sre.org/InstallationGuide.html#Extensions).

## Building

If you want to build the extension yourself, install `gradle` and run:
 
```
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra buildExtension
```

## Common Issues

### 7-Zip returned unsupported method

Modern versions of PCSX2 store save states using zstd compression, which Ghidra's zip implementation doesn't support. To work around this you have to add `SavestateZstdCompression` to `false` in the `EmuCore` section of your `PCSX2.ini` or `PCSX2_vm.ini` to `disabled` if you are using an older version before Qt. (i.e 1.6.0)

### Decompilation fails for some functions

Try disabling the `Decompiler Parameter ID` analyzer.

### Symbols aren't being demangled

Enable the `Use Deprecated Demangler` option in the settings for the `Demangler GNU` analyzer.
