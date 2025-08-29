# Ollvm-plugins

[Chinese](./README.md) | English
**Note: This project is still in an experimental stage.**
## Plugins
This project aims to implement plugin-style `Ollvm` code obfuscation, eliminating the need to modify `LLVM` and `Clang` related code or recompile them. This makes development and obfuscation more convenient and decouples the obfuscator from the compiler.

## [SsageParuders/SsagePass](https://github.com/SsageParuders/SsagePass)
This project primarily references the implementation of `SsagePass`, but it fixes API incompatibility issues with newer `LLVM` versions, adds more complex logic for certain random number generators, and ensures correct obfuscation strength. Some experimental new features have also been added.

## Current Issues
1. For some unknown reason, if this project is compiled using `Ollvm-clang`, `clang` will use an incorrect `prng_seed()` function to generate random numbers. However, this function does not exist in this project. This seems to be caused by `clang`'s dynamic link library. This function is flawed, which appears to be a legacy issue from earlier `Ollvm` versions. It can lead to an unterminated string in `this->seed.append(hex_byte);`, causing `free` to an illegal memory address. This version of the code has already resolved this specific issue. Future modifications to the `Ollvm-clang` version of this function are being considered. However, related dependencies and issues need further investigation. A temporary solution is to compile with an official, clean `clang` version.

## Currently Stable Passes
- [x] [VMFlatten](SsagePass/Obfuscation/src/VMFlatten.cpp)
- [ ] [TSXProtect](SsagePass/Obfuscation/src/TSXProtect.cpp)
- [x] [StringEncryption](SsagePass/Obfuscation/src/StringEncryption.cpp)
- [x] [SplitBasicBlock](SsagePass/Obfuscation/src/SplitBasicBlock.cpp)
- [x] [MBAObfuscation](SsagePass/Obfuscation/src/MBAObfuscation.cpp)
- [x] [IndirectCall](SsagePass/Obfuscation/src/IndirectCall.cpp)
- [x] [IndirectBranch](SsagePass/Obfuscation/src/IndirectBranch.cpp)
- [x] [FunctionWrapper](SsagePass/Obfuscation/src/FunctionWrapper.cpp)
- [x] [FlatteningEnhanced](SsagePass/Obfuscation/include/FlatteningEnhanced.h)
- [ ] [Flattening](SsagePass/Obfuscation/src/Flattening.cpp)
- [ ] [IntegrityCheck](SsagePass/Obfuscation/src/IntegrityCheck.cpp)
- [x] [BogusControlFlow](SsagePass/Obfuscation/src/BogusControlFlow.cpp)

Unchecked items indicate existing issues or are in an experimental stage.

## License

This project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License. You can view the full license [here](LICENSE).
Commercial use of this project is strictly