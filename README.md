# Ollvm-plugins

中文 | [English](./README_en.md)
**注意该项目仍然处于实验性阶段**
## Plugins
该项目旨在实现插件式的 `Ollvm` 代码混淆，这样可以不需要修改`LLVM`和`Clang`相关代码。也不需要重新编译。使得开发和混淆更加方便，解耦了混淆器和编译器。

## [SsageParuders/SsagePass](https://github.com/SsageParuders/SsagePass)
该项目主要参考`SsagePass`的实现，但是修复了新版本`LLVM`的`API`不兼容的问题，对于某些随机生成器增加了更复杂的逻辑，正确混淆强度。加入了一些实验性的新功能。

## 当前存在的一些问题
1. 由于某种未知原因如果使用 `Ollvm-clang` 编译该项目，`clang` 会使用一个错误的 `prng_seed()` 函数来生成随机数，但是这个函数在本项目中并不存在，这似乎是`clang`的动态链接库导致的。但是这个函数是存在缺陷的，这个问题似乎是早期的 `Ollvm` 版本遗留的问题。会在`this->seed.append(hex_byte);`发生字符串未结束导致`free`到非法内存，该版本的代码已经解决了这个问题。考虑后续修改`Ollvm-clang`这个函数。但是相关的依赖和问题还需要进一步确定。临时的解决办法是使用官方的干净的`clang`版本进行编译。

## 目前较为稳定的PASS
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

没有勾选的表示存在问题或者处于实验性阶段。


## License

This project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License. You can view the full license [here](LICENSE).
根据该License严禁将该项目用于任何商用目的。
![CC BY-NC License](https://licensebuttons.net/l/by-nc/4.0/88x31.png)