# 参考官方文档:https://llvm.org/docs/CMake.html#developing-llvm-passes-out-of-source
# 参考文献资料:https://github.com/LeadroyaL/llvm-pass-tutorial

## 请确保编译器是来自NDK的clang 自举编译
cmake_minimum_required(VERSION 3.13.4)
# SET (CMAKE_C_COMPILER_WORKS 1)
# SET (CMAKE_CXX_COMPILER_WORKS 1)
set(CMAKE_C_COMPILER /home/ssage/Android/ndk-llvm/out/install/linux-x86/clang-dev/bin/clang) # 调用原生NDK的clang 来自AOSP
set(CMAKE_CXX_COMPILER /home/ssage/Android/ndk-llvm/out/install/linux-x86/clang-dev/bin/clang) # 调用原生NDK的clang++ 来自AOSP

project(SsagePass) # 项目名称
# we need LLVM_HOME in order not automatically set LLVM_DIR
set(ENV{LLVM_HOME} /home/ssage/Android/ndk-llvm/out/install/linux-x86/clang-dev) # 指定LLVM_HOME为来自原生NDK的
set(ENV{LLVM_DIR} /home/ssage/Android/ndk-llvm/out/install/linux-x86/clang-dev/lib64/cmake/llvm) # 指定cmake文件 如此可以连接到LLVM库

find_package(LLVM REQUIRED CONFIG) # 寻找LLVM依赖包
add_definitions(${LLVM_DEFINITIONS}) # 预定义
include_directories(/home/ssage/Android/ndk-llvm/out/install/linux-x86/clang-dev/include) # LLVM的头文件
include_directories("./include") # 包含 ./include 文件夹中的头文件 主要是为Pass项目服务
link_directories(${LLVM_LIBRARY_DIRS}) # LLVM依赖库

## 如果LLVM版本高于10 则需要启用C++14特性
set(CMAKE_CXX_STANDARD 14) # LLVM启用14特性
## 确保使用llvm的libc++ 而不是来自gcc的libstdc++
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++") # libc++
include_directories(/home/ssage/Android/ndk-llvm/out/install/linux-x86/clang-dev/include/c++/v1) # libc++的头文件包含路径
set(CMAKE_SKIP_RPATH ON)

add_library( SsageObfuscator MODULE # 生成动态库文件
  src/SplitBasicBlock.cpp
  src/Utils.cpp
  src/CryptoUtils.cpp
  src/Flattening.cpp
  src/LegacyLowerSwitch.cpp
  src/PMRegistration.cpp
  src/StringEncryption.cpp
  src/IndirectBranch.cpp
  src/FunctionWrapper.cpp
  src/BogusControlFlow.cpp
  src/VMFlatten.cpp
  src/IndirectCall.cpp
  src/ObfuscationOptions.cpp
  src/IPObfuscationContext.cpp
  src/MBAObfuscation.cpp
  src/MBAUtils.cpp
  src/FlatteningEnhanced.cpp
)

# Use C++11 to compile your pass (i.e., supply -std=c++11).
target_compile_features(SsageObfuscator PRIVATE 
  cxx_range_for cxx_auto_type
)

# LLVM is (typically) built with no C++ RTTI. We need to match that;
# otherwise, we'll get linker errors about missing RTTI data.
set_target_properties(SsageObfuscator PROPERTIES
  COMPILE_FLAGS 
)