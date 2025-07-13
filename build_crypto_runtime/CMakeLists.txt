cmake_minimum_required(VERSION 3.16)
project(CryptoRuntimeBuilder LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找 LLVM，我们需要 llvm-link
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVM-Link: ${LLVM_LINK_EXECUTABLE}")

# --- 1. 包含 black3 子目录，让它运行自己的平台检测 ---
# 我们将它构建为静态库，但我们实际上不会使用这个库本身。
# 我们只想要它为我们选择正确的源文件。
# EXCLUDE_FROM_ALL 确保在常规构建中不会构建它。
add_subdirectory(../SsagePass/Obfuscation/black3 EXCLUDE_FROM_ALL)

# --- 2. 从 blake3 目标中提取它选择的源文件列表 ---
get_target_property(BLAKE3_SOURCES blake3 SOURCES)
message(STATUS "BLAKE3 sources selected by its CMake: ${BLAKE3_SOURCES}")

# --- 3. 定义我们自己的 OBJECT 库，使用提取的源文件 ---
add_library(CryptoRuntimeObjects OBJECT
    ../SsagePass/Obfuscation/src/crypto_runtime.cpp
    ${BLAKE3_SOURCES}
)

# 为我们的库设置正确的 include 目录
target_include_directories(CryptoRuntimeObjects PRIVATE
    ../SsagePass/Obfuscation/include
    ../SsagePass/Obfuscation/black3  # black3 自身的 include
)

# --- 4. 强制我们自己的库编译成 LLVM bitcode ---
target_compile_options(CryptoRuntimeObjects PRIVATE -emit-llvm)

# --- 5. 添加自定义命令，使用 llvm-link 链接我们的 bitcode 对象 ---
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/crypto_runtime.bc
    COMMAND ${LLVM_LINK_EXECUTABLE} -o ${CMAKE_CURRENT_BINARY_DIR}/crypto_runtime.bc $<TARGET_OBJECTS:CryptoRuntimeObjects>
    DEPENDS CryptoRuntimeObjects
    COMMENT "Linking all runtime bitcode objects into crypto_runtime.bc"
)

# --- 6. 创建一个目标来触发整个过程 ---
add_custom_target(generate_runtime ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/crypto_runtime.bc
)
