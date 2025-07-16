cmake_minimum_required(VERSION 3.10.0)
project(llvmpass VERSION 0.1.0 LANGUAGES C CXX)

# 添加子目录
add_subdirectory(SsagePass/Obfuscation/blake3/c)

#set(LLVM_DIR "/home/ljs/oritestinstall")
#set(LLVM_DIR "/home/ljs/oritestinstall/bin")
set(LLVM_DIR "/home/ljs/llvmall")
# 找到 LLVM
find_package(LLVM REQUIRED CONFIG)
find_package(LLD REQUIRED CONFIG)  # 手动查找 LLD
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")


message(STATUS "LLD version: ${LLD_VERSION}")


# 导出编译 .json 文件
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#include_directories(${LLVM_INCLUDE_DIRS})
#add_definitions(${LLVM_DEFINITIONS})

# 设置使用 libstdc++
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libstdc++ -fno-rtti")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -stdlib=libstdc++ -fno-rtti")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -stdlib=libstdc++ -fno-rtti")


# 自动收集所有 .cpp 文件
file(GLOB OBFUSCATION_SOURCES
    "SsagePass/Obfuscation/src/*.cpp"
)

set(PLUGIN_SOURCES
    ${OBFUSCATION_SOURCES}
)

# 设置编译选项
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 创建共享库目标 - 这行是关键！
add_library(LLVMHello MODULE ${PLUGIN_SOURCES})

# 设置模块属性
set_target_properties(LLVMHello PROPERTIES
    PREFIX ""
    SUFFIX ".so"
    LINKER_LANGUAGE CXX
)

# 不链接任何LLVM库，让opt提供这些符号
target_link_libraries(LLVMHello PRIVATE BLAKE3::blake3)

# 确保使用正确的编译标志
target_compile_definitions(LLVMHello PRIVATE ${LLVM_DEFINITIONS} LLVM_ENABLE_DUMP)

# 添加包含目录：LLVM头文件 + 自定义Obfuscation头文件
target_include_directories(LLVMHello PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/SsagePass/Obfuscation/include # 项目的 Obfuscation 头文件目录放在前面
    # 下面这行是多余且错误的，因为 target_link_libraries(BLAKE3::blake3) 会自动处理
    # ${CMAKE_CURRENT_SOURCE_DIR}/SsagePass/Obfuscation_lld/black3 
    ${LLVM_INCLUDE_DIRS} # LLVM 的标准头文件目录放在后面
)


target_compile_options(LLVMHello PRIVATE -stdlib=libstdc++)
# 禁用未定义符号的检查（让opt提供这些符号）
if(APPLE)
    target_link_options(LLVMHello PRIVATE -undefined dynamic_lookup -stdlib=libstdc++)
else()
    # 检查链接器类型并使用适当的选项
    execute_process(COMMAND ${CMAKE_LINKER} --help
        OUTPUT_VARIABLE LINKER_HELP_OUTPUT
        ERROR_QUIET)

    if(LINKER_HELP_OUTPUT MATCHES "--allow-shlibs-undefined")
        target_link_options(LLVMHello PRIVATE -Wl,--allow-shlibs-undefined -stdlib=libstdc++)
    else()
        # 使用替代方案：不检查未定义符号
        target_link_options(LLVMHello PRIVATE -Wl,--unresolved-symbols=ignore-all -stdlib=libstdc++)
    endif()
endif()

# 新增：创建自定义目标来生成和安装 crypto_runtime.bc
add_custom_target(crypto_runtime
    # 步骤 1: 编译 .cpp 为 .bc，并添加 black3 的头文件路径
    COMMAND ${CMAKE_CXX_COMPILER}
        -std=c++20 -O0 -g -fPIC
        # -mllvm -enable-cffobf
        # -mllvm -enable-splitobf
        # -mllvm -enable-subobf
        # -mllvm -enable-indibran
        # -mllvm -enable-strcry
        # -mllvm -enable-funcwra
        -emit-llvm -c ${CMAKE_CURRENT_SOURCE_DIR}/SsagePass/Obfuscation/src/crypto_runtime.cpp
        -o ${CMAKE_BINARY_DIR}/crypto_runtime.bc
        -I${CMAKE_CURRENT_SOURCE_DIR}/SsagePass/Obfuscation/include
        -I${CMAKE_CURRENT_SOURCE_DIR}/SsagePass/Obfuscation/blake3/c
    # 步骤 2: 确保目标目录存在
    COMMAND ${CMAKE_COMMAND} -E make_directory "$ENV{HOME}/.ollvm"
    # 步骤 3: 复制生成的 .bc 文件到目标位置
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/crypto_runtime.bc "$ENV{HOME}/.ollvm/crypto_runtime.bc"
    COMMENT "Generating and installing crypto_runtime.bc to ~/.ollvm"
    VERBATIM
)

# 新增：将 crypto_runtime 添加为 LLVMHello 的依赖项
# 这样在构建 LLVMHello.so 时会自动生成 crypto_runtime.bc
add_dependencies(LLVMHello crypto_runtime)
