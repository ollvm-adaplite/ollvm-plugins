cmake_minimum_required(VERSION 3.11.0)

# --- 修改 1: 启用 vcpkg (必须在 project() 之前) ---
if(WIN32)
    set(CMAKE_TOOLCHAIN_FILE "E:/code/lib/vcpkg/scripts/buildsystems/vcpkg.cmake")
    set(USER_HOME_DIR "$ENV{USERPROFILE}")
else()
    set(USER_HOME_DIR "$ENV{HOME}")
endif()


project(llvmpass VERSION 0.1.0 LANGUAGES C CXX)





add_definitions(-D_GLIBCXX_USE_CXX11_ABI=1)
# 导出clangd所需的查找路径
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 添加子目录
add_subdirectory(SsagePass/Obfuscation/blake3/c)

# --- 修改 2: 在查找 LLVM 之前查找 ZLIB (解决 LLVMSupport 依赖 ZLIB::ZLIB 的报错) ---
find_package(ZLIB REQUIRED)

#set(LLVM_DIR "/home/ljs/oritestinstall")
#set(LLVM_DIR "/home/ljs/oritestinstall/bin")
set(LLVM_DIR "E:/code/lib/llvminstall/bin")
# 找到 LLVM
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

# --- 修改 3: 仅在 Windows 下配置 LLVM 库链接 ---
if(WIN32)
    # 添加：包含 LLVM 的 CMake helper，以便使用 llvm_map_components_to_libnames
    include(AddLLVM)

    set(LLVM_LINK_COMPONENTS
        Core
        Support
        TransformUtils
        Analysis
        Passes
        BitReader
        BitWriter
        BinaryFormat
        Demangle
    )
    llvm_map_components_to_libnames(llvm_libs ${LLVM_LINK_COMPONENTS})


endif()

# 兼容老版变量（可选，但常用）
include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

# 设置使用 libstdc++
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -fno-rtti ")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}  -fno-rtti")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}  -fno-rtti")


# 自动收集所有 .cpp 文件
file(GLOB OBFUSCATION_SOURCES
    "SsagePass/Obfuscation/src/*.cpp"
)

set(PLUGIN_SOURCES
    SsagePass/Obfuscation/src/main.cpp
    ${OBFUSCATION_SOURCES}
)

# 设置编译选项
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 创建共享库目标 - 这行是关键！
add_library(OllvmPlugins MODULE ${PLUGIN_SOURCES})



# 设置模块属性
set_target_properties(OllvmPlugins PROPERTIES
    PREFIX ""
    SUFFIX ".so"
    LINKER_LANGUAGE CXX
)


# --- 修改 4: 基础链接库 ---
target_link_libraries(OllvmPlugins PRIVATE
    BLAKE3::blake3
)

# --- 修改 5: 仅在 Windows 下链接 LLVM 库 ---
if(WIN32)
    target_link_libraries(OllvmPlugins PRIVATE ${llvm_libs})
endif()

# 确保使用正确的编译标志
target_compile_definitions(OllvmPlugins PRIVATE ${LLVM_DEFINITIONS} LLVM_ENABLE_DUMP)

# 添加包含目录：LLVM头文件 + 自定义Obfuscation头文件
target_include_directories(OllvmPlugins PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/SsagePass/Obfuscation/include # 项目的 Obfuscation 头文件目录放在前面
    # 下面这行是多余且错误的，因为 target_link_libraries(BLAKE3::blake3) 会自动处理
    # ${CMAKE_CURRENT_SOURCE_DIR}/SsagePass/Obfuscation_lld/black3 
    ${LLVM_INCLUDE_DIRS} # LLVM 的标准头文件目录放在后面
)

# 明确指定使用 libstdc++ 进行编译
target_compile_options(OllvmPlugins PRIVATE)

# 禁用未定义符号的检查（让opt提供这些符号）
if(APPLE)
    target_link_options(OllvmPlugins PRIVATE -undefined dynamic_lookup)
elseif(UNIX)
    # 检查链接器类型并使用适当的选项
    execute_process(COMMAND ${CMAKE_LINKER} --help
        OUTPUT_VARIABLE LINKER_HELP_OUTPUT
        ERROR_QUIET)

    if(LINKER_HELP_OUTPUT MATCHES "--allow-shlibs-undefined")
        # 明确指定使用 libstdc++ 并链接 libstdc++abi
        target_link_options(OllvmPlugins PRIVATE -Wl,--allow-shlibs-undefined)
    else()
        # 使用替代方案：不检查未定义符号，并明确指定使用 libstdc++ 和链接 libstdc++abi
        target_link_options(OllvmPlugins PRIVATE -Wl,--unresolved-symbols=ignore-all)
    endif()
endif()

# 新增：创建自定义目标来生成和安装 crypto_runtime.bc
add_custom_target(crypto_runtime
    # 步骤 1: 编译 .cpp 为 .bc，并添加 black3 的头文件路径
    COMMAND ${CMAKE_CXX_COMPILER}
    -std=c++23 -O0 -g 
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
    # 为 .bc 文件的编译也明确指定 libstdc++
    # 步骤 2: 确保目标目录存在 
    COMMAND ${CMAKE_COMMAND} -E make_directory "${USER_HOME_DIR}/.ollvm"
    # 步骤 3: 复制生成的 .bc 文件到目标位置 
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/crypto_runtime.bc "${USER_HOME_DIR}/.ollvm/crypto_runtime.bc"
    COMMENT "Generating and installing crypto_runtime.bc to ~/.ollvm"
    VERBATIM
)

add_custom_target(flattening_runtime
    COMMAND ${CMAKE_CXX_COMPILER}
    -std=c++23 -O0 -g 
    -emit-llvm -c ${CMAKE_CURRENT_SOURCE_DIR}/SsagePass/Obfuscation/src/flattening_runtime.cpp
    -o ${CMAKE_BINARY_DIR}/flattening_runtime.bc
    -I${CMAKE_CURRENT_SOURCE_DIR}/SsagePass/Obfuscation/include
    -I${CMAKE_CURRENT_SOURCE_DIR}/SsagePass/Obfuscation/blake3/c
    # 安装到 home 目录 
    COMMAND ${CMAKE_COMMAND} -E make_directory "${USER_HOME_DIR}/.ollvm"
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/flattening_runtime.bc "${USER_HOME_DIR}/.ollvm/flattening_runtime.bc"
    COMMENT "Generating and installing flattening_runtime.bc to ~/.ollvm"
    VERBATIM
)


add_dependencies(OllvmPlugins crypto_runtime flattening_runtime)
