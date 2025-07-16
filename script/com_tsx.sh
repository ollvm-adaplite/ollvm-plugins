#!/bin/bash
set -e
PASS_PLUGIN="./build/LLVMHello.so"
# 1. 编译 check 共享库
clang++ -O0 -fpass-plugin=${PASS_PLUGIN} -fPIC -shared -o libcheck.so checklib.cpp

# 2. 编译 hook.so
gcc -shared -fPIC -o hook.so hook.c

# 3. 编译受保护的可执行文件 test_protected
#    请将下面的路径替换为你自己编译出的 Pass 库

clang++ -O0 -fPIC -pie -Wl,-E \
      -fpass-plugin=${PASS_PLUGIN}  \
      -mrtm \
      -L. -lcheck \
      testhook.c -o test_protected ./build/SsagePass/Obfuscation/black3/libblake3.a

# 4. 运行并尝试 hook
echo -e "\n=== Running test_protected with LD_PRELOAD=hook.so ==="
LD_PRELOAD=./hook.so ./test_protected