#!/bin/bash
clang++ -emit-llvm -g -fno-omit-frame-pointer -stdlib=libc++   -S test.cpp  -o test.ll

#echo -e "\n=== 第2步：应用Pass生成修改后的IR ==="
#clang++ -Og -g -fno-omit-frame-pointer -stdlib=libc++  -fpass-plugin=./build/LLVMHello.so -emit-llvm -S test.cpp  -o charge_test.ll

#clang++ -Og -g -fsanitize=address -stdlib=libc++  -fno-omit-frame-pointer -fpass-plugin=./build/LLVMHello.so    test.cpp -o charge_test.out
rm ./charge_test.out
clang++ -Og -g -std=c++20  -fno-omit-frame-pointer -fpass-plugin=./build/LLVMHello.so    test.cpp -o charge_test.out ./build/SsagePass/Obfuscation/black3/libblake3.a
#echo -e "\n=== 第3步：显示修改后的IR代码 ==="
#cat charge_test.ll
./charge_test.out
echo -e "\n\n"
#llilibc charge_test.ll
