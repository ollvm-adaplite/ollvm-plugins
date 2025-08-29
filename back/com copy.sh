#!/bin/bash




clang++-21 -emit-llvm -std=c++23 -g -fno-omit-frame-pointer -stdlib=libc++   -S test.cpp  -o test.ll


#clang++ -Og -g -fno-omit-frame-pointer -stdlib=libc++  -fpass-plugin=./build/OllvmPlugins.so -emit-llvm -S test.cpp  -o charge_test.ll

#clang++ -Og -g -fsanitize=address -stdlib=libc++  -fno-omit-frame-pointer -fpass-plugin=./build/OllvmPlugins.so    test.cpp -o charge_test.out
rm ./charge_test.out

clang++-21 -Og -g -std=c++23  -fno-omit-frame-pointer -fpass-plugin=./build/OllvmPlugins.so    test.cpp -o charge_test.out ./build/SsagePass/Obfuscation/blake3/c/libblake3.a

#cat charge_test.ll
./charge_test.out
echo -e "\n\n"
#llilibc charge_test.ll
