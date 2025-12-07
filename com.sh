#!/bin/bash




clang++-21 -emit-llvm -std=c++23 -g -fno-omit-frame-pointer    -S test.cpp  -o test.ll


#clang++ -Og -g -fno-omit-frame-pointer   -fpass-plugin=./build/OllvmPlugins.so -emit-llvm -S test.cpp  -o charge_test.ll

#clang++ -Og -g -fsanitize=address   -fno-omit-frame-pointer -fpass-plugin=./build/OllvmPlugins.so    test.cpp -o charge_test.out
rm ./charge_test.out

clang++-21 -v  -no-pie  -g -std=c++23 -fno-omit-frame-pointer -fpass-plugin=./build/OllvmPlugins.so test.cpp -o charge_test.out ./build/SsagePass/Obfuscation/blake3/c/libblake3.a 

#cat charge_test.ll
./charge_test.out
echo -e "\n\n"
#llilibc charge_test.ll
