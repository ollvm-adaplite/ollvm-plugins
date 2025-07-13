#!/bin/bash
clang++ -std=c++20 -O0 -mllvm  -enable-cffobf    -mllvm -enable-splitobf -mllvm -enable-subobf -mllvm -enable-indibran -mllvm -enable-strcry -mllvm -enable-funcwra     -emit-llvm -c SsagePass/Obfuscation/src/crypto_runtime.cpp -o crypto_runtime.bc -I/home/ljs/code/llvmpass/SsagePass/Obfuscation/include/

rm ~/.ollvm/crypto_runtime.bc
mv crypto_runtime.bc ~/.ollvm