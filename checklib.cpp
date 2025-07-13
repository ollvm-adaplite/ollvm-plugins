#include <stdio.h>

// 防止 inline
__attribute__((noinline))
extern "C" int check(int input) {
    return input == 123456;
}