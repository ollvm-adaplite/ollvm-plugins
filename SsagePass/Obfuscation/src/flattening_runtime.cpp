#include "flattening_runtime.h"
#include "blake3.h" 
#include <cstring>

// 简单的混沌 Collatz 实现
// 融合了线性同余生成器(LCG)的特性，使其不仅符合奇偶性，还具有随机性
uint64_t __ollvm_collatz_step(uint64_t state, uint64_t discriminator) {
    // 基础 Collatz 逻辑
    uint64_t next;
    if (state % 2 == 0) {
        next = state / 2;
    } else {
        next = 3 * state + 1;
    }
    
    // 引入干扰因子 (discriminator)，使得同一个 state 可以有多种演变路径
    return next ^ discriminator;
}

// 包装 Blake3 Hash
uint64_t __ollvm_blake3_hash(uint64_t state, uint64_t flowkey) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    
    // 输入 State 和 FlowKey，这必须与 Pass 中的 calculateHash 顺序一致
    blake3_hasher_update(&hasher, &state, sizeof(state));
    blake3_hasher_update(&hasher, &flowkey, sizeof(flowkey));
    
    uint8_t output[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
    
    // 取低 64 位作为 Switch 分发凭证
    uint64_t result;
    std::memcpy(&result, output, sizeof(uint64_t));
    return result;
}

// FlowKey 更新函数
// 使用位循环移位和异或
uint64_t __ollvm_mix_flowkey(uint64_t flowkey, uint64_t modifier) {
    // ROL 13
    uint64_t rotated = (flowkey << 13) | (flowkey >> (64 - 13));
    return rotated ^ modifier;
}