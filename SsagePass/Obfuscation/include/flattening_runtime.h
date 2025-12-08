#ifndef FLATTENING_RUNTIME_H
#define FLATTENING_RUNTIME_H

#include <cstdint>
#include <cstddef>

#if defined(__clang__) || defined(__GNUC__)
#define OLLVM_EXPORT extern "C" __attribute__((visibility("default")))
#define OLLVM_INLINE inline __attribute__((always_inline))
#else
#define OLLVM_EXPORT extern "C"
#define OLLVM_INLINE inline
#endif

#if defined(__clang__) || defined(__GNUC__)
#define NO_FLA_VER2 __attribute__((annotate("no_fla_ver2")))
#else
#define NO_FLA_VER2
#endif

// 运行时辅助函数 API

// Collatz 步进函数：模拟 3n+1 或 n/2
// discriminator 用于区分不同的步进变种，增加分析难度
OLLVM_EXPORT NO_FLA_VER2 uint64_t __ollvm_collatz_step(uint64_t state, uint64_t discriminator);

// 使用 BLAKE3 算法计算 Hash，返回 64 位截断值
OLLVM_EXPORT NO_FLA_VER2 uint64_t __ollvm_blake3_hash(uint64_t state, uint64_t flowkey);

// FlowKey 混合函数：用于根据前驱块更新 Key
OLLVM_EXPORT NO_FLA_VER2 uint64_t __ollvm_mix_flowkey(uint64_t flowkey, uint64_t modifier);

#endif // FLATTENING_RUNTIME_H