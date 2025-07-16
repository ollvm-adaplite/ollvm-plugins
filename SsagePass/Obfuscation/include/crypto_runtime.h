#ifndef CRYPTO_RUNTIME_H
#define CRYPTO_RUNTIME_H

#include <cstddef>
#include <cstdint>
#include <vector>

// 定义一个自定义属性宏，用于标记不应被完整性校验插桩的函数。
// Clang/GCC 的 `annotate` 属性会将一个字符串元数据附加到 LLVM IR 中的函数上，
// 我们的 Pass 可以读取这个元数据。
#if defined(__clang__) || defined(__GNUC__)
#define NO_IC_INSTRUMENT __attribute__((annotate("no_ic_instrument")))
#else
#define NO_IC_INSTRUMENT
#endif

// 编译时使用的加密函数
// Encrypts data and produces a 16-byte authentication tag using
// XChaCha20-Poly1305.
void NO_IC_INSTRUMENT xchacha20_poly1305_encrypt(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &nonce, // Now 24 bytes for XChaCha20
    const std::vector<uint8_t> &aad,   // Associated Authenticated Data
    const std::vector<uint8_t> &plaintext, std::vector<uint8_t> &ciphertext,
    std::vector<uint8_t> &tag);


// 运行时使用的解密函数，提供给LLVM Pass生成的代码调用
// NOTE: This function MUST be marked with 'extern "C"' to have a predictable
// C-style name.
extern "C" {
// Decrypts data in-place if the tag is valid.
// Returns 1 on success, 0 on authentication failure.
// On failure, it terminates the program.
int NO_IC_INSTRUMENT __aead_xchacha20_poly1305_decrypt(
    uint8_t *ciphertext, // The ciphertext to be decrypted in-place
    size_t text_len, const uint8_t *aad, size_t aad_len, const uint8_t *key,
    const uint8_t *nonce, // Now 24 bytes for XChaCha20
    const uint8_t *tag);

// 运行时校验函数
void NO_IC_INSTRUMENT __verify_self_integrity();
void NO_IC_INSTRUMENT __verify_memory_integrity(const void *function_addr);
[[noreturn]] void NO_IC_INSTRUMENT __tsx_tamper_handler();

}
static uintptr_t NO_IC_INSTRUMENT get_program_base_address() ;

#endif // CRYPTO_RUNTIME_H