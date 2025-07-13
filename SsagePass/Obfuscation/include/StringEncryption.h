#ifndef LLVM_STRING_ENCRYPTION_H
#define LLVM_STRING_ENCRYPTION_H

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include <vector>
#include <cstdint>

namespace llvm {

class GlobalVariable;
class StructType;

class StringEncryptionPass : public PassInfoMixin<StringEncryptionPass> {
public:
    // 使用 explicit 避免隐式转换
    explicit StringEncryptionPass(bool flag) : flag(flag) {}

    // Pass 的主入口点
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);

    // 告知 Pass Manager 此 Pass 总是需要运行
    static bool isRequired() { return true; }

private:
    bool flag;

    // 用于在模块中插入解密逻辑的辅助函数
    void insertDecryptionCtor(
    Module &M, GlobalVariable *EncryptedGV, StructType *EncryptedStructTy,
    const std::vector<uint8_t> &key, const std::vector<uint8_t> &nonce,
    const std::vector<uint8_t> &aad);
};

// 用于创建 Pass 实例的工厂函数
StringEncryptionPass *createStringEncryption(bool flag);

} // namespace llvm

#endif // LLVM_STRING_ENCRYPTION_H