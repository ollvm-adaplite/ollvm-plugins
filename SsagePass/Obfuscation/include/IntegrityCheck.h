#ifndef LLVM_INTEGRITY_CHECK_H
#define LLVM_INTEGRITY_CHECK_H

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"

namespace llvm {

class IntegrityCheckPass : public PassInfoMixin<IntegrityCheckPass> {
public:
    explicit IntegrityCheckPass(bool flag) : flag(flag) {}

    // Pass 的主入口点
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);

    // 告知 Pass Manager 此 Pass 总是需要运行
    static bool isRequired() { return true; }

private:
    bool flag;
};

// 用于创建 Pass 实例的工厂函数
IntegrityCheckPass *createIntegrityCheck(bool flag);

} // namespace llvm

#endif // LLVM_INTEGRITY_CHECK_H