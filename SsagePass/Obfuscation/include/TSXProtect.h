#ifndef LLVM_TSX_PROTECT_H
#define LLVM_TSX_PROTECT_H

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"

namespace llvm {

class TSXProtectPass : public PassInfoMixin<TSXProtectPass> {
public:
    // 使用 explicit 避免隐式转换
    explicit TSXProtectPass(bool flag) : Enabled(flag) {}

    // Pass 的主入口点
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);

    // 告知 Pass Manager 此 Pass 总是需要运行
    static bool isRequired() { return true; }

private:
    bool Enabled;
    bool hasRTM = true ;
    bool RTMchecked = false;
};

// 用于创建 Pass 实例的工厂函数
TSXProtectPass *createTSXProtectPass(bool flag);

} // namespace llvm

#endif // LLVM_TSX_PROTECT_H