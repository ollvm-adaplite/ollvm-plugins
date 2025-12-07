#ifndef _FlatteningEnhancedver2_H_
#define _FlatteningEnhancedver2_H_

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Pass.h"
#include <vector>
#include <map>
#include <random>

namespace llvm {

    struct BlockInfo {
        uint64_t stateID;      // 分配给该块的 Collatz 状态 ID
        uint64_t flowKeyIn;    // 进入该块时预期的 FlowKey
        uint64_t flowKeyOut;   // 离开该块时计算出的 FlowKey
    };

    class FlatteningEnhancedver2 : public PassInfoMixin<FlatteningEnhancedver2> {
    public:
        bool flag;
        
        FlatteningEnhancedver2(bool flag) : flag(flag) {}
        
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
        
        static bool isRequired() { return true; }

    private:
        std::mt19937_64 rng; 

        // 核心逻辑
        void doFlattening(Function &F, Function *funcHash, Function *funcCollatz, Function *funcMixKey, Module &M);
        
        // 辅助函数：链接运行时
        void linkRuntime(Module &M);
        
        // 辅助函数：处理常量加密
        void encryptConstants(BasicBlock *BB, Value *flowKeyVar, uint64_t expectedKey);
        
        // 辅助函数：编译期计算 Blake3 Hash
        uint64_t calculateCompileTimeHash(uint64_t state, uint64_t flowkey);
    };

    FlatteningEnhancedver2 *createFlatteningEnhancedver2(bool flag);

} // namespace llvm

#endif