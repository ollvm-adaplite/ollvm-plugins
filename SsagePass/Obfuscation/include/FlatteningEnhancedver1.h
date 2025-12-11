#ifndef _FlatteningEnhancedver1_H_
#define _FlatteningEnhancedver1_H_

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include <list>
#include <vector>

// User libs
#include "compat/CallSite.h"
#include "CryptoUtils.h"
#include "Utils.h"

using namespace std;
using namespace llvm;

namespace llvm{ // 平坦化控制流增强版
    class FlatteningEnhancedver1 : public PassInfoMixin<FlatteningEnhancedver1>{
        public:
            bool flag;
            bool initialized;
            FlatteningEnhancedver1(bool flag){
                this->flag = flag;
            } // 携带flag的构造函数
            PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM); // Pass实现函数
            CallSite* HandleCallSite(CallSite *CS); //
            static bool isRequired() { return true; } // 直接返回true即可

            std::vector<BasicBlock *> *getBlocks(Function *function, std::vector<BasicBlock *> *lists);
            Function *buildUpdateKeyFunc(Module *m);
            unsigned int getUniqueNumber(std::vector<unsigned int> *rand_list);
            void DoFlatteningEnhancedver1(Function *f, int seed, Function *updateFunc);
    };

    FlatteningEnhancedver1 *createFlatteningEnhancedver1(bool flag); // 平坦化控制流增强版
    
}
#endif