#include "Flattening.h"
#include "FlatteningEnhanced.h" // 包含 FlatteningEnhanced 类的声明
#include "FunctionWrapper.h"
#include "IndirectBranch.h"
#include "IndirectCall.h"
#include "IntegrityCheck.h" // 包含 IntegrityCheck 类的声明
#include "MBAObfuscation.h"
#include "SplitBasicBlock.h"
#include "StringEncryption.h"
#include "TSXProtect.h"
#include "VMFlatten.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Scalar/SimplifyCFG.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include "llvm/CodeGen/UnreachableBlockElim.h" // For UnreachableBlockElimPass
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Verifier.h"                  // For verifyFunction
#include "llvm/Transforms/Utils/Local.h"       // For DemotePHIToStack
#include "llvm/Transforms/Utils/LowerInvoke.h" // For LowerInvokePass

// User libs (确保这些路径在 CMakeLists.txt 中正确设置)
#include "CryptoUtils.h"     // 已在 FlatteningEnhanced.h 中包含
#include "Utils.h"           // 已在 FlatteningEnhanced.h 中包含
#include "compat/CallSite.h" // 已在 FlatteningEnhanced.h 中包含

#include <algorithm> // For std::find
#include <cstdlib>
#include <ctime>
#include <list>
#include <map>
#include <unordered_map>
#include <utility>
#include <vector>

#define DEBUG_PRINT_FOR_FLATTENING_ENHANCED
#ifdef DEBUG_PRINT_FOR_FLATTENING_ENHANCED
// 如果开启调试打印，使用 llvm::errs() 输出调试信息
// 黄色打印
#define debugPrint(msg)                                                        \
  do {                                                                         \
                                                                               \
    outs() << "\033[1;33m[FlatteningEnhanced:" << __LINE__ << "] " << msg      \
           << "\033[0m\n";                                                     \
                                                                               \
  } while (0);
#else
#define debugPrint
#endif

// 使用 llvm 命名空间，因为 FlatteningEnhanced.h 中类和函数都在此命名空间
using namespace llvm;

// --- HelloPass (for testing or other purposes, kept as is) ---
struct HelloPass : public PassInfoMixin<HelloPass> {
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM) {
    errs() << "=== HelloPass::run called for function: " << F.getName()
           << " ===\n";
    bool Changed = false;
    if (F.getName() == "main") {
      errs() << "Found main function, inserting hello message\n";
      insertHelloMessage(F);
      Changed = true;
    }

    std::vector<BinaryOperator *> toReplace;
    for (auto &BB : F) {
      for (auto &I : BB) {
        if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
          if (BO->getOpcode() == Instruction::Add) {
            errs() << "Found ADD instruction to replace\n";
            toReplace.push_back(BO);
          }
        }
      }
    }

    for (auto *BO : toReplace) {
      ob_add(BO);
      Changed = true;
    }
    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }

private:
  void insertHelloMessage(Function &F) {
    Module *M = F.getParent();
    LLVMContext &Context = M->getContext();
    FunctionType *printfType =
        FunctionType::get(Type::getInt32Ty(Context),
                          PointerType::get(Type::getInt8Ty(Context), 0), true);
    FunctionCallee printfFunc = M->getOrInsertFunction("printf", printfType);
    BasicBlock &EntryBB = F.getEntryBlock();
    Instruction *FirstInst = &*EntryBB.begin();
    IRBuilder<> Builder(FirstInst);
    Value *StrPtr =
        Builder.CreateGlobalStringPtr("hello run!123 from HelloPass\n");
    Builder.CreateCall(printfFunc, {StrPtr});
  }

  void ob_add(BinaryOperator *bo) {
    IRBuilder<> builder(bo);
    Value *negB = builder.CreateNeg(bo->getOperand(1));
    Value *result = builder.CreateSub(bo->getOperand(0), negB);
    if (auto *newBO = dyn_cast<BinaryOperator>(result)) {
      newBO->setHasNoSignedWrap(bo->hasNoSignedWrap());
      newBO->setHasNoUnsignedWrap(bo->hasNoUnsignedWrap());
    }
    bo->replaceAllUsesWith(result);
    bo->eraseFromParent();
  }
};

// --- LLVM Pass Plugin Registration ---
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "MyPasses", LLVM_VERSION_STRING,

          [](PassBuilder &PB) {
            /* PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "hello-pass") {
                    MPM.addPass(createModuleToFunctionPassAdaptor(HelloPass()));
                    return true;
                  }
                  if (Name == "vm-flatten") {
                    // --- 修改这里，不再需要解引用 ---
                    //MPM.addPass(createModuleToFunctionPassAdaptor(llvm::createVMFlatten_withoutptr(true,0)));
                    MPM.addPass(llvm::FlatteningEnhanced(
                            true));
                    return true;
                  }

                  return false;
                }); */

            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel Level) {
                  // --- 修改这里，不再需要解引用 ---
                  /* MPM.addPass(createModuleToFunctionPassAdaptor(llvm::createVMFlatten_withoutptr(true,2)));

                  MPM.addPass(llvm::FlatteningEnhanced(
                            true)); */

                  /*            llvm::FunctionPassManager FPM;
                   FPM.addPass(llvm::createFunctionWrapperwithoutptr(true)); */

                  // --- 修改这里，不再需要解引用 ---
                  /* MPM.addPass(createModuleToFunctionPassAdaptor(llvm::createVMFlatten_withoutptr(true,2)));

                  MPM.addPass(llvm::FlatteningEnhanced(
                            true)); */
                  /* MPM.addPass(createModuleToFunctionPassAdaptor(llvm::VMFlattenPass(true,0)));
                   */
                  /*  MPM.addPass(llvm::StringEncryptionPass(
                           true)); */

                  MPM.addPass(llvm::IntegrityCheckPass(true));

                  /*  MPM.addPass(createModuleToFunctionPassAdaptor(
                       llvm::FlatteningPass(true))); */
                  /* MPM.addPass(createModuleToFunctionPassAdaptor(llvm::TSXProtectPass(true)));
                   */
                });
          }};
}
