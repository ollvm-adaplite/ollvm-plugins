#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

using namespace llvm;

namespace {
// 新的Pass Manager版本
struct HelloPass : public PassInfoMixin<HelloPass> {
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM) {
    errs() << "=== HelloPass::run called for function: " << F.getName()
           << " ===\n";

    // 在main函数开头添加打印语句
    if (F.getName() == "main") {
      errs() << "Found main function, inserting hello message\n";
      insertHelloMessage(F);
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

    errs() << "Found " << toReplace.size() << " ADD instructions to replace\n";

    for (auto *BO : toReplace) {
      ob_add(BO);
    }

    bool changed = !toReplace.empty() || F.getName() == "main";
    errs() << "HelloPass finished, changed=" << changed << "\n";

    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }

private:
  void insertHelloMessage(Function &F) {
    errs() << "Inserting hello message into main function\n";
    Module *M = F.getParent();
    LLVMContext &Context = M->getContext();

    // 获取或创建printf函数声明
    FunctionType *printfType =
        FunctionType::get(Type::getInt32Ty(Context),
                          PointerType::get(Type::getInt8Ty(Context), 0), true);

    FunctionCallee printfFunc = M->getOrInsertFunction("printf", printfType);

    // 获取第一个基本块的第一条指令
    BasicBlock &EntryBB = F.getEntryBlock();
    Instruction *FirstInst = &*EntryBB.begin();

    // 创建IRBuilder在第一条指令前插入
    IRBuilder<> Builder(FirstInst);

    // 创建字符串指针
    Value *StrPtr = Builder.CreateGlobalStringPtr("hello run!123\n");

    // 创建printf调用
    Builder.CreateCall(printfFunc, {StrPtr});

    errs() << "Hello message inserted successfully\n";
  }

  void ob_add(BinaryOperator *bo) {
    errs() << "Replacing ADD instruction with SUB+NEG\n";
    IRBuilder<> builder(bo);

    // 生成 -b
    Value *negB = builder.CreateNeg(bo->getOperand(1));
    // 生成 a - (-b)
    Value *result = builder.CreateSub(bo->getOperand(0), negB);

    if (auto *newBO = dyn_cast<BinaryOperator>(result)) {
      newBO->setHasNoSignedWrap(bo->hasNoSignedWrap());
      newBO->setHasNoUnsignedWrap(bo->hasNoUnsignedWrap());
    }

    bo->replaceAllUsesWith(result);
    bo->eraseFromParent();
    errs() << "ADD instruction replaced successfully\n";
  }
};
} // namespace

// 使用更标准的Pass注册方式
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "MyHello1", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            // 注册函数Pass

            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel Level) {
                    errs() << "Pipeline start callback for module pass\n";
                  MPM.addPass(createModuleToFunctionPassAdaptor(HelloPass()));
                });
           /*  PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  errs() << "Function pass callback: " << Name << '\n';
                  if (Name == "myhello") {
                    errs() << "Adding HelloPass to function pipeline\n";
                    FPM.addPass(HelloPass());
                    return true;
                  }
                  return false;
                });

            // 也注册模块Pass回调（有些版本需要）
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  errs() << "Module pass callback: " << Name << '\n';
                  if (Name == "myhello1") {
                    errs() << "Adding HelloPass to module pipeline\n";
                    MPM.addPass(createModuleToFunctionPassAdaptor(HelloPass()));
                    return true;
                  }
                  return false;
                }); */
          }};
}