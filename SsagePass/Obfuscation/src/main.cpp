#include "Flattening.h"
#include "FlatteningEnhanced.h"  // 包含 FlatteningEnhanced 类的声明
#include "FlatteningEnhancedver2.h"
#include "FlatteningEnhancedver1.h"
#include "FunctionWrapper.h"
#include "IndirectBranch.h"
#include "IndirectCall.h"
#include "IntegrityCheck.h"  // 包含 IntegrityCheck 类的声明
#include "MBAObfuscation.h"
#include "SplitBasicBlock.h"
#include "StringEncryption.h"
#include "TSXProtect.h"
#include "VMFlatten.h"
#include "BogusControlFlow.h"

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

#include "llvm/CodeGen/UnreachableBlockElim.h"  // For UnreachableBlockElimPass
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Verifier.h"                   // For verifyFunction
#include "llvm/Transforms/Utils/Local.h"        // For DemotePHIToStack
#include "llvm/Transforms/Utils/LowerInvoke.h"  // For LowerInvokePass

// User libs (确保这些路径在 CMakeLists.txt 中正确设置)
#include "CryptoUtils.h"      // 已在 FlatteningEnhanced.h 中包含
#include "Utils.h"            // 已在 FlatteningEnhanced.h 中包含
#include "compat/CallSite.h"  // 已在 FlatteningEnhanced.h 中包含

#include <algorithm>  // For std::find
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
#define debugPrint(msg)                                                       \
    do                                                                        \
    {                                                                         \
        outs() << "\033[1;33m[FlatteningEnhanced:" << __LINE__ << "] " << msg \
               << "\033[0m\n";                                                \
                                                                              \
    } while (0);
#else
#define debugPrint
#endif

// 使用 llvm 命名空间，因为 FlatteningEnhanced.h 中类和函数都在此命名空间
using namespace llvm;



// --- LLVM Pass Plugin Registration ---

// --- 修改开始：添加 Windows 导出宏 ---
#ifdef _WIN32
#define PLUGIN_EXPORT __declspec(dllexport)
#else
#define PLUGIN_EXPORT LLVM_ATTRIBUTE_WEAK
#endif
// --- 修改结束 ---

// 将 LLVM_ATTRIBUTE_WEAK 替换为 PLUGIN_EXPORT
extern "C" PLUGIN_EXPORT ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo()
{
    return {LLVM_PLUGIN_API_VERSION, "MyPasses", LLVM_VERSION_STRING,

            [](PassBuilder& PB)
            {
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
                        [](ModulePassManager& MPM, OptimizationLevel Level)
                        {
                            // --- 修改这里，不再需要解引用 ---
                            // MPM.addPass(createModuleToFunctionPassAdaptor(llvm::createVMFlatten_withoutptr(true,2)));

                            /*            llvm::FunctionPassManager FPM;
                   FPM.addPass(llvm::createFunctionWrapperwithoutptr(true)); */

                            // --- 修改这里，不再需要解引用 ---
                            //             MPM.addPass(createModuleToFunctionPassAdaptor(llvm::createVMFlatten_withoutptr(true,2)));

                            //    MPM.addPass(llvm::FlatteningEnhanced(
                            //              true));
                            //             MPM.addPass(createModuleToFunctionPassAdaptor(llvm::VMFlattenPass(true, 2)));
                            //             MPM.addPass(createModuleToFunctionPassAdaptor(llvm::MBAObfuscation(true)));
                            //            MPM.addPass(createModuleToFunctionPassAdaptor(llvm::IndirectCallPass(true)));
                            //  MPM.addPass(llvm::StringEncryptionPass(
                            // true));
                            MPM.addPass(llvm::IntegrityCheckPass(true));
                            /*  MPM.addPass(llvm::FlatteningEnhanced(
                                    true)); */
                         /*    MPM.addPass(llvm::FlatteningEnhancedver2(
                                    true)); */

                            //  MPM.addPass(llvm::IndirectBranchPass(true));
                            // MPM.addPass(llvm::FunctionWrapperPass(true));
                            /*  MPM.addPass(createModuleToFunctionPassAdaptor(llvm::BogusControlFlowPass(true))); */

                            /*      MPM.addPass(createModuleToFunctionPassAdaptor(
                       llvm::FlatteningPass(true))); */

                            /* MPM.addPass(createModuleToFunctionPassAdaptor(llvm::TSXProtectPass(true)));
                   */
                        });
            }};
}
