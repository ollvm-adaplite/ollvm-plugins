#include "IntegrityCheck.h"
#include "Utils.h" // 假设 toObfuscate 在此定义

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include <llvm/ADT/SmallString.h>

#include <algorithm>
#include <cstdlib>
#include <map>
#include <set> // 用于黑名单
#include <string>
#include <vector>

#define DEBUG_TYPE "integrity-check"

using namespace llvm;
#define debug
#ifdef debug
#define debugprint(fmt, ...)                                                   \
  do {                                                                         \
    fprintf(stderr, fmt, ##__VA_ARGS__);                                       \
  } while (0)
#else
#define debugprint(fmt, ...)                                                   \
  do {                                                                         \
  } while (0)
#endif

static void linkRuntime(Module &M) {
  debugprint("Linking runtime module...");
  SmallString<256> primaryPath;
  std::string homePathDesc;

#ifdef _WIN32
  const char *homeEnv = getenv("USERPROFILE");
  if (homeEnv) {
    primaryPath.assign(homeEnv);
    sys::path::append(primaryPath, ".ollvm", "crypto_runtime.bc");
    homePathDesc = "%USERPROFILE%\\.ollvm";
  }
#else
  const char *homeEnv = getenv("HOME");
  if (homeEnv) {
    primaryPath.assign(homeEnv);
    sys::path::append(primaryPath, ".ollvm", "crypto_runtime.bc");
    homePathDesc = "$HOME/.ollvm";
  }
#endif

  StringRef secondaryPath = "crypto_runtime.bc";

  Expected<std::unique_ptr<MemoryBuffer>> bufferOrErr = errorCodeToError(
      std::make_error_code(std::errc::no_such_file_or_directory));

  if (!primaryPath.empty()) {
    if (auto primaryBuffer = MemoryBuffer::getFile(primaryPath)) {
      bufferOrErr = std::move(*primaryBuffer);
    }
  }

  if (!bufferOrErr) {
    if (auto secondaryBuffer = MemoryBuffer::getFile(secondaryPath)) {
      bufferOrErr = std::move(*secondaryBuffer);
    }
  }

  if (!bufferOrErr) {
    consumeError(bufferOrErr.takeError());
    errs() << "IntegrityCheck Error: 'crypto_runtime.bc' not found.\n";
    return;
  }

  auto runtimeModuleOrErr =
      parseBitcodeFile(bufferOrErr.get()->getMemBufferRef(), M.getContext());
  if (Error err = runtimeModuleOrErr.takeError()) {
    handleAllErrors(std::move(err), [&](const ErrorInfoBase &EI) {
      errs() << "IntegrityCheck Error: Could not parse runtime bitcode file: "
             << EI.message() << "\n";
    });
    return;
  }
  std::unique_ptr<Module> runtimeModule = std::move(runtimeModuleOrErr.get());
#ifndef debug
  StripDebugInfo(*runtimeModule);
#endif

  // --- START OF CHANGE 1 ---
  // 将运行时库中所有全局符号的链接类型设置为 WeakODR。
  // 这允许链接器在遇到多个定义时合并它们，而不会报错。
  for (Function &F : *runtimeModule) {
    if (F.hasExternalLinkage()) {
      F.setLinkage(GlobalValue::WeakODRLinkage);
    }
  }
  for (GlobalVariable &GV : runtimeModule->globals()) {
    if (GV.hasExternalLinkage()) {
      GV.setLinkage(GlobalValue::WeakODRLinkage);
    }
  }
  // --- END OF CHANGE ---

  debugprint("Linking runtime module with %zu functions.\n",
             runtimeModule->size());

  if (Linker::linkModules(M, std::move(runtimeModule))) {
    errs() << "IntegrityCheck Error: Failed to link runtime module.\n";
  }
}

PreservedAnalyses IntegrityCheckPass::run(Module &M,
                                          ModuleAnalysisManager &AM) {
  bool isToObfuscate = false;
  for (Function &F : M) {
    if (toObfuscate(flag, &F, "intcheck")) {
      isToObfuscate = true;
      break;
    }
  }
  if (!isToObfuscate) {
    return PreservedAnalyses::all();
  }

  debugprint("IntegrityCheckPass: Module %s is marked for obfuscation.\n",
             M.getName().str().c_str());

  static bool runtimeLinked = false;
  if (!runtimeLinked) {
    linkRuntime(M);
    runtimeLinked = true;
  }

  LLVMContext &Ctx = M.getContext();

  // --- 1. 收集所有带 "no_ic_instrument" 注解的函数 ---
  // 我们通过解析 llvm.global.annotations 这个特殊的全局变量来找到它们。
  // 这些函数（主要来自 crypto_runtime.cpp）不应该被插桩，以避免无限递归。
  std::set<Function *> noInstrumentFuncs;
  if (GlobalVariable *GA = M.getGlobalVariable("llvm.global.annotations")) {
    if (ConstantArray *CA = dyn_cast<ConstantArray>(GA->getInitializer())) {
      for (Value *Op : CA->operands()) {
        if (ConstantStruct *CS = dyn_cast<ConstantStruct>(Op)) {
          if (Function *F =
                  dyn_cast<Function>(CS->getOperand(0)->stripPointerCasts())) {
            if (GlobalVariable *AnnotationGL = dyn_cast<GlobalVariable>(
                    CS->getOperand(1)->stripPointerCasts())) {
              if (Constant *Initializer = AnnotationGL->getInitializer()) {
                if (ConstantDataArray *CDA =
                        dyn_cast<ConstantDataArray>(Initializer)) {
                  StringRef Annotation = CDA->getAsString();
                  if (Annotation.starts_with("no_ic_instrument")) {
                    noInstrumentFuncs.insert(F);
                    debugprint("  - Found no_ic_instrument on: %s\n",
                               F->getName().str().c_str());
                  }
                }
              }
            }
          }
        }
      }
    }
    // 注解已被处理，可以安全地移除这个全局变量，减小最终文件大小
    GA->eraseFromParent();
  }

  // --- 2. 收集所有需要“保护”的函数 (不再检查链接属性) ---
  std::vector<Function *> protectedFuncs;

  // 定义一个函数名黑名单。包含这些子串的函数将被忽略，以避免链接问题。
  const std::vector<StringRef> nameBlacklist = {
      "allocat", "deallocat",
      "stringbuf", // 针对 std::basic_stringbuf
                               // 您可以根据遇到的链接错误，向这个列表添加更多关键字
  };

  // 规则1：跳过函数声明、我们自己的校验/运行时函数，以及被注解的函数
  for (Function &F : M) {
    StringRef funcName = F.getName();

    // 规则1：跳过函数声明、我们自己的校验/运行时函数，以及被注解的函数

    if (F.isDeclaration() || funcName == "__verify_self_integrity" ||
        funcName == "__verify_memory_integrity" ||
        noInstrumentFuncs.count(&F)) {
      continue;
    }

    if (!F.hasExternalLinkage() && !F.hasInternalLinkage()) {
      debugprint("  - Skipping function with weak/special linkage: %s\n",
                 funcName.str().c_str());
      continue;
    }

    // 规则2：检查函数名是否包含黑名单中的任何子串
    bool isBlacklisted = false;
    for (const auto &blacklistedStr : nameBlacklist) {
      if (funcName.contains(blacklistedStr)) {
        debugprint("  - Skipping blacklisted function: %s (contains '%s')\n",
                   funcName.str().c_str(), blacklistedStr.str().c_str());
        isBlacklisted = true;
        break;
      }
    }
    if (isBlacklisted) {
      continue;
    }

    // 如果通过了所有检查，则将其添加到保护列表
    protectedFuncs.push_back(&F);
  }

  // 排序以确保 Pass 和 Python 脚本的顺序一致
  std::sort(protectedFuncs.begin(), protectedFuncs.end(),
            [](const Function *A, const Function *B) {
              return A->getName() < B->getName();
            });

  debugprint("Found %zu total functions to protect (including internal).\n",
             protectedFuncs.size());

  // --- 3. 创建所有占位符和新的标记表 ---

  

  // 1. 定义标记结构体类型: struct FuncMarker { const char* name; const void*
  // addr; };
  StructType *FuncMarkerTy = StructType::getTypeByName(Ctx, "FuncMarker");
  if (!FuncMarkerTy) {
    FuncMarkerTy =
        StructType::create(Ctx,
                           {PointerType::getUnqual(Type::getInt8Ty(Ctx)),
                            PointerType::getUnqual(Type::getInt8Ty(Ctx))},
                           "FuncMarker");
  }

  // 2. 为所有受保护的函数创建标记条目
  std::vector<Constant *> markerEntries;
  for (Function *F : protectedFuncs) {
    // 为函数名创建一个全局字符串常量
    Constant *funcNameStr =
        ConstantDataArray::getString(Ctx, F->getName(), true);
    auto *funcNameGV =
        new GlobalVariable(M, funcNameStr->getType(), true,
                           GlobalValue::PrivateLinkage, funcNameStr, ".str");
    funcNameGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

    // 获取函数名和函数本身的指针
    Constant *funcNamePtr = ConstantExpr::getPointerCast(
        funcNameGV, PointerType::getUnqual(Type::getInt8Ty(Ctx)));
    Constant *funcAddrPtr = ConstantExpr::getPointerCast(
        F, PointerType::getUnqual(Type::getInt8Ty(Ctx)));

    // 创建标记结构体常量
    markerEntries.push_back(
        ConstantStruct::get(FuncMarkerTy, {funcNamePtr, funcAddrPtr}));
  }

  // 3. 创建标记表本身
  ArrayType *MarkerTableTy = ArrayType::get(FuncMarkerTy, markerEntries.size());
  Constant *MarkerTableInitializer =
      ConstantArray::get(MarkerTableTy, markerEntries);
  auto *markerTableGV =
      new GlobalVariable(M, MarkerTableTy, true, GlobalValue::ExternalLinkage,
                         MarkerTableInitializer, "__ic_function_marker_table");
  markerTableGV->setSection(".ic_markers,a"); // 移除 'w' 标志，设为只读

  // --- END OF NEW IMPLEMENTATION ---

  // --- START OF CHANGE ---
  // 核心修复：在创建具名结构体之前，先按名称查找。
  // 这可以防止在 LTO 模式下因合并多个编译单元而导致重复的类型定义。
  StructType *EncryptedHashTy =
      StructType::getTypeByName(Ctx, "encrypted_hash");
  if (!EncryptedHashTy) {
    EncryptedHashTy =
        StructType::create(Ctx,
                           {ArrayType::get(Type::getInt8Ty(Ctx), 32),
                            ArrayType::get(Type::getInt8Ty(Ctx), 24),
                            ArrayType::get(Type::getInt8Ty(Ctx), 16)},
                           "encrypted_hash");
  }
  // --- END OF CHANGE ---

  // --- 核心修复：查找并安全地修改/替换弱符号，避免悬空指针 ---

  // 将所有 Pass 创建的全局变量的链接类型从 ExternalLinkage 更改为
  // WeakODRLinkage。
  GlobalVariable *textHashGV =
      M.getGlobalVariable("__text_section_encrypted_hash");
  if (textHashGV) {
    textHashGV->setLinkage(GlobalValue::WeakODRLinkage);
    textHashGV->setInitializer(ConstantAggregateZero::get(EncryptedHashTy));
  } else {
    textHashGV = new GlobalVariable(M, EncryptedHashTy, true,
                                    GlobalValue::WeakODRLinkage,
                                    ConstantAggregateZero::get(EncryptedHashTy),
                                    "__text_section_encrypted_hash");
  }
  textHashGV->setSection(".ic_texthash,a"); // 移除 'w' 标志，设为只读

  // 处理 __integrity_check_key (类型匹配，可以直接修改)
  Type *KeyTy = ArrayType::get(Type::getInt8Ty(Ctx), 32);
  GlobalVariable *keyGV = M.getGlobalVariable("__integrity_check_key");
  if (keyGV) {
    keyGV->setLinkage(GlobalValue::WeakODRLinkage);
    keyGV->setInitializer(ConstantAggregateZero::get(KeyTy));
  } else {
    keyGV = new GlobalVariable(M, KeyTy, true, GlobalValue::WeakODRLinkage,
                               ConstantAggregateZero::get(KeyTy),
                               "__integrity_check_key");
  }
  keyGV->setSection(".ic_key,a"); // 移除 'w' 标志，设为只读

  // 处理 __protected_funcs_info_table (类型不匹配，必须安全替换)
  // --- START OF CHANGE ---
  // 对 protected_func_info 结构体也应用相同的“检查-若不存在则创建”模式。
  StructType *FuncInfoTy =
      StructType::getTypeByName(Ctx, "protected_func_info");
  if (!FuncInfoTy) {
    FuncInfoTy = StructType::create(
        Ctx, {Type::getInt64Ty(Ctx), Type::getInt64Ty(Ctx), EncryptedHashTy},
        "protected_func_info");
  }
  // --- END OF CHANGE ---

  // --- FIX: Allocate enough space for the worst-case scenario ---
  // The table must be large enough to hold all candidate functions plus one
  // terminator.
  ArrayType *InfoTableTy =
      ArrayType::get(FuncInfoTy, protectedFuncs.size() + 1);

  // 核心修复：创建一个非零的初始化器来填充表格。
  // 这可以防止链接器将 .ic_functable 节优化为 .bss
  // 节（只在内存中，不从文件加载）。
  // 通过提供非零的初始数据，我们强制链接器将其作为 .data 节处理，
  // 确保 encheck.py 写入的数据在程序启动时被加载到内存。

  // 1. 为 encrypted_hash 创建一个虚拟的非零常量
  Constant *dummyEncHash = ConstantStruct::get(
      EncryptedHashTy,
      {ConstantDataArray::get(
           Ctx, ArrayRef<uint8_t>(std::vector<uint8_t>(32, 0xAA))),
       ConstantDataArray::get(
           Ctx, ArrayRef<uint8_t>(std::vector<uint8_t>(24, 0xBB))),
       ConstantDataArray::get(
           Ctx, ArrayRef<uint8_t>(std::vector<uint8_t>(16, 0xCC)))});

  // 2. 为 protected_func_info 创建一个虚拟的非零常量
  Constant *dummyFuncInfo = ConstantStruct::get(
      FuncInfoTy, {ConstantInt::get(Type::getInt64Ty(Ctx), 1), // dummy addr
                   ConstantInt::get(Type::getInt64Ty(Ctx), 1), // dummy size
                   dummyEncHash});

  // 3. 创建一个由虚拟条目组成的数组，以填充整个预留空间
  std::vector<Constant *> dummyTableEntries(protectedFuncs.size() + 1,
                                            dummyFuncInfo);
  Constant *TableInitializer =
      ConstantArray::get(InfoTableTy, dummyTableEntries);

  GlobalVariable *tableGV;
  if (GlobalVariable *OldGV =
          M.getGlobalVariable("__protected_funcs_info_table")) {
    // 1. 创建新的、类型正确的全局变量，使用临时名称
    auto *NewGV = new GlobalVariable(
        M, InfoTableTy, true, GlobalValue::WeakODRLinkage, TableInitializer,
        "__protected_funcs_info_table_new");

    // 2. 将所有对旧变量的引用替换为对新变量的引用（通过bitcast保持类型兼容）
    if (!OldGV->use_empty()) {
      Constant *CastedNewGV = ConstantExpr::getBitCast(NewGV, OldGV->getType());
      OldGV->replaceAllUsesWith(CastedNewGV);
    }

    // 3. 现在可以安全地删除旧变量了
    OldGV->eraseFromParent();

    // 4. 将新变量重命名为最终名称
    NewGV->setName("__protected_funcs_info_table");
    tableGV = NewGV;
  } else {
    // Fallback: 如果弱符号不存在，直接创建
    tableGV =
        new GlobalVariable(M, InfoTableTy, true, GlobalValue::WeakODRLinkage,
                           TableInitializer, "__protected_funcs_info_table");
  }
  tableGV->setSection(".ic_functable,a"); // 移除 'w' 标志，设为只读

  // // 函数名列表 (.ic_fnames) 现在是可选的
  // std::string name_blob;
  // for (const auto *F : protectedFuncs) {
  //   name_blob += F->getName().str();
  //   name_blob += '\0';
  // }
  // ArrayType *NameListTy =
  //     ArrayType::get(Type::getInt8Ty(Ctx), name_blob.size());
  // Constant *NameListData = ConstantDataArray::getString(Ctx, name_blob,
  // false); auto *nameListGV =
  //     new GlobalVariable(M, NameListTy, true, GlobalValue::WeakODRLinkage,
  //                        NameListData, "__protected_funcs_name_list");

  // // --- END OF CHANGE 2 ---

  // // --- START OF CHANGE 4 ---
  // // 函数名列表是只读的，所以只需要 "a" (ALLOC) 标志
  // nameListGV->setSection(".ic_fnames,a");
  // // --- END OF CHANGE 4 ---

  appendToUsed(M, {textHashGV, keyGV, tableGV, markerTableGV});

  // --- 4. 注入静态校验逻辑 (不变) ---
  FunctionCallee VerifySelfFunc =
      M.getOrInsertFunction("__verify_self_integrity", Type::getVoidTy(Ctx));
  Function *CtorFunc =
      Function::Create(FunctionType::get(Type::getVoidTy(Ctx), false),
                       GlobalValue::InternalLinkage, "__integrity_ctor", &M);
  BasicBlock *CtorBB = BasicBlock::Create(Ctx, "entry", CtorFunc);
  IRBuilder<> CtorBuilder(CtorBB);
  CtorBuilder.CreateCall(VerifySelfFunc, {});
  CtorBuilder.CreateRetVoid();
  appendToGlobalCtors(M, CtorFunc, 0, nullptr);

  // --- 5. 注入动态校验逻辑 (核心修改) ---
  // --- NEW: The verification function now takes a pointer (address) ---
  FunctionCallee VerifyMemFunc =
      M.getOrInsertFunction("__verify_memory_integrity", Type::getVoidTy(Ctx),
                            PointerType::getUnqual(Type::getInt8Ty(Ctx)));

  // The funcIndexMap is no longer needed.
  // std::map<Function *, int> funcIndexMap;
  // for (size_t i = 0; i < protectedFuncs.size(); ++i) {
  //   funcIndexMap[protectedFuncs[i]] = i;
  // }

  // **只对不在属性黑名单中的函数进行插桩**
  for (Function *F : protectedFuncs) {
    // 如果函数带有 "no_ic_instrument" 属性，或者以"__"开头，则跳过插桩
    if (noInstrumentFuncs.count(F)) {
      debugprint("  - Skipping instrumentation for '%s' (Attribute)\n",
                 F->getName().str().c_str());
      continue;
    }
    if (F->getName().starts_with("__")) {
      debugprint("  - Skipping instrumentation for '%s' (Prefix)\n",
                 F->getName().str().c_str());
      continue;
    }

    // --- NEW: Pass the function's address directly ---
    debugprint("  - Instrumenting function: '%s' (Passing address)\n",
               F->getName().str().c_str());

    // Cast the function pointer to i8* to match the callee signature
    Constant *funcPtr = ConstantExpr::getPointerCast(
        F, PointerType::getUnqual(Type::getInt8Ty(Ctx)));

    IRBuilder<> EntryBuilder(&F->getEntryBlock().front());
    EntryBuilder.CreateCall(VerifyMemFunc, {funcPtr});

    for (BasicBlock &BB : *F) {
      if (auto *Ret = dyn_cast<ReturnInst>(BB.getTerminator())) {
        IRBuilder<> ExitBuilder(Ret);
        ExitBuilder.CreateCall(VerifyMemFunc, {funcPtr});
      }
    }
  }

  return PreservedAnalyses::none();
}

IntegrityCheckPass *llvm::createIntegrityCheck(bool flag) {
  return new IntegrityCheckPass(flag);
}