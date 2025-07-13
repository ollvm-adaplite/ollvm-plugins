// 这个PASS 通常没有什么作用因为大多数的CPU都不支持RTM
#include "TSXProtect.h"
#include "Utils.h" // 假设 toObfuscate 在此定义

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Analysis/TargetTransformInfo.h" // 新增
// #include "llvm/Target/X86/X86Subtarget.h"
#include "llvm/Target/TargetMachine.h" // 新增
#include "llvm/Support/Path.h" // 新增
#include "llvm/IR/DebugInfo.h" // 新增

// 新增：用于链接运行时和读取位码的头文件
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/MemoryBuffer.h"
#define debug
#ifdef debug

#define debugprint(msg)                                                        \
  do {                                                                         \
    outs() << "\033[1;33m[TSXProtect] " << msg << "\033[0m\n";                 \
  } while (0)

#else
#define debugprint(msg)                                                        \
  do {                                                                         \
  // 如果没有开启调试打印，则不输出任何内容
(void)msg; // 避免未使用变量警告
}
while (0)
#endif

using namespace llvm;

#define DEBUG_TYPE "tsx-protect"

// 命令行选项，用于全局启用此 Pass
static cl::opt<bool>
    EnableTSXProtect("tsx-protect",
                     cl::desc("Enable TSX-based anti-hooking protection"),
                     cl::init(false));

// TSX事务成功开始时，_xbegin返回的常量
constexpr int XBEGIN_STARTED = -1;

// 将预编译的运行时模块链接到当前模块中。
// 此函数借鉴自 StringEncryption.cpp
static void linkRuntime(Module &M) {
  debugprint("Linking TSXProtect runtime module...");
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
  
  Expected<std::unique_ptr<MemoryBuffer>> bufferOrErr =
      errorCodeToError(std::make_error_code(std::errc::no_such_file_or_directory));

  // 1. 尝试从主路径加载
  if (!primaryPath.empty()) {
    if (auto primaryBuffer = MemoryBuffer::getFile(primaryPath)) {
      bufferOrErr = std::move(*primaryBuffer);
    }
  }

  // 2. 如果主路径失败, 尝试从次路径加载
  if (!bufferOrErr) {
    if (auto secondaryBuffer = MemoryBuffer::getFile(secondaryPath)) {
      bufferOrErr = std::move(*secondaryBuffer);
    }
  }

  // 3. 如果两个路径都失败，则报错并退出
  if (!bufferOrErr) {
    consumeError(bufferOrErr.takeError()); // 清除错误以打印自定义消息
    errs() << "TSXProtect Error: 'crypto_runtime.bc' not found.\n";
    errs() << "Please compile crypto_runtime.cpp to LLVM bitcode and place it in one of the following locations:\n";
    if (!homePathDesc.empty()) {
      errs() << "  1. " << homePathDesc << " (preferred)\n";
    }
    errs() << "  2. The current working directory.\n";
    return;
  }

  auto runtimeModuleOrErr =
      parseBitcodeFile(bufferOrErr.get()->getMemBufferRef(), M.getContext());
  if (Error err = runtimeModuleOrErr.takeError()) {
    handleAllErrors(std::move(err), [&](const ErrorInfoBase &EI) {
      errs() << "TSXProtect Error: Could not parse runtime bitcode file: "
             << EI.message() << "\n";
    });
    return;
  }
  std::unique_ptr<Module> runtimeModule = std::move(runtimeModuleOrErr.get());

  // 剥离调试信息以减小最终二进制文件大小
  StripDebugInfo(*runtimeModule);

  // 将所有非导出符号（除了我们需要的API函数）的链接属性设为 internal
  // 这样做可以帮助优化器移除未使用的函数
  for (Function &F : *runtimeModule) {
    if (F.getName() != "__tsx_tamper_handler" &&
        F.getName() != "__aead_xchacha20_poly1305_decrypt" &&
        !F.isDeclaration()) {
      F.setLinkage(GlobalValue::InternalLinkage);
    }
  }

  Linker linker(M);
  if (linker.linkInModule(std::move(runtimeModule))) {
    errs() << "TSXProtect Error: Failed to link runtime module.\n";
  }
  debugprint("TSXProtect runtime module linked successfully.");
}

/* 将 cpuid.h 的包含移到全局作用域 */
#if !defined(__i386__) && !defined(__x86_64__)
/* 非 x86 架构不需要包含 cpuid.h */
#else
#if __has_include(<cpuid.h>)
#include <cpuid.h>
#endif
#endif
static __inline__ int cpu_has_rtm(void) {
#if !defined(__i386__) && !defined(__x86_64__)
  /* 非 x86 架构直接返回 0 */
  return 0;
#else
  /* ① 先尝试 GCC / Clang 提供的 <cpuid.h>  */
#if __has_include(<cpuid.h>)
  unsigned int eax, ebx, ecx, edx;
  if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx))
    return 0;             /* CPUID 07H 不存在 */
  return (ebx >> 11) & 1; /* EBX.bit11 == RTM */

#else /* ② 没有 <cpuid.h> → fallback 到内联汇编 */

#if defined(__x86_64__)
  /* ---------------- 64‑bit ---------------- */
  unsigned int ebx;
  __asm__ volatile("cpuid"
                   : "=b"(ebx) /* EBX 输出 */
                   : "a"(7), "c"(0)
                   : "edx");
  return (ebx >> 11) & 1;

#else /* ----------- 32‑bit i386 ----------- */
  unsigned int ebx, tmp;

#if defined(__PIC__)
  /* 在 32‑bit PIC 下 EBX 是 GOT 指针 —— 必须手动保存 */
  __asm__ volatile("xchg{l} %%ebx, %1 \n\t" /* 保存 EBX → tmp */
                   "cpuid                 \n\t"
                   "xchg{l} %%ebx, %1" /* 恢复 EBX */
                   : "=a"(tmp), "+r"(tmp), "=c"(tmp), "=d"(tmp), "=b"(ebx)
                   : "a"(7), "c"(0)
                   : "cc");
#else
  __asm__ volatile("cpuid" : "=b"(ebx) : "a"(7), "c"(0) : "edx");
#endif /* __PIC__ */

  return (ebx >> 11) & 1;
#endif /* __x86_64__ */
#endif /* <cpuid.h> */
#endif /* !x86 */
}

PreservedAnalyses TSXProtectPass::run(Function &F,
                                      FunctionAnalysisManager &AM) {

  if (!Triple(F.getParent()->getTargetTriple()).isX86()) {
    return PreservedAnalyses::all();
  }
  // 检查是否启用此 Pass
  if (!RTMchecked && hasRTM) {
    this->hasRTM = cpu_has_rtm();
  }
  if(!hasRTM) {
    errs() << "TSXProtect: CPU does not support RTM, skipping TSXProtectPass.\n";
    return PreservedAnalyses::all();
  }

  debugprint("Running TSXProtectPass on function " + F.getName().str());
  // 检查是否需要对该函数进行混淆

  if (!toObfuscate(Enabled, &F, "tsx")) {
    return PreservedAnalyses::all();
  }

  // 如果函数是声明（没有函数体），则跳过
  if (F.isDeclaration()) {
    return PreservedAnalyses::all();
  }

  // 避免保护中止处理函数自身及相关函数，防止无限递归
  if (F.getName() == "__tsx_tamper_handler" ||
      F.getName().starts_with("secure_terminate")) {
    return PreservedAnalyses::all();
  }
  F.addFnAttr("target-features", "+rtm");

  Module *M = F.getParent();

  // 每个模块只链接一次运行时。使用一个静态标志来防止重复链接。
  static bool runtimeLinked = false;
  if (!runtimeLinked) {
    linkRuntime(*M);
    runtimeLinked = true;

    /* // **新增：链接后立即验证关键函数是否存在**
    if (!M->getFunction("__tsx_tamper_handler")) {
      errs()
          << "TSXProtect FATAL ERROR: Runtime function '__tsx_tamper_handler' "
             "not found after linking crypto_runtime.bc. "
          << "Please ensure crypto_runtime.bc is compiled correctly and "
             "available in the execution path.\n";
      // 放弃对该函数的混淆，因为依赖项缺失
      return PreservedAnalyses::all();
    } */

  }

  errs() << "TSXProtect: Applying transaction protection to function @"
         << F.getName() << "\n";

  LLVMContext &Ctx = M->getContext();
  IRBuilder<> Builder(Ctx);

  // 1. 获取或插入LLVM的TSX内在函数和我们的中止处理函数
  FunctionCallee XBegin =
      M->getOrInsertFunction("llvm.x86.xbegin", Builder.getInt32Ty());
  FunctionCallee XEnd =
      M->getOrInsertFunction("llvm.x86.xend", Builder.getVoidTy());

  // 注意：__tsx_tamper_handler 现在从链接的 crypto_runtime.bc 中获取。
  FunctionCallee TamperHandler =
      M->getOrInsertFunction("__tsx_tamper_handler", Builder.getVoidTy());

  // 2. 重构函数控制流，以包裹原始函数体
  BasicBlock *EntryBB = &F.getEntryBlock();
  BasicBlock *TxBodyBB = EntryBB->splitBasicBlock(EntryBB->begin(), "tsx.body");
  BasicBlock *AbortBB = BasicBlock::Create(Ctx, "tsx.abort", &F);

  // 清空原入口块的终结指令，并填充新的TSX启动逻辑
  EntryBB->getTerminator()->eraseFromParent();
  Builder.SetInsertPoint(EntryBB);

  // 3. 在新的入口块中构建TSX启动逻辑
  Value *Status = Builder.CreateCall(XBegin, {}, "tsx.status");
  Value *SuccessCond = Builder.CreateICmpEQ(
      Status, Builder.getInt32(XBEGIN_STARTED), "tsx.success");
  Builder.CreateCondBr(SuccessCond, TxBodyBB, AbortBB);

  // 4. 构建中止逻辑块
  Builder.SetInsertPoint(AbortBB);
  Builder.CreateCall(TamperHandler, {});
  // 调用处理函数后，程序不应继续正常执行，以防止绕过
  Builder.CreateUnreachable();

  // 5. 在所有函数退出点前插入 _xend 指令
  for (BasicBlock &BB : F) {
    // 获取基本块的终结指令。这种写法兼容性更好。
    auto *TI = BB.getTerminator();

    // 确保基本块有终结指令
    if (TI != nullptr) {
      // 同时处理常规返回 (ret) 和异常处理路径返回 (resume)
      if (isa<ReturnInst>(TI) || isa<ResumeInst>(TI)) {
        Builder.SetInsertPoint(TI);
        Builder.CreateCall(XEnd, {});
      }
    }
  }

  // 因为我们修改了CFG，所以不能保留任何分析结果
  return PreservedAnalyses::none();
}

// 工厂函数实现
TSXProtectPass *llvm::createTSXProtectPass(bool flag) {
  return new TSXProtectPass(flag);
}
