#include "StringEncryption.h"
#include "Utils.h"          // 假设 toObfuscate 在此定义
#include "crypto_runtime.h" // 用于编译时加密

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Support/Path.h" // 新增

// 新增：用于链接运行时和读取位码的头文件
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/IR/DebugInfo.h"

#include <llvm/ADT/SmallString.h>
#include <random> // For std::random_device, std::mt19937
#include <string>
#include <vector>
#include <cstdlib> // 新增
#include <random> // For std::random_device, std::mt19937


#define DEBUG_TYPE "strenc"

using namespace llvm;

static cl::opt<bool> OnlyStr("mmonlystr",
                             cl::desc("Encrypt string variable only"),
                             cl::init(true));

// --- 辅助函数 ---

// 生成密码学安全的随机字节向量。
static std::vector<uint8_t> getRandomBytes(size_t n) {
  // 使用线程局部变量确保多线程安全和性能
  static thread_local std::random_device rd;
  static thread_local std::mt19937 gen(rd());
  std::uniform_int_distribution<uint8_t> dist(0, 255);

  std::vector<uint8_t> bytes(n);
  for (size_t i = 0; i < n; ++i) {
    bytes[i] = dist(gen);
  }
  return bytes;
}

// 生成一个在 [min, max] 范围内的安全随机整数。
static int getSecureRandomInt(int min, int max) {
  static thread_local std::random_device rd;
  static thread_local std::mt19937 gen(rd());
  std::uniform_int_distribution<> dist(min, max);
  return dist(gen);
}

// 基于全局变量名生成唯一的构造函数名。
static std::string genCtorName(GlobalVariable *GV) {
  return "ctor_dec_" + GV->getName().str();
}

// 将预编译的加密运行时模块链接到当前模块中。
static void linkRuntime(Module &M) {
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
  
  // 此变量将持有最终结果。先用一个通用错误来初始化。
  Expected<std::unique_ptr<MemoryBuffer>> bufferOrErr =
      errorCodeToError(std::make_error_code(std::errc::no_such_file_or_directory));

  // 1. 尝试从主路径加载
  if (!primaryPath.empty()) {
    // MemoryBuffer::getFile 返回 ErrorOr<...>, 它可以在if语句中被检查。
    // 如果成功，我们将持有的 buffer 移动到我们的 Expected 变量中。
    if (auto primaryBuffer = MemoryBuffer::getFile(primaryPath)) {
      bufferOrErr = std::move(*primaryBuffer);
    }
  }

  // 2. 如果主路径失败 (即 bufferOrErr 仍持有错误), 尝试从次路径加载
  if (!bufferOrErr) {
    if (auto secondaryBuffer = MemoryBuffer::getFile(secondaryPath)) {
      bufferOrErr = std::move(*secondaryBuffer);
    }
  }

  // 3. 如果两个路径都失败，则报错并退出
  if (!bufferOrErr) {
    consumeError(bufferOrErr.takeError()); // 清除错误以打印自定义消息
    errs() << "Error: 'crypto_runtime.bc' not found.\n";
    errs() << "Please compile crypto_runtime.cpp to LLVM bitcode and place it in one of the following locations:\n";
    if (!homePathDesc.empty()) {
      errs() << "  1. " << homePathDesc << " (preferred)\n";
    }
    errs() << "  2. The current working directory.(clang working directory)\n";
    return;
  }

  auto runtimeModuleOrErr =
      parseBitcodeFile(bufferOrErr.get()->getMemBufferRef(), M.getContext());
  if (Error err = runtimeModuleOrErr.takeError()) {
    handleAllErrors(std::move(err), [&](const ErrorInfoBase &EI) {
      errs() << "Error: Could not parse runtime bitcode file: " << EI.message()
             << "\n";
    });
    return;
  }
  std::unique_ptr<Module> runtimeModule = std::move(runtimeModuleOrErr.get());

  // 剥离调试信息
  StripDebugInfo(*runtimeModule);

  // 将所有非导出符号（除了我们需要的解密函数）的链接属性设为 internal
  for (Function &F : *runtimeModule) {
    if (F.getName() != "__aead_xchacha20_poly1305_decrypt" &&
        F.getName() != "__tsx_tamper_handler" && // 新增：同时保留TSX处理函数
        !F.isDeclaration()) {
      F.setLinkage(GlobalValue::InternalLinkage);
    }
  }

  Linker linker(M);
  if (linker.linkInModule(std::move(runtimeModule))) {
    errs() << "Error: Failed to link runtime module.\n";
  }
}

#define debug
#ifdef debug

#define debugprint(msg) \
  do { \
    outs() << "\033[1;33m[StringEncryption] " << msg << "\033[0m\n"; \
  } while (0)

#else
#define debugprint(msg) \
  do { \
    // 如果没有开启调试打印，则不输出任何内容
    (void)msg; // 避免未使用变量警告
  } while (0)
#endif

// --- Pass 主逻辑 ---

PreservedAnalyses StringEncryptionPass::run(Module &M,
                                            ModuleAnalysisManager &AM) {
  bool isToObfuscate = false;
  debugprint("Running StringEncryptionPass on module " + M.getName().str());
  for (Function &F : M) {
    if (toObfuscate(flag, &F, "strenc")) {
      isToObfuscate = true;
      break;
    }
  }
  if (!isToObfuscate) {
    return PreservedAnalyses::all();
  }

  // 每个进程只链接一次运行时模块。
  static bool runtimeLinked = false;
  if (!runtimeLinked) {
    linkRuntime(M);
    runtimeLinked = true;
  }

  std::vector<GlobalVariable *> GVs;
  for (GlobalVariable &GV : M.globals()) {
    GVs.push_back(&GV);
  }

  for (GlobalVariable *GV : GVs) {
    if (!GV->hasInitializer() || !GV->isConstant() ||
        !GV->getValueType()->isArrayTy()) {
      continue;
    }
    if (GV->hasSection() && (GV->getSection().contains("llvm.metadata") ||
                             GV->getSection().contains("OBJC"))) {
      continue;
    }
    if (OnlyStr && !GV->getName().contains(".str")) {
      continue;
    }

    auto *arrData = dyn_cast<ConstantDataArray>(GV->getInitializer());
    if (!arrData)
      continue;

    StringRef rawData = arrData->getAsString();
    if (rawData.empty())
      continue;

    std::vector<uint8_t> plaintext(rawData.begin(), rawData.end());

    // 1. 执行编译时加密
    // 使用全局变量的名称作为 AAD
    std::string gv_name = GV->getName().str();
    std::vector<uint8_t> aad(gv_name.begin(), gv_name.end());
    std::vector<uint8_t> key = getRandomBytes(32);
    std::vector<uint8_t> nonce =
        getRandomBytes(24); // Changed from 12 to 24 for XChaCha20
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
    xchacha20_poly1305_encrypt(key, nonce, aad, plaintext, ciphertext, tag);

    // 2. 创建新的加密数据结构: { [N x i8], [16 x i8] }
    LLVMContext &Ctx = M.getContext();
    Type *Int8Ty = Type::getInt8Ty(Ctx);
    Type *CiphertextTy = ArrayType::get(Int8Ty, ciphertext.size());
    Type *TagTy = ArrayType::get(Int8Ty, 16);
    StructType *EncryptedStructTy =
        StructType::create(Ctx, {CiphertextTy, TagTy}, "encrypted_payload");

    Constant *CiphertextConst = ConstantDataArray::get(Ctx, ciphertext);
    Constant *TagConst = ConstantDataArray::get(Ctx, tag);
    Constant *EncryptedStructConst =
        ConstantStruct::get(EncryptedStructTy, {CiphertextConst, TagConst});

    auto *EncryptedGV = new GlobalVariable(
        M, EncryptedStructTy, false, GlobalValue::PrivateLinkage,
        EncryptedStructConst, GV->getName() + ".enc");

    // 3. 将旧全局变量的所有用途替换为指向新结构体中密文成员的指针
    std::vector<Constant *> GEPIndices;
    GEPIndices.push_back(ConstantInt::get(Type::getInt32Ty(Ctx), 0));
    GEPIndices.push_back(ConstantInt::get(Type::getInt32Ty(Ctx), 0));
    Constant *ptrToCiphertext = ConstantExpr::getGetElementPtr(
        EncryptedStructTy, EncryptedGV, GEPIndices);

    GV->replaceAllUsesWith(ptrToCiphertext);
    GV->eraseFromParent();

    // 4. 在全局构造函数中生成运行时解密逻辑
    insertDecryptionCtor(M, EncryptedGV, EncryptedStructTy, key, nonce, aad);
  }

  return PreservedAnalyses::all();
}

void StringEncryptionPass::insertDecryptionCtor(
    Module &M, GlobalVariable *EncryptedGV, StructType *EncryptedStructTy,
    const std::vector<uint8_t> &key, const std::vector<uint8_t> &nonce,
    const std::vector<uint8_t> &aad) {
  LLVMContext &Ctx = M.getContext();

  FunctionType *CtorTy = FunctionType::get(Type::getVoidTy(Ctx), false);
  Function *CtorF = Function::Create(CtorTy, GlobalValue::InternalLinkage,
                                     genCtorName(EncryptedGV), &M);

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", CtorF);
  BasicBlock *DispatchBB = BasicBlock::Create(Ctx, "dispatch", CtorF);
  BasicBlock *EndBB = BasicBlock::Create(Ctx, "end", CtorF);

  IRBuilder<> Builder(EntryBB);

  // --- 策略1: 数据分散与双重随机化 ---
  // 随机化块大小 (4 or 8 bytes)
  const size_t possibleChunkSizes[] = { 4, 8};
  const size_t chunkSize =  possibleChunkSizes[getSecureRandomInt(0, 1)];

  // 随机化块数 (8-16)
  const int numChunks = getSecureRandomInt(8, 16);
  const size_t keySize = 32; // 密钥大小固定为32字节
  const size_t paddedKeySize = numChunks * chunkSize;

  // 根据随机的 chunkSize 获取对应的 LLVM 整数类型
  Type *ChunkIntTy = Type::getIntNTy(Ctx, chunkSize * 8);

  std::vector<uint8_t> paddedKey(paddedKeySize, 0);
  memcpy(paddedKey.data(), key.data(), keySize);

  std::vector<GlobalVariable *> obfuscatedKeyChunks;
  std::vector<GlobalVariable *> maskChunks;

  for (int i = 0; i < numChunks; ++i) {
    uint64_t keyChunk = 0; // 使用u64作为通用缓冲区
    uint64_t maskChunk = 0;
    memcpy(&keyChunk, paddedKey.data() + i * chunkSize, chunkSize);

    std::vector<uint8_t> randomMaskBytes = getRandomBytes(chunkSize);
    memcpy(&maskChunk, randomMaskBytes.data(), chunkSize);

    uint64_t obfuscatedChunk = keyChunk ^ maskChunk;

    obfuscatedKeyChunks.push_back(
        new GlobalVariable(M, ChunkIntTy, true, GlobalValue::PrivateLinkage,
                           ConstantInt::get(ChunkIntTy, obfuscatedChunk),
                           ".obf_key_chunk_" + std::to_string(i)));
    maskChunks.push_back(
        new GlobalVariable(M, ChunkIntTy, true, GlobalValue::PrivateLinkage,
                           ConstantInt::get(ChunkIntTy, maskChunk),
                           ".mask_chunk_" + std::to_string(i)));

    uint64_t dummy_data = 0;
    std::vector<uint8_t> dummy_bytes = getRandomBytes(chunkSize);
    memcpy(&dummy_data, dummy_bytes.data(), chunkSize);
    new GlobalVariable(M, ChunkIntTy, true, GlobalValue::PrivateLinkage,
                       ConstantInt::get(ChunkIntTy, dummy_data),
                       ".dummy_data_" + std::to_string(i));
  }

  // --- 策略2: 控制流平坦化 ---
  Type *KeyArrayTy = ArrayType::get(Type::getInt8Ty(Ctx), paddedKeySize);
  Value *deobfuscatedKeyPtr =
      Builder.CreateAlloca(KeyArrayTy, nullptr, "deobf_key_stack");

  Type *Int32Ty = Type::getInt32Ty(Ctx);
  Value *state = Builder.CreateAlloca(Int32Ty, nullptr, "state");
  Builder.CreateStore(Builder.getInt32(0), state);
  Builder.CreateBr(DispatchBB);

  Builder.SetInsertPoint(DispatchBB);
  Value *currentState = Builder.CreateLoad(Int32Ty, state, "current_state");
  SwitchInst *TheSwitch = Builder.CreateSwitch(currentState, EndBB, numChunks);

  for (int i = 0; i < numChunks; ++i) {
    BasicBlock *CaseBB =
        BasicBlock::Create(Ctx, "case_" + std::to_string(i), CtorF);
    TheSwitch->addCase(Builder.getInt32(i), CaseBB);
    Builder.SetInsertPoint(CaseBB);

    Value *obfChunk = Builder.CreateLoad(ChunkIntTy, obfuscatedKeyChunks[i]);
    Value *maskChunk = Builder.CreateLoad(ChunkIntTy, maskChunks[i]);
    Value *deobfChunk = Builder.CreateXor(obfChunk, maskChunk, "deobf_chunk");

    // 将恢复的块存回栈上的密钥数组
    Value *chunkPtr = Builder.CreateBitCast(deobfuscatedKeyPtr,
                                            PointerType::getUnqual(ChunkIntTy));
    Value *destPtr =
        Builder.CreateInBoundsGEP(ChunkIntTy, chunkPtr, Builder.getInt32(i));
    Builder.CreateStore(deobfChunk, destPtr);

    Builder.CreateStore(Builder.getInt32(i + 1), state);
    Builder.CreateBr(DispatchBB);
  }

  // --- 状态机结束，继续执行正常逻辑 ---
  Builder.SetInsertPoint(EndBB);

  // ... (后续调用解密函数的代码保持不变) ...
  Type *Int8Ty = Type::getInt8Ty(Ctx);
  Type *NonceArrayTy = ArrayType::get(Int8Ty, 24); // Changed from 12 to 24
  auto *NonceGV =
      new GlobalVariable(M, NonceArrayTy, true, GlobalValue::PrivateLinkage,
                         ConstantDataArray::get(Ctx, nonce), ".nonce");

  // 新增：创建并存储 AAD 数据作为全局变量
  Type *AadArrayTy = ArrayType::get(Int8Ty, aad.size());
  auto *AadGV = 
      new GlobalVariable(M, AadArrayTy, true, GlobalValue::PrivateLinkage,
                         ConstantDataArray::get(Ctx, aad), ".aad");

  Value *CiphertextPtr = Builder.CreateStructGEP(EncryptedStructTy, EncryptedGV,
                                                 0, "ciphertext.ptr");
  Value *TagPtr =
      Builder.CreateStructGEP(EncryptedStructTy, EncryptedGV, 1, "tag.ptr");

  Function *DecryptFunc = M.getFunction("__aead_xchacha20_poly1305_decrypt");
  if (!DecryptFunc) {
    errs() << "Error: Runtime function '__aead_xchacha20_poly1305_decrypt' not "
              "found after linking.\n";
    CtorF->eraseFromParent();
    return;
  }

  size_t ciphertext_len =
      cast<ArrayType>(EncryptedStructTy->getElementType(0))->getNumElements();

  Type *Int8PtrTy = PointerType::getUnqual(Ctx);
  Type *Int64Ty = Type::getInt64Ty(Ctx);

  Builder.CreateCall(DecryptFunc->getFunctionType(), DecryptFunc,
                     {CiphertextPtr, 
                      ConstantInt::get(Int64Ty, ciphertext_len),
                      Builder.CreatePointerCast(AadGV, Int8PtrTy),
                      ConstantInt::get(Int64Ty, aad.size()),
                      Builder.CreatePointerCast(deobfuscatedKeyPtr, Int8PtrTy),
                      Builder.CreatePointerCast(NonceGV, Int8PtrTy), 
                      TagPtr});

  Builder.CreateRetVoid();

  appendToGlobalCtors(M, CtorF, 0);
}

// Pass 注册
StringEncryptionPass *llvm::createStringEncryption(bool flag) {
  return new StringEncryptionPass(flag);
}