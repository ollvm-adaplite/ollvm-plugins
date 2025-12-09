#include "IntegrityCheck.h"
#include "Utils.h" 

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/Cloning.h" 

#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include <llvm/ADT/SmallString.h>

#include <algorithm>
#include <cstdlib>
#include <map>
#include <set> 
#include <string>
#include <vector>
#include <random>


#define DEBUG_TYPE "integrity-check"

#define debug

using namespace llvm;

static cl::opt<int> CheckProbability("ic-prob", 
    cl::desc("Probability (0-100) to inject MBA-based integrity check dependencies"), 
    cl::init(40));

#ifdef debug
#define debugprint(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define debugprint(fmt, ...)
#endif




// ============================================================================
// Internal MBA Helper Functions
// ============================================================================
namespace {
    
    // -------------------------------------------------------------------------
    // Utils
    // -------------------------------------------------------------------------
    bool getBool() {
        static std::mt19937 rng(std::random_device{}());
        return std::uniform_int_distribution<int>(0, 1)(rng);
    }

    int getRange(int min, int max) {
        static std::mt19937 rng(std::random_device{}());
        return std::uniform_int_distribution<int>(min, max)(rng);
    }

    // -------------------------------------------------------------------------
    // Phase 1: Recursive MBA Tree Generation (The "True" Logic)
    // -------------------------------------------------------------------------
    Value* generateMBATree(IRBuilder<> &Builder, Value *A, Value *B, unsigned OpCode, int Depth) {
        if (Depth <= 0 || !A->getType()->isIntegerTy()) {
            switch (OpCode) {
                case Instruction::Add: return Builder.CreateAdd(A, B);
                case Instruction::Sub: return Builder.CreateSub(A, B);
                case Instruction::Xor: return Builder.CreateXor(A, B);
                case Instruction::And: return Builder.CreateAnd(A, B);
                case Instruction::Or:  return Builder.CreateOr(A, B);
                default: return Builder.CreateAdd(A, B);
            }
        }

        switch (OpCode) {
            case Instruction::Add: {
                // Identity: x + y = (x ^ y) + 2*(x & y)
                // Expanded: (x ^ y) + ((x & y) << 1)
                Value *Xor = generateMBATree(Builder, A, B, Instruction::Xor, Depth - 1);
                Value *And = generateMBATree(Builder, A, B, Instruction::And, Depth - 1);
                Value *TwoAnd = Builder.CreateMul(And, ConstantInt::get(A->getType(), 2));
                return Builder.CreateAdd(Xor, TwoAnd);
            }
            case Instruction::Sub: {
                // Identity: x - y = (x ^ y) - 2*(~x & y)
                Value *Xor = generateMBATree(Builder, A, B, Instruction::Xor, Depth - 1);
                Value *NotA = Builder.CreateNot(A);
                Value *And = generateMBATree(Builder, NotA, B, Instruction::And, Depth - 1);
                Value *Term2 = Builder.CreateMul(And, ConstantInt::get(A->getType(), 2));
                return Builder.CreateSub(Xor, Term2);
            }
            case Instruction::Xor: {
                // Identity: x ^ y = (x | y) - (x & y)
                Value *Or = generateMBATree(Builder, A, B, Instruction::Or, Depth - 1);
                Value *And = generateMBATree(Builder, A, B, Instruction::And, Depth - 1);
                return Builder.CreateSub(Or, And);
            }
            case Instruction::And: {
                // Identity: x & y = ~(~x | ~y) (De Morgan)
                Value *NotA = Builder.CreateNot(A);
                Value *NotB = Builder.CreateNot(B);
                Value *Or = generateMBATree(Builder, NotA, NotB, Instruction::Or, Depth - 1);
                return Builder.CreateNot(Or);
            }
            case Instruction::Or: {
                // Identity: x | y = (x + y) - (x & y)
                Value *Add = generateMBATree(Builder, A, B, Instruction::Add, Depth - 1);
                Value *And = generateMBATree(Builder, A, B, Instruction::And, Depth - 1);
                return Builder.CreateSub(Add, And);
            }
        }
        return Builder.CreateAdd(A, B);
    }

    // -------------------------------------------------------------------------
    // Phase 2: Convergent Chaos Loop
    // -------------------------------------------------------------------------
    // 在当前 BB 插入一个计算 LCG 的循环，以此生成一个不透明谓词 (Always True)。
    // 副作用：会分割 BasicBlock，修改 CFG。
    Value* createOpaquePredicateLoop(IRBuilder<> &Builder) {
        Function *F = Builder.GetInsertBlock()->getParent();
        LLVMContext &Ctx = F->getContext();
        
        // 1. 准备 CFG 修改
        // 当前插入点所在的 Block 为 PreBB
        BasicBlock *PreBB = Builder.GetInsertBlock();
        // 将原 Block 从插入点切分，后半部分为 MergeBB
        BasicBlock *MergeBB = PreBB->splitBasicBlock(Builder.GetInsertPoint(), "ic.chaos.merge");
        
        // 移除 splitBasicBlock 自动创建的无条件跳转，我们需要插入自己的流图
        PreBB->getTerminator()->eraseFromParent();
        
        // 创建循环结构 Block
        BasicBlock *HeaderBB = BasicBlock::Create(Ctx, "ic.chaos.header", F, MergeBB);
        BasicBlock *BodyBB   = BasicBlock::Create(Ctx, "ic.chaos.body", F, MergeBB);

        // -------------------------------------------------
        // 2. PreBB -> Header
        // -------------------------------------------------
        Builder.SetInsertPoint(PreBB);
        
        // LCG 参数 Setup (Linear Congruential Generator)
        // X_{n+1} = (a * X_n + c)
        // 使用标准 LCG 参数
        uint32_t a = 1664525;
        uint32_t c = 1013904223;
        uint32_t start_val = static_cast<uint32_t>(getRange(0, 100000)); // 随机种子
        int iterations = getRange(5, 12); // 随机迭代次数

        // 静态预计算 Expected Value
        uint32_t expected_val = start_val;
        for(int i=0; i<iterations; ++i) {
            expected_val = a * expected_val + c; // Implicit mod 2^32
        }

        Builder.CreateBr(HeaderBB);

        // -------------------------------------------------
        // 3. Header (Phi Nodes)
        // -------------------------------------------------
        Builder.SetInsertPoint(HeaderBB);
        // 循环计数器 IV
        PHINode *IV = Builder.CreatePHI(Type::getInt32Ty(Ctx), 2, "iv"); // 0 .. iterations
        IV->addIncoming(ConstantInt::get(Type::getInt32Ty(Ctx), 0), PreBB);
        
        // LCG 状态 State
        PHINode *State = Builder.CreatePHI(Type::getInt32Ty(Ctx), 2, "state");
        State->addIncoming(ConstantInt::get(Type::getInt32Ty(Ctx), start_val), PreBB);

        // 退出条件: IV < iterations
        Value *Cond = Builder.CreateICmpULT(IV, ConstantInt::get(Type::getInt32Ty(Ctx), iterations));
        Builder.CreateCondBr(Cond, BodyBB, MergeBB);

        // -------------------------------------------------
        // 4. Body (Update Logic)
        // -------------------------------------------------
        Builder.SetInsertPoint(BodyBB);
        
        // State = State * a + c
        Value *Mul = Builder.CreateMul(State, ConstantInt::get(Type::getInt32Ty(Ctx), a));
        Value *NextState = Builder.CreateAdd(Mul, ConstantInt::get(Type::getInt32Ty(Ctx), c));
        
        // IV = IV + 1
        Value *NextIV = Builder.CreateAdd(IV, ConstantInt::get(Type::getInt32Ty(Ctx), 1));
        
        // 回填 Header Phi
        IV->addIncoming(NextIV, BodyBB);
        State->addIncoming(NextState, BodyBB);
        
        Builder.CreateBr(HeaderBB);

        // -------------------------------------------------
        // 5. Merge (Check Result)
        // -------------------------------------------------
        Builder.SetInsertPoint(MergeBB, MergeBB->begin());
        
        // 获取循环结束后的 State
        // 由于是从 Header 跳转到 Merge (当条件不可满足时)，我们需要一个 PHI 来接住 State
        // 注意：当 Cond (IV < Iter) 为 False 时，State 的值即为最终值吗？
        // Header 中的 State PHI 在第 N 次循环开始前的值，即为第 N-1 次运算的结果。
        // 当我们循环 N 次，Header 会被执行 N+1 次。第 N+1 次进入 Header 时 IV=N, State=Val_N, Cond=False -> Jump Merge.
        // 所以直接取 Header 中的 State PHI 即可。
        PHINode *FinalState = Builder.CreatePHI(Type::getInt32Ty(Ctx), 1, "final_state");
        FinalState->addIncoming(State, HeaderBB);

        // 构造谓词: FinalState == Expected (Always True)
        Value *IsCorrect = Builder.CreateICmpEQ(FinalState, ConstantInt::get(Type::getInt32Ty(Ctx), expected_val), "opaque_pred");
        
        return IsCorrect; // i1
    }

    // -------------------------------------------------------------------------
    // Phase 3: Wrapper Functions (Complexity Injection)
    // -------------------------------------------------------------------------
    
    Value* createMBAAdd(IRBuilder<> &Builder, Value *Val1, Value *Val2) {
        // 1. 注入混沌循环，获取一个总是为真的不透明谓词
        // 注意：这会修改 CFG，Builder 的插入点会自动移到 MergeBB
        Value *OpaquePred = createOpaquePredicateLoop(Builder);

        // 2. 生成 True Path (复杂递归 MBA)
        // 在 MergeBB 中生成
        int depth = getRange(1, 5); 
        Value *TrueVal = generateMBATree(Builder, Val1, Val2, Instruction::Add, depth);

        // 3. 生成 False Path (Garbage / Junk Code)
        // 简单的 x + y + random
        Value *SimpleAdd = Builder.CreateAdd(Val1, Val2);
        Value *Junk = Builder.CreateAdd(SimpleAdd, ConstantInt::get(Val1->getType(), getRange(1, 1000)));

        // 4. 使用 Select 选择 (Z3 必须同时求解 True 和 False 路径，且依赖于循环结果)
        // Result = OpaquePred ? MBA_Res : Junk
        return Builder.CreateSelect(OpaquePred, TrueVal, Junk, "mba.sel");
    }

    Value* createMBASub(IRBuilder<> &Builder, Value *Val1, Value *Val2) {
        // 同上逻辑
        Value *OpaquePred = createOpaquePredicateLoop(Builder);
        
        int depth = getRange(1, 2);
        Value *TrueVal = generateMBATree(Builder, Val1, Val2, Instruction::Sub, depth);
        
        Value *SimpleSub = Builder.CreateSub(Val1, Val2);
        Value *Junk = Builder.CreateAdd(SimpleSub, ConstantInt::get(Val1->getType(), 0xDEAD));

        return Builder.CreateSelect(OpaquePred, TrueVal, Junk, "mba.sel");
    }
}

static void linkRuntime(Module &M) {
    debugprint("Linking runtime module...\n");
    SmallString<256> primaryPath;
#ifdef _WIN32
    const char *homeEnv = getenv("USERPROFILE");
    if (homeEnv) {
        primaryPath.assign(homeEnv);
        sys::path::append(primaryPath, ".ollvm", "crypto_runtime.bc");
    }
#else
    const char *homeEnv = getenv("HOME");
    if (homeEnv) {
        primaryPath.assign(homeEnv);
        sys::path::append(primaryPath, ".ollvm", "crypto_runtime.bc");
    }
#endif
    StringRef secondaryPath = "crypto_runtime.bc";
    Expected<std::unique_ptr<MemoryBuffer>> bufferOrErr = errorCodeToError(std::make_error_code(std::errc::no_such_file_or_directory));

    if (!primaryPath.empty()) {
        if (auto primaryBuffer = MemoryBuffer::getFile(primaryPath)) bufferOrErr = std::move(*primaryBuffer);
    }
    if (!bufferOrErr) {
        if (auto secondaryBuffer = MemoryBuffer::getFile(secondaryPath)) bufferOrErr = std::move(*secondaryBuffer);
    }
    if (!bufferOrErr) {
        consumeError(bufferOrErr.takeError());
        errs() << "IntegrityCheck Error: 'crypto_runtime.bc' not found.\n";
        return;
    }
    auto runtimeModuleOrErr = parseBitcodeFile(bufferOrErr.get()->getMemBufferRef(), M.getContext());
    if (Error err = runtimeModuleOrErr.takeError()) {
        handleAllErrors(std::move(err), [&](const ErrorInfoBase &EI) { errs() << "IntegrityCheck Error: Bitcode error: " << EI.message() << "\n"; });
        return;
    }
    std::unique_ptr<Module> runtimeModule = std::move(runtimeModuleOrErr.get());
#ifndef debug
    StripDebugInfo(*runtimeModule);
#endif
    for (Function &F : *runtimeModule) if (F.hasExternalLinkage()) F.setLinkage(GlobalValue::WeakODRLinkage);
    for (GlobalVariable &GV : runtimeModule->globals()) if (GV.hasExternalLinkage()) GV.setLinkage(GlobalValue::WeakODRLinkage);
    if (Linker::linkModules(M, std::move(runtimeModule))) errs() << "IntegrityCheck Error: Link failed.\n";
}

PreservedAnalyses IntegrityCheckPass::run(Module &M, ModuleAnalysisManager &AM)
{
    bool isToObfuscate = false;
    for (Function &F : M) {
        if (toObfuscate(flag, &F, "intcheck")) {
            isToObfuscate = true;
            break;
        }
    }
    if (!isToObfuscate) return PreservedAnalyses::all();

    static bool runtimeLinked = false;
    if (!runtimeLinked) {
        linkRuntime(M);
        runtimeLinked = true;
    }

    LLVMContext &Ctx = M.getContext();
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> probDist(0, 100);

    // 1. Filter Functions (Annotations)
    std::set<Function *> noInstrumentFuncs;
    if (GlobalVariable *GA = M.getGlobalVariable("llvm.global.annotations")) {
        if (ConstantArray *CA = dyn_cast<ConstantArray>(GA->getInitializer())) {
            for (Value *Op : CA->operands()) {
                if (ConstantStruct *CS = dyn_cast<ConstantStruct>(Op)) {
                    if (Function *F = dyn_cast<Function>(CS->getOperand(0)->stripPointerCasts())) {
                        if (GlobalVariable *AGL = dyn_cast<GlobalVariable>(CS->getOperand(1)->stripPointerCasts())) {
                            if (ConstantDataArray *CDA = dyn_cast<ConstantDataArray>(AGL->getInitializer())) {
                                if (CDA->getAsString().starts_with("no_ic_instrument")) noInstrumentFuncs.insert(F);
                            }
                        }
                    }
                }
            }
        }
        GA->eraseFromParent();
    }

    // 2. Select Protected Functions
    std::vector<Function *> protectedFuncs;
    const std::vector<StringRef> nameBlacklist = { 
        "allocat", "deallocat", "stringbuf", "gthread", "thread", 
        "__verify", "__integrity", "__cxx_global_var_init", "_GLOBAL__sub_I" 
    };

    for (Function &F : M) {
        StringRef funcName = F.getName();
        if (F.isDeclaration() || funcName.contains("__verify") || funcName.contains("__integrity") || noInstrumentFuncs.count(&F)) continue;
        if (!F.hasExternalLinkage() && !F.hasInternalLinkage()) continue;
        
        bool isBlacklisted = false;
        for (const auto &s : nameBlacklist) if (funcName.contains(s)) isBlacklisted = true;
        if (F.empty() || F.size() == 0) isBlacklisted = true;
        if (isBlacklisted) continue;

        protectedFuncs.push_back(&F);
    }
    std::sort(protectedFuncs.begin(), protectedFuncs.end(), [](const Function *A, const Function *B) { return A->getName() < B->getName(); });

    // 3. Create Tables
    StructType *FuncMarkerTy = StructType::getTypeByName(Ctx, "FuncMarker");
    if (!FuncMarkerTy) FuncMarkerTy = StructType::create(Ctx, {PointerType::getUnqual(Type::getInt8Ty(Ctx)), PointerType::getUnqual(Type::getInt8Ty(Ctx))}, "FuncMarker");

    std::vector<Constant *> markerEntries;
    for (Function *F : protectedFuncs) {
        Constant *N = ConstantDataArray::getString(Ctx, F->getName(), true);
        auto *GV = new GlobalVariable(M, N->getType(), true, GlobalValue::PrivateLinkage, N, ".str");
        GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        markerEntries.push_back(ConstantStruct::get(FuncMarkerTy, {
            ConstantExpr::getPointerCast(GV, PointerType::getUnqual(Type::getInt8Ty(Ctx))),
            ConstantExpr::getPointerCast(F, PointerType::getUnqual(Type::getInt8Ty(Ctx)))
        }));
    }
    if (!markerEntries.empty()) {
        ArrayType *MTTy = ArrayType::get(FuncMarkerTy, markerEntries.size());
        auto *MGV = new GlobalVariable(M, MTTy, true, GlobalValue::ExternalLinkage, ConstantArray::get(MTTy, markerEntries), "__ic_function_marker_table");
        MGV->setSection(".ic_markers");
        appendToUsed(M, {MGV});
    }

    StructType *EncryptedHashTy = StructType::getTypeByName(Ctx, "encrypted_hash");
    if (!EncryptedHashTy) EncryptedHashTy = StructType::create(Ctx, {ArrayType::get(Type::getInt8Ty(Ctx), 32), ArrayType::get(Type::getInt8Ty(Ctx), 24), ArrayType::get(Type::getInt8Ty(Ctx), 16)}, "encrypted_hash");

    auto getWeakGV = [&](const char* name, Type* Ty, const char* sec) {
        GlobalVariable *GV = M.getGlobalVariable(name);
        if (GV) {
            GV->setLinkage(GlobalValue::WeakODRLinkage);
            GV->setInitializer(ConstantAggregateZero::get(Ty));
        } else {
            GV = new GlobalVariable(M, Ty, true, GlobalValue::WeakODRLinkage, ConstantAggregateZero::get(Ty), name);
        }
        GV->setSection(sec);
        return GV;
    };

    Value* textHashGV = getWeakGV("__text_section_encrypted_hash", EncryptedHashTy, ".ic_texthash,a");
    Value* keyGV = getWeakGV("__integrity_check_key", ArrayType::get(Type::getInt8Ty(Ctx), 32), ".ic_key,a");

    const size_t TABLE_SZ = (protectedFuncs.size() + 1) * 88 + 48;
    ArrayType *TableTy = ArrayType::get(Type::getInt8Ty(Ctx), TABLE_SZ);
    GlobalVariable *tableGV;
    if (GlobalVariable *Old = M.getGlobalVariable("__protected_funcs_info_table")) {
        auto *New = new GlobalVariable(M, TableTy, true, GlobalValue::WeakODRLinkage, ConstantAggregateZero::get(TableTy), "__protected_funcs_info_table_new");
        if (!Old->use_empty()) Old->replaceAllUsesWith(ConstantExpr::getBitCast(New, Old->getType()));
        Old->eraseFromParent();
        New->setName("__protected_funcs_info_table");
        tableGV = New;
    } else {
        tableGV = new GlobalVariable(M, TableTy, true, GlobalValue::WeakODRLinkage, ConstantAggregateZero::get(TableTy), "__protected_funcs_info_table");
    }
    tableGV->setSection(".ic_functable,a");
    appendToUsed(M, {cast<GlobalVariable>(textHashGV), cast<GlobalVariable>(keyGV), tableGV});

    // 4. Runtime Interface
    FunctionCallee VerifyMemFuncCallee = M.getOrInsertFunction("__verify_memory_integrity", 
        Type::getInt64Ty(Ctx), 
        PointerType::getUnqual(Type::getInt8Ty(Ctx))
    );
    Function* VerifyMemFunc = dyn_cast<Function>(VerifyMemFuncCallee.getCallee());
    if(!VerifyMemFunc) return PreservedAnalyses::none();

#ifndef debug
    VerifyMemFunc->addFnAttr(Attribute::AlwaysInline);
    VerifyMemFunc->setLinkage(GlobalValue::PrivateLinkage);
#endif

    // [Phase 1: Entry/Exit Check]
    for (Function *F : protectedFuncs) {
        Constant *funcPtr = ConstantExpr::getPointerCast(F, PointerType::getUnqual(Type::getInt8Ty(Ctx)));
        CallInst *entryCall = CallInst::Create(VerifyMemFunc, {funcPtr}, "", &*F->getEntryBlock().getFirstInsertionPt());
        #ifndef debug
        InlineFunctionInfo IFI;
        InlineFunction(*entryCall, IFI);
        #endif

        std::vector<ReturnInst *> rets;
        for (BasicBlock &BB : *F) if (auto *Ret = dyn_cast<ReturnInst>(BB.getTerminator())) rets.push_back(Ret);
        for (ReturnInst *Ret : rets) {
            CallInst *exitCall = CallInst::Create(VerifyMemFunc, {funcPtr}, "", Ret);
            #ifndef debug
            InlineFunctionInfo IFI2;
            InlineFunction(*exitCall, IFI2);
            #endif
        }
    }

    // [Phase 2: MBA Injection]
    int injectionCount = 0;
    for (Function *F : protectedFuncs) {
        if (F->getName().contains("global_var_init")) continue; // Avoid global ctors which are sensitive

        std::vector<Instruction*> targets;
        for (BasicBlock &BB : *F) {
            if (BB.isEHPad()) continue; 
            for (Instruction &I : BB) {
                // Strict type check: only standard integers. Vectors are NOT supported by current MBA logic.
                auto isValidType = [](Type *T) {
                    if (!T->isIntegerTy()) return false;
                    unsigned bw = T->getIntegerBitWidth();
                    return true;
                };

                if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
                    if (isValidType(BO->getType()) && isValidType(BO->getOperand(0)->getType())) targets.push_back(&I);
                } else if (auto *IC = dyn_cast<ICmpInst>(&I)) {
                    if (isValidType(IC->getOperand(0)->getType())) targets.push_back(&I);
                } else if (auto *SW = dyn_cast<SwitchInst>(&I)) {
                    if (isValidType(SW->getCondition()->getType())) targets.push_back(&I);
                } else if (auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {
                     // [FIX]: GEP injection allows only the first index (pointer arithmetic).
                     // Subsequent indices might be struct offsets which MUST be constant.
                     if (GEP->getNumOperands() > 1) { // Has at least one index
                         Value *firstIdx = GEP->getOperand(1);
                         if (isValidType(firstIdx->getType())) targets.push_back(&I);
                     }
                }
            }
        }

        for (Instruction *Inst : targets) {
            if (probDist(rng) > CheckProbability) continue;

            IRBuilder<> Builder(Inst);
            Constant *FuncPtr = ConstantExpr::getPointerCast(F, PointerType::getUnqual(Type::getInt8Ty(Ctx)));
            Value *FuncAddrVal = Builder.CreatePtrToInt(FuncPtr, Type::getInt64Ty(Ctx), "ic.ra");
            CallInst *CheckRet = Builder.CreateCall(VerifyMemFunc, {FuncPtr}, "ic.chk"); // Returns RealAddr
            Value *Delta = createMBASub(Builder, CheckRet, FuncAddrVal); // Delta == 0 if valid

            Value *OpToHack = nullptr;
            int OpIdx = -1;

            if (auto *BO = dyn_cast<BinaryOperator>(Inst)) {
                OpIdx = 0; OpToHack = BO->getOperand(0);
            } else if (auto *IC = dyn_cast<ICmpInst>(Inst)) {
                OpIdx = 0; OpToHack = IC->getOperand(0);
            } else if (auto *SW = dyn_cast<SwitchInst>(Inst)) {
                OpToHack = SW->getCondition();
            } else if (auto *GEP = dyn_cast<GetElementPtrInst>(Inst)) {
                // [FIX]: Always inject into Operand 1 (First index)
                OpIdx = 1;
                OpToHack = GEP->getOperand(OpIdx);
            }

            if (OpToHack) {
                Value *AdjustedDelta = Builder.CreateZExtOrTrunc(Delta, OpToHack->getType(), "ic.dt");
                Value *TaintedOp = createMBAAdd(Builder, OpToHack, AdjustedDelta);
                
                if (auto *SW = dyn_cast<SwitchInst>(Inst)) SW->setCondition(TaintedOp);
                else Inst->setOperand(OpIdx, TaintedOp);
                
                injectionCount++;
            }
        }
    }
    debugprint("IntegrityCheck: Data-flow injected %d times.\n", injectionCount);

    // 5. Static Ctor
    FunctionCallee VerifySelfFunc = M.getOrInsertFunction("__verify_self_integrity", Type::getVoidTy(Ctx));
    Function *CtorFunc = Function::Create(FunctionType::get(Type::getVoidTy(Ctx), false), GlobalValue::InternalLinkage, "__integrity_ctor", &M);
    CtorFunc->addFnAttr("no_ic_instrument");
    BasicBlock *CtorBB = BasicBlock::Create(Ctx, "entry", CtorFunc);
    IRBuilder<> CtorBuilder(CtorBB);
    CtorBuilder.CreateCall(VerifySelfFunc, {});
    CtorBuilder.CreateRetVoid();
    appendToGlobalCtors(M, CtorFunc, 0, nullptr);

    return PreservedAnalyses::none();
}

IntegrityCheckPass *llvm::createIntegrityCheck(bool flag) {
    return new IntegrityCheckPass(flag);
}