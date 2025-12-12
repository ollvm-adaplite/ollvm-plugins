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
#include "llvm/ADT/SmallString.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"

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
namespace
{

// -------------------------------------------------------------------------
// Utils
// -------------------------------------------------------------------------
bool getBool()
{
    static std::mt19937 rng(std::random_device{}());
    return std::uniform_int_distribution<int>(0, 1)(rng);
}

int getRange(int min, int max)
{
    static std::mt19937 rng(std::random_device{}());
    return std::uniform_int_distribution<int>(min, max)(rng);
}

// -------------------------------------------------------------------------
// Phase 1: Recursive MBA Tree Generation (The "True" Logic)
// -------------------------------------------------------------------------
Value* generateMBATree(IRBuilder<>& Builder, Value* A, Value* B, unsigned OpCode, int Depth)
{
    if (Depth <= 0 || !A->getType()->isIntegerTy())
    {
        switch (OpCode)
        {
            case Instruction::Add:
                return Builder.CreateAdd(A, B);
            case Instruction::Sub:
                return Builder.CreateSub(A, B);
            case Instruction::Xor:
                return Builder.CreateXor(A, B);
            case Instruction::And:
                return Builder.CreateAnd(A, B);
            case Instruction::Or:
                return Builder.CreateOr(A, B);
            default:
                return Builder.CreateAdd(A, B);
        }
    }

    switch (OpCode)
    {
        case Instruction::Add:
        {
            // Identity: x + y = (x ^ y) + 2*(x & y)
            // Expanded: (x ^ y) + ((x & y) << 1)
            Value* Xor = generateMBATree(Builder, A, B, Instruction::Xor, Depth - 1);
            Value* And = generateMBATree(Builder, A, B, Instruction::And, Depth - 1);
            Value* TwoAnd = Builder.CreateMul(And, ConstantInt::get(A->getType(), 2));
            return Builder.CreateAdd(Xor, TwoAnd);
        }
        case Instruction::Sub:
        {
            // Identity: x - y = (x ^ y) - 2*(~x & y)
            Value* Xor = generateMBATree(Builder, A, B, Instruction::Xor, Depth - 1);
            Value* NotA = Builder.CreateNot(A);
            Value* And = generateMBATree(Builder, NotA, B, Instruction::And, Depth - 1);
            Value* Term2 = Builder.CreateMul(And, ConstantInt::get(A->getType(), 2));
            return Builder.CreateSub(Xor, Term2);
        }
        case Instruction::Xor:
        {
            // Identity: x ^ y = (x | y) - (x & y)
            Value* Or = generateMBATree(Builder, A, B, Instruction::Or, Depth - 1);
            Value* And = generateMBATree(Builder, A, B, Instruction::And, Depth - 1);
            return Builder.CreateSub(Or, And);
        }
        case Instruction::And:
        {
            // Identity: x & y = ~(~x | ~y) (De Morgan)
            Value* NotA = Builder.CreateNot(A);
            Value* NotB = Builder.CreateNot(B);
            Value* Or = generateMBATree(Builder, NotA, NotB, Instruction::Or, Depth - 1);
            return Builder.CreateNot(Or);
        }
        case Instruction::Or:
        {
            // Identity: x | y = (x + y) - (x & y)
            Value* Add = generateMBATree(Builder, A, B, Instruction::Add, Depth - 1);
            Value* And = generateMBATree(Builder, A, B, Instruction::And, Depth - 1);
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
Value* createOpaquePredicateLoop(IRBuilder<>& Builder)
{
    Function* F = Builder.GetInsertBlock()->getParent();
    LLVMContext& Ctx = F->getContext();

    // 1. 准备 CFG 修改
    // 当前插入点所在的 Block 为 PreBB
    BasicBlock* PreBB = Builder.GetInsertBlock();
    // 将原 Block 从插入点切分，后半部分为 MergeBB
    BasicBlock* MergeBB = PreBB->splitBasicBlock(Builder.GetInsertPoint(), "ic.chaos.merge");

    // 移除 splitBasicBlock 自动创建的无条件跳转，我们需要插入自己的流图
    PreBB->getTerminator()->eraseFromParent();

    // 创建循环结构 Block
    BasicBlock* HeaderBB = BasicBlock::Create(Ctx, "ic.chaos.header", F, MergeBB);
    BasicBlock* BodyBB = BasicBlock::Create(Ctx, "ic.chaos.body", F, MergeBB);

    // -------------------------------------------------
    // 2. PreBB -> Header
    // -------------------------------------------------
    Builder.SetInsertPoint(PreBB);

    // LCG 参数 Setup (Linear Congruential Generator)
    // X_{n+1} = (a * X_n + c)
    // 使用标准 LCG 参数
    uint32_t a = 1664525;
    uint32_t c = 1013904223;
    uint32_t start_val = static_cast<uint32_t>(getRange(0, 100000));  // 随机种子
    int iterations = getRange(5, 12);                                 // 随机迭代次数

    // 静态预计算 Expected Value
    uint32_t expected_val = start_val;
    for (int i = 0; i < iterations; ++i)
    {
        expected_val = a * expected_val + c;  // Implicit mod 2^32
    }

    Builder.CreateBr(HeaderBB);

    // -------------------------------------------------
    // 3. Header (Phi Nodes)
    // -------------------------------------------------
    Builder.SetInsertPoint(HeaderBB);
    // 循环计数器 IV
    PHINode* IV = Builder.CreatePHI(Type::getInt32Ty(Ctx), 2, "iv");  // 0 .. iterations
    IV->addIncoming(ConstantInt::get(Type::getInt32Ty(Ctx), 0), PreBB);

    // LCG 状态 State
    PHINode* State = Builder.CreatePHI(Type::getInt32Ty(Ctx), 2, "state");
    State->addIncoming(ConstantInt::get(Type::getInt32Ty(Ctx), start_val), PreBB);

    // 退出条件: IV < iterations
    Value* Cond = Builder.CreateICmpULT(IV, ConstantInt::get(Type::getInt32Ty(Ctx), iterations));
    Builder.CreateCondBr(Cond, BodyBB, MergeBB);

    // -------------------------------------------------
    // 4. Body (Update Logic)
    // -------------------------------------------------
    Builder.SetInsertPoint(BodyBB);

    // State = State * a + c
    Value* Mul = Builder.CreateMul(State, ConstantInt::get(Type::getInt32Ty(Ctx), a));
    Value* NextState = Builder.CreateAdd(Mul, ConstantInt::get(Type::getInt32Ty(Ctx), c));

    // IV = IV + 1
    Value* NextIV = Builder.CreateAdd(IV, ConstantInt::get(Type::getInt32Ty(Ctx), 1));

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
    PHINode* FinalState = Builder.CreatePHI(Type::getInt32Ty(Ctx), 1, "final_state");
    FinalState->addIncoming(State, HeaderBB);

    // 构造谓词: FinalState == Expected (Always True)
    Value* IsCorrect = Builder.CreateICmpEQ(FinalState, ConstantInt::get(Type::getInt32Ty(Ctx), expected_val), "opaque_pred");

    return IsCorrect;  // i1
}

// -------------------------------------------------------------------------
// Phase 3: Wrapper Functions (Complexity Injection)
// -------------------------------------------------------------------------

Value* createMBAAdd(IRBuilder<>& Builder, Value* Val1, Value* Val2)
{
    // 1. 注入混沌循环，获取一个总是为真的不透明谓词
    // 注意：这会修改 CFG，Builder 的插入点会自动移到 MergeBB
    Value* OpaquePred = createOpaquePredicateLoop(Builder);

    // 2. 生成 True Path (复杂递归 MBA)
    // 在 MergeBB 中生成
    int depth = getRange(1, 5);
    Value* TrueVal = generateMBATree(Builder, Val1, Val2, Instruction::Add, depth);

    // 3. 生成 False Path (Garbage / Junk Code)
    // 简单的 x + y + random
    Value* SimpleAdd = Builder.CreateAdd(Val1, Val2);
    Value* Junk = Builder.CreateAdd(SimpleAdd, ConstantInt::get(Val1->getType(), getRange(1, 1000)));

    // 4. 使用 Select 选择 (Z3 必须同时求解 True 和 False 路径，且依赖于循环结果)
    // Result = OpaquePred ? MBA_Res : Junk
    return Builder.CreateSelect(OpaquePred, TrueVal, Junk, "mba.sel");
}

Value* createMBASub(IRBuilder<>& Builder, Value* Val1, Value* Val2)
{
    // 同上逻辑
    Value* OpaquePred = createOpaquePredicateLoop(Builder);

    int depth = getRange(1, 2);
    Value* TrueVal = generateMBATree(Builder, Val1, Val2, Instruction::Sub, depth);

    Value* SimpleSub = Builder.CreateSub(Val1, Val2);
    Value* Junk = Builder.CreateAdd(SimpleSub, ConstantInt::get(Val1->getType(), 0xDEAD));

    return Builder.CreateSelect(OpaquePred, TrueVal, Junk, "mba.sel");
}
}  // namespace

static void linkRuntime(Module& M)
{
    debugprint("Linking runtime module...\n");
    SmallString<256> primaryPath;

    // --- 修改开始：统一的环境变量检查逻辑 (兼容 Windows/Linux) ---
    const char* homeEnv = getenv("HOME");
    if (!homeEnv)
    {
        homeEnv = getenv("USERPROFILE");  // Windows fallback
    }

    if (homeEnv)
    {
        primaryPath.assign(homeEnv);
        sys::path::append(primaryPath, ".ollvm", "crypto_runtime.bc");
    }
    // --- 修改结束 ---

    StringRef secondaryPath = "crypto_runtime.bc";
    Expected<std::unique_ptr<MemoryBuffer>> bufferOrErr = errorCodeToError(std::make_error_code(std::errc::no_such_file_or_directory));

    if (!primaryPath.empty())
    {
        if (auto primaryBuffer = MemoryBuffer::getFile(primaryPath)) bufferOrErr = std::move(*primaryBuffer);
    }
    if (!bufferOrErr)
    {
        if (auto secondaryBuffer = MemoryBuffer::getFile(secondaryPath)) bufferOrErr = std::move(*secondaryBuffer);
    }
    if (!bufferOrErr)
    {
        consumeError(bufferOrErr.takeError());
        errs() << "IntegrityCheck Error: 'crypto_runtime.bc' not found.\n";
        return;
    }
    auto runtimeModuleOrErr = parseBitcodeFile(bufferOrErr.get()->getMemBufferRef(), M.getContext());
    if (Error err = runtimeModuleOrErr.takeError())
    {
        handleAllErrors(std::move(err), [&](const ErrorInfoBase& EI)
                        { errs() << "IntegrityCheck Error: Bitcode error: " << EI.message() << "\n"; });
        return;
    }
    std::unique_ptr<Module> runtimeModule = std::move(runtimeModuleOrErr.get());
#ifndef debug
    StripDebugInfo(*runtimeModule);
#endif
    for (Function& F : *runtimeModule)
        if (F.hasExternalLinkage()) F.setLinkage(GlobalValue::WeakODRLinkage);
    for (GlobalVariable& GV : runtimeModule->globals())
        if (GV.hasExternalLinkage()) GV.setLinkage(GlobalValue::WeakODRLinkage);
    if (Linker::linkModules(M, std::move(runtimeModule))) errs() << "IntegrityCheck Error: Link failed.\n";
}

PreservedAnalyses IntegrityCheckPass::run(Module& M, ModuleAnalysisManager& AM)
{
    bool isToObfuscate = false;
    for (Function& F : M)
    {
        if (toObfuscate(flag, &F, "intcheck"))
        {
            isToObfuscate = true;
            break;
        }
    }
    if (!isToObfuscate) return PreservedAnalyses::all();

    static bool runtimeLinked = false;
    if (!runtimeLinked)
    {
        linkRuntime(M);
        runtimeLinked = true;
    }

    LLVMContext& Ctx = M.getContext();
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> probDist(0, 100);

    // 1. Filter Functions (Annotations)
    std::set<Function*> noInstrumentFuncs;
    if (GlobalVariable* GA = M.getGlobalVariable("llvm.global.annotations"))
    {
        if (ConstantArray* CA = dyn_cast<ConstantArray>(GA->getInitializer()))
        {
            for (Value* Op : CA->operands())
            {
                if (ConstantStruct* CS = dyn_cast<ConstantStruct>(Op))
                {
                    if (Function* F = dyn_cast<Function>(CS->getOperand(0)->stripPointerCasts()))
                    {
                        if (GlobalVariable* AGL = dyn_cast<GlobalVariable>(CS->getOperand(1)->stripPointerCasts()))
                        {
                            if (ConstantDataArray* CDA = dyn_cast<ConstantDataArray>(AGL->getInitializer()))
                            {
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
    std::vector<Function*> protectedFuncs;
    const std::vector<StringRef> nameBlacklist = {
            "allocat", "deallocat", "stringbuf", "gthread", "thread",
            "__verify", "__integrity", "__cxx_global_var_init", "_GLOBAL__sub_I"};

    for (Function& F : M)
    {
        StringRef funcName = F.getName();
        if (F.isDeclaration() || funcName.contains("__verify") || funcName.contains("__integrity") || noInstrumentFuncs.count(&F)) continue;
        if (!F.hasExternalLinkage() && !F.hasInternalLinkage()) continue;

        bool isBlacklisted = false;
        for (const auto& s : nameBlacklist)
            if (funcName.contains(s)) isBlacklisted = true;
        if (F.empty() || F.size() == 0) isBlacklisted = true;
        if (isBlacklisted) continue;

        protectedFuncs.push_back(&F);
    }
    std::sort(protectedFuncs.begin(), protectedFuncs.end(), [](const Function* A, const Function* B)
              { return A->getName() < B->getName(); });

    // 3. Create Tables
    StructType* FuncMarkerTy = StructType::getTypeByName(Ctx, "FuncMarker");
    if (!FuncMarkerTy) FuncMarkerTy = StructType::create(Ctx, {PointerType::getUnqual(Type::getInt8Ty(Ctx)), PointerType::getUnqual(Type::getInt8Ty(Ctx))}, "FuncMarker");

    // [FIX] 定义节区名称变量，方便复用
    Triple T(M.getTargetTriple());
    bool isWindows = T.isOSWindows();
    const char* markerSectionName = isWindows ? ".ic_mark" : ".ic_markers";

    std::vector<Constant*> markerEntries;
    for (Function* F : protectedFuncs)
    {
        Constant* N = ConstantDataArray::getString(Ctx, F->getName(), true);
        auto* GV = new GlobalVariable(M, N->getType(), true, GlobalValue::PrivateLinkage, N, ".str");
        GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

        // 仅在非 debug 模式下将字符串数据强制放入标记节区！
        // 这样 encheck.py 擦除该节区时，字符串也会被物理清除。
        // 在 debug 模式下保留在默认节区 (.rdata)，方便调试。
#ifndef debug
        GV->setSection(markerSectionName);
#endif

        markerEntries.push_back(ConstantStruct::get(FuncMarkerTy, {ConstantExpr::getPointerCast(GV, PointerType::getUnqual(Type::getInt8Ty(Ctx))),
                                                                   ConstantExpr::getPointerCast(F, PointerType::getUnqual(Type::getInt8Ty(Ctx)))}));
    }
    if (!markerEntries.empty())
    {
        ArrayType* MTTy = ArrayType::get(FuncMarkerTy, markerEntries.size());
        auto* MGV = new GlobalVariable(M, MTTy, true, GlobalValue::ExternalLinkage, ConstantArray::get(MTTy, markerEntries), "__ic_function_marker_table");

        // 表格本身也放在同一个节区
        MGV->setSection(markerSectionName);

        appendToUsed(M, {MGV});
    }

    StructType* EncryptedHashTy = StructType::getTypeByName(Ctx, "encrypted_hash");
    if (!EncryptedHashTy) EncryptedHashTy = StructType::create(Ctx, {ArrayType::get(Type::getInt8Ty(Ctx), 32), ArrayType::get(Type::getInt8Ty(Ctx), 24), ArrayType::get(Type::getInt8Ty(Ctx), 16)}, "encrypted_hash");

    // [MODIFIED] 使用非零初始化器
    auto getWeakGV = [&](const char* name, Type* Ty, const char* sec)
    {
        GlobalVariable* GV = M.getGlobalVariable(name);
        Constant* Init = getNonZeroInitializer(M, Ty);  // 使用非零填充

        if (GV)
        {
            GV->setLinkage(GlobalValue::WeakODRLinkage);
            GV->setInitializer(Init);
        }
        else
        {
            GV = new GlobalVariable(M, Ty, true, GlobalValue::WeakODRLinkage, Init, name);
        }
        GV->setSection(sec);
        return GV;
    };

    // Windows PE 节名限制为 8 字节。
    // .ic_texthash (12) -> .ic_text
    // .ic_functable (13) -> .ic_func
    // .ic_key (7) -> .ic_key
    const char* sec_texthash = isWindows ? ".ic_text" : ".ic_texthash,a";
    const char* sec_key = isWindows ? ".ic_key" : ".ic_key,a";
    const char* sec_table = isWindows ? ".ic_func" : ".ic_functable,a";

    Value* textHashGV = getWeakGV("__text_section_encrypted_hash", EncryptedHashTy, sec_texthash);
    Value* keyGV = getWeakGV("__integrity_check_key", ArrayType::get(Type::getInt8Ty(Ctx), 32), sec_key);

    const size_t TABLE_SZ = (protectedFuncs.size() + 1) * 88 + 48;
    ArrayType* TableTy = ArrayType::get(Type::getInt8Ty(Ctx), TABLE_SZ);
    GlobalVariable* tableGV;

    // [MODIFIED] Table 也使用非零初始化
    Constant* TableInit = getNonZeroInitializer(M, TableTy);

    if (GlobalVariable* Old = M.getGlobalVariable("__protected_funcs_info_table"))
    {
        auto* New = new GlobalVariable(M, TableTy, true, GlobalValue::WeakODRLinkage, TableInit, "__protected_funcs_info_table_new");
        if (!Old->use_empty()) Old->replaceAllUsesWith(ConstantExpr::getBitCast(New, Old->getType()));
        Old->eraseFromParent();
        New->setName("__protected_funcs_info_table");
        tableGV = New;
    }
    else
    {
        tableGV = new GlobalVariable(M, TableTy, true, GlobalValue::WeakODRLinkage, TableInit, "__protected_funcs_info_table");
    }
    tableGV->setSection(sec_table);
    appendToUsed(M, {cast<GlobalVariable>(textHashGV), cast<GlobalVariable>(keyGV), tableGV});

    // 4. Runtime Interface
    FunctionCallee VerifyMemFuncCallee = M.getOrInsertFunction("__verify_memory_integrity",
                                                               Type::getInt64Ty(Ctx),
                                                               PointerType::getUnqual(Type::getInt8Ty(Ctx)));
    Function* VerifyMemFunc = dyn_cast<Function>(VerifyMemFuncCallee.getCallee());
    if (!VerifyMemFunc) return PreservedAnalyses::none();

#ifndef debug
    VerifyMemFunc->addFnAttr(Attribute::AlwaysInline);
    VerifyMemFunc->setLinkage(GlobalValue::PrivateLinkage);
#endif

    // [Phase 1 & 2 Merged: Check & Data-Flow Binding]
    // 核心逻辑：插入校验调用，并将其返回值（预期为函数地址）减去真实函数地址得到 0，
    // 然后利用 MBA 将这个“0”混入到业务逻辑的加减乘除和内存寻址中。

    int injectionCount = 0;

    for (Function* F : protectedFuncs)
    {
        if (F->isDeclaration() || F->empty()) continue;

        // 1. 在入口处插入校验调用
        BasicBlock& EntryBB = F->getEntryBlock();
        IRBuilder<> EntryBuilder(&*EntryBB.getFirstInsertionPt());

        // 获取函数地址 (ptr)
        Value* FuncPtr = EntryBuilder.CreateBitCast(F, PointerType::getUnqual(Ctx));

        // 调用 __verify_memory_integrity(FuncPtr)
        CallInst* VerifyCall = EntryBuilder.CreateCall(VerifyMemFunc, {FuncPtr});

        // 2. 构造“零值噪声” (Zero Noise)
        Value* FuncAddrInt = EntryBuilder.CreatePtrToInt(FuncPtr, Type::getInt64Ty(Ctx));
        Value* Noise64 = EntryBuilder.CreateSub(VerifyCall, FuncAddrInt, "ic_noise");

        // 3. 收集可以注入依赖的指令
        std::vector<Instruction*> Targets;
        for (BasicBlock& BB : *F)
        {
            for (Instruction& I : BB)
            {
                // 跳过我们刚插入的指令
                if (&I == VerifyCall || &I == dyn_cast<Instruction>(FuncAddrInt) || &I == dyn_cast<Instruction>(Noise64)) continue;

                // 跳过 PHI 节点
                if (isa<PHINode>(I) || I.isTerminator())
                {
                    // 特殊处理 Terminators
                    if (auto* Ret = dyn_cast<ReturnInst>(&I))
                    {
                        if (Ret->getReturnValue() && Ret->getReturnValue()->getType()->isIntegerTy())
                        {
                            Targets.push_back(Ret);
                        }
                    }
                    else if (auto* Sw = dyn_cast<SwitchInst>(&I))
                    {
                        if (Sw->getCondition()->getType()->isIntegerTy())
                        {
                            Targets.push_back(Sw);
                        }
                    }
                    else if (auto* Br = dyn_cast<BranchInst>(&I))
                    {
                        if (Br->isConditional())
                        {
                            Targets.push_back(Br);
                        }
                    }
                    continue;
                }

                // 支持 BinaryOperator, ICmp
                if (auto* BO = dyn_cast<BinaryOperator>(&I))
                {
                    if (BO->getType()->isIntegerTy())
                    {
                        Targets.push_back(BO);
                    }
                }
                else if (auto* Cmp = dyn_cast<ICmpInst>(&I))
                {
                    Targets.push_back(Cmp);
                }
                // [FIX] 恢复 GEP 支持，但增加安全检查
                else if (auto* GEP = dyn_cast<GetElementPtrInst>(&I))
                {
                    // 检查最后一个操作数是否是结构体索引
                    if (GEP->getNumOperands() > 1)
                    {
                        unsigned opIdx = GEP->getNumOperands() - 1;
                        unsigned idxPos = opIdx - 1;

                        gep_type_iterator GTI = gep_type_begin(GEP);
                        for (unsigned j = 0; j < idxPos; ++j) ++GTI;

                        // 只有当索引的不是结构体时，才允许修改
                        if (!GTI.isStruct())
                        {
                            Targets.push_back(GEP);
                        }
                    }
                }
            }
        }

        // 4. 随机注入依赖
        for (Instruction* Inst : Targets)
        {
            if (probDist(rng) > CheckProbability) continue;

            IRBuilder<> Builder(Inst);

            Value* OpToCorrupt = nullptr;
            unsigned OpIdx = 0;

            if (auto* BO = dyn_cast<BinaryOperator>(Inst))
            {
                OpIdx = 1;
                if (BO->getNumOperands() > 1) OpToCorrupt = BO->getOperand(OpIdx);
            }
            else if (auto* Cmp = dyn_cast<ICmpInst>(Inst))
            {
                OpIdx = 0;
                OpToCorrupt = Cmp->getOperand(OpIdx);
            }
            else if (auto* GEP = dyn_cast<GetElementPtrInst>(Inst))
            {
                OpIdx = GEP->getNumOperands() - 1;
                OpToCorrupt = GEP->getOperand(OpIdx);
            }
            else if (auto* Ret = dyn_cast<ReturnInst>(Inst))
            {
                OpIdx = 0;
                OpToCorrupt = Ret->getReturnValue();
            }
            else if (auto* Sw = dyn_cast<SwitchInst>(Inst))
            {
                OpIdx = 0;
                OpToCorrupt = Sw->getCondition();
            }
            else if (auto* Br = dyn_cast<BranchInst>(Inst))
            {
                OpIdx = 0;
                OpToCorrupt = Br->getCondition();
            }

            if (!OpToCorrupt || !OpToCorrupt->getType()->isIntegerTy()) continue;

            Value* LocalNoise = Noise64;
            Type* OpTy = OpToCorrupt->getType();

            // 特殊处理 i1 类型 (用于 Branch)
            if (OpTy->isIntegerTy(1))
            {
                // 使用右移异或 (Xorshift) 将高位信息折叠到低位
                Value* Shifted = Builder.CreateLShr(Noise64, ConstantInt::get(Type::getInt64Ty(Ctx), 4));
                Value* FoldedNoise = Builder.CreateXor(Noise64, Shifted, "ic_folded_noise");
                LocalNoise = Builder.CreateTrunc(FoldedNoise, OpTy);
            }
            else
            {
                if (OpTy->getPrimitiveSizeInBits() < 64)
                {
                    LocalNoise = Builder.CreateTrunc(Noise64, OpTy);
                }
                else if (OpTy->getPrimitiveSizeInBits() > 64)
                {
                    LocalNoise = Builder.CreateZExt(Noise64, OpTy);
                }
            }

            // 5. 使用 MBA 注入依赖
            Value* CorruptedOp = nullptr;

            if (OpTy->isIntegerTy(1))
            {
                // [优化] i1 类型的 MBA 混淆效果较差，先扩展到 i32
                Value* Cond32 = Builder.CreateZExt(OpToCorrupt, Type::getInt32Ty(Ctx));
                Value* Noise32 = Builder.CreateZExt(LocalNoise, Type::getInt32Ty(Ctx));
                Value* Res32 = generateMBATree(Builder, Cond32, Noise32, Instruction::Xor, 2);
                CorruptedOp = Builder.CreateTrunc(Res32, Type::getInt1Ty(Ctx));
            }
            else
            {
                CorruptedOp = generateMBATree(Builder, OpToCorrupt, LocalNoise, Instruction::Add, 2);
            }

            Inst->setOperand(OpIdx, CorruptedOp);
            injectionCount++;
        }
    }
    debugprint("IntegrityCheck: Data-flow injected %d times.\n", injectionCount);

    // 5. Static Ctor
    FunctionCallee VerifySelfFunc = M.getOrInsertFunction("__verify_self_integrity", Type::getVoidTy(Ctx));
    Function* CtorFunc = Function::Create(FunctionType::get(Type::getVoidTy(Ctx), false), GlobalValue::InternalLinkage, "__integrity_ctor", &M);
    CtorFunc->addFnAttr("no_ic_instrument");
    BasicBlock* CtorBB = BasicBlock::Create(Ctx, "entry", CtorFunc);
    IRBuilder<> CtorBuilder(CtorBB);
    CtorBuilder.CreateCall(VerifySelfFunc, {});
    CtorBuilder.CreateRetVoid();
    appendToGlobalCtors(M, CtorFunc, 0, nullptr);

    return PreservedAnalyses::none();
}

// [NEW] 辅助函数：生成非零初始化器 (填充 0xCC)
// 强制链接器在磁盘上分配空间，避免 PointerToRawData 为 0
Constant* IntegrityCheckPass::getNonZeroInitializer(Module& M, Type* Ty)
{
    LLVMContext& Ctx = M.getContext();

    // 处理 i8 数组 (用于 Key 和 Table)
    if (auto* ArrTy = dyn_cast<ArrayType>(Ty))
    {
        if (ArrTy->getElementType()->isIntegerTy(8))
        {
            std::vector<uint8_t> data(ArrTy->getNumElements(), 0xCC);
            return ConstantDataArray::get(Ctx, data);
        }
    }

    // 处理结构体 (用于 EncryptedHash)
    if (auto* StTy = dyn_cast<StructType>(Ty))
    {
        std::vector<Constant*> Elements;
        for (unsigned i = 0; i < StTy->getNumElements(); ++i)
        {
            Type* ElemTy = StTy->getElementType(i);
            // 递归处理结构体内的数组
            if (auto* ArrTy = dyn_cast<ArrayType>(ElemTy))
            {
                if (ArrTy->getElementType()->isIntegerTy(8))
                {
                    std::vector<uint8_t> data(ArrTy->getNumElements(), 0xCC);
                    Elements.push_back(ConstantDataArray::get(Ctx, data));
                    continue;
                }
            }
            Elements.push_back(Constant::getNullValue(ElemTy));
        }
        return ConstantStruct::get(StTy, Elements);
    }

    return Constant::getNullValue(Ty);
}

IntegrityCheckPass* llvm::createIntegrityCheck(bool flag)
{
    return new IntegrityCheckPass(flag);
}