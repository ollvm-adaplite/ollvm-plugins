/**
 * @file FlatteningEnhancedver2.cpp
 * @brief 
 * @author Lux-QAQ
 * @version 1.0.1
 * @date 2025-12-09
 * 
 * @copyright Copyright (c) 2025  Lux-QAQ
 * 
*/
#include "FlatteningEnhancedver2.h"
#include "llvm/IR/InlineAsm.h"
#include "Utils.h"
#include "CryptoUtils.h"
#include "blake3.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ValueMapper.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"

#include <vector>
#include <algorithm>
#include <random>
#include <iostream>
#include <cstring>
#include <set>

using namespace llvm;
using namespace std;

#define DEBUG_TYPE "flattening-enhanced"

// 定义 debug 宏控制内联行为及垃圾块插桩
#define debug

FlatteningEnhancedver2* llvm::createFlatteningEnhancedver2(bool flag)
{
    return new FlatteningEnhancedver2(flag);
}

uint64_t getRand64()
{
    static std::mt19937_64 gen(std::random_device{}());
    return gen();
}

void FlatteningEnhancedver2::linkRuntime(Module& M)
{
    LLVMContext& Ctx = M.getContext();
    const char* homeEnv = getenv("HOME");
    if (!homeEnv)
    {
        homeEnv = getenv("USERPROFILE");
    }
    std::string path = homeEnv ? (std::string(homeEnv) + "/.ollvm/flattening_runtime.bc") : "flattening_runtime.bc";

    errs() << "[Flattening] Linking runtime from: " << path << "\n";

    ErrorOr<std::unique_ptr<MemoryBuffer>> bufferOrErr = MemoryBuffer::getFile(path);
    if (!bufferOrErr)
    {
        errs() << "[Flattening] Warning: flattening_runtime.bc not found. Runtime integration may fail.\n";
        return;
    }

    auto runtimeModuleOrErr = parseBitcodeFile(bufferOrErr.get()->getMemBufferRef(), Ctx);
    if (!runtimeModuleOrErr)
    {
        errs() << "[Flattening] Error parsing runtime bitcode.\n";
        return;
    }

    Linker linker(M);
    if (linker.linkInModule(std::move(runtimeModuleOrErr.get())))
    {
        errs() << "[Flattening] Error linking runtime module.\n";
    }
}

uint64_t FlatteningEnhancedver2::calculateCompileTimeHash(uint64_t state, uint64_t flowkey)
{
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, &state, sizeof(state));
    blake3_hasher_update(&hasher, &flowkey, sizeof(flowkey));
    uint8_t output[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
    uint64_t result;
    std::memcpy(&result, output, sizeof(uint64_t));
    return result;
}

PreservedAnalyses FlatteningEnhancedver2::run(Module& M, ModuleAnalysisManager& AM)
{
    if (!flag) return PreservedAnalyses::all();

    std::set<Function*> preLinkFuncs;
    for (Function& F : M)
    {
        preLinkFuncs.insert(&F);
    }

    linkRuntime(M);

    std::vector<Function*> newRuntimeFuncs;
    for (Function& F : M)
    {
        if (preLinkFuncs.find(&F) == preLinkFuncs.end())
        {
            newRuntimeFuncs.push_back(&F);
        }
    }

    Function* funcHash = M.getFunction("__ollvm_blake3_hash");
    Function* funcCollatz = M.getFunction("__ollvm_collatz_step");
    Function* funcMixKey = M.getFunction("__ollvm_mix_flowkey");

    if (!funcHash || !funcCollatz || !funcMixKey)
    {
        errs() << "[Flattening] Error: Runtime functions not found.\n";
        return PreservedAnalyses::all();
    }

    for (Function* RF : newRuntimeFuncs)
    {
        if (RF->isDeclaration()) continue;
        RF->setLinkage(GlobalValue::InternalLinkage);

#ifndef debug
        std::string randomName = "f_" + std::to_string(getRand64());
        RF->setName(randomName);
#endif

#ifdef debug
        RF->addFnAttr(Attribute::NoInline);
        RF->removeFnAttr(Attribute::AlwaysInline);
        RF->removeFnAttr(Attribute::InlineHint);
#else
        RF->addFnAttr(Attribute::AlwaysInline);
        RF->removeFnAttr(Attribute::NoInline);
#endif
    }

    std::vector<Function*> funcs;
    std::set<Function*> runtimeFuncSet(newRuntimeFuncs.begin(), newRuntimeFuncs.end());

    for (Function& F : M)
    {
        if (F.isDeclaration()) continue;

        if (runtimeFuncSet.count(&F)) continue;
        StringRef n = F.getName();
        if (n.contains("std::") ||         // C++ 标准库
            n.contains("std@@") ||         // Windows std 库
            n.starts_with("_ZSt") ||       // GNU std:: 符号修饰前缀
            n.starts_with("_ZNSt") ||      // GNU std:: 符号修饰前缀
            n.starts_with("__cxx") ||      // C++ 运行时辅助
            n.starts_with("__clang") ||    // Clang 辅助
            n.starts_with("llvm.") ||      // LLVM 内置函数
            n.contains("allocator") ||     // 内存分配器
            n.contains("vector") ||        // 容器
            n.contains("basic_string") ||  // 字符串
            n.contains("_GLOBAL__"))       // 全局构造/析构

        {
            // 调试时可以打开这行查看跳过了哪些函数
            // errs() << "[Flattening] Skipping system/std function: " << n << "\n";
            continue;
        }

        if (toObfuscate(flag, &F, "fla"))
        {
            funcs.push_back(&F);
        }
    }

    for (Function* F : funcs)
    {
        doFlattening(*F, funcHash, funcCollatz, funcMixKey, M);
    }

    return PreservedAnalyses::none();
}

void FlatteningEnhancedver2::encryptConstants(BasicBlock* BB, Value* flowKeyVar, uint64_t expectedKey)
{
    if (BB->isLandingPad()) return;

    for (Instruction& I : *BB)
    {
        if (PHINode* phi = dyn_cast<PHINode>(&I)) continue;
        if (I.isTerminator()) continue;

        for (unsigned i = 0; i < I.getNumOperands(); ++i)
        {
            ConstantInt* CI = dyn_cast<ConstantInt>(I.getOperand(i));
            if (!CI) continue;
            if (CI->getBitWidth() > 64) continue;

            bool canReplace = true;

            if (GetElementPtrInst* GEP = dyn_cast<GetElementPtrInst>(&I))
            {
                if (i > 0)
                {
                    unsigned idxPos = i - 1;
                    gep_type_iterator GTI = gep_type_begin(GEP);
                    for (unsigned j = 0; j < idxPos; ++j) ++GTI;
                    if (GTI.isStruct()) canReplace = false;
                }
            }
            else if (isa<SwitchInst>(&I))
            {
                if (i > 0) canReplace = false;
            }
            else if (CallBase* CB = dyn_cast<CallBase>(&I))
            {
                if (CB->isInlineAsm())
                {
                    canReplace = false;
                }
                else if (CB->isArgOperand(&I.getOperandUse(i)))
                {
                    unsigned argIdx = CB->getArgOperandNo(&I.getOperandUse(i));
                    if (CB->paramHasAttr(argIdx, Attribute::ImmArg))
                    {
                        canReplace = false;
                    }
                    else if (Function* F = CB->getCalledFunction())
                    {
                        if (F->isIntrinsic())
                        {
                            switch (F->getIntrinsicID())
                            {
                                case Intrinsic::memcpy:
                                case Intrinsic::memmove:
                                case Intrinsic::memset:
                                    if (argIdx == CB->arg_size() - 1) canReplace = false;
                                    break;
                                case Intrinsic::objectsize:
                                    if (argIdx == 1 || argIdx == 2) canReplace = false;
                                    break;
                                case Intrinsic::expect:
                                    if (argIdx == 1) canReplace = false;
                                    break;
                                default:
                                    break;
                            }
                        }
                    }
                }
                else
                {
                    canReplace = false;
                }
            }
            else if (isa<LandingPadInst>(&I) || isa<CatchPadInst>(&I) || isa<CleanupPadInst>(&I))
            {
                canReplace = false;
            }
            else if (isa<ShuffleVectorInst>(&I))
            {
                canReplace = false;
            }

            if (!canReplace) continue;

            uint64_t val = CI->getZExtValue();
            uint64_t encrypted = val ^ expectedKey;

            IRBuilder<> builder(&I);
            Value* loadedKey = builder.CreateLoad(Type::getInt64Ty(BB->getContext()), flowKeyVar);
            Value* castedKey = builder.CreateIntCast(loadedKey, CI->getType(), false);

            Value* encConst = ConstantInt::get(CI->getType(), encrypted);
            Value* decrypted = builder.CreateXor(encConst, castedKey);

            I.setOperand(i, decrypted);
        }
    }
}

void FlatteningEnhancedver2::doFlattening(Function& F, Function* funcHash, Function* funcCollatz, Function* funcMixKey, Module& M)
{
    // 1. 处理 PHI 节点
    std::vector<PHINode*> tmpPhi;
    for (BasicBlock& BB : F)
    {
        for (Instruction& I : BB)
        {
            if (PHINode* phi = dyn_cast<PHINode>(&I))
            {
                tmpPhi.push_back(phi);
            }
        }
    }
    for (PHINode* phi : tmpPhi)
    {
        DemotePHIToStack(phi, F.getEntryBlock().getTerminator()->getIterator());
    }

    // [NEW] 识别并排除 EH 相关块 (仅在 Windows 下启用)
    // Windows SEH/C++ EH 要求 funclet 结构完整，不能被打散到 Switch 中
    std::set<BasicBlock*> ehBlocks;

#ifdef _WIN32
    std::vector<BasicBlock*> worklist;
    
    for (BasicBlock& BB : F) {
        if (BB.isEHPad()) {
            ehBlocks.insert(&BB);
            worklist.push_back(&BB);
        }
    }

    while (!worklist.empty()) {
        BasicBlock* BB = worklist.back();
        worklist.pop_back();

        Instruction* term = BB->getTerminator();
        
        // CatchReturnInst / CleanupReturnInst 标志着 funclet 的结束，不继续追踪后继
        if (isa<CatchReturnInst>(term)) continue;
        if (isa<CleanupReturnInst>(term)) continue;
        if (isa<ResumeInst>(term)) continue;
        
        // 对于 InvokeInst，NormalDest 通常在同一个 funclet 中
        if (InvokeInst* invoke = dyn_cast<InvokeInst>(term)) {
            BasicBlock* normalDest = invoke->getNormalDest();
            if (ehBlocks.find(normalDest) == ehBlocks.end()) {
                ehBlocks.insert(normalDest);
                worklist.push_back(normalDest);
            }
            // UnwindDest 是新的 EH pad，已经在初始集合中或会被处理
            continue;
        }

        // 对于 Branch / Switch，后继块属于同一个 funclet
        for (BasicBlock* succ : successors(BB)) {
            if (ehBlocks.find(succ) == ehBlocks.end()) {
                ehBlocks.insert(succ);
                worklist.push_back(succ);
            }
        }
    }
#endif

    // 2. 收集原始基本块 (Windows 下排除 EH 块)
    std::vector<BasicBlock*> origBlocks;
    for (BasicBlock& BB : F)
    {
        // 在 Linux 下 ehBlocks 为空，条件永远为真，行为与旧版本一致
        if (ehBlocks.find(&BB) == ehBlocks.end()) {
            origBlocks.push_back(&BB);
        }
    }

    if (origBlocks.size() <= 1) return;

    BasicBlock* entryBlock = origBlocks[0];
    origBlocks.erase(origBlocks.begin());

    // 确保 Entry Block 只有一条跳转指令指向第一个真实块
    if (entryBlock->getTerminator()->getNumSuccessors() > 1)
    {
        BasicBlock* newBlock = entryBlock->splitBasicBlock(entryBlock->getTerminator(), "entry_split");
        origBlocks.insert(origBlocks.begin(), newBlock);
    }

    LLVMContext& Ctx = F.getContext();
    IRBuilder<> builder(Ctx);

    // 3. 初始化调度变量
    builder.SetInsertPoint(entryBlock->getTerminator());
    AllocaInst* stateVar = builder.CreateAlloca(Type::getInt64Ty(Ctx), nullptr, "stateVar");
    AllocaInst* flowKeyVar = builder.CreateAlloca(Type::getInt64Ty(Ctx), nullptr, "flowKeyVar");

    uint64_t initState = getRand64();
    uint64_t initKey = getRand64();
    builder.CreateStore(ConstantInt::get(Type::getInt64Ty(Ctx), initState), stateVar);
    builder.CreateStore(ConstantInt::get(Type::getInt64Ty(Ctx), initKey), flowKeyVar);

    // 4. 分配 BlockInfo
    std::map<BasicBlock*, BlockInfo> blockInfos;
    BasicBlock* firstRealBlock = origBlocks[0];
    blockInfos[firstRealBlock] = {initState, initKey, 0};

    for (BasicBlock* BB : origBlocks)
    {
        if (BB == firstRealBlock) continue;
        blockInfos[BB] = {getRand64(), getRand64(), 0};
    }

    // [NEW] 预生成垃圾块信息
    int junkBlockCount = getRand64() % 20 + 8;
    struct JunkInfo
    {
        uint64_t state;
        uint64_t key;
    };
    std::vector<JunkInfo> junkInfos;
    for (int i = 0; i < junkBlockCount; ++i)
    {
        junkInfos.push_back({getRand64(), getRand64()});
    }

    // 5. 创建调度循环结构
    BasicBlock* loopHead = BasicBlock::Create(Ctx, "loopHead", &F);
    BasicBlock* loopDefault = BasicBlock::Create(Ctx, "loopDefault", &F);
    BasicBlock* loopEnd = BasicBlock::Create(Ctx, "loopEnd", &F);

    entryBlock->getTerminator()->eraseFromParent();
    builder.SetInsertPoint(entryBlock);
    builder.CreateBr(loopHead);

    // [Helper] 创建不透明谓词
    auto createOpaqueFalse = [&](Value* x, Value* y) -> Value*
    {
        Value* Or = builder.CreateOr(x, y);
        Value* Add = builder.CreateAdd(x, y);
        Value* And = builder.CreateAnd(x, y);
        Value* Sub = builder.CreateSub(Or, Add);
        Value* Res = builder.CreateAdd(Sub, And);
        return builder.CreateICmpNE(Res, ConstantInt::get(Type::getInt64Ty(Ctx), 0));
    };

    // [Helper] 注入虚假分支
    auto injectFakeBranch = [&](Value* realState, Value* realKey, Value* ctxState, Value* ctxKey) -> std::pair<Value*, Value*>
    {
        Value* OpFalse = createOpaqueFalse(ctxState, ctxKey);
        JunkInfo& fakeTarget = junkInfos[getRand64() % junkInfos.size()];
        Value* FakeState = ConstantInt::get(Type::getInt64Ty(Ctx), fakeTarget.state);
        Value* FakeKey = ConstantInt::get(Type::getInt64Ty(Ctx), fakeTarget.key);
        Value* SelState = builder.CreateSelect(OpFalse, FakeState, realState);
        Value* SelKey = builder.CreateSelect(OpFalse, FakeKey, realKey);
        return {SelState, SelKey};
    };

    // [Helper] 计算并更新下一个状态
    auto updateStateAndJump = [&](BasicBlock* currBB, BasicBlock* targetBB, Value* loadState, Value* loadKey)
    {
        BlockInfo& targetInfo = blockInfos[targetBB];
        BlockInfo& currInfo = blockInfos[currBB];

        uint64_t disc = getRand64();
        // Collatz 逻辑: (state % 2 == 0 ? state / 2 : 3 * state + 1) ^ disc
        uint64_t simulatedNextState = (currInfo.stateID % 2 == 0 ? currInfo.stateID / 2 : 3 * currInfo.stateID + 1) ^ disc;
        uint64_t stateCorr = simulatedNextState ^ targetInfo.stateID;

        // Key Mix 逻辑: ROL(key, 13) ^ modifier
        uint64_t rotatedKey = (currInfo.flowKeyIn << 13) | (currInfo.flowKeyIn >> (64 - 13));
        uint64_t keyCorr = rotatedKey ^ targetInfo.flowKeyIn;

        uint64_t encStateCorr = stateCorr ^ currInfo.flowKeyIn;
        uint64_t encKeyCorr = keyCorr ^ currInfo.flowKeyIn;

        Value* nextStateBase = builder.CreateCall(funcCollatz, {loadState, ConstantInt::get(Type::getInt64Ty(Ctx), disc)});
        Value* decStateCorr = builder.CreateXor(ConstantInt::get(Type::getInt64Ty(Ctx), encStateCorr), loadKey);
        Value* decKeyCorr = builder.CreateXor(ConstantInt::get(Type::getInt64Ty(Ctx), encKeyCorr), loadKey);

        Value* nextState = builder.CreateXor(nextStateBase, decStateCorr);
        Value* nextKey = builder.CreateCall(funcMixKey, {loadKey, decKeyCorr});

        auto [finalState, finalKey] = injectFakeBranch(nextState, nextKey, loadState, loadKey);

        builder.CreateStore(finalState, stateVar);
        builder.CreateStore(finalKey, flowKeyVar);
        builder.CreateBr(loopHead);
    };

    // 6. 处理每个原始块
    for (BasicBlock* BB : origBlocks)
    {
        BB->moveBefore(loopEnd);

        // 加密常量 (EH 块不在 origBlocks 中，因此不会被加密，这是安全的)
        encryptConstants(BB, flowKeyVar, blockInfos[BB].flowKeyIn);

        // LandingPad 特殊处理 (Linux 下会执行，Windows 下 origBlocks 不含 LandingPad)
        if (BB->isLandingPad())
        {
            if (LandingPadInst* LPI = BB->getLandingPadInst())
            {
                IRBuilder<> lpBuilder(LPI->getNextNode());
                BlockInfo& info = blockInfos[BB];
                lpBuilder.CreateStore(ConstantInt::get(Type::getInt64Ty(Ctx), info.stateID), stateVar);
                lpBuilder.CreateStore(ConstantInt::get(Type::getInt64Ty(Ctx), info.flowKeyIn), flowKeyVar);
            }
        }

        Instruction* term = BB->getTerminator();
        builder.SetInsertPoint(term);
        Value* loadState = builder.CreateLoad(Type::getInt64Ty(Ctx), stateVar);
        Value* loadKey = builder.CreateLoad(Type::getInt64Ty(Ctx), flowKeyVar);

        if (isa<ReturnInst>(term) || isa<ResumeInst>(term))
        {
            continue;
        }
        else if (term->getNumSuccessors() == 1)
        {
            BasicBlock* target = term->getSuccessor(0);
            updateStateAndJump(BB, target, loadState, loadKey);
            term->eraseFromParent();
        }
        else if (BranchInst* br = dyn_cast<BranchInst>(term))
        {
            if (br->isConditional())
            {
                Value* cond = br->getCondition();
                BasicBlock* trueBB = br->getSuccessor(0);
                BasicBlock* falseBB = br->getSuccessor(1);

                auto calcNext = [&](BasicBlock* target) -> std::pair<Value*, Value*>
                {
                    BlockInfo& targetInfo = blockInfos[target];
                    BlockInfo& currInfo = blockInfos[BB];
                    uint64_t disc = getRand64();
                    uint64_t simState = (currInfo.stateID % 2 == 0 ? currInfo.stateID / 2 : 3 * currInfo.stateID + 1) ^ disc;
                    uint64_t stateCorr = simState ^ targetInfo.stateID;
                    uint64_t rotKey = (currInfo.flowKeyIn << 13) | (currInfo.flowKeyIn >> (64 - 13));
                    uint64_t keyCorr = rotKey ^ targetInfo.flowKeyIn;
                    uint64_t encStateCorr = stateCorr ^ currInfo.flowKeyIn;
                    uint64_t encKeyCorr = keyCorr ^ currInfo.flowKeyIn;

                    Value* nsBase = builder.CreateCall(funcCollatz, {loadState, ConstantInt::get(Type::getInt64Ty(Ctx), disc)});
                    Value* dsCorr = builder.CreateXor(ConstantInt::get(Type::getInt64Ty(Ctx), encStateCorr), loadKey);
                    Value* dkCorr = builder.CreateXor(ConstantInt::get(Type::getInt64Ty(Ctx), encKeyCorr), loadKey);
                    Value* ns = builder.CreateXor(nsBase, dsCorr);
                    Value* nk = builder.CreateCall(funcMixKey, {loadKey, dkCorr});
                    return {ns, nk};
                };

                auto [nsTrue, nkTrue] = calcNext(trueBB);
                auto [nsFalse, nkFalse] = calcNext(falseBB);

                Value* nextState = builder.CreateSelect(cond, nsTrue, nsFalse);
                Value* nextKey = builder.CreateSelect(cond, nkTrue, nkFalse);

                auto [finalState, finalKey] = injectFakeBranch(nextState, nextKey, loadState, loadKey);

                builder.CreateStore(finalState, stateVar);
                builder.CreateStore(finalKey, flowKeyVar);
                builder.CreateBr(loopHead);
                term->eraseFromParent();
            }
        }
        else if (SwitchInst* sw = dyn_cast<SwitchInst>(term))
        {
            for (unsigned i = 0; i < sw->getNumSuccessors(); ++i)
            {
                BasicBlock* dst = sw->getSuccessor(i);
                BasicBlock* trampoline = BasicBlock::Create(Ctx, "sw_trampoline", &F);
                trampoline->moveBefore(loopEnd);

                builder.SetInsertPoint(trampoline);
                updateStateAndJump(BB, dst, loadState, loadKey);

                sw->setSuccessor(i, trampoline);
            }
        }
        else if (InvokeInst* invoke = dyn_cast<InvokeInst>(term))
        {
            BasicBlock* normalDest = invoke->getNormalDest();
            BasicBlock* trampoline = BasicBlock::Create(Ctx, "invoke_trampoline", &F);
            trampoline->moveBefore(loopEnd);

            builder.SetInsertPoint(trampoline);
            updateStateAndJump(BB, normalDest, loadState, loadKey);

            invoke->setNormalDest(trampoline);
            // UnwindDest 保持不变，指向 EH Pad (它不在 Switch 中，这是正确的)
        }
    }

    // 7. 构建 Switch 调度器
    builder.SetInsertPoint(loopHead);
    Value* currState = builder.CreateLoad(Type::getInt64Ty(Ctx), stateVar);
    Value* currKey = builder.CreateLoad(Type::getInt64Ty(Ctx), flowKeyVar);

    Value* hashVal = builder.CreateCall(funcHash, {currState, currKey});

    SwitchInst* sw = builder.CreateSwitch(hashVal, loopDefault, origBlocks.size() + junkBlockCount);

    for (BasicBlock* BB : origBlocks)
    {
        BlockInfo& info = blockInfos[BB];
        uint64_t targetHash = calculateCompileTimeHash(info.stateID, info.flowKeyIn);
        sw->addCase(ConstantInt::get(Type::getInt64Ty(Ctx), targetHash), BB);
    }

    // 8. 生成并连接垃圾块
    std::vector<BasicBlock*> junkBlocks;

    for (int i = 0; i < junkBlockCount; ++i)
    {
        BasicBlock* srcBB = origBlocks[getRand64() % origBlocks.size()];
        ValueToValueMapTy VMap;
        BasicBlock* junkBB = CloneBasicBlock(srcBB, VMap, "junk", &F);
        junkBB->moveBefore(loopEnd);

        for (Instruction& I : *junkBB)
        {
            RemapInstruction(&I, VMap, RF_IgnoreMissingLocals | RF_NoModuleLevelChanges);
        }

        for (auto I = junkBB->rbegin(); I != junkBB->rend();)
        {
            Instruction* Inst = &(*I);
            ++I;
            if (Inst->isTerminator())
            {
                Inst->eraseFromParent();
                continue;
            }

            if (getRand64() % 3 == 0 && !Inst->getType()->isVoidTy())
            {
                Inst->replaceAllUsesWith(UndefValue::get(Inst->getType()));
                Inst->eraseFromParent();
            }
            else if (auto* BO = dyn_cast<BinaryOperator>(Inst))
            {
                BO->swapOperands();
            }
        }

        builder.SetInsertPoint(junkBB);

#ifdef debug
        FunctionType* VoidTy = FunctionType::get(Type::getVoidTy(Ctx), false);
        InlineAsm* Trap = InlineAsm::get(VoidTy, "int3", "", true);
        builder.CreateCall(Trap);
#endif

        uint64_t nextStateID, nextKeyIn;
        if (getRand64() % 10 < 5)
        {
            JunkInfo& target = junkInfos[getRand64() % junkInfos.size()];
            nextStateID = target.state;
            nextKeyIn = target.key;
        }
        else
        {
            BasicBlock* targetBB = origBlocks[getRand64() % origBlocks.size()];
            nextStateID = blockInfos[targetBB].stateID;
            nextKeyIn = blockInfos[targetBB].flowKeyIn;
        }

        Value* curState = builder.CreateLoad(Type::getInt64Ty(Ctx), stateVar);
        Value* Zero = builder.CreateXor(curState, curState);
        Value* NextStateVal = ConstantInt::get(Type::getInt64Ty(Ctx), nextStateID);
        Value* ObfState = builder.CreateXor(NextStateVal, Zero);

        builder.CreateStore(ObfState, stateVar);
        builder.CreateStore(ConstantInt::get(Type::getInt64Ty(Ctx), nextKeyIn), flowKeyVar);
        builder.CreateBr(loopHead);

        junkBlocks.push_back(junkBB);
    }

    for (int i = 0; i < junkBlockCount; ++i)
    {
        uint64_t hash = calculateCompileTimeHash(junkInfos[i].state, junkInfos[i].key);
        sw->addCase(ConstantInt::get(Type::getInt64Ty(Ctx), hash), junkBlocks[i]);
    }

    // 9. 处理 Default 块
    builder.SetInsertPoint(loopDefault);
    Value* junkState = builder.CreateLoad(Type::getInt64Ty(Ctx), stateVar);
    uint64_t randomDiscriminator = getRand64();
    Value* junkNext = builder.CreateCall(funcCollatz, {junkState, ConstantInt::get(Type::getInt64Ty(Ctx), randomDiscriminator)});
    builder.CreateStore(junkNext, stateVar);
    builder.CreateBr(loopHead);

    if (loopEnd->empty()) loopEnd->eraseFromParent();

    // [NEW] Windows 特有：修复 EH 块出口 (CatchReturn -> Trampoline -> Loop)
#ifdef _WIN32
    for (BasicBlock* BB : ehBlocks)
    {
        if (CatchReturnInst* CRI = dyn_cast<CatchReturnInst>(BB->getTerminator()))
        {
            BasicBlock* target = CRI->getSuccessor();
            // 如果目标块在平坦化列表中（即它是正常代码块）
            if (blockInfos.count(target))
            {
                BasicBlock* trampoline = BasicBlock::Create(Ctx, "catchret_trampoline", &F);
                trampoline->moveBefore(loopEnd);
                
                IRBuilder<> tBuilder(trampoline);
                BlockInfo& info = blockInfos[target];
                // 直接设置目标状态，因为我们是从非平坦化区域回来的
                tBuilder.CreateStore(ConstantInt::get(Type::getInt64Ty(Ctx), info.stateID), stateVar);
                tBuilder.CreateStore(ConstantInt::get(Type::getInt64Ty(Ctx), info.flowKeyIn), flowKeyVar);
                tBuilder.CreateBr(loopHead);
                
                CRI->setSuccessor(trampoline);
            }
        }
    }
#endif

    errs() << "  Flattening complete for " << F.getName() << "\n";
}