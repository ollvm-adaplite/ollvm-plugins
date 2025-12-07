#include "FlatteningEnhancedver2.h"
#include <llvm-21/llvm/IR/InlineAsm.h>
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

FlatteningEnhancedver2 *llvm::createFlatteningEnhancedver2(bool flag)
{
    return new FlatteningEnhancedver2(flag);
}

uint64_t getRand64()
{
    static std::mt19937_64 gen(std::random_device{}());
    return gen();
}

void FlatteningEnhancedver2::linkRuntime(Module &M)
{
    LLVMContext &Ctx = M.getContext();
    const char *homeEnv = getenv("HOME");
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

PreservedAnalyses FlatteningEnhancedver2::run(Module &M, ModuleAnalysisManager &AM)
{
    if (!flag) return PreservedAnalyses::all();

    // 参考 IntegrityCheck.cpp 的逻辑，识别 "no_ic_instrument" 标记
    std::set<Function *> noFlattenFuncs;
    if (GlobalVariable *GA = M.getGlobalVariable("llvm.global.annotations"))
    {
        if (ConstantArray *CA = dyn_cast<ConstantArray>(GA->getInitializer()))
        {
            for (Value *Op : CA->operands())
            {
                if (ConstantStruct *CS = dyn_cast<ConstantStruct>(Op))
                {
                    if (Function *F = dyn_cast<Function>(CS->getOperand(0)->stripPointerCasts()))
                    {
                        if (GlobalVariable *AGL = dyn_cast<GlobalVariable>(CS->getOperand(1)->stripPointerCasts()))
                        {
                            if (ConstantDataArray *CDA = dyn_cast<ConstantDataArray>(AGL->getInitializer()))
                            {
                                // 如果函数被标记为 no_ic_instrument，则跳过平坦化
                                if (CDA->getAsString().starts_with("no_ic_instrument"))
                                {
                                    noFlattenFuncs.insert(F);
                                    errs() << "[Flattening] Skipping function (annotation): " << F->getName() << "\n";
                                }
                            }
                        }
                    }
                }
            }
        }
        // 注意：这里我们不删除 GA (GA->eraseFromParent())，
        // 因为 IntegrityCheck Pass 可能在之后运行，它也需要读取这些注解。
    }

    std::set<Function *> preLinkFuncs;
    for (Function &F : M)
    {
        preLinkFuncs.insert(&F);
    }

    linkRuntime(M);

    std::vector<Function *> newRuntimeFuncs;
    for (Function &F : M)
    {
        if (preLinkFuncs.find(&F) == preLinkFuncs.end())
        {
            newRuntimeFuncs.push_back(&F);
        }
    }

    Function *funcHash = M.getFunction("__ollvm_blake3_hash");
    Function *funcCollatz = M.getFunction("__ollvm_collatz_step");
    Function *funcMixKey = M.getFunction("__ollvm_mix_flowkey");

    if (!funcHash || !funcCollatz || !funcMixKey)
    {
        errs() << "[Flattening] Error: Runtime functions not found.\n";
        return PreservedAnalyses::all();
    }

    for (Function *RF : newRuntimeFuncs)
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

    std::vector<Function *> funcs;
    std::set<Function *> runtimeFuncSet(newRuntimeFuncs.begin(), newRuntimeFuncs.end());

    for (Function &F : M)
    {
        if (F.isDeclaration()) continue;
        if (runtimeFuncSet.count(&F)) continue;
        // 检查注解过滤
        if (noFlattenFuncs.count(&F)) continue;
        
        if (toObfuscate(flag, &F, "fla"))
        {
            funcs.push_back(&F);
        }
    }

    for (Function *F : funcs)
    {
        doFlattening(*F, funcHash, funcCollatz, funcMixKey, M);
    }

    return PreservedAnalyses::none();
}

void FlatteningEnhancedver2::encryptConstants(BasicBlock *BB, Value *flowKeyVar, uint64_t expectedKey)
{
    if (BB->isLandingPad()) return;

    for (Instruction &I : *BB)
    {
        if (PHINode *phi = dyn_cast<PHINode>(&I)) continue;
        if (I.isTerminator()) continue;

        for (unsigned i = 0; i < I.getNumOperands(); ++i)
        {
            ConstantInt *CI = dyn_cast<ConstantInt>(I.getOperand(i));
            if (!CI) continue;
            if (CI->getBitWidth() > 64) continue;

            bool canReplace = true;

            if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(&I))
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
            else if (CallBase *CB = dyn_cast<CallBase>(&I))
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
                    else if (Function *F = CB->getCalledFunction())
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
            Value *loadedKey = builder.CreateLoad(Type::getInt64Ty(BB->getContext()), flowKeyVar);
            Value *castedKey = builder.CreateIntCast(loadedKey, CI->getType(), false);

            Value *encConst = ConstantInt::get(CI->getType(), encrypted);
            Value *decrypted = builder.CreateXor(encConst, castedKey);

            I.setOperand(i, decrypted);
        }
    }
}

void FlatteningEnhancedver2::doFlattening(Function &F, Function *funcHash, Function *funcCollatz, Function *funcMixKey, Module &M)
{
    std::vector<PHINode *> tmpPhi;
    for (BasicBlock &BB : F)
    {
        for (Instruction &I : BB)
        {
            if (PHINode *phi = dyn_cast<PHINode>(&I))
            {
                tmpPhi.push_back(phi);
            }
        }
    }
    for (PHINode *phi : tmpPhi)
    {
        DemotePHIToStack(phi, F.getEntryBlock().getTerminator()->getIterator());
    }

    std::vector<BasicBlock *> origBlocks;
    for (BasicBlock &BB : F)
    {
        origBlocks.push_back(&BB);
    }

    if (origBlocks.size() <= 1) return;

    BasicBlock *entryBlock = origBlocks[0];
    origBlocks.erase(origBlocks.begin());

    if (entryBlock->getTerminator()->getNumSuccessors() > 1)
    {
        BasicBlock *newBlock = entryBlock->splitBasicBlock(entryBlock->getTerminator(), "entry_split");
        origBlocks.insert(origBlocks.begin(), newBlock);
    }

    LLVMContext &Ctx = F.getContext();
    IRBuilder<> builder(Ctx);

    builder.SetInsertPoint(entryBlock->getTerminator());
    AllocaInst *stateVar = builder.CreateAlloca(Type::getInt64Ty(Ctx), nullptr, "stateVar");
    AllocaInst *flowKeyVar = builder.CreateAlloca(Type::getInt64Ty(Ctx), nullptr, "flowKeyVar");

    uint64_t initState = getRand64();
    uint64_t initKey = getRand64();
    builder.CreateStore(ConstantInt::get(Type::getInt64Ty(Ctx), initState), stateVar);
    builder.CreateStore(ConstantInt::get(Type::getInt64Ty(Ctx), initKey), flowKeyVar);

    std::map<BasicBlock *, BlockInfo> blockInfos;
    BasicBlock *firstRealBlock = origBlocks[0];
    blockInfos[firstRealBlock] = {initState, initKey, 0};

    for (BasicBlock *BB : origBlocks)
    {
        if (BB == firstRealBlock) continue;
        blockInfos[BB] = {getRand64(), getRand64(), 0};
    }

    BasicBlock *loopHead = BasicBlock::Create(Ctx, "loopHead", &F);
    BasicBlock *loopDefault = BasicBlock::Create(Ctx, "loopDefault", &F);
    BasicBlock *loopEnd = BasicBlock::Create(Ctx, "loopEnd", &F);

    entryBlock->getTerminator()->eraseFromParent();
    builder.SetInsertPoint(entryBlock);
    builder.CreateBr(loopHead);

    for (BasicBlock *BB : origBlocks)
    {
        BB->moveBefore(loopEnd);

        encryptConstants(BB, flowKeyVar, blockInfos[BB].flowKeyIn);

        // 异常处理修复：在 LandingPad 块开头重置 Key 和 State
        if (BB->isLandingPad())
        {
            // 使用 getLandingPadInst() 替代 getFirstNonPHI()，更加安全规范
            if (LandingPadInst *LPI = BB->getLandingPadInst())
            {
                // 在 LandingPad 指令之后插入，因为 LandingPad 必须是块的第一条非 PHI 指令
                // LPI->getNextNode() 获取下一条指令作为插入点
                IRBuilder<> lpBuilder(LPI->getNextNode());
                BlockInfo &info = blockInfos[BB];
                lpBuilder.CreateStore(ConstantInt::get(Type::getInt64Ty(Ctx), info.stateID), stateVar);
                lpBuilder.CreateStore(ConstantInt::get(Type::getInt64Ty(Ctx), info.flowKeyIn), flowKeyVar);
            }
        }

        Instruction *term = BB->getTerminator();
        builder.SetInsertPoint(term);
        Value *loadState = builder.CreateLoad(Type::getInt64Ty(Ctx), stateVar);
        Value *loadKey = builder.CreateLoad(Type::getInt64Ty(Ctx), flowKeyVar);

        if (term->getNumSuccessors() == 0)
        {
            continue;
        }
        else if (term->getNumSuccessors() == 1)
        {
            BasicBlock *target = term->getSuccessor(0);
            BlockInfo &targetInfo = blockInfos[target];

            uint64_t disc = getRand64();
            uint64_t simulatedNextState = (blockInfos[BB].stateID % 2 == 0 ? blockInfos[BB].stateID / 2 : 3 * blockInfos[BB].stateID + 1) ^ disc;
            uint64_t stateCorr = simulatedNextState ^ targetInfo.stateID;

            uint64_t rotatedKey = (blockInfos[BB].flowKeyIn << 13) | (blockInfos[BB].flowKeyIn >> (64 - 13));
            uint64_t keyCorr = rotatedKey ^ targetInfo.flowKeyIn;

            uint64_t encStateCorr = stateCorr ^ blockInfos[BB].flowKeyIn;
            uint64_t encKeyCorr = keyCorr ^ blockInfos[BB].flowKeyIn;

            Value *nextStateBase = builder.CreateCall(funcCollatz, {loadState, ConstantInt::get(Type::getInt64Ty(Ctx), disc)});
            Value *decStateCorr = builder.CreateXor(ConstantInt::get(Type::getInt64Ty(Ctx), encStateCorr), loadKey);
            Value *decKeyCorr = builder.CreateXor(ConstantInt::get(Type::getInt64Ty(Ctx), encKeyCorr), loadKey);

            Value *nextState = builder.CreateXor(nextStateBase, decStateCorr);
            Value *nextKey = builder.CreateCall(funcMixKey, {loadKey, decKeyCorr});

            builder.CreateStore(nextState, stateVar);
            builder.CreateStore(nextKey, flowKeyVar);
            builder.CreateBr(loopHead);

            term->eraseFromParent();
        }
        else if (term->getNumSuccessors() == 2)
        {
            if (BranchInst *br = dyn_cast<BranchInst>(term))
            {
                Value *cond = br->getCondition();
                BasicBlock *trueBB = br->getSuccessor(0);
                BasicBlock *falseBB = br->getSuccessor(1);

                uint64_t discTrue = getRand64();
                uint64_t simStateTrue = (blockInfos[BB].stateID % 2 == 0 ? blockInfos[BB].stateID / 2 : 3 * blockInfos[BB].stateID + 1) ^ discTrue;
                uint64_t stateCorrTrue = simStateTrue ^ blockInfos[trueBB].stateID;

                uint64_t rotKey = (blockInfos[BB].flowKeyIn << 13) | (blockInfos[BB].flowKeyIn >> (64 - 13));
                uint64_t keyCorrTrue = rotKey ^ blockInfos[trueBB].flowKeyIn;

                uint64_t discFalse = getRand64();
                uint64_t simStateFalse = (blockInfos[BB].stateID % 2 == 0 ? blockInfos[BB].stateID / 2 : 3 * blockInfos[BB].stateID + 1) ^ discFalse;
                uint64_t stateCorrFalse = simStateFalse ^ blockInfos[falseBB].stateID;
                uint64_t keyCorrFalse = rotKey ^ blockInfos[falseBB].flowKeyIn;

                uint64_t encStateCorrTrue = stateCorrTrue ^ blockInfos[BB].flowKeyIn;
                uint64_t encStateCorrFalse = stateCorrFalse ^ blockInfos[BB].flowKeyIn;
                uint64_t encKeyCorrTrue = keyCorrTrue ^ blockInfos[BB].flowKeyIn;
                uint64_t encKeyCorrFalse = keyCorrFalse ^ blockInfos[BB].flowKeyIn;

                Value *selDisc = builder.CreateSelect(cond, ConstantInt::get(Type::getInt64Ty(Ctx), discTrue), ConstantInt::get(Type::getInt64Ty(Ctx), discFalse));
                Value *selEncStateCorr = builder.CreateSelect(cond, ConstantInt::get(Type::getInt64Ty(Ctx), encStateCorrTrue), ConstantInt::get(Type::getInt64Ty(Ctx), encStateCorrFalse));
                Value *selEncKeyCorr = builder.CreateSelect(cond, ConstantInt::get(Type::getInt64Ty(Ctx), encKeyCorrTrue), ConstantInt::get(Type::getInt64Ty(Ctx), encKeyCorrFalse));

                Value *nextStateBase = builder.CreateCall(funcCollatz, {loadState, selDisc});
                Value *decStateCorr = builder.CreateXor(selEncStateCorr, loadKey);
                Value *decKeyCorr = builder.CreateXor(selEncKeyCorr, loadKey);

                Value *nextState = builder.CreateXor(nextStateBase, decStateCorr);
                Value *nextKey = builder.CreateCall(funcMixKey, {loadKey, decKeyCorr});

                builder.CreateStore(nextState, stateVar);
                builder.CreateStore(nextKey, flowKeyVar);
                builder.CreateBr(loopHead);

                term->eraseFromParent();
            }
            else if (InvokeInst *invoke = dyn_cast<InvokeInst>(term))
            {
                BasicBlock *normalBB = invoke->getNormalDest();
                BasicBlock *trampoline = BasicBlock::Create(Ctx, "invoke_trampoline", &F);
                trampoline->moveBefore(loopEnd);
                invoke->setNormalDest(trampoline);

                builder.SetInsertPoint(trampoline);
                BlockInfo &targetInfo = blockInfos[normalBB];

                uint64_t disc = getRand64();
                uint64_t simulatedNextState = (blockInfos[BB].stateID % 2 == 0 ? blockInfos[BB].stateID / 2 : 3 * blockInfos[BB].stateID + 1) ^ disc;
                uint64_t stateCorr = simulatedNextState ^ targetInfo.stateID;

                uint64_t rotatedKey = (blockInfos[BB].flowKeyIn << 13) | (blockInfos[BB].flowKeyIn >> (64 - 13));
                uint64_t keyCorr = rotatedKey ^ targetInfo.flowKeyIn;

                uint64_t encStateCorr = stateCorr ^ blockInfos[BB].flowKeyIn;
                uint64_t encKeyCorr = keyCorr ^ blockInfos[BB].flowKeyIn;

                Value *nextStateBase = builder.CreateCall(funcCollatz, {loadState, ConstantInt::get(Type::getInt64Ty(Ctx), disc)});
                Value *decStateCorr = builder.CreateXor(ConstantInt::get(Type::getInt64Ty(Ctx), encStateCorr), loadKey);
                Value *decKeyCorr = builder.CreateXor(ConstantInt::get(Type::getInt64Ty(Ctx), encKeyCorr), loadKey);

                Value *nextState = builder.CreateXor(nextStateBase, decStateCorr);
                Value *nextKey = builder.CreateCall(funcMixKey, {loadKey, decKeyCorr});

                builder.CreateStore(nextState, stateVar);
                builder.CreateStore(nextKey, flowKeyVar);
                builder.CreateBr(loopHead);
            }
        }
        else
        {
            if (SwitchInst *sw = dyn_cast<SwitchInst>(term))
            {
                for (unsigned i = 0; i < sw->getNumSuccessors(); ++i)
                {
                    BasicBlock *dst = sw->getSuccessor(i);
                    BasicBlock *trampoline = BasicBlock::Create(Ctx, "sw_trampoline", &F);
                    trampoline->moveBefore(loopEnd);

                    builder.SetInsertPoint(trampoline);
                    BlockInfo &targetInfo = blockInfos[dst];

                    uint64_t disc = getRand64();
                    uint64_t simulatedNextState = (blockInfos[BB].stateID % 2 == 0 ? blockInfos[BB].stateID / 2 : 3 * blockInfos[BB].stateID + 1) ^ disc;
                    uint64_t stateCorr = simulatedNextState ^ targetInfo.stateID;

                    uint64_t rotatedKey = (blockInfos[BB].flowKeyIn << 13) | (blockInfos[BB].flowKeyIn >> (64 - 13));
                    uint64_t keyCorr = rotatedKey ^ targetInfo.flowKeyIn;

                    uint64_t encStateCorr = stateCorr ^ blockInfos[BB].flowKeyIn;
                    uint64_t encKeyCorr = keyCorr ^ blockInfos[BB].flowKeyIn;

                    Value *nextStateBase = builder.CreateCall(funcCollatz, {loadState, ConstantInt::get(Type::getInt64Ty(Ctx), disc)});
                    Value *decStateCorr = builder.CreateXor(ConstantInt::get(Type::getInt64Ty(Ctx), encStateCorr), loadKey);
                    Value *decKeyCorr = builder.CreateXor(ConstantInt::get(Type::getInt64Ty(Ctx), encKeyCorr), loadKey);

                    Value *nextState = builder.CreateXor(nextStateBase, decStateCorr);
                    Value *nextKey = builder.CreateCall(funcMixKey, {loadKey, decKeyCorr});

                    builder.CreateStore(nextState, stateVar);
                    builder.CreateStore(nextKey, flowKeyVar);
                    builder.CreateBr(loopHead);

                    sw->setSuccessor(i, trampoline);
                }
            }
        }
    }

    builder.SetInsertPoint(loopHead);
    Value *currState = builder.CreateLoad(Type::getInt64Ty(Ctx), stateVar);
    Value *currKey = builder.CreateLoad(Type::getInt64Ty(Ctx), flowKeyVar);

    Value *hashVal = builder.CreateCall(funcHash, {currState, currKey});

    SwitchInst *sw = builder.CreateSwitch(hashVal, loopDefault, origBlocks.size());

    for (BasicBlock *BB : origBlocks)
    {
        BlockInfo &info = blockInfos[BB];
        uint64_t targetHash = calculateCompileTimeHash(info.stateID, info.flowKeyIn);
        sw->addCase(ConstantInt::get(Type::getInt64Ty(Ctx), targetHash), BB);
    }

    int junkBlockCount = getRand64() % 20 + 8;
    std::vector<BasicBlock *> junkBlocks;

    for (int i = 0; i < junkBlockCount; ++i)
    {
        BasicBlock *srcBB = origBlocks[getRand64() % origBlocks.size()];

        ValueToValueMapTy VMap;
        BasicBlock *junkBB = CloneBasicBlock(srcBB, VMap, "junk", &F);
        junkBB->moveBefore(loopEnd);

        for (Instruction &I : *junkBB)
        {
            RemapInstruction(&I, VMap, RF_IgnoreMissingLocals | RF_NoModuleLevelChanges);
        }

        for (auto I = junkBB->rbegin(); I != junkBB->rend();)
        {
            Instruction *Inst = &(*I);
            ++I;

            if (Inst->isTerminator())
            {
                Inst->eraseFromParent();
                continue;
            }

            if (getRand64() % 2 == 0)
            {
                if (!Inst->getType()->isVoidTy())
                {
                    Inst->replaceAllUsesWith(UndefValue::get(Inst->getType()));
                }
                Inst->eraseFromParent();
            }
            else
            {
                if (auto *BO = dyn_cast<BinaryOperator>(Inst))
                {
                    BO->swapOperands();
                }
            }
        }

        builder.SetInsertPoint(junkBB);

#ifdef debug
        FunctionType *VoidTy = FunctionType::get(Type::getVoidTy(Ctx), false);
        InlineAsm *Trap = InlineAsm::get(VoidTy, "int3", "", true);
        builder.CreateCall(Trap);
#endif

        Value *curState = builder.CreateLoad(Type::getInt64Ty(Ctx), stateVar);
        Value *curKey = builder.CreateLoad(Type::getInt64Ty(Ctx), flowKeyVar);

        uint64_t randDisc = getRand64();
        uint64_t randMod = getRand64();

        Value *nextState = builder.CreateCall(funcCollatz, {curState, ConstantInt::get(Type::getInt64Ty(Ctx), randDisc)});
        Value *nextKey = builder.CreateCall(funcMixKey, {curKey, ConstantInt::get(Type::getInt64Ty(Ctx), randMod)});

        builder.CreateStore(nextState, stateVar);
        builder.CreateStore(nextKey, flowKeyVar);
        builder.CreateBr(loopHead);

        junkBlocks.push_back(junkBB);
    }

    for (BasicBlock *junkBB : junkBlocks)
    {
        uint64_t randomHash = getRand64();
        sw->addCase(ConstantInt::get(Type::getInt64Ty(Ctx), randomHash), junkBB);
    }

    builder.SetInsertPoint(loopDefault);
    Value *junkState = builder.CreateLoad(Type::getInt64Ty(Ctx), stateVar);

    uint64_t randomDiscriminator = getRand64();
    Value *junkNext = builder.CreateCall(funcCollatz, {junkState, ConstantInt::get(Type::getInt64Ty(Ctx), randomDiscriminator)});

    builder.CreateStore(junkNext, stateVar);
    builder.CreateBr(loopHead);

    if (loopEnd->empty())
    {
        loopEnd->eraseFromParent();
    }

    errs() << "  Flattening complete for " << F.getName() << "\n";
}