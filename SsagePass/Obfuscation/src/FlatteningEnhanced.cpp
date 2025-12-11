/**
 * @file FlatteningEnhanced.cpp
 * @brief 
 * @author Lux-QAQ
 * @version 1.0.1
 * @date 2025-12-09
 * 
 * @copyright Copyright (c) 2025  Lux-QAQ
 * 
*/
#include "FlatteningEnhanced.h"
#include "CryptoUtils.h"
#include "Utils.h"
#include "MBAUtils.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/IR/NoFolder.h"
#include <cstdlib>
#include <ctime>
#include <vector>
#include <map>
#include <set>
#include <sstream>
#include <algorithm>

using namespace llvm;
using std::map;
using std::vector;

// 生成随机函数名
static std::string genRandomName(int len)
{
    static const char alphanum[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
    std::string s;
    for (int i = 0; i < len; ++i)
    {
        s += alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    return s;
}

// 检查并创建递归不透明谓词辅助函数
Function *getOrCreateRecursiveHelper(Module &M)
{
    for (Function &F : M)
    {
        if (F.getName().starts_with("__ollvm_rec_"))
        {
            return &F;
        }
    }

    LLVMContext &Ctx = M.getContext();
    IRBuilder<> builder(Ctx);

    std::vector<Type *> params = {Type::getInt32Ty(Ctx), Type::getInt32Ty(Ctx)};
    FunctionType *funcType = FunctionType::get(Type::getInt32Ty(Ctx), params, false);

    std::string funcName = "__ollvm_rec_" + genRandomName(8);
    Function *func = Function::Create(funcType, GlobalValue::InternalLinkage, funcName, M);
    func->addFnAttr(Attribute::NoInline);

    BasicBlock *entry = BasicBlock::Create(Ctx, "entry", func);
    BasicBlock *recurse = BasicBlock::Create(Ctx, "recurse", func);
    BasicBlock *base = BasicBlock::Create(Ctx, "base", func);

    builder.SetInsertPoint(entry);
    Function::arg_iterator args = func->arg_begin();
    Value *x = args++;
    Value *y = args++;

    Value *cond = builder.CreateICmpSLE(x, ConstantInt::get(Type::getInt32Ty(Ctx), 0));
    builder.CreateCondBr(cond, base, recurse);

    builder.SetInsertPoint(recurse);
    Value *subX = builder.CreateSub(x, ConstantInt::get(Type::getInt32Ty(Ctx), 1));
    Value *addY = builder.CreateAdd(y, ConstantInt::get(Type::getInt32Ty(Ctx), 1));

    Value *call = builder.CreateCall(func, {subX, addY});
    Value *res = builder.CreateXor(call, x);
    builder.CreateRet(res);

    builder.SetInsertPoint(base);
    builder.CreateRet(y);

    return func;
}

PreservedAnalyses FlatteningEnhanced::run(Module &M, ModuleAnalysisManager &AM)
{
    srand(time(NULL));
    Function *recursivePredFunc = getOrCreateRecursiveHelper(M);

    std::vector<Function *> funcs;
    for (Function &F : M)
    {
        if (F.getName().starts_with("__ollvm_rec_")) continue;
        if (!F.isDeclaration() && toObfuscate(flag, &F, "fla"))
        {
            funcs.push_back(&F);
        }
    }

    for (Function *F : funcs)
    {
        DoFlatteningEnhanced(F, rand(), recursivePredFunc);
    }

    return PreservedAnalyses::all();
}

std::vector<BasicBlock *> *
FlatteningEnhanced::getBlocks(Function *function,
                              std::vector<BasicBlock *> *lists)
{
    lists->clear();
    for (BasicBlock &basicBlock : *function)
        lists->push_back(&basicBlock);
    return lists;
}

unsigned int
FlatteningEnhanced::getUniqueNumber(std::vector<unsigned int> *rand_list)
{
    unsigned int num = rand();
    while (true)
    {
        bool found = false;
        for (unsigned int n : *rand_list)
        {
            if (n == num)
            {
                found = true;
                break;
            }
        }
        if (!found) break;
        num = rand();
    }
    rand_list->push_back(num);
    return num;
}

// 创建一个复杂的循环迭代不透明谓词
Value *createComplexIterPredicate(IRBuilder<> &irb, Value *contextVar)
{
    Module *M = irb.GetInsertBlock()->getModule();
    Function *F = irb.GetInsertBlock()->getParent();
    LLVMContext &Ctx = M->getContext();

    BasicBlock *originalBlock = irb.GetInsertBlock();
    BasicBlock *continueBlock;

    if (irb.GetInsertPoint() == originalBlock->end())
    {
        continueBlock = BasicBlock::Create(Ctx, "pred_continue", F);
    }
    else
    {
        continueBlock = originalBlock->splitBasicBlock(irb.GetInsertPoint(), "pred_continue");
        originalBlock->getTerminator()->eraseFromParent();
    }

    BasicBlock *loopHeader = BasicBlock::Create(Ctx, "pred_loop_h", F, continueBlock);
    BasicBlock *loopBody = BasicBlock::Create(Ctx, "pred_loop_b", F, continueBlock);
    BasicBlock *loopEnd = BasicBlock::Create(Ctx, "pred_loop_e", F, continueBlock);

    IRBuilder<> origBuilder(originalBlock);
    origBuilder.CreateBr(loopHeader);

    irb.SetInsertPoint(loopHeader);
    PHINode *i = irb.CreatePHI(Type::getInt32Ty(Ctx), 2, "i");
    PHINode *x = irb.CreatePHI(Type::getInt32Ty(Ctx), 2, "x");
    i->addIncoming(ConstantInt::get(Type::getInt32Ty(Ctx), 0), originalBlock);
    x->addIncoming(contextVar, originalBlock);

    Value *loopCond = irb.CreateICmpSLT(i, ConstantInt::get(Type::getInt32Ty(Ctx), 5 + (rand() % 5)));
    irb.CreateCondBr(loopCond, loopBody, loopEnd);

    irb.SetInsertPoint(loopBody);
    Value *v1 = irb.CreateXor(x, i);
    Value *v2 = irb.CreateMul(i, ConstantInt::get(Type::getInt32Ty(Ctx), 3));
    Value *newX = irb.CreateAdd(v1, v2);
    Value *newI = irb.CreateAdd(i, ConstantInt::get(Type::getInt32Ty(Ctx), 1));

    i->addIncoming(newI, loopBody);
    x->addIncoming(newX, loopBody);
    irb.CreateBr(loopHeader);

    irb.SetInsertPoint(loopEnd);
    Value *x_plus_1 = irb.CreateAdd(x, ConstantInt::get(Type::getInt32Ty(Ctx), 1));
    Value *prod = irb.CreateMul(x, x_plus_1);
    Value *mod = irb.CreateURem(prod, ConstantInt::get(Type::getInt32Ty(Ctx), 2));
    Value *pred = irb.CreateICmpNE(mod, ConstantInt::get(Type::getInt32Ty(Ctx), 0));

    irb.CreateBr(continueBlock);
    irb.SetInsertPoint(continueBlock);

    return pred;
}

void FlatteningEnhanced::DoFlatteningEnhanced(Function *f, int seed, Function *recursiveHelper)
{
    srand(seed);
    std::vector<BasicBlock *> origBB;
    getBlocks(f, &origBB);
    if (origBB.size() <= 1) return;

    // 1. Demote PHI nodes to Stack
    for (BasicBlock *bb : origBB)
    {
        std::vector<PHINode *> phis;
        for (Instruction &I : *bb)
        {
            if (PHINode *phi = dyn_cast<PHINode>(&I))
            {
                phis.push_back(phi);
            }
        }
        for (PHINode *phi : phis)
        {
            DemotePHIToStack(phi);
        }
    }

    origBB.clear();
    getBlocks(f, &origBB);

    // 2. 分离 Entry Block 的 Allocas 和 Logic
    BasicBlock *oldEntry = &f->getEntryBlock();

    BasicBlock::iterator splitIt = oldEntry->begin();
    while (splitIt != oldEntry->end() && (isa<AllocaInst>(*splitIt) || isa<DbgInfoIntrinsic>(*splitIt)))
    {
        ++splitIt;
    }

    BasicBlock *newEntry = oldEntry->splitBasicBlock(splitIt, "newEntry");

    auto it = std::find(origBB.begin(), origBB.end(), oldEntry);
    if (it != origBB.end())
    {
        *it = newEntry;
    }
    else
    {
        origBB.insert(origBB.begin(), newEntry);
    }

    oldEntry->getTerminator()->eraseFromParent();

    // 3. 准备平坦化结构
    BasicBlock *loopEntry = BasicBlock::Create(f->getContext(), "loopEntry", f);
    BasicBlock *loopEnd = BasicBlock::Create(f->getContext(), "loopEnd", f);
    BasicBlock *swDefault = BasicBlock::Create(f->getContext(), "switchDefault", f);
    BasicBlock *bogusBB = BasicBlock::Create(f->getContext(), "bogusBlock", f);
    Type *i32Ty = Type::getInt32Ty(f->getContext());

    // 填充虚假块
    IRBuilder<> bogusBuilder(bogusBB);
    bogusBuilder.CreateAdd(ConstantInt::get(i32Ty, rand()), ConstantInt::get(i32Ty, rand()));
    bogusBuilder.CreateBr(bogusBB);

    // 4. 设置 Entry Block (oldEntry)
    IRBuilder<> entryBuilder(oldEntry);
    AllocaInst *swVarPtr = entryBuilder.CreateAlloca(i32Ty, nullptr, "swVar");

    std::vector<unsigned int> rand_list;
    unsigned int startKey = getUniqueNumber(&rand_list);
    entryBuilder.CreateStore(ConstantInt::get(i32Ty, startKey), swVarPtr);
    entryBuilder.CreateBr(loopEntry);

    // 5. 构建 Loop Entry
    IRBuilder<> loopBuilder(loopEntry);
    Value *currSwCtx = loopBuilder.CreateLoad(i32Ty, swVarPtr);

    if (rand() % 2 == 0)
    {
        Value *isBogus = createComplexIterPredicate(loopBuilder, currSwCtx);
        BasicBlock *realSwitchBlock = BasicBlock::Create(f->getContext(), "realSwitch", f);
        loopBuilder.CreateCondBr(isBogus, bogusBB, realSwitchBlock);
        loopBuilder.SetInsertPoint(realSwitchBlock);
    }
    else
    {
        Value *zero = ConstantInt::get(i32Ty, 0);
        Value *retVal = loopBuilder.CreateCall(recursiveHelper, {zero, currSwCtx});
        Value *cond = loopBuilder.CreateICmpEQ(retVal, currSwCtx);
        BasicBlock *realSwitchBlock = BasicBlock::Create(f->getContext(), "realSwitch", f);
        loopBuilder.CreateCondBr(cond, realSwitchBlock, bogusBB);
        loopBuilder.SetInsertPoint(realSwitchBlock);
    }

    Value *swVar = loopBuilder.CreateLoad(i32Ty, swVarPtr);
    SwitchInst *swInst = loopBuilder.CreateSwitch(swVar, swDefault);

    // 6. 映射 Block -> Key
    map<BasicBlock *, unsigned int> blockKeys;
    for (BasicBlock *bb : origBB)
    {
        if (blockKeys.empty())
        {
            blockKeys[bb] = startKey;
        }
        else
        {
            blockKeys[bb] = getUniqueNumber(&rand_list);
        }
        swInst->addCase(cast<ConstantInt>(ConstantInt::get(i32Ty, blockKeys[bb])), bb);
    }

    swInst->addCase(cast<ConstantInt>(ConstantInt::get(i32Ty, getUniqueNumber(&rand_list))), bogusBB);

    // 7. 修正跳转
    for (BasicBlock *bb : origBB)
    {
        auto *term = bb->getTerminator();
        if (!term) continue;
        IRBuilder<> termBuilder(bb);
        termBuilder.SetInsertPoint(term);

        if (isa<ReturnInst>(term))
        {
            continue;
        }
        else if (isa<UnreachableInst>(term))
        {
            continue;
        }
        else if (BranchInst *br = dyn_cast<BranchInst>(term))
        {
            if (br->isUnconditional())
            {
                BasicBlock *succ = br->getSuccessor(0);
                unsigned int targetKey = blockKeys[succ];

                BinaryOperator *op = BinaryOperator::Create(Instruction::Add,
                                                            ConstantInt::get(i32Ty, 0), ConstantInt::get(i32Ty, targetKey), "", term);

                int64_t *mba_terms = generateLinearMBA(10);
                mba_terms[2] += 1;
                mba_terms[4] += 1;
                Value *mbaExpr = insertLinearMBA(mba_terms, op);

                termBuilder.CreateStore(mbaExpr, swVarPtr);
                op->eraseFromParent();

                termBuilder.CreateBr(loopEnd);
                term->eraseFromParent();
            }
            else
            {
                BasicBlock *trueSucc = br->getSuccessor(0);
                BasicBlock *falseSucc = br->getSuccessor(1);
                unsigned int trueKey = blockKeys[trueSucc];
                unsigned int falseKey = blockKeys[falseSucc];

                Value *cond = br->getCondition();
                Value *sel = termBuilder.CreateSelect(cond, ConstantInt::get(i32Ty, trueKey), ConstantInt::get(i32Ty, falseKey), "nextKey");

                BinaryOperator *dummyPoly = BinaryOperator::Create(Instruction::Add,
                                                                   ConstantInt::get(i32Ty, 0), ConstantInt::get(i32Ty, 0), "dummyPoly", term);

                Value *polyMBA = insertPolynomialMBA(sel, dummyPoly);
                dummyPoly->eraseFromParent();

                termBuilder.CreateStore(polyMBA, swVarPtr);
                termBuilder.CreateBr(loopEnd);
                term->eraseFromParent();
            }
        }
        else if (SwitchInst *sw = dyn_cast<SwitchInst>(term))
        {
            vector<std::pair<ConstantInt *, BasicBlock *>> cases;
            for (auto mk : sw->cases()) cases.push_back({mk.getCaseValue(), mk.getCaseSuccessor()});
            BasicBlock *def = sw->getDefaultDest();
            Value *cond = sw->getCondition();  // 先保存 Condition

            // 修复：先创建新 Switch，再删除旧 Switch
            SwitchInst *newSw = termBuilder.CreateSwitch(cond, def, cases.size());

            sw->eraseFromParent();  // 现在可以安全删除了

            map<BasicBlock *, BasicBlock *> trampolines;
            auto getTrampoline = [&](BasicBlock *target)
            {
                if (trampolines.count(target)) return trampolines[target];
                BasicBlock *trampoline = BasicBlock::Create(f->getContext(), "trampoline", f);
                IRBuilder<> tb(trampoline);

                unsigned int key = blockKeys[target];
                BinaryOperator *op = BinaryOperator::Create(Instruction::Add,
                                                            ConstantInt::get(i32Ty, key), ConstantInt::get(i32Ty, 0), "", trampoline);
                int64_t *terms = generateLinearMBA(10);
                terms[2] += 1;
                terms[4] += 1;
                Value *mba = insertLinearMBA(terms, op);
                tb.CreateStore(mba, swVarPtr);
                op->eraseFromParent();

                tb.CreateBr(loopEnd);
                return trampolines[target] = trampoline;
            };

            newSw->setDefaultDest(getTrampoline(def));
            for (auto &c : cases)
            {
                newSw->addCase(c.first, getTrampoline(c.second));
            }
        }
    }

    IRBuilder<> defBuilder(swDefault);
    defBuilder.CreateBr(loopEnd);

    IRBuilder<> endBuilder(loopEnd);
    endBuilder.CreateBr(loopEntry);
}

FlatteningEnhanced *llvm::createFlatteningEnhanced(bool flag)
{
    return new FlatteningEnhanced(flag);
}