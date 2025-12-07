#include "FlatteningEnhanced.h"
#include "CryptoUtils.h"
#include "Utils.h"
#include "MBAUtils.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Transforms/Utils/Local.h"
#include <cstdlib>
#include <ctime>
#include <list>
#include <map>
#include <set>
#include <utility>
#include <vector>
#include <random>
#include <sstream>

// #define debug

using namespace llvm;

// -------------------------------------------------------------------------
// Helper: Random String
// -------------------------------------------------------------------------
static std::string genRandomString(int length) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string result;
    result.resize(length);
    for(int i = 0; i < length; i++) {
        result[i] = charset[cryptoutils->get_uint64_t() % (sizeof(charset) - 1)];
    }
    return result;
}

#ifdef debug
#define GEN_NAME(X) (X)
#define DEBUG_LOG(msg) dbg(msg)
void dbg(StringRef msg) { errs() << "[FlatteningEnhanced] " << msg << "\n"; }
#else
#define GEN_NAME(X) (genRandomString(8))
#define DEBUG_LOG(msg)
#endif

// -------------------------------------------------------------------------
// Helper: Random Utils
// -------------------------------------------------------------------------
static bool getBool() {
    return cryptoutils->get_uint8_t() % 2 == 1;
}

static int getRange(int min, int max) {
    if (max <= min) return min;
    return min + (cryptoutils->get_uint32_t() % (max - min + 1));
}

// -------------------------------------------------------------------------
// 4. 多样化 MBA (Polymorphic MBA) & Chaos Loop Refs
// -------------------------------------------------------------------------

// MBA Add: (A ^ B) + 2*(A & B)
static Value* createMBAAdd(IRBuilder<> &Builder, Value *Val1, Value *Val2) {
    Value *Xor = Builder.CreateXor(Val1, Val2);
    Value *And = Builder.CreateAnd(Val1, Val2);
    Value *Two = ConstantInt::get(Val1->getType(), 2);
    Value *Mul = Builder.CreateMul(And, Two);
    return Builder.CreateAdd(Xor, Mul);
}

// 混沌循环不透明谓词 (Chaos Loop Opaque Predicate)
// 生成一个运行时计算为 True 的条件，但依赖于不可预测的循环迭代，极难被符号执行求解。
// 副作用：会分割当前 Block。
static Value* createChaosLoop(IRBuilder<> &Builder, Function *F) {
    BasicBlock *PreBB = Builder.GetInsertBlock();
    // 在当前插入点分割 Block，后半部分（包含原Terminator）成为 MergeBB
    BasicBlock *MergeBB = PreBB->splitBasicBlock(Builder.GetInsertPoint(), GEN_NAME("chaos_merge"));
    // 移除 splitBasicBlock 自动产生的跳转，我们将插入 Header
    PreBB->getTerminator()->eraseFromParent();
    
    BasicBlock *HeaderBB = BasicBlock::Create(F->getContext(), GEN_NAME("chaos_header"), F, MergeBB);
    BasicBlock *BodyBB = BasicBlock::Create(F->getContext(), GEN_NAME("chaos_body"), F, MergeBB);
    
    // --- 1. PreBB (Setup) ---
    Builder.SetInsertPoint(PreBB);
    uint32_t x0 = getRange(10, 1000);
    uint32_t y0 = getRange(10, 1000);
    int iterations = getRange(4, 7); // 保持较小以减少运行时开销
    
    // 静态预计算预期结果
    uint32_t x = x0, y = y0;
    for(int i=0; i<iterations; ++i) {
        // 模拟循环体内的逻辑
        x = (x + y) ^ 0xDEADBEEF; 
        y = (y + x) + 0xCAFEBABE;
    }
    
    Builder.CreateBr(HeaderBB);
    
    // --- 2. Loop Header ---
    Builder.SetInsertPoint(HeaderBB);
    PHINode *IV = Builder.CreatePHI(Type::getInt32Ty(F->getContext()), 2, GEN_NAME("iv"));
    PHINode *X = Builder.CreatePHI(Type::getInt32Ty(F->getContext()), 2, GEN_NAME("x"));
    PHINode *Y = Builder.CreatePHI(Type::getInt32Ty(F->getContext()), 2, GEN_NAME("y"));
    
    IV->addIncoming(ConstantInt::get(Type::getInt32Ty(F->getContext()), 0), PreBB);
    X->addIncoming(ConstantInt::get(Type::getInt32Ty(F->getContext()), x0), PreBB);
    Y->addIncoming(ConstantInt::get(Type::getInt32Ty(F->getContext()), y0), PreBB);
    
    Value *cond = Builder.CreateICmpULT(IV, ConstantInt::get(Type::getInt32Ty(F->getContext()), iterations));
    Builder.CreateCondBr(cond, BodyBB, MergeBB);
    
    // --- 3. Loop Body ---
    Builder.SetInsertPoint(BodyBB);
    
    // 注入 MBA 操作使语义更难以分析
    // x = (x + y) ^ 0xDEADBEEF
    Value *Sum = createMBAAdd(Builder, X, Y); 
    Value *XNext = Builder.CreateXor(Sum, ConstantInt::get(Type::getInt32Ty(F->getContext()), 0xDEADBEEF));
    
    // y = (y + x) + 0xCAFEBABE
    // 注意：这里使用的是更新后的 x (XNext) 还是旧 x?
    // 上面 C++ 模拟代码是串行的: x=...; y=...+x; 所以这里用 XNext
    Value *Sum2 = createMBAAdd(Builder, Y, XNext); 
    Value *YNext = Builder.CreateAdd(Sum2, ConstantInt::get(Type::getInt32Ty(F->getContext()), 0xCAFEBABE));
    
    Value *IVNext = Builder.CreateAdd(IV, ConstantInt::get(Type::getInt32Ty(F->getContext()), 1));
    
    IV->addIncoming(IVNext, BodyBB);
    X->addIncoming(XNext, BodyBB);
    Y->addIncoming(YNext, BodyBB);
    
    Builder.CreateBr(HeaderBB);
    
    // --- 4. Merge ---
    Builder.SetInsertPoint(MergeBB, MergeBB->begin());
    PHINode *FinalX = Builder.CreatePHI(Type::getInt32Ty(F->getContext()), 1);
    FinalX->addIncoming(X, HeaderBB);
    
    // Predicate: FinalX == Expected (Always True)
    return Builder.CreateICmpEQ(FinalX, ConstantInt::get(Type::getInt32Ty(F->getContext()), x));
}


// -------------------------------------------------------------------------
// 5. 增强型 Junk Code (抗 DCE)
// -------------------------------------------------------------------------
static BasicBlock* createJunkBlock(Function *f, BasicBlock *target, int seed) {
    BasicBlock *junkBB = BasicBlock::Create(f->getContext(), GEN_NAME("Junk"), f);
    IRBuilder<> builder(junkBB);
    
    // 随机执行一些读取操作，避免被视为纯死代码
    Module *M = f->getParent();
    GlobalVariable *GV = nullptr;
    for (auto &G : M->globals()) { 
        if (G.getValueType()->isIntegerTy()) {
            GV = &G; 
            break; 
        }
    }
    if (GV) {
        builder.CreateLoad(GV->getValueType(), GV, true);
    }
    
    // 垃圾块不应直接终止，而应跳回 target (LoopEnd)，或者跳向另一个垃圾块
    builder.CreateBr(target);
    
    return junkBB;
}

// -------------------------------------------------------------------------
// 3. 基本块分割 (Splitting Basic Blocks)
// -------------------------------------------------------------------------
static void splitBasicBlocks(Function *f) {
    std::vector<BasicBlock *> origBB;
    for (BasicBlock &bb : *f) origBB.push_back(&bb);

    for (BasicBlock *bb : origBB) {
        if (bb == &f->getEntryBlock() || isa<PHINode>(bb->begin())) continue;
        // 随机决定是否分割 (30% 概率)
        if (getRange(0, 100) < 30 && bb->size() > 4) {
             BasicBlock::iterator it = bb->begin();
             std::advance(it, bb->size() / 2); 
             bb->splitBasicBlock(it, GEN_NAME("SplitBB"));
        }
    }
}

// -------------------------------------------------------------------------
// Main Flattening Logic
// -------------------------------------------------------------------------

unsigned int
FlatteningEnhanced::getUniqueNumber(std::vector<unsigned int> *rand_list) {
    unsigned int num = (unsigned int)cryptoutils->get_uint64_t();
    while (true) {
        bool state = true;
        for (auto n : *rand_list) if (n == num) { state = false; break; }
        if (state) break;
        num = (unsigned int)cryptoutils->get_uint64_t();
    }
    return num;
}

void FlatteningEnhanced::DoFlatteningEnhanced(Function *f, int seed, Function *updateFunc)
{
    DEBUG_LOG("Starting Enhanced Flattening with IndirectBr & Chaos Loops...");
    
    // 1. 基本块分割：增加粒度
    splitBasicBlocks(f);
    
    std::vector<BasicBlock*> origBB;
    getBlocks(f, &origBB);
    if (origBB.size() <= 1) return;

    BasicBlock *oldEntry = &f->getEntryBlock();
    BasicBlock *firstbb = oldEntry->getTerminator()->getSuccessor(0);
    
    BasicBlock::iterator iter = oldEntry->end();
    iter--;
    if (oldEntry->size() > 1) iter--;
    BasicBlock *splited = oldEntry->splitBasicBlock(iter, GEN_NAME("FirstBB"));
    firstbb = splited;
    origBB.insert(origBB.begin(), splited);

    // 移除异常处理块
    std::vector<BasicBlock *> removeBB;
    for (auto b : origBB) {
        if (InvokeInst *invoke = dyn_cast<InvokeInst>(b->getTerminator()))
            removeBB.push_back(invoke->getUnwindDest());
    }
    for (auto b : removeBB) {
        auto found = std::find(origBB.begin(), origBB.end(), b);
        if (found != origBB.end()) origBB.erase(found);
    }

    IRBuilder<> irb(&*oldEntry->getFirstInsertionPt());

    // =========================================================================
    // 2. 准备 Context 和 跳转表 (IndirectBr)
    // =========================================================================
    
    // 改变传统 Switch 结构：使用 IndirectBr (Computed Goto)
    // switchVar 存储的是目标 BlockAddress (i8*)
    AllocaInst *switchVar = irb.CreateAlloca(Type::getInt8Ty(f->getContext())->getPointerTo(), nullptr, GEN_NAME("pc"));
    
    // 初始化 switchVar 指向 FirstBB
    BlockAddress *firstAddr = BlockAddress::get(firstbb);
    irb.CreateStore(firstAddr, switchVar);

    // 构建 Loop 结构
    BasicBlock *newEntry = oldEntry;
    BasicBlock *loopHead = BasicBlock::Create(f->getContext(), GEN_NAME("LoopHead"), f, newEntry);
    BasicBlock *loopEndType = BasicBlock::Create(f->getContext(), GEN_NAME("LoopBack"), f, newEntry); 
     
    newEntry->moveBefore(loopHead);
    newEntry->getTerminator()->eraseFromParent();
    BranchInst::Create(loopHead, newEntry);
    
    // LoopHead: 读取目标地址并跳转
    irb.SetInsertPoint(loopHead);
    LoadInst *targetAddr = irb.CreateLoad(Type::getInt8Ty(f->getContext())->getPointerTo(), switchVar, GEN_NAME("target"));
    
    // 创建 IndirectBr，由于需要列出所有可能目标，暂时只创建指令，稍后填充 Destination
    IndirectBrInst *indirectBr = IndirectBrInst::Create(targetAddr, origBB.size() + 10, loopHead);

    // LoopBack (LoopEnd) -> LoopHead
    // 所有 Block 执行完后都跳到这里，再跳回 Head
    BranchInst::Create(loopHead, loopEndType);

    // =========================================================================
    // 3. 生成 Junk Blocks (增强可达性混淆)
    // =========================================================================
    std::vector<BasicBlock *> junkBBs;
    int numJunk = getRange(2, 4); 
    for(int i=0; i<numJunk; ++i) {
        BasicBlock *dud = createJunkBlock(f, loopEndType, i);
        junkBBs.push_back(dud);
        origBB.push_back(dud); // Junk 也是“有效”的 IndirectBr 目标
    }

    // 将所有可能的块添加到 IndirectBr 的目标列表
    for (BasicBlock *bb : origBB) {
        if (bb == newEntry || bb == loopHead || bb == loopEndType) continue;
        indirectBr->addDestination(bb);
        bb->moveBefore(loopEndType);
    }

    // =========================================================================
    // 4. 重构原逻辑：使用 Chaos Loop 保护跳转
    // =========================================================================
    
    for (auto bb : origBB) {
        if (bb == newEntry || bb == loopHead || bb == loopEndType) continue;
        
        // 忽略纯 Junk 块的内部逻辑处理（因为我们在 createJunkBlock 处理了）
        bool isJunk = (std::find(junkBBs.begin(), junkBBs.end(), bb) != junkBBs.end());
        if (isJunk) continue;

        auto *term = bb->getTerminator();
        if (isa<ReturnInst>(term) || isa<UnreachableInst>(term)) continue;
        
        // 插入点：Terminator 之前
        irb.SetInsertPoint(term);
        
        // 生成混沌循环不透明谓词 (Chaos Loop)
        // chaosPred 恒为 True，但静态分析难以确定。
        // createChaosLoop 会将当前 BB 分割为 PreBB (Loop Setup) -> Loop -> MergeBB
        // 此时 irb 会被更新，并且后续指令应当插入在 MergeBB
        Value *chaosPred = createChaosLoop(irb, f); 
        
        // 由于 splitBlock，原 Terminator (term) 现在位于 MergeBB 的末尾
        // createChaosLoop 返回后，irb 的 InsertPoint 位于 MergeBB 的开始位置
        // 我们需要重新定位到 term 之前 (或者直接使用 term)
        BasicBlock *currentBB = irb.GetInsertBlock();
        term = currentBB->getTerminator(); 

        if(BranchInst *br = dyn_cast<BranchInst>(term)) {
            if (br->isUnconditional()) {
                BasicBlock *succ = br->getSuccessor(0);
                
                // Real Address
                Value *realAddr = BlockAddress::get(succ);
                // Fake Address (随机选一个 Junk Block)
                BasicBlock *fakeDest = junkBBs[getRange(0, junkBBs.size()-1)];
                Value *fakeAddr = BlockAddress::get(fakeDest);
                
                // Masked Pointer Selection: switchVar = chaosPred ? realAddr : fakeAddr
                // 求解器会被迫考虑 fakeAddr 这条路径，认为 Junk Block 是可达的
                Value *selAddr = irb.CreateSelect(chaosPred, realAddr, fakeAddr);
                
                irb.CreateStore(selAddr, switchVar);
                BranchInst::Create(loopEndType, currentBB);
                term->eraseFromParent();
            } 
            else { // Conditional
                BasicBlock *trueSucc = br->getSuccessor(0);
                BasicBlock *falseSucc = br->getSuccessor(1);
                
                Value *cond = br->getCondition();
                
                // Real Selection
                // Use Select instead of branching to avoid creating new edges in CFG
                Value *trueAddr = BlockAddress::get(trueSucc);
                Value *falseAddr = BlockAddress::get(falseSucc);
                Value *condSel = irb.CreateSelect(cond, trueAddr, falseAddr);
                
                // Fake Address
                BasicBlock *fakeDest = junkBBs[getRange(0, junkBBs.size()-1)];
                Value *fakeAddr = BlockAddress::get(fakeDest);
                
                // Double Layer Selection
                // switchVar = chaosPred ? (cond ? trueAddr : falseAddr) : fakeAddr
                Value *finalSel = irb.CreateSelect(chaosPred, condSel, fakeAddr);
                
                irb.CreateStore(finalSel, switchVar);
                BranchInst::Create(loopEndType, currentBB);
                term->eraseFromParent();
            }
        }
        else if (isa<SwitchInst>(term)) {
             // 对于原有的 SwitchInst，暂不做处理，防止过度复杂
             // 在标准 Flattening 中应该将 Switch 展开。
        }
    }
    
    fixStack(*f);
    DEBUG_LOG("Flattening Completed.");
}

PreservedAnalyses FlatteningEnhanced::run(Module &M, ModuleAnalysisManager &AM)
{
    for (Function &f : M)
    {
        if (toObfuscate(flag, &f, "enfla"))
        {
            outs() << "\033[1;32m[FlatteningEnhanced] Function: " << f.getName()
                   << "\033[0m\n";
            DoFlatteningEnhanced(&f, 0, nullptr);
        }
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