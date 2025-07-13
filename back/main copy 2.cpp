#include "FlatteningEnhanced.h" // 包含 FlatteningEnhanced 类的声明
#include "VMFlatten.h"
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

#include "llvm/CodeGen/UnreachableBlockElim.h" // For UnreachableBlockElimPass
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Verifier.h"                  // For verifyFunction
#include "llvm/Transforms/Utils/Local.h"       // For DemotePHIToStack
#include "llvm/Transforms/Utils/LowerInvoke.h" // For LowerInvokePass

// User libs (确保这些路径在 CMakeLists.txt 中正确设置)
#include "CryptoUtils.h"     // 已在 FlatteningEnhanced.h 中包含
#include "Utils.h"           // 已在 FlatteningEnhanced.h 中包含
#include "compat/CallSite.h" // 已在 FlatteningEnhanced.h 中包含

#include <algorithm> // For std::find
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
#define debugPrint(msg)                                                        \
  do {                                                                         \
                                                                               \
    outs() << "\033[1;33m[FlatteningEnhanced:" << __LINE__ << "] " << msg      \
           << "\033[0m\n";                                                     \
                                                                               \
  } while (0);
#else
#define debugPrint
#endif

// 使用 llvm 命名空间，因为 FlatteningEnhanced.h 中类和函数都在此命名空间
using namespace llvm;

// FlatteningEnhanced 类成员函数的实现
PreservedAnalyses llvm::FlatteningEnhanced::run(Module &M,
                                                ModuleAnalysisManager &AM) {
  // vector<CallSite *> callsites; // CallSite
  // 在新版LLVM中处理方式不同，暂时注释
  Function *updateFunc = buildUpdateKeyFunc(&M);

  bool Changed = false;
  for (Function &f : M) {
    if (llvm::toObfuscate(flag, &f, "enfla")) { // 显式调用 llvm::toObfuscate
      outs() << "\033[1;32m[FlatteningEnhanced] Function: " << f.getName()
             << "\033[0m\n";

      if (&f == updateFunc)
        continue;
      // 确保函数是可调用的

      DoFlatteningEnhanced(&f, 0, updateFunc);
      Changed = true;
    }
  }

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
unsigned int
FlatteningEnhanced::getUniqueNumber(std::vector<unsigned int> *rand_list) {
  unsigned int num = rand();
  while (true) {
    bool state = true;
    for (std::vector<unsigned int>::iterator n = rand_list->begin();
         n != rand_list->end(); n++)
      if (*n == num) {
        state = false;
        break;
      }
    if (state)
      break;
    num = rand();
  }
  return num;
}

std::vector<BasicBlock *> *
llvm::FlatteningEnhanced::getBlocks(Function *function,
                                    std::vector<BasicBlock *> *lists) {
  lists->clear();
  for (BasicBlock &basicBlock : *function)
    lists->push_back(&basicBlock);
  return lists;
}

Function *FlatteningEnhanced::buildUpdateKeyFunc(Module *m) {
  LLVMContext &ctx = m->getContext();
  IRBuilder<> irb(ctx);

  std::vector<Type *> params;
  params.push_back(Type::getInt8Ty(ctx));                       // flag
  params.push_back(Type::getInt32Ty(ctx));                      // len
  params.push_back(PointerType::get(Type::getInt32Ty(ctx), 0)); // posArray
  params.push_back(PointerType::get(Type::getInt32Ty(ctx), 0)); // keyArray
  params.push_back(Type::getInt32Ty(ctx));                      // num

  FunctionType *funcType =
      FunctionType::get(Type::getVoidTy(ctx), params, false);
  Function *func = Function::Create(funcType, GlobalValue::PrivateLinkage,
                                    Twine("ollvm"), m);

  BasicBlock *entry = BasicBlock::Create(ctx, "entry", func);
  BasicBlock *cond = BasicBlock::Create(ctx, "cond", func);
  BasicBlock *update = BasicBlock::Create(ctx, "update", func);
  BasicBlock *end = BasicBlock::Create(ctx, "end", func);

  Function::arg_iterator iter = func->arg_begin();
  Value *flag = iter++;
  Value *len = iter++;
  Value *posArray = iter++;
  Value *keyArray = iter++;
  Value *num = iter;

  irb.SetInsertPoint(entry);
  AllocaInst *i = irb.CreateAlloca(irb.getInt32Ty());
  irb.CreateStore(irb.getInt32(0), i);
  irb.CreateCondBr(irb.CreateICmpEQ(flag, irb.getInt8(0)), cond, end);

  irb.SetInsertPoint(cond);
  Value *iVal = irb.CreateLoad(irb.getInt32Ty(), i);
  irb.CreateCondBr(irb.CreateICmpSLT(iVal, len), update, end);

  irb.SetInsertPoint(update);
  iVal = irb.CreateLoad(irb.getInt32Ty(), i); // reload i
  Value *posPtr = irb.CreateGEP(irb.getInt32Ty(), posArray, iVal);
  Value *pos = irb.CreateLoad(irb.getInt32Ty(), posPtr);
  Value *keyPtr = irb.CreateGEP(irb.getInt32Ty(), keyArray, pos);
  Value *keyVal = irb.CreateLoad(irb.getInt32Ty(), keyPtr);
  Value *xorVal = irb.CreateXor(keyVal, num);
  irb.CreateStore(xorVal, keyPtr);
  irb.CreateStore(irb.CreateAdd(iVal, irb.getInt32(1)), i);
  irb.CreateBr(cond);

  irb.SetInsertPoint(end);
  irb.CreateRetVoid();

  return func;
}

// 给第一层 dispatcher 生成 XOR 掩码
static unsigned getSeedXor(int seed) {
  // 简单示例：种子异或一个常量
  return (unsigned)seed ^ 0x5A5A5A5A;
}

// 给第二层 segment dispatcher 生成每段的 XOR 掩码
static unsigned getSegmentXor(unsigned segmentIndex, int seed) {
  // 示例：用段号和种子混合
  return ((segmentIndex + 1) * 0x1234567u) ^ (unsigned)seed;
}

// 给每个基本块分配一个 case 值
static unsigned getCaseForBlock(const llvm::BasicBlock *BB) {
  // 简单：用指针地址做哈希后取低位
  auto x = reinterpret_cast<uintptr_t>(BB);
  // mix bits
  x ^= (x >> 13);
  x *= 0x9E3779B97F4A7C15ULL;
  x ^= (x >> 17);
  return (unsigned)x;
}
static unsigned getJunkCase(int seed, unsigned idx) {
  uint64_t x = (uint64_t)seed;
  x = x * 0x9E3779B97F4A7C15ULL + idx;
  x ^= (x >> 16);
  x *= 0x85EBCA6BULL;
  return (unsigned)(x & 0xFFFFFFFFu);
}

void FlatteningEnhanced::DoFlatteningEnhanced(Function *f, int seed,
                                              Function *updateFunc) {
  srand(seed);
  std::vector<BasicBlock *> origBB;
  getBlocks(f, &origBB);
  if (origBB.size() <= 1)
    return;

  BasicBlock *oldEntry = &f->getEntryBlock();
  BranchInst *firstBr = NULL;
  if (isa<BranchInst>(oldEntry->getTerminator()))
    firstBr = cast<BranchInst>(oldEntry->getTerminator());
  BasicBlock *firstbb = oldEntry->getTerminator()->getSuccessor(0);

  BasicBlock::iterator iter = oldEntry->end(); // Split the first basic block
  iter--;
  if (oldEntry->size() > 1)
    iter--;
  BasicBlock *splited = oldEntry->splitBasicBlock(iter, Twine("FirstBB"));
  firstbb = splited;
  origBB.insert(origBB.begin(), splited);

  // remove the block which contains landingpad inst
  std::vector<BasicBlock *> removeBB;
  for (std::vector<BasicBlock *>::iterator b = origBB.begin();
       b != origBB.end(); b++) {
    BasicBlock *block = *b;
    Value *inst = block->getTerminator();
    if (isa<InvokeInst>(*inst)) {
      InvokeInst *invoke = (InvokeInst *)inst;
      // removeBB.push_back(block);
      removeBB.push_back(invoke->getUnwindDest());
    }
  }

  for (std::vector<BasicBlock *>::iterator b = removeBB.begin();
       b != removeBB.end(); b++) {
    BasicBlock *block = *b;
    std::vector<BasicBlock *>::iterator find =
        std::find(origBB.begin(), origBB.end(), block);
    if (find != origBB.end())
      origBB.erase(find);
  }

  IRBuilder<> irb(&*oldEntry->getFirstInsertionPt()); // generate context info
                                                      // key for each block
  Value *visitedArray =
      irb.CreateAlloca(irb.getInt8Ty(), irb.getInt32(origBB.size()));
  Value *keyArray =
      irb.CreateAlloca(irb.getInt32Ty(), irb.getInt32(origBB.size()));
  irb.CreateMemSet(visitedArray, irb.getInt8(0), origBB.size(), (MaybeAlign)0);
  irb.CreateMemSet(keyArray, irb.getInt8(0), origBB.size() * 4, (MaybeAlign)0);

  
  int idx = 0;
  std::vector<unsigned int> key_list;
  DominatorTree tree(*f);
  std::map<BasicBlock *, unsigned int> key_map;
  std::map<BasicBlock *, unsigned int> index_map;
  for (std::vector<BasicBlock *>::iterator b = origBB.begin();
       b != origBB.end(); b++) {
    BasicBlock *block = *b;
    unsigned int num = getUniqueNumber(&key_list);
    key_list.push_back(num);
    key_map[block] = 0;
  }
  for (std::vector<BasicBlock *>::iterator b = origBB.begin();
       b != origBB.end(); ++b, ++idx) {
    BasicBlock *block = *b;
    std::vector<Constant *> doms;
    int i = 0;
    // 收集支配信息
    for (std::vector<BasicBlock *>::iterator bb = origBB.begin();
         bb != origBB.end(); ++bb, ++i) {
      BasicBlock *block0 = *bb;
      if (block0 != block && tree.dominates(block, block0)) {
        doms.push_back(irb.getInt32(i));
        key_map[block0] ^= key_list[idx];
      }
    }

    // 设置插入点到当前块的 terminator 之前
    irb.SetInsertPoint(block->getTerminator());

    // 1) 生成 visitedArray[idx] 的指针，明确元素类型 i8
    Value *ptr =
        irb.CreateGEP(irb.getInt8Ty(), visitedArray, irb.getInt32(idx));
    // 原来：CreateLoad(ptr->getType()->getPointerElementType(), ptr)
    // 现改为：显式加载 i8
    Value *visited = irb.CreateLoad(irb.getInt8Ty(), ptr);

    if (!doms.empty()) {
      // 2) 构造 doms 常量数组
      ArrayType *arrayType = ArrayType::get(irb.getInt32Ty(), doms.size());
      Constant *doms_array =
          ConstantArray::get(arrayType, ArrayRef<Constant *>(doms));

      GlobalVariable *dom_variable =
          new GlobalVariable(*f->getParent(), arrayType,
                             /*isConstant=*/false, GlobalValue::PrivateLinkage,
                             doms_array, "doms");
      dom_variable->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

      // 原来：CreateGEP(dom_variable->getType()->getPointerElementType(),
      // dom_variable, {...}) 现改为：显式用 arrayType 作为元素类型
      Value *domPtr = irb.CreateGEP(arrayType, dom_variable,
                                    {irb.getInt32(0), irb.getInt32(0)});

      // 调用 updateFunc，参数顺序和逻辑完全不变
      irb.CreateCall(FunctionCallee(updateFunc),
                     {visited, irb.getInt32((unsigned)doms.size()), domPtr,
                      keyArray, irb.getInt32(key_list[idx])});
    }

    // 3) 标记已访问
    irb.CreateStore(irb.getInt8(1), ptr);

    index_map[block] = idx;
  }

  //
  //- patch 1

  BasicBlock *newEntry = oldEntry; // Prepare basic block
  BasicBlock *loopBegin =
      BasicBlock::Create(f->getContext(), "LoopBegin", f, newEntry);
  BasicBlock *defaultCase =
      BasicBlock::Create(f->getContext(), "DefaultCase", f, newEntry);
  BasicBlock *loopEnd =
      BasicBlock::Create(f->getContext(), "LoopEnd", f, newEntry);
  newEntry->moveBefore(loopBegin);
  BranchInst::Create(
      loopEnd, defaultCase); // Create branch instruction,link basic blocks
  BranchInst::Create(loopBegin, loopEnd);
  newEntry->getTerminator()->eraseFromParent();
  BranchInst::Create(loopBegin, newEntry);
  AllocaInst *switchVar =
      new AllocaInst(Type::getInt32Ty(f->getContext()), 0, Twine("switchVar"),
                     newEntry->getTerminator()); // Create switch variable
  LoadInst *swValue =
      new LoadInst(switchVar->getAllocatedType(), switchVar, "cmd", loopBegin);
  SwitchInst *sw = SwitchInst::Create(swValue, defaultCase, 0, loopBegin);
  std::vector<unsigned int> rand_list;
  unsigned int startNum = 0;
  for (std::vector<BasicBlock *>::iterator b = origBB.begin();
       b != origBB.end(); b++) // Put basic blocks into switch structure
  {
    BasicBlock *block = *b;
    unsigned int num = getUniqueNumber(&rand_list);
    rand_list.push_back(num);
    if (block == newEntry)
      continue;
    block->moveBefore(loopEnd);
    if (block == firstbb)
      startNum = num;
    ConstantInt *numCase =
        cast<ConstantInt>(ConstantInt::get(sw->getCondition()->getType(), num));
    sw->addCase(numCase, block);
  }
  ConstantInt *startVal = cast<ConstantInt>(ConstantInt::get(
      sw->getCondition()->getType(), startNum)); // Set the entry value
  new StoreInst(startVal, switchVar, newEntry->getTerminator());
  // errs()<<"Put Block Into Switch\n";
  for (std::vector<BasicBlock *>::iterator b = origBB.begin();
       b != origBB.end(); b++) // Handle successors
  {
    BasicBlock *block = *b;
    irb.SetInsertPoint(block);
    if (block == newEntry)
      continue;
    if (isa<BranchInst>(*block->getTerminator())) {
      if (block->getTerminator()->getNumSuccessors() == 1) {
        BasicBlock *succ = block->getTerminator()->getSuccessor(0);
        ConstantInt *caseNum = sw->findCaseDest(succ);
        if (!caseNum) {
          unsigned int num = getUniqueNumber(&rand_list);
          rand_list.push_back(num);
          caseNum = cast<ConstantInt>(
              ConstantInt::get(sw->getCondition()->getType(), num));
          errs() << "WTF!\n";
        }
        unsigned int fixNum =
            caseNum->getValue().getZExtValue() ^ key_map[block];

        // 删除旧的 terminator
        block->getTerminator()->eraseFromParent();

        // 重新插入Store/Xor
        irb.SetInsertPoint(block);

        // 显式用 i32 作为 keyArray 的元素类型
        Value *keyPtr = irb.CreateGEP(irb.getInt32Ty(), keyArray,
                                      irb.getInt32(index_map[block]));
        Value *curKey = irb.CreateLoad(irb.getInt32Ty(), keyPtr);
        Value *newKey = irb.CreateXor(
            curKey, ConstantInt::get(sw->getCondition()->getType(), fixNum));
        irb.CreateStore(newKey, switchVar);

        // 恢复分支
        BranchInst::Create(loopEnd, block);

      } else if (block->getTerminator()->getNumSuccessors() == 2) {
        BasicBlock *succTrue = block->getTerminator()->getSuccessor(0);
        BasicBlock *succFalse = block->getTerminator()->getSuccessor(1);

        ConstantInt *numTrue = sw->findCaseDest(succTrue);
        ConstantInt *numFalse = sw->findCaseDest(succFalse);

        if (!numTrue) {
          unsigned int num = getUniqueNumber(&rand_list);
          rand_list.push_back(num);
          numTrue = cast<ConstantInt>(
              ConstantInt::get(sw->getCondition()->getType(), num));
          errs() << "WTF!\n";
        }
        if (!numFalse) {
          unsigned int num = getUniqueNumber(&rand_list);
          rand_list.push_back(num);
          numFalse = cast<ConstantInt>(
              ConstantInt::get(sw->getCondition()->getType(), num));
          errs() << "WTF!\n";
        }

        unsigned int fixNumTrue =
            numTrue->getValue().getZExtValue() ^ key_map[block];
        unsigned int fixNumFalse =
            numFalse->getValue().getZExtValue() ^ key_map[block];

        BranchInst *oldBr = cast<BranchInst>(block->getTerminator());
        SelectInst *select = SelectInst::Create(
            oldBr->getCondition(),
            ConstantInt::get(sw->getCondition()->getType(), fixNumTrue),
            ConstantInt::get(sw->getCondition()->getType(), fixNumFalse),
            Twine("choice"), block->getTerminator());

        block->getTerminator()->eraseFromParent();

        irb.SetInsertPoint(block);

        // 同样显式用 i32
        Value *keyPtr = irb.CreateGEP(irb.getInt32Ty(), keyArray,
                                      irb.getInt32(index_map[block]));
        Value *curKey = irb.CreateLoad(irb.getInt32Ty(), keyPtr);
        Value *newKey = irb.CreateXor(curKey, select);
        irb.CreateStore(newKey, switchVar);

        BranchInst::Create(loopEnd, block);
      }
    } else
      continue;
  }
  fixStack(*f);
  // 验证函数: 无效验证 不需要了
  /*  if (verifyFunction(*f, &errs())) {
     errs() << "FlatteningEnhanced: Function verification failed for "
            << f->getName() << "\n";
     f->dump();
     exit(1);
   } */
}

// Factory function for the pass
FlatteningEnhanced *llvm::createFlatteningEnhanced(bool flag) {
  return new FlatteningEnhanced(flag);
}

// --- HelloPass (for testing or other purposes, kept as is) ---
struct HelloPass : public PassInfoMixin<HelloPass> {
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM) {
    errs() << "=== HelloPass::run called for function: " << F.getName()
           << " ===\n";
    bool Changed = false;
    if (F.getName() == "main") {
      errs() << "Found main function, inserting hello message\n";
      insertHelloMessage(F);
      Changed = true;
    }

    std::vector<BinaryOperator *> toReplace;
    for (auto &BB : F) {
      for (auto &I : BB) {
        if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
          if (BO->getOpcode() == Instruction::Add) {
            errs() << "Found ADD instruction to replace\n";
            toReplace.push_back(BO);
          }
        }
      }
    }

    for (auto *BO : toReplace) {
      ob_add(BO);
      Changed = true;
    }
    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }

private:
  void insertHelloMessage(Function &F) {
    Module *M = F.getParent();
    LLVMContext &Context = M->getContext();
    FunctionType *printfType =
        FunctionType::get(Type::getInt32Ty(Context),
                          PointerType::get(Type::getInt8Ty(Context), 0), true);
    FunctionCallee printfFunc = M->getOrInsertFunction("printf", printfType);
    BasicBlock &EntryBB = F.getEntryBlock();
    Instruction *FirstInst = &*EntryBB.begin();
    IRBuilder<> Builder(FirstInst);
    Value *StrPtr =
        Builder.CreateGlobalStringPtr("hello run!123 from HelloPass\n");
    Builder.CreateCall(printfFunc, {StrPtr});
  }

  void ob_add(BinaryOperator *bo) {
    IRBuilder<> builder(bo);
    Value *negB = builder.CreateNeg(bo->getOperand(1));
    Value *result = builder.CreateSub(bo->getOperand(0), negB);
    if (auto *newBO = dyn_cast<BinaryOperator>(result)) {
      newBO->setHasNoSignedWrap(bo->hasNoSignedWrap());
      newBO->setHasNoUnsignedWrap(bo->hasNoUnsignedWrap());
    }
    bo->replaceAllUsesWith(result);
    bo->eraseFromParent();
  }
};

// --- LLVM Pass Plugin Registration ---
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "MyPasses", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "hello-pass") {
                    MPM.addPass(createModuleToFunctionPassAdaptor(HelloPass()));
                    return true;
                  }
                  if (Name == "vm-flatten") { 
                    // --- 修改这里，不再需要解引用 ---
                    MPM.addPass(createModuleToFunctionPassAdaptor(llvm::createVMFlatten_withoutptr(true))); 
                    return true;
                  }
                  return false;
                });
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel Level) {
                  // --- 修改这里，不再需要解引用 ---
                  MPM.addPass(createModuleToFunctionPassAdaptor(llvm::createVMFlatten_withoutptr(true))); 
                });
          }};
}