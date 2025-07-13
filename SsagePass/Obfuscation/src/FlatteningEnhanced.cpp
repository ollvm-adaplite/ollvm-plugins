
#include "FlatteningEnhanced.h"
#include "CryptoUtils.h"
#include "Utils.h"
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
#include <utility>
#include <vector>

using namespace llvm;

PreservedAnalyses FlatteningEnhanced::run(Module &M,
                                          ModuleAnalysisManager &AM) {
  vector<CallSite *> callsites;
  Function *updateFunc = buildUpdateKeyFunc(&M);

  for (Function &f : M) {
    if (toObfuscate(flag, &f, "enfla")) {
      outs() << "\033[1;32m[FlatteningEnhanced] Function: " << f.getName()
             << "\033[0m\n"; // 打印一下被混淆函数的symbol

      if (&f == updateFunc)
        continue;
      DoFlatteningEnhanced(&f, 0, updateFunc);
    }
  }

  return PreservedAnalyses::all();
}

std::vector<BasicBlock *> *
FlatteningEnhanced::getBlocks(Function *function,
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

/**
 * @brief 便于调用函数包装器
 *
 * @param flag
 * @return FunctionPass*
 */
FlatteningEnhanced *llvm::createFlatteningEnhanced(bool flag) {
  return new FlatteningEnhanced(flag);
}
