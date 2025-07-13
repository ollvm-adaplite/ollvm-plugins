// 这个B玩意不知道为什么 老是会卡死循环 , 谨慎使用

#include "VMFlatten.h"
#include "llvm/IR/Instruction.h"   // Required for TerminatorInst
#include "llvm/IR/IntrinsicInst.h" // <<<<<< 这行是关键
#include "llvm/IR/Verifier.h"      // Required for verifyFunction
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h" // Required for
// DemotePHIToStack etc.

#define DEBUG_PRINT
#ifdef DEBUG_PRINT
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

PreservedAnalyses VMFlattenPass::run(Function &F, FunctionAnalysisManager &AM) {
  Function *tmp = &F;
  StringRef funcName = F.getName();

  // 扩大跳过范围，避免破坏C++运行时
  if ( // funcName == "main" ||
       // funcName.starts_with("std::") ||           // 跳过所有std命名空间函数
      // funcName.starts_with("__cxa_") ||          // C++运行时
      // funcName.starts_with("_Unwind_") ||        // 异常展开
      // funcName.starts_with("_ZSt") ||            // std函数的mangled名
      // funcName.starts_with("_ZN3std") || // std命名空间
     // funcName.starts_with("_ZNSt")           // std命名空间
     funcName.contains("_Function_handler")||  // 特别跳过Function_handler
     funcName.contains("_M_manager") 
      //  funcName.contains("__invoke") ||            // 函数调用包装器
      //   funcName.contains("function") ||            // 包含function的函数
      //   funcName.contains("lambda") ||              // Lambda相关
      //   funcName.contains("_M_invoke") ||           // 成员函数调用
      // F.hasPersonalityFn() || // 有异常处理的函数
      // F.isDeclaration()
      )
   { // 声明而非定义

    debugPrint("Skipping function: " + funcName);
    return PreservedAnalyses::all();
  }



  if (toObfuscate(flag, tmp, "vmf")) {
    debugPrint("Function : " + F.getName());
    DoFlatten(tmp, 0);
  }

  return PreservedAnalyses::none();
}

std::vector<BasicBlock *> *
VMFlattenPass::getBlocks(Function *function, std::vector<BasicBlock *> *lists) {
  lists->clear();
  for (BasicBlock &basicBlock : *function) {
    lists->push_back(&basicBlock);
  }
  return lists;
}

unsigned int
VMFlattenPass::getUniqueNumber(std::vector<unsigned int> *rand_list) {
  unsigned int num = rand();
  while (true) {
    bool state = true;
    for (std::vector<unsigned int>::iterator n = rand_list->begin();
         n != rand_list->end(); n++) {
      if (*n == num) {
        state = false;
        break;
      }
    }
    if (state) {
      break;
    }
    num = rand();
  }
  return num;
}

bool VMFlattenPass::valueEscapes(Instruction *Inst) {
  const BasicBlock *BB = Inst->getParent();
  for (const User *U : Inst->users()) {
    const Instruction *UI = cast<Instruction>(U);
    if (UI->getParent() != BB || isa<PHINode>(UI))
      return true;
  }
  return false;
}

Node *VMFlattenPass::newNode(unsigned int value) {
  Node *node = (Node *)malloc(sizeof(Node));
  node->value = value;
  node->bb1 = node->bb2 = NULL;
  return node;
}

VMInst *VMFlattenPass::newInst(unsigned int type, unsigned int op1,
                               unsigned int op2) {
  VMInst *code = (VMInst *)malloc(sizeof(VMInst));
  code->type = type;
  code->op1 = op1;
  code->op2 = op2;
  return code;
}

void VMFlattenPass::create_node_inst(std::vector<VMInst *> *all_inst,
                                     std::map<Node *, unsigned int> *inst_map,
                                     Node *node) {
  VMInst *code = newInst(RUN_BLOCK, node->value, 0);
  all_inst->push_back(code);
  inst_map->insert(
      std::map<Node *, unsigned int>::value_type(node, all_inst->size() - 1));
}

Node *VMFlattenPass::findBBNode(BasicBlock *bb, std::vector<Node *> *all_node) {
  for (std::vector<Node *>::iterator i = all_node->begin();
       i != all_node->end(); i++) {
    if (bb == (*i)->data) {
      return *i;
    }
  }
  return NULL;
}

void VMFlattenPass::gen_inst(std::vector<VMInst *> *all_inst,
                             std::map<Node *, unsigned int> *inst_map,
                             Node *node) {
  // assert(!(node->bb1==NULL && node->bb2!=NULL));
  if (!node)
    return;
  if (node->bb1 != NULL && node->bb2 == NULL) {
    if (inst_map->count(node->bb1) == 0) {
      create_node_inst(all_inst, inst_map, node->bb1);
      gen_inst(all_inst, inst_map, node->bb1);
    } else {
      unsigned int addr = (*inst_map->find(node->bb1)).second * 3;
      VMInst *code = newInst(JMP_BORING, addr, 0);
      all_inst->push_back(code);
    }
  } else if (node->bb2 != NULL) {
    VMInst *code = newInst(JMP_SELECT, 0, 0);
    all_inst->push_back(code);
    if (inst_map->count(node->bb1) == 0) {
      create_node_inst(all_inst, inst_map, node->bb1);
      gen_inst(all_inst, inst_map, node->bb1);
    }
    if (inst_map->count(node->bb2) == 0) {
      create_node_inst(all_inst, inst_map, node->bb2);
      gen_inst(all_inst, inst_map, node->bb2);
    }
    code->op1 = (*inst_map->find(node->bb1)).second * 3;
    code->op2 = (*inst_map->find(node->bb2)).second * 3;
  } else {
    return;
  }
}

void VMFlattenPass::dump_inst(std::vector<VMInst *> *all_inst) {
  unsigned int x = 0;
  for (std::vector<VMInst *>::iterator i = all_inst->begin();
       i != all_inst->end(); i++) {
    // printf("\033[1;32m0x%02x: \033[0m", x++);
    VMInst *c = *i;
    if (c->type == RUN_BLOCK) {
      // printf("\033[1;32mRUN_BLOCK 0x%02x\033[0m\n", c->op1);
    }
    if (c->type == JMP_BORING) {
      // printf("\033[1;32mJMP_BORING 0x%02x\033[0m\n", c->op1);
    }
    if (c->type == JMP_SELECT) {
      // printf("\033[1;32mJMP_SELECT 0x%02x 0x%02x\033[0m\n", c->op1, c->op2);
    }
  }
}
inline std::set<llvm::BasicBlock *> getEHBlocks(llvm::Function *F) {
  std::set<llvm::BasicBlock *> EH;
  std::queue<llvm::BasicBlock *> WL;

  for (llvm::BasicBlock &BB : *F) {
    if (llvm::isa<llvm::InvokeInst>(BB.getTerminator()) || BB.isLandingPad() ||
        llvm::isa<llvm::ResumeInst>(BB.getTerminator())) {
      EH.insert(&BB);
      if (BB.isLandingPad())
        WL.push(&BB);
    }
  }

  while (!WL.empty()) {
    llvm::BasicBlock *BB = WL.front();
    WL.pop();
    if (llvm::isa<llvm::ReturnInst>(BB->getTerminator()) ||
        llvm::isa<llvm::ResumeInst>(BB->getTerminator()) ||
        llvm::isa<llvm::UnreachableInst>(BB->getTerminator()))
      continue;

    for (llvm::BasicBlock *Succ : llvm::successors(BB)) {
      if (EH.insert(Succ).second) {
        WL.push(Succ);
      }
    }
  }

  return EH;
}

std::set<BasicBlock *> getEHBlocks2(Function *F) {
  std::set<BasicBlock *> EH;
  std::queue<BasicBlock *> WL;

  for (BasicBlock &BB : *F) {
    if (isa<InvokeInst>(BB.getTerminator()) || BB.isLandingPad() ||
        isa<ResumeInst>(BB.getTerminator())) {
      EH.insert(&BB);
      if (BB.isLandingPad())
        WL.push(&BB);
    }
  }

  while (!WL.empty()) {
    BasicBlock *BB = WL.front();
    WL.pop();
    if (isa<ReturnInst>(BB->getTerminator()) ||
        isa<ResumeInst>(BB->getTerminator()) ||
        isa<UnreachableInst>(BB->getTerminator()))
      continue;

    for (BasicBlock *Succ : successors(BB)) {
      if (EH.insert(Succ).second) { // 插入成功说明是新块
        WL.push(Succ);
      }
    }
  }

  return EH;
}

void VMFlattenPass::DoFlatten(Function *f, int seed) {
  srand(seed);
  LLVMContext &Ctx = f->getContext();

  // =================================================================
  // 1) 首先完整识别所有异常处理相关的基本块 - 不要删除它们
  // =================================================================
  // 增强异常处理识别
  std::set<BasicBlock *> ehRelatedBlocks;
  std::queue<BasicBlock *> workList;

  for (BasicBlock &BB : *f) {
    bool isEHBlock = false;

    // 检查所有可能的异常相关指令
    for (Instruction &I : BB) {
      if (isa<InvokeInst>(&I) || isa<LandingPadInst>(&I) ||
          isa<ResumeInst>(&I) || isa<CatchSwitchInst>(&I) ||
          isa<CatchReturnInst>(&I) || isa<CleanupReturnInst>(&I)) {
        isEHBlock = true;
        break;
      }

      // 更全面的异常相关函数检查
      if (CallInst *CI = dyn_cast<CallInst>(&I)) {
        Function *CalledF = CI->getCalledFunction();
        if (CalledF) {
          StringRef name = CalledF->getName();
          if (name.starts_with("__cxa_") || name.starts_with("_Unwind_") ||
              name.starts_with("_ZTI") || // typeinfo
              name.starts_with("_ZTV") || // vtable
              name.contains("exception") || name.contains("terminate") ||
              name.contains("catch") || name == "__clang_call_terminate") {
            isEHBlock = true;
            break;
          }
        }
      }
    }

    // 检查是否是landingpad或包含personality函数
    if (BB.isLandingPad() || isa<ResumeInst>(BB.getTerminator())) {
      isEHBlock = true;
    }

    if (isEHBlock) {
      ehRelatedBlocks.insert(&BB);
      workList.push(&BB);
    }
  }

  // 递归收集所有可达的异常处理块
  while (!workList.empty()) {
    BasicBlock *current = workList.front();
    workList.pop();

    // 向前传播 - 处理前驱
    for (BasicBlock *pred : predecessors(current)) {
      if (ehRelatedBlocks.insert(pred).second) {
        workList.push(pred);
      }
    }

    // 向后传播 - 处理后继
    for (BasicBlock *succ : successors(current)) {
      if (ehRelatedBlocks.insert(succ).second) {
        workList.push(succ);
      }
    }
  }

  // 特别处理 invoke 指令的 unwind 目标
  for (BasicBlock &BB : *f) {
    if (InvokeInst *II = dyn_cast<InvokeInst>(BB.getTerminator())) {
      BasicBlock *unwindDest = II->getUnwindDest();
      if (ehRelatedBlocks.insert(unwindDest).second) {
        workList.push(unwindDest);

        // 继续递归处理 unwind 目标的所有后继
        while (!workList.empty()) {
          BasicBlock *current = workList.front();
          workList.pop();
          for (BasicBlock *succ : successors(current)) {
            if (ehRelatedBlocks.insert(succ).second) {
              workList.push(succ);
            }
          }
        }
      }
    }
  }

  // =================================================================
  // 2) 获取所有基本块，但排除异常处理相关的块
  // =================================================================
  std::vector<BasicBlock *> origBB;
  getBlocks(f, &origBB);

  // 从混淆目标中移除异常处理相关的块
  origBB.erase(std::remove_if(origBB.begin(), origBB.end(),
                              [&ehRelatedBlocks](BasicBlock *BB) {
                                return ehRelatedBlocks.count(BB) > 0;
                              }),
               origBB.end());

  debugPrint("Original blocks: " +
             std::to_string(origBB.size() + ehRelatedBlocks.size()) +
             ", EH blocks: " + std::to_string(ehRelatedBlocks.size()) +
             ", Flattening blocks: " + std::to_string(origBB.size()));

  if (origBB.size() <= 1) {
    errs() << "[VM] Too few blocks to flatten, skipping.\n";
    return;
  }

  // =================================================================
  // 3) 正常的 VM 平坦化处理（只处理非异常块）
  // =================================================================

  unsigned int rand_val = seed;
  Function::iterator tmp = f->begin();
  BasicBlock *oldEntry = &*tmp;

  // 确保入口块不在异常处理块中
  if (ehRelatedBlocks.count(oldEntry)) {
    errs() << "[VM] Entry block is EH-related, cannot flatten safely.\n";
    return;
  }

  // 移除入口块
  origBB.erase(std::remove(origBB.begin(), origBB.end(), oldEntry),
               origBB.end());

  BranchInst *firstBr = nullptr;
  if (isa<BranchInst>(oldEntry->getTerminator())) {
    firstBr = cast<BranchInst>(oldEntry->getTerminator());
  }

  BasicBlock *firstbb = oldEntry->getTerminator()->getSuccessor(0);

  // 检查第一个后继是否是异常块
  if (ehRelatedBlocks.count(firstbb)) {
    errs() << "[VM] First successor is EH-related, cannot flatten safely.\n";
    return;
  }

  if ((firstBr != nullptr && firstBr->isConditional()) ||
      oldEntry->getTerminator()->getNumSuccessors() > 2) {
    BasicBlock::iterator iter = oldEntry->end();
    iter--;
    if (oldEntry->size() > 1) {
      iter--;
    }
    BasicBlock *splited = oldEntry->splitBasicBlock(iter, Twine("FirstBB"));
    firstbb = splited;
    origBB.insert(origBB.begin(), splited);
  }

  // =================================================================
  // 4) 其余的 VM 平坦化代码保持不变
  // =================================================================
  std::vector<Node *> all_node;
  std::vector<unsigned int> rand_list;

  for (BasicBlock *BB : origBB) {
    unsigned int num = getUniqueNumber(&rand_list);
    rand_list.push_back(num);
    Node *tmp = newNode(num);
    all_node.push_back(tmp);
    tmp->data = BB;
  }

  for (Node *node : all_node) {
    BasicBlock *bb = node->data;
    Instruction *term = bb->getTerminator();

    if (term->getNumSuccessors() == 2) {
      BasicBlock *bb1 = term->getSuccessor(0);
      BasicBlock *bb2 = term->getSuccessor(1);

      // 检查后继是否是异常块
      if (ehRelatedBlocks.count(bb1) || ehRelatedBlocks.count(bb2)) {
        errs() << "[VM] Block " << bb->getName()
               << " has EH successors, skipping connection.\n";
        continue;
      }

      Node *n1 = findBBNode(bb1, &all_node);
      Node *n2 = findBBNode(bb2, &all_node);
      node->bb1 = n1;
      node->bb2 = n2;

    } else if (term->getNumSuccessors() == 1) {
      BasicBlock *bb1 = term->getSuccessor(0);

      // 检查后继是否是异常块
      if (ehRelatedBlocks.count(bb1)) {
        errs() << "[VM] Block " << bb->getName()
               << " has EH successor, skipping connection.\n";
        continue;
      }

      Node *n = findBBNode(bb1, &all_node);
      node->bb1 = n;
    }
  }
  Node *start = findBBNode(firstbb, &all_node);
  if (!start) {
    errs() << "[VM] Cannot find start node, aborting.\n";
    return;
  }
  Node *fake = newNode(0x7FFFFFFF);
  std::vector<VMInst *> all_inst;
  std::map<Node *, unsigned int> inst_map;
  fake->bb1 = start;
  gen_inst(&all_inst, &inst_map, fake);
  dump_inst(&all_inst);

  std::vector<Constant *> opcodes;
  for (std::vector<VMInst *>::iterator i = all_inst.begin();
       i != all_inst.end(); i++) {
    VMInst *inst = *i;
    opcodes.push_back(
        ConstantInt::get(Type::getInt32Ty(f->getContext()), inst->type));
    opcodes.push_back(
        ConstantInt::get(Type::getInt32Ty(f->getContext()), inst->op1));
    opcodes.push_back(
        ConstantInt::get(Type::getInt32Ty(f->getContext()), inst->op2));
  }

  ArrayType *AT =
      ArrayType::get(Type::getInt32Ty(f->getContext()), opcodes.size());
  Constant *opcode_array =
      ConstantArray::get(AT, ArrayRef<Constant *>(opcodes));
  GlobalVariable *oparr_var = new GlobalVariable(
      *(f->getParent()), AT, false, GlobalValue::LinkageTypes::PrivateLinkage,
      opcode_array, "opcodes");

  // 去除第一个基本块末尾的跳转
  oldEntry->getTerminator()->eraseFromParent();
  AllocaInst *vm_pc = new AllocaInst(Type::getInt32Ty(f->getContext()), 0,
                                     Twine("VMpc"), oldEntry);
  ConstantInt *init_pc = ConstantInt::get(Type::getInt32Ty(f->getContext()), 0);
  new StoreInst(init_pc, vm_pc, oldEntry);
  AllocaInst *vm_flag = new AllocaInst(Type::getInt32Ty(f->getContext()), 0,
                                       Twine("VMJmpFlag"), oldEntry);
  BasicBlock *vm_entry =
      BasicBlock::Create(f->getContext(), "VMEntry", f, firstbb);

  BranchInst::Create(vm_entry, oldEntry);
  IRBuilder<> IRB(vm_entry);
  // LLVMContext &Ctx = f->getContext();
  Value *zero = ConstantInt::get(Type::getInt32Ty(Ctx), 0);

  Value *op1_offset =
      IRB.CreateAdd(IRB.CreateLoad(Type::getInt32Ty(Ctx), vm_pc),
                    ConstantInt::get(Type::getInt32Ty(Ctx), 1));
  Value *op2_offset =
      IRB.CreateAdd(IRB.CreateLoad(Type::getInt32Ty(Ctx), vm_pc),
                    ConstantInt::get(Type::getInt32Ty(Ctx), 2));

  Value *optypeGEP =
      IRB.CreateGEP(oparr_var->getValueType(), oparr_var,
                    {zero, IRB.CreateLoad(Type::getInt32Ty(Ctx), vm_pc)});

                    
  Value *optype = IRB.CreateLoad(Type::getInt32Ty(Ctx), optypeGEP);

  Value *op1GEP =
      IRB.CreateGEP(oparr_var->getValueType(), oparr_var, {zero, op1_offset});
  Value *op1 = IRB.CreateLoad(Type::getInt32Ty(Ctx), op1GEP);

  Value *op2GEP =
      IRB.CreateGEP(oparr_var->getValueType(), oparr_var, {zero, op2_offset});
  Value *op2 = IRB.CreateLoad(Type::getInt32Ty(Ctx), op2GEP);

  IRB.CreateStore(IRB.CreateAdd(IRB.CreateLoad(Type::getInt32Ty(Ctx), vm_pc),
                                ConstantInt::get(Type::getInt32Ty(Ctx), 3)),
                  vm_pc);
  BasicBlock *run_block =
      BasicBlock::Create(f->getContext(), "RunBlock", f, firstbb);
  BasicBlock *jmp_boring =
      BasicBlock::Create(f->getContext(), "JmpBoring", f, firstbb);
  BasicBlock *jmp_select =
      BasicBlock::Create(f->getContext(), "JmpSelect", f, firstbb);
  BasicBlock *defaultCase =
      BasicBlock::Create(f->getContext(), "Default", f, firstbb);
  BranchInst::Create(vm_entry, defaultCase);
  SwitchInst *switch1 = IRB.CreateSwitch(optype, defaultCase, 0);
  switch1->addCase(
      ConstantInt::get(Type::getInt32Ty(f->getContext()), RUN_BLOCK),
      run_block);
  switch1->addCase(
      ConstantInt::get(Type::getInt32Ty(f->getContext()), JMP_BORING),
      jmp_boring);
  switch1->addCase(
      ConstantInt::get(Type::getInt32Ty(f->getContext()), JMP_SELECT),
      jmp_select);

  // create run_block's basicblock
  // the first choice
  IRB.SetInsertPoint(run_block);
  /*
      std::vector<Constant *> bb_addrs;
      for(std::vector<BasicBlock *>::iterator
b=origBB.begin();b!=origBB.end();b++){ BasicBlock *block=*b;
          bb_addrs.push_back(BlockAddress::get(block));
      }
      ArrayType
*AT_=ArrayType::get(Type::getInt8PtrTy(f->getContext()),bb_addrs.size());
      Constant
*addr_array=ConstantArray::get(AT_,ArrayRef<Constant*>(bb_addrs));
      GlobalVariable *address_arr_var=new
GlobalVariable(*(f->getParent()),AT_,false,GlobalValue::LinkageTypes::PrivateLinkage,addr_array,"address_table");
      Value
*load=IRB.CreateLoad(IRB.CreateGEP(address_arr_var,{zero,op1}),"address");
      IndirectBrInst
*indirBr=IndirectBrInst::Create(load,bb_addrs.size(),run_block);
      for(std::vector<BasicBlock *>::iterator
b=origBB.begin();b!=origBB.end();b++)
{
          BasicBlock *block=*b;
          indirBr->addDestination(block);
      }
  */
  // the seconde choice
  SwitchInst *switch2 = IRB.CreateSwitch(op1, defaultCase, 0);
  for (std::vector<BasicBlock *>::iterator b = origBB.begin();
       b != origBB.end(); b++) {
    BasicBlock *block = *b;
    block->moveBefore(defaultCase);
    Node *t = findBBNode(block, &all_node);
    ConstantInt *numCase = cast<ConstantInt>(
        ConstantInt::get(switch2->getCondition()->getType(), t->value));
    switch2->addCase(numCase, block);
  }

  for (BasicBlock *block : origBB) {
    // 1. 检查该块是否具有异常相关的特征
    bool isExceptionRelated = false;

    // 检查块是否在异常相关块集合中
    if (ehRelatedBlocks.count(block)) {
      errs() << "[VM] Skipping known exception-related block: "
             << block->getName() << "\n";
      continue;
    }

    // 检查是否有任何与异常相关的指令
    for (Instruction &I : *block) {
      if (isa<InvokeInst>(&I) || isa<LandingPadInst>(&I) ||
          isa<ResumeInst>(&I) || isa<CatchReturnInst>(&I) ||
          isa<CatchSwitchInst>(&I) || isa<CleanupReturnInst>(&I)) {
        isExceptionRelated = true;
        break;
      }

      // 检查函数调用，如果是异常相关函数则标记
      if (CallInst *CI = dyn_cast<CallInst>(&I)) {
        Function *F = CI->getCalledFunction();
        if (F && (F->getName().starts_with("__cxa_") ||
                  F->getName().starts_with("_Unwind_") ||
                  F->getName().contains("exception"))) {
          isExceptionRelated = true;
          break;
        }
      }
    }

    if (isExceptionRelated) {
      errs() << "[VM] Skipping block with exception instructions: "
             << block->getName() << "\n";
      continue;
    }

    // 2. 检查终结指令和后继
    Instruction *term = block->getTerminator();
    if (!term)
      continue;

    // 只处理纯BranchInst
    if (!isa<BranchInst>(term)) {
      /* errs() << "[VM] Skipping non-branch terminator in: " <<
         block->getName()
             << "\n"; */
      debugPrint("Skipping non-branch terminator in: " + block->getName());
      continue;
    }

    BranchInst *BI = cast<BranchInst>(term);

    // 3. 检查后继是否有任何一个在异常处理路径上
    bool hasEHSuccessor = false;
    for (unsigned i = 0; i < BI->getNumSuccessors(); i++) {
      BasicBlock *succ = BI->getSuccessor(i);
      if (ehRelatedBlocks.count(succ)) {
        hasEHSuccessor = true;
        break;
      }
    }

    if (hasEHSuccessor) {
      errs() << "[VM] Skipping branch with EH successor in: "
             << block->getName() << "\n";
      continue;
    }

    // 4. 安全修改非异常相关分支
    IRBuilder<> IRB(BI);
    LLVMContext &Ctx = block->getContext();

    if (BI->isUnconditional()) {
      debugPrint("Handling unconditional branch in: " + block->getName());
      // 创建新分支指令前保存原信息
      BranchInst *newBr = BranchInst::Create(defaultCase, block);
      // 删除之前的分支指令
      BI->eraseFromParent();
    } else {
      /* errs() << "[VM] Handling conditional branch in: " << block->getName()
             << "\n"; */
      debugPrint("Handling conditional branch in: " + block->getName());
      // 先保存条件值到VM标志
      Value *cond = BI->getCondition();
      Value *flagVal = IRB.CreateSelect(
          cond, ConstantInt::get(Type::getInt32Ty(Ctx), 1),
          ConstantInt::get(Type::getInt32Ty(Ctx), 0), "vm_flag_val");
      IRB.CreateStore(flagVal, vm_flag);
      // 创建新的无条件分支
      BranchInst *newBr = BranchInst::Create(defaultCase, block);
      // 删除旧的条件分支
      BI->eraseFromParent();
    }
  }
  outs() << "\033[1;32m[VMFlattening] Finished processing blocks.\033[0m\n";
  IRB.SetInsertPoint(jmp_boring);
  IRB.CreateStore(op1, vm_pc);
  IRB.CreateBr(vm_entry);

  IRB.SetInsertPoint(jmp_select);
  BasicBlock *select_true =
      BasicBlock::Create(f->getContext(), "JmpSelectTrue", f, firstbb);
  BasicBlock *select_false =
      BasicBlock::Create(f->getContext(), "JmpSelectFalse", f, firstbb);
  IRB.CreateCondBr(
      IRB.CreateICmpEQ(IRB.CreateLoad(Type::getInt32Ty(Ctx), vm_flag),
                       ConstantInt::get(Type::getInt32Ty(Ctx), 1)),
      select_true, select_false);
  IRB.SetInsertPoint(select_true);
  IRB.CreateStore(op1, vm_pc);
  IRB.CreateBr(vm_entry);
  IRB.SetInsertPoint(select_false);
  IRB.CreateStore(op2, vm_pc);
  IRB.CreateBr(vm_entry);

  std::vector<PHINode *> tmpPhi;
  std::vector<Instruction *> tmpReg;
  BasicBlock *bbEntry = &*f->begin();

  // 处理函数中的所有指令，DemoteRegToStack 和 DemotePHIToStack
  // outs()<< "\033[1;32m[VMFlattening] Demoting registers and PHI
  // nodes.\033[0m\n";
  debugPrint("Demoting registers and PHI nodes in the function.");
  // 这里的 tmpPhi 和 tmpReg 用于存储需要 Demote 的 PHI 节点和寄存器
  // 通过循环处理，直到没有需要 Demote 的寄存器和 PHI 节点

  BasicBlock &EntryBB = f->getEntryBlock(); // 入口块
  Instruction *AllocaIP = &*EntryBB.getFirstInsertionPt();

  const unsigned MAX_ITERATIONS = 50000; // 最大迭代次数
  unsigned iterations = 0;
  std::vector<Instruction *> lastIterRegs; // 记录上一次迭代处理的寄存器

  do {
    tmpPhi.clear();
    tmpReg.clear();
    for (Function::iterator i = f->begin(); i != f->end(); i++) {
      for (BasicBlock::iterator j = i->begin(); j != i->end(); j++) {
        if (isa<PHINode>(j)) {
          PHINode *phi = cast<PHINode>(j);
          tmpPhi.push_back(phi);
          continue;
        }
        if (!(isa<AllocaInst>(j) && j->getParent() == bbEntry) &&
            (valueEscapes(&*j) || j->isUsedOutsideOfBlock(&*i))) {
          tmpReg.push_back(&*j);
          continue;
        }
      }
    }

    // 检查是否和上一轮迭代处理的是相同的寄存器集合
    bool sameRegsAsBefore = false;
    if (tmpReg.size() == lastIterRegs.size() && tmpReg.size() > 0) {
      sameRegsAsBefore = true;
      for (unsigned i = 0; i < tmpReg.size(); i++) {
        if (tmpReg[i] != lastIterRegs[i]) {
          sameRegsAsBefore = false;
          break;
        }
      }
    }

    // 如果处理的是相同的寄存器集合，或已达到最大迭代次数，则退出循环
    if ((sameRegsAsBefore && iterations > 0) ||
        ++iterations >= MAX_ITERATIONS) {
      /* outs()
          << "\033[1;33m[VMFlattening] Warning: Breaking demoting loop after "
          << iterations
          << " iterations, could not demote all registers.\033[0m\n"; */

      debugPrint("Breaking demoting loop after " + std::to_string(iterations) +
                 " iterations.");

      break;
    }

    // 保存本轮处理的寄存器列表，用于下一轮比较
    lastIterRegs = tmpReg;

    /* outs() << "\033[1;32m[VMFlattening] Found " << tmpReg.size()
           << " registers and " << tmpPhi.size()
           << " PHI nodes to demote.\033[0m\n"; */

    debugPrint("Found " + std::to_string(tmpReg.size()) + " registers and " +
               std::to_string(tmpPhi.size()) + " PHI nodes to demote.");

    // 对于找到的寄存器和 PHI 节点，进行 Demote 操作
    for (unsigned int i = 0; i < tmpReg.size(); i++) {
      DemoteRegToStack(*tmpReg.at(i), f->begin()->getTerminator());
    }

    /* // 对于 PHI 节点，使用 DemotePHIToStack 进行处理
    outs() << "\033[1;32m[VMFlattening] Demoting PHI nodes to stack.\033[0m\n";
  */

    debugPrint("Demoting PHI nodes to stack, count: " +
               std::to_string(tmpPhi.size()));

    for (unsigned int i = 0; i < tmpPhi.size(); i++) {
      PHINode *phi = cast<PHINode>(tmpPhi.at(i));
      BasicBlock &entry = f->getEntryBlock();
      auto insertionPoint = entry.getFirstInsertionPt();
      DemotePHIToStack(phi, insertionPoint);
    }

  } while (tmpReg.size() != 0 || tmpPhi.size() != 0);

  // 验证函数，检查IR是否一致
  bool verificationErrors = verifyFunction(*f, &errs());
  if (verificationErrors) {
    outs() << "\033[1;31m[VMFlattening] Warning: Function verification failed "
              "after flattening!\033[0m\n";
    outs() << "\033[1;31m[VMFlattening] Please check the function IR for "
              "issues.\033[0m\n";
  } else {
    /* outs()
        << "\033[1;32m[VMFlattening] Function verified successfully.\033[0m\n";
     */
    debugPrint("Function verified successfully after flattening.");
  }
}

VMFlattenPass *llvm::createVMFlatten(bool flag) {
  return new VMFlattenPass(flag);
}

VMFlattenPass llvm::createVMFlatten_withoutptr(bool flag,int optLevel ) {
  return VMFlattenPass(flag,optLevel);
}