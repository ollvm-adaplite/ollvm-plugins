#include "Flattening.h"
#include "LegacyLowerSwitch.h"
#include "SplitBasicBlock.h"
#include "Utils.h"
#include <queue> // 添加queue头文件
#include <set>   // 添加set头文件
// namespace
using namespace llvm;
using std::vector;

#define DEBUG_TYPE "flattening" // 调试标识
// Stats
STATISTIC(Flattened, "Functions flattened");

PreservedAnalyses FlatteningPass::run(Function &F,
                                      FunctionAnalysisManager &AM) {
  Function *tmp = &F; // 传入的Function
  // 判断是否需要开启控制流平坦化
  if (toObfuscate(flag, tmp, "ofla")) {
    outs() << "\033[1;32m[Flattening] Function : " << F.getName()
           << "\033[0m\n"; // 打印一下被混淆函数的symbol
    INIT_CONTEXT(F);
    // 不再自动进行基本块分割
    // SplitBasicBlockPass *pass = createSplitBasicBlock(flag); //
    // 在控制流平坦化之前先进行基本块分割 以提高混淆程度 pass->run(F, AM);
    flatten(*tmp);
    ++Flattened;
  }
  return PreservedAnalyses::none();
}

void FlatteningPass::flatten(Function &F) {
  // outs() << "\033[1;32mFunction size : " << F.size() << "\033[0m\n";
  //  基本块数量不超过1则无需平坦化
  if (F.size() <= 1) {
    // outs() << "\033[0;33mFunction size is lower then one\033[0m\n"; //
    // warning
    return;
  }

  // =================================================================
  // 1) 首先完整识别所有异常处理相关的基本块 - 不要删除它们
  // =================================================================
  std::set<BasicBlock *> ehRelatedBlocks;
  std::queue<BasicBlock *> workList;

  for (BasicBlock &BB : F) {
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
  for (BasicBlock &BB : F) {
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

  // Lower switch
  // 调用 Lower switch 会导致崩溃
  // FunctionPass *pass = createLowerSwitchPass();
  // pass->runOnFunction(F);

  // Lower switch
  // 在PMRegistration内优先进行Lower switch可能效果好些？
  FunctionPass *lower = createLegacyLowerSwitchPass();
  lower->runOnFunction(F);
  // outs() << "\033[1;32mLower switch had open\033[0m\n";

  // 将除入口块（第一个基本块）和异常处理块以外的基本块保存到一个 vector
  // 容器中，便于后续处理 首先保存所有基本块
  vector<BasicBlock *> origBB;
  for (BasicBlock &BB : F) {
    if (ehRelatedBlocks.count(&BB)) { // 跳过异常处理块
      continue;
    }
    origBB.push_back(&BB);
  }

  if (origBB
          .empty()) { // 如果所有块都是异常处理块或者只有一个块，则不进行平坦化
    return;
  }
  // 从vector中去除第一个基本块
  BasicBlock &entryBB = F.getEntryBlock();
  if (ehRelatedBlocks.count(
          &entryBB)) { // 如果入口块是异常处理块，则不进行平坦化
    errs() << "Flattening: Entry block is EH-related, skipping flattening for "
              "function "
           << F.getName() << "\n";
    return;
  }

  // 从 origBB 中移除 entryBB，如果它存在的话
  auto it = std::remove(origBB.begin(), origBB.end(), &entryBB);
  origBB.erase(it, origBB.end());

  // 如果第一个基本块的末尾是条件跳转，单独分离
  // 确保 entryBB 的终结指令不是 EH 相关的
  if (BranchInst *br = dyn_cast<BranchInst>(entryBB.getTerminator())) {
    if (br->isConditional()) {
      // 检查分离出的新块是否会成为异常处理块的直接前驱，或者其后继是否是异常处理块
      // 这一步比较复杂，简单起见，如果 entryBB
      // 的后继是异常处理块，我们可能需要更复杂的逻辑 目前的逻辑是，如果 newBB
      // 被创建，它会被加入到 origBB 中进行平坦化 如果 newBB 的原始后继是 EH
      // 块，那么在后续处理中，对 newBB 的修改需要小心
      bool canSplit = true;
      for (unsigned i = 0; i < br->getNumSuccessors(); ++i) {
        if (ehRelatedBlocks.count(br->getSuccessor(i))) {
          // 如果条件跳转的任何一个分支是EH块，则不分离，以避免破坏EH逻辑
          // 或者，可以选择不平坦化这个入口块的条件跳转
          canSplit = false;
          errs() << "Flattening: Entry block's conditional branch successor is "
                    "EH-related. Skipping split for "
                 << entryBB.getName() << " in " << F.getName() << "\n";
          break;
        }
      }
      if (canSplit) {
        BasicBlock *newBB = entryBB.splitBasicBlock(br, "newBB");
        if (!ehRelatedBlocks.count(
                newBB)) { // 确保新块不是EH块 (理论上不应该是)
          origBB.insert(origBB.begin(), newBB);
        }
      }
    }
  }

  if (origBB.empty()) { // 如果分离后 origBB 为空
                        // (例如，只有一个可平坦化的块，即分离出的newBB)
    return;
  }

  // 创建分发块和返回块
  BasicBlock *dispatchBB =
      BasicBlock::Create(*CONTEXT, "dispatchBB", &F, &entryBB);
  BasicBlock *returnBB = BasicBlock::Create(*CONTEXT, "returnBB", &F, &entryBB);
  BranchInst::Create(dispatchBB, returnBB);
  entryBB.moveBefore(dispatchBB); // 将原始入口块移到分发块之前
  // 去除第一个基本块末尾的跳转 (如果它不是EH相关的跳转)
  if (entryBB.getTerminator() && !isa<InvokeInst>(entryBB.getTerminator()) &&
      !isa<ResumeInst>(entryBB.getTerminator()) &&
      !isa<CatchSwitchInst>(entryBB.getTerminator()) &&
      !isa<CatchReturnInst>(entryBB.getTerminator()) &&
      !isa<CleanupReturnInst>(entryBB.getTerminator())) {
    entryBB.getTerminator()->eraseFromParent();
  } else if (entryBB.getTerminator() == nullptr) {
    // 可能已经被 splitBasicBlock 移除了
  } else {
    errs() << "Flattening: Entry block terminator is EH related, not removing. "
              "Function: "
           << F.getName() << "\n";
    // 如果入口块的终止是EH相关的，我们不能简单删除它，这可能需要更复杂的处理
    // 或者直接放弃对此函数的平坦化
    // 为简单起见，这里可以先回退，或者打印错误并继续（可能导致IR错误）
    // 此处我们选择不创建到 dispatchBB 的跳转，因为原始跳转需要保留
    // 这意味着平坦化可能不完整或行为不符合预期
    // 安全起见，可以考虑直接返回
    dispatchBB->eraseFromParent();
    returnBB->eraseFromParent();
    return;
  }
  // 使第一个基本块跳转到dispatchBB
  BranchInst *brDispatchBB = BranchInst::Create(dispatchBB, &entryBB);

  // 在入口块插入alloca和store指令创建并初始化switch变量，初始值为随机值
  int randNumCase = rand();
  AllocaInst *swVarPtr = new AllocaInst(TYPE_I32, 0, "swVar.ptr", brDispatchBB);
  new StoreInst(CONST_I32(randNumCase), swVarPtr, brDispatchBB);
  // 在分发块插入load指令读取switch变量
  LoadInst *swVar =
      new LoadInst(TYPE_I32, swVarPtr, "swVar", false, dispatchBB);
  // 在分发块插入switch指令实现基本块的调度
  BasicBlock *swDefault =
      BasicBlock::Create(*CONTEXT, "swDefault", &F, returnBB);
  BranchInst::Create(returnBB, swDefault);
  SwitchInst *swInst = SwitchInst::Create(swVar, swDefault, 0, dispatchBB);
  // 将原基本块插入到返回块之前，并分配case值
  for (BasicBlock *BB : origBB) {
    if (ehRelatedBlocks.count(BB))
      continue; // 跳过异常处理块
    BB->moveBefore(returnBB);
    swInst->addCase(CONST_I32(randNumCase), BB);
    randNumCase = rand();
  }

  // 在每个基本块最后添加修改switch变量的指令和跳转到返回块的指令
  for (BasicBlock *BB : origBB) {
    if (ehRelatedBlocks.count(BB))
      continue; // 跳过异常处理块

    // retn BB
    if (BB->getTerminator()->getNumSuccessors() == 0) {
      continue;
    }
    // 非条件跳转
    else if (BB->getTerminator()->getNumSuccessors() == 1) {
      BasicBlock *sucBB = BB->getTerminator()->getSuccessor(0);
      if (ehRelatedBlocks.count(sucBB)) { // 如果后继是EH块，则不修改此跳转
        errs() << "Flattening: Successor of " << BB->getName()
               << " is EH-related (" << sucBB->getName()
               << "), skipping modification.\n";
        continue;
      }
      Instruction *term = BB->getTerminator(); // 保存终止指令以便正确插入
      term->eraseFromParent();                 // 先删除旧的终止指令
      ConstantInt *numCase = swInst->findCaseDest(sucBB);
      if (!numCase) {
        errs() << "Flattening: Warning - Unconditional branch in BasicBlock "
               << BB->getName() << " of Function " << F.getName()
               << " targets a block (" << sucBB->getName()
               << ") not found in switch cases. Using a default/random case "
                  "value.\n";
        numCase = CONST_I32(randNumCase); // 使用最后一个生成的随机数作为备用
      }
      new StoreInst(numCase, swVarPtr, BB); // 插入到BB的末尾
      BranchInst::Create(returnBB, BB);     // 插入到BB的末尾
    }
    // 条件跳转
    else if (BB->getTerminator()->getNumSuccessors() == 2) {
      Instruction *term = BB->getTerminator();
      if (BranchInst *br = dyn_cast<BranchInst>(term)) {
        if (br->isConditional()) {
          BasicBlock *succTrue = br->getSuccessor(0);
          BasicBlock *succFalse = br->getSuccessor(1);

          if (ehRelatedBlocks.count(succTrue) ||
              ehRelatedBlocks.count(succFalse)) { // 如果任一后继是EH块
            errs() << "Flattening: Conditional branch successor in "
                   << BB->getName()
                   << " is EH-related, skipping modification.\n";
            continue;
          }

          ConstantInt *numCaseTrue = swInst->findCaseDest(succTrue);
          ConstantInt *numCaseFalse = swInst->findCaseDest(succFalse);

          if (!numCaseTrue) {
            errs() << "Flattening: Warning - True successor ("
                   << succTrue->getName()
                   << ") of conditional branch in BasicBlock " << BB->getName()
                   << " of Function " << F.getName()
                   << " not found in switch cases. Using a default/random case "
                      "value.\n";
            numCaseTrue =
                CONST_I32(randNumCase); // 使用最后一个生成的随机数作为备用
          }
          if (!numCaseFalse) {
            errs() << "Flattening: Warning - False successor ("
                   << succFalse->getName()
                   << ") of conditional branch in BasicBlock " << BB->getName()
                   << " of Function " << F.getName()
                   << " not found in switch cases. Using a default/random case "
                      "value.\n";
            numCaseFalse =
                CONST_I32(randNumCase); // 使用最后一个生成的随机数作为备用
          }

          // 此时 numCaseTrue 和 numCaseFalse 保证不是 C++ nullptr
          SelectInst *sel = SelectInst::Create(br->getCondition(), numCaseTrue,
                                               numCaseFalse, "", term);
          term->eraseFromParent(); // 在 SelectInst 创建之后，新指令插入之前删除
          new StoreInst(sel, swVarPtr, BB); // 插入到BB的末尾
          BranchInst::Create(returnBB, BB); // 插入到BB的末尾
        } else {
          errs() << "Flattening: Warning - Encountered a non-conditional "
                    "BranchInst with 2 successors in BasicBlock "
                 << BB->getName() << " of Function " << F.getName()
                 << ". Skipping modification of this terminator.\n";
        }
      } else {
        errs() << "Flattening: Warning - Terminator in BasicBlock "
               << BB->getName() << " of Function " << F.getName()
               << " has 2 successors but is not a BranchInst (actual type: "
               << term->getOpcodeName()
               << "). Skipping modification of this terminator.\n";
      }
    }
  }
  fixStack(F); // 修复逃逸变量和PHI指令
}

FlatteningPass *llvm::createFlattening(bool flag) {
  return new FlatteningPass(flag);
}

FlatteningPass llvm::createFlatteningWithOutPtr(bool flag) {
  return new FlatteningPass(flag);
}