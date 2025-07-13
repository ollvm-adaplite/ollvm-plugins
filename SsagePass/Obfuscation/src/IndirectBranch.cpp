/*
    LLVM Indirect Branching Pass
    Copyright (C) 2017 Zhang(https://github.com/Naville/)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "IndirectBranch.h"

PreservedAnalyses IndirectBranchPass::run(Module &M,
                                          ModuleAnalysisManager &AM) {
  vector<Function *> funcs;
  for (Module::iterator iter = M.begin(); iter != M.end(); iter++) {
    funcs.push_back(&*iter);
  }
  for (Function *F : funcs) {
    if (toObfuscate(flag, F, "indibr")) {
      outs() << "\033[1;32m[IndirectBranch] Function : " << F->getName()
             << "\033[0m\n"; // 打印一下被混淆函数的symbol
      HandleFunction(*F);
    }
  }
  return PreservedAnalyses::all();
}

bool IndirectBranchPass::HandleFunction(Function &Func) {
  if (this->initialized == false) {
    initialize(*Func.getParent());
    this->initialized = true;
  }
  vector<BranchInst *> BIs;
  for (inst_iterator I = inst_begin(Func); I != inst_end(Func); I++) {
    Instruction *Inst = &(*I);
    if (BranchInst *BI = dyn_cast<BranchInst>(Inst)) {
      BIs.push_back(BI);
    }
  } // Finish collecting branching conditions
  Value *zero =
      ConstantInt::get(Type::getInt32Ty(Func.getParent()->getContext()), 0);
  for (BranchInst *BI : BIs) {
    IRBuilder<> IRB(BI);
    vector<BasicBlock *> BBs;
    // We use the condition's evaluation result to generate the GEP
    // instruction  False evaluates to 0 while true evaluates to 1.  So here
    // we insert the false block first
    if (BI->isConditional()) {
      BBs.push_back(BI->getSuccessor(1));
    }
    BBs.push_back(BI->getSuccessor(0));
    LLVMContext &Ctx = Func.getParent()->getContext();      // (<1>)
    PointerType *I8PtrTy = PointerType::get(Ctx, /*AS=*/0); // (<2>)
    ArrayType *AT = ArrayType::get(I8PtrTy, BBs.size());    // (<3>)
    vector<Constant *> BlockAddresses;
    for (unsigned i = 0; i < BBs.size(); i++) {
      BlockAddresses.push_back(BlockAddress::get(BBs[i]));
    }
    GlobalVariable *LoadFrom = NULL;

    if (BI->isConditional() ||
        indexmap.find(BI->getSuccessor(0)) == indexmap.end()) {
      // Create a new GV for conditional branches or when no mapping exists
      Constant *BlockAddressArray =
          ConstantArray::get(AT, ArrayRef<Constant *>(BlockAddresses));
      LoadFrom = new GlobalVariable(*Func.getParent(), AT, false,
                                    GlobalValue::LinkageTypes::PrivateLinkage,
                                    BlockAddressArray,
                                    "Oo0ooO0o00OConditionalLocalIndirectBranchi"
                                    "ngTable"); // 移除Hikari特征
      appendToCompilerUsed(*Func.getParent(), {LoadFrom});
    } else {
      // Try to get the global table, if it doesn't exist, create a local one
      LoadFrom = Func.getParent()->getGlobalVariable(
          "IndirectBranchingGlobalTable", true);
      
      // 如果全局表不存在，创建一个本地表
      if (!LoadFrom) {
        errs() << "Warning: Global table not found, creating local table for unconditional branch\n";
        Constant *BlockAddressArray =
            ConstantArray::get(AT, ArrayRef<Constant *>(BlockAddresses));
        LoadFrom = new GlobalVariable(*Func.getParent(), AT, false,
                                      GlobalValue::LinkageTypes::PrivateLinkage,
                                      BlockAddressArray,
                                      "Oo0ooO0o00OLocalIndirectBranchingTable");
        appendToCompilerUsed(*Func.getParent(), {LoadFrom});
      }
    }
    
    // 添加空指针检查
    if (!LoadFrom) {
      errs() << "Error: LoadFrom is still null after creation attempts\n";
      continue; // 跳过这个分支指令
    }
    
    Value *index = NULL;
    if (BI->isConditional()) {
      Value *condition = BI->getCondition();
      index = IRB.CreateZExt(condition,
                             Type::getInt32Ty(Func.getParent()->getContext()));
    } else {
      // 检查索引映射是否存在
      auto it = indexmap.find(BI->getSuccessor(0));
      if (it != indexmap.end()) {
        index = ConstantInt::get(Type::getInt32Ty(Func.getParent()->getContext()),
                                 it->second);
      } else {
        // 如果没有映射，使用 0 作为索引
        errs() << "Warning: No index mapping found for basic block, using index 0\n";
        index = ConstantInt::get(Type::getInt32Ty(Func.getParent()->getContext()), 0);
      }
    }
    
    // 确保索引不为空
    if (!index) {
      errs() << "Error: index is null in IndirectBranchPass::HandleFunction\n";
      continue;
    }
    
    // 根据 LoadFrom 的来源确定类型
    Type *LoadFromType = nullptr;
    if (BI->isConditional() || indexmap.find(BI->getSuccessor(0)) == indexmap.end()) {
      // 对于新创建的局部表，我们知道类型是 AT
      LoadFromType = AT;
    } else {
      // 对于全局表，尝试获取其值类型
      if (LoadFrom->hasInitializer()) {
        LoadFromType = LoadFrom->getInitializer()->getType();
      } else {
        // 后备方案
        LoadFromType = AT;
      }
    }
    
    // 创建 GEP 时使用正确的类型
    Value *GEP = IRB.CreateGEP(LoadFromType, LoadFrom, {zero, index});
    
    PointerType *I8PtrTy2 = PointerType::get(IRB.getContext(), 0); // (<6>)
    LoadInst *LI = IRB.CreateLoad(I8PtrTy2, GEP,
                                  "IndirectBranchingTargetAddress"); // (<7>)
    IndirectBrInst *indirBr = IndirectBrInst::Create(LI, BBs.size());
    for (BasicBlock *BB : BBs) {
      indirBr->addDestination(BB);
    }
    ReplaceInstWithInst(BI, indirBr);
  }
  return true;
}

bool IndirectBranchPass::initialize(Module &M) {
  // 检查全局表是否已经存在
  if (M.getGlobalVariable("IndirectBranchingGlobalTable", true)) {
    errs() << "Global table already exists, skipping creation\n";
    return true;
  }
  
  vector<Constant *> BBs;
  unsigned long long i = 0;
  for (auto F = M.begin(); F != M.end(); F++) {
    for (auto BB = F->begin(); BB != F->end(); BB++) {
      BasicBlock *BBPtr = &*BB;
      if (BBPtr != &(BBPtr->getParent()->getEntryBlock())) {
        indexmap[BBPtr] = i++;
        BBs.push_back(BlockAddress::get(BBPtr));
      }
    }
  }
  
  // 如果没有基本块需要映射，不创建全局表
  if (BBs.empty()) {
    errs() << "No basic blocks to map, skipping global table creation\n";
    return true;
  }
  
  LLVMContext &Ctx = M.getContext();                   // (<8>)
  PointerType *I8PtrTy = PointerType::get(Ctx, 0);     // (<9>)
  ArrayType *AT = ArrayType::get(I8PtrTy, BBs.size()); // (10)
  Constant *BlockAddressArray =
      ConstantArray::get(AT, ArrayRef<Constant *>(BBs));
  GlobalVariable *Table = new GlobalVariable(
      M, AT, false, GlobalValue::LinkageTypes::InternalLinkage,
      BlockAddressArray, "IndirectBranchingGlobalTable");
  appendToCompilerUsed(M, {Table});
  
  errs() << "Created global table with " << BBs.size() << " entries\n";
  return true;
}

bool IndirectBranchPass::doFinalization(Module &M) {
  indexmap.clear();
  initialized = false;
  return false;
}

/**
 * @brief 便于调用间接指令
 *
 * @param flag
 * @return FunctionPass*
 */
IndirectBranchPass *llvm::createIndirectBranch(bool flag) {
  return new IndirectBranchPass(flag);
}

IndirectBranchPass llvm::createIndirectBranchWithOutPtr(bool flag) {
  return  IndirectBranchPass(flag);
}