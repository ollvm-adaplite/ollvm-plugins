#include "IndirectCall.h"

using namespace llvm;
using std::vector;

/**
 * @brief
 *
 * @param F
 * @param AM
 * @return PreservedAnalyses
 */
PreservedAnalyses IndirectCallPass::run(Function &F,
                                        FunctionAnalysisManager &AM) {
  // 判断是否需要开启间接调用
  if (toObfuscate(flag, &F, "icall")) {
    outs() << "\033[1;32m[IndirectCall] Function : " << F.getName()
           << "\033[0m\n"; // 打印一下被混淆函数的symbol
    doIndirctCall(F);
  }
  return PreservedAnalyses::none();
}

bool IndirectCallPass::doIndirctCall(Function &Fn) {
  // outs() << "0\n";
  if (Options && Options->skipFunction(Fn.getName())) {
    // outs() << "0000\n";
    return false;
  }
  // outs() << "1\n";
  LLVMContext &Ctx = Fn.getContext();
  CalleeNumbering.clear();
  Callees.clear();
  CallSites.clear();

  NumberCallees(Fn);

  if (Callees.empty()) {
    return false;
  }
  // outs() << "2\n";
  uint32_t V = RandomEngine.get_uint32_t() & ~3;
  ConstantInt *EncKey = ConstantInt::get(Type::getInt32Ty(Ctx), V, false);

  const IPObfuscationContext::IPOInfo *SecretInfo = nullptr;
  if (IPO) {
    SecretInfo = IPO->getIPOInfo(&Fn);
  }
  // outs() << "3\n";
  Value *MySecret;
  if (SecretInfo) {
    MySecret = SecretInfo->SecretLI;
  } else {
    MySecret = ConstantInt::get(Type::getInt32Ty(Ctx), 0, true);
  }
  // outs() << "4\n";
  ConstantInt *Zero = ConstantInt::get(Type::getInt32Ty(Ctx), 0);
  GlobalVariable *Targets = getIndirectCallees(Fn, EncKey);

  // outs() << "5\n";
  for (auto CI : CallSites) {
    SmallVector<Value *, 8> Args;
    SmallVector<AttributeSet, 8> ArgAttrVec;
    CallSite CS(CI);
    Instruction *Call = CS.getInstruction();
    Function *Callee = CS.getCalledFunction();
    FunctionType *FTy = CS.getFunctionType();
    IRBuilder<> IRB(Call);
    Args.clear();
    ArgAttrVec.clear();
    Value *Idx = ConstantInt::get(Type::getInt32Ty(Ctx),
                                  CalleeNumbering[CS.getCalledFunction()]);
    /* 取出全局变量的 “值类型” [N x i8*] 作为 GEP 的元素类型 */
    Type *ArrTy = Targets->getValueType();
    Value *GEP = IRB.CreateGEP(ArrTy, Targets, {Zero, Idx}); // ①

    /* 加载元素：显式传入 i8* 的类型 */
    PointerType *I8PtrTy = PointerType::get(IRB.getContext(), 0);        // ②
    LoadInst *EncDestAddr = IRB.CreateLoad(I8PtrTy, GEP, CI->getName()); // ③

    Constant *X;
    if (SecretInfo) {
      X = ConstantExpr::getSub(SecretInfo->SecretCI, EncKey);
    } else {
      X = ConstantExpr::getSub(Zero, EncKey);
    }
    const AttributeList &CallPAL = CS.getAttributes();
    CallSite::arg_iterator I = CS.arg_begin();
    unsigned i = 0;
    for (unsigned e = FTy->getNumParams(); i != e; ++I, ++i) {
      Args.push_back(*I);
      AttributeSet Attrs = CallPAL.getParamAttrs(i);
      ArgAttrVec.push_back(Attrs);
    }
    for (CallSite::arg_iterator E = CS.arg_end(); I != E; ++I, ++i) {
      Args.push_back(*I);
      ArgAttrVec.push_back(CallPAL.getParamAttrs(i));
    }
    AttributeList NewCallPAL =
        AttributeList::get(IRB.getContext(), CallPAL.getFnAttrs(),
                           CallPAL.getRetAttrs(), ArgAttrVec);
    Value *Secret = IRB.CreateSub(X, MySecret);
    Type *I8Ty = Type::getInt8Ty(Ctx); // 元素类型显式写明
    Value *DestAddr = IRB.CreateGEP(I8Ty, EncDestAddr, Secret);

    Value *FnPtr = IRB.CreateBitCast(DestAddr, FTy->getPointerTo());
    FnPtr->setName("Call_" + Callee->getName());
    CallInst *NewCall = IRB.CreateCall(FTy, FnPtr, Args, Call->getName());
    NewCall->setAttributes(NewCallPAL);
    NewCall->setCallingConv(CS.getCallingConv());
    Call->replaceAllUsesWith(NewCall);
    Call->eraseFromParent();
  }
  return true;
}

/**
 * @brief
 *
 * @param F
 * @param EncKey
 * @return GlobalVariable*
 */
GlobalVariable *IndirectCallPass::getIndirectCallees(Function &F,
                                                     ConstantInt *EncKey) {
  std::string GVName(F.getName().str() + "_IndirectCallees");
  GlobalVariable *GV = F.getParent()->getNamedGlobal(GVName);
  if (GV) {
    return GV;
  }
  // callee's address
  std::vector<Constant *> Elements;

  PointerType *I8PtrTy = PointerType::get(F.getContext(), 0); // 通用 i8* (a) 若未来想支持 非 0 地址空间，第二个参数记得调整。
  Type *I8Ty = Type::getInt8Ty(F.getContext()); // 元素 i8                 (b)
  for (auto Callee : Callees) {
    Constant *CE = ConstantExpr::getBitCast(Callee, I8PtrTy); // (c)
    CE = ConstantExpr::getGetElementPtr(I8Ty, CE, EncKey);    // (d)
    Elements.push_back(CE);
  }

  ArrayType *ATy = ArrayType::get(I8PtrTy, Elements.size()); // (e)

  Constant *CA = ConstantArray::get(ATy, ArrayRef<Constant *>(Elements));
  GV =
      new GlobalVariable(*F.getParent(), ATy, false,
                         GlobalValue::LinkageTypes::PrivateLinkage, CA, GVName);
  appendToCompilerUsed(*F.getParent(), {GV});
  return GV;
}

/**
 * @brief
 *
 * @param F
 */
void IndirectCallPass::NumberCallees(Function &F) {
  for (auto &BB : F) {
    for (auto &I : BB) {
      if (dyn_cast<CallInst>(&I)) {
        CallSite CS(&I);
        Function *Callee = CS.getCalledFunction();
        if (Callee == nullptr) {
          continue;
        }
        if (Callee->isIntrinsic()) {
          continue;
        }
        CallSites.push_back((CallInst *)&I);
        if (CalleeNumbering.count(Callee) == 0) {
          CalleeNumbering[Callee] = Callees.size();
          Callees.push_back(Callee);
        }
      }
    }
  }
}

/**
 * @brief
 *
 * @param flag
 * @return IndirectCallPass*
 */
IndirectCallPass *llvm::createIndirectCall(bool flag) {
  return new IndirectCallPass(flag);
}

/**
 * @brief
 *
 * @param flag
 * @return IndirectCallPass*
 */
IndirectCallPass llvm::createIndirectCallWithOutPtr(bool flag) {
  return  IndirectCallPass(flag);
}