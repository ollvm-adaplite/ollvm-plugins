#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
//#include "llvm/LinkAllPasses.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/Local.h"

#include "CryptoUtils.h"
#include "Utils.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <queue>
#include <sstream>
#include <vector>

#define RUN_BLOCK 1
#define JMP_BORING 2
#define JMP_SELECT 3
#define VM_EXIT 4 // 新增：VM退出指令

using namespace std;
using namespace llvm;

namespace llvm { //
struct Node {
  unsigned int value;
  Node *bb1, *bb2;
  BasicBlock *data;
};
struct VMInst {
  unsigned int type;
  unsigned int op1, op2;
};
class VMFlattenPass : public PassInfoMixin<VMFlattenPass> {
public:
  bool flag;
  int opt_level = 1; // 优化级别

  VMFlattenPass(bool flag) { this->flag = flag; } // 携带flag的构造函数
  VMFlattenPass(bool flag, int optLevel) {
    this->flag = flag;
    this->opt_level = optLevel; // 携带flag和optLevel的构造函数
  }
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
  std::vector<BasicBlock *> *getBlocks(Function *function,
                                       std::vector<BasicBlock *> *lists); //
  unsigned int getUniqueNumber(std::vector<unsigned int> *rand_list);
  Node *newNode(unsigned int value);
  VMInst *newInst(unsigned int type, unsigned int op1, unsigned int op2);
  bool valueEscapes(Instruction *Inst);
  void create_node_inst(std::vector<VMInst *> *all_inst,
                        std::map<Node *, unsigned int> *inst_map, Node *node);
  void dump_inst(std::vector<VMInst *> *all_inst);
  void gen_inst(std::vector<VMInst *> *all_inst,
                std::map<Node *, unsigned int> *inst_map, Node *node);
  Node *findBBNode(BasicBlock *bb, std::vector<Node *> *all_node);
  void DoFlatten(Function *f, int seed);
  // --- Add this static method ---
  static StringRef name() { return "VMFlattenPass"; }
  void validateVMInstructions(std::vector<VMInst *> *all_inst);
  // -----------------------------
  static bool isRequired() { return true; } // 直接返回true即可
};
VMFlattenPass *createVMFlatten(bool flag); // 创建间接跳转
VMFlattenPass createVMFlatten_withoutptr(bool flag,
                                         int optLevel); // 不再返回指针
} // namespace llvm