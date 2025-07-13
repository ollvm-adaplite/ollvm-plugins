/**
 * @file Utils.cpp
 * @author SsageParuders
 * @brief 本代码参考原OLLVM项目:https://github.com/obfuscator-llvm/obfuscator
 *        感谢地球人前辈的指点
 * @version 0.1
 * @date 2022-07-14
 *
 * @copyright Copyright (c) 2022
 *
 */
#include "Utils.h"
#include "llvm/ADT/SmallVector.h"      // 新增：用于 StringRef::split
#include "llvm/Support/Error.h"        // 新增：用于处理 MemoryBuffer 的错误
#include "llvm/Support/MemoryBuffer.h" // 新增：用于 MemoryBuffer
#include "llvm/Transforms/Utils/Local.h"
#include <cstdlib> // 用于 rand()
#include <mutex>   // 用于 std::once_flag

#include <functional> // 用于 std::ref (可选，但有时与 seed_seq 一起使用)

// 将匿名命名空间移到这里
namespace { 
    // 匿名命名空间，用于内部链接的辅助元素
    // 全局的随机设备，用于为每个线程的引擎生成种子
    std::random_device global_random_device;

    // 生成一个新种子的函数
    unsigned int generate_new_seed() {
        return global_random_device();
    }

    // 获取线程局部随机数引擎的函数
    // 每个线程将拥有自己的引擎实例，并使用来自 global_random_device 的唯一种子进行初始化
    std::mt19937& get_thread_local_rng() { // No llvm:: prefix, now in anonymous namespace
        thread_local static std::mt19937 thread_rng(generate_new_seed());
        return thread_rng;
    }

    // 使用线程局部引擎生成范围内的随机整数
    int get_random_int(int min, int max) { // No llvm:: prefix, now in anonymous namespace
        if (min > max) {
            std::swap(min, max); // 确保 min <= max
        }
        std::uniform_int_distribution<int> dist(min, max);
        return dist(get_thread_local_rng()); // Call the anonymous namespaced version
    }
} // 匿名命名空间结束
using namespace llvm;
using std::vector;

LLVMContext *CONTEXT = nullptr;

/**
 * @brief 参考资料:https://www.jianshu.com/p/0567346fd5e8
 *        作用是读取llvm.global.annotations中的annotation值 从而实现过滤函数
 * 只对单独某功能开启PASS
 * @param f
 * @return std::string
 */
std::string llvm::readAnnotate(Function *f) { // 取自原版ollvm项目
  std::string annotation = "";
  /* Get annotation variable */
  GlobalVariable *glob =
      f->getParent()->getGlobalVariable("llvm.global.annotations");
  if (glob != NULL) {
    /* Get the array */
    if (ConstantArray *ca = dyn_cast<ConstantArray>(glob->getInitializer())) {
      for (unsigned i = 0; i < ca->getNumOperands(); ++i) {
        /* Get the struct */
        if (ConstantStruct *structAn =
                dyn_cast<ConstantStruct>(ca->getOperand(i))) {
          if (ConstantExpr *expr =
                  dyn_cast<ConstantExpr>(structAn->getOperand(0))) {
            /*
             * If it's a bitcast we can check if the annotation is concerning
             * the current function
             */
            if (expr->getOpcode() == Instruction::BitCast &&
                expr->getOperand(0) == f) {
              ConstantExpr *note = cast<ConstantExpr>(structAn->getOperand(1));
              /*
               * If it's a GetElementPtr, that means we found the variable
               * containing the annotations
               */
              if (note->getOpcode() == Instruction::GetElementPtr) {
                if (GlobalVariable *annoteStr =
                        dyn_cast<GlobalVariable>(note->getOperand(0))) {
                  if (ConstantDataSequential *data =
                          dyn_cast<ConstantDataSequential>(
                              annoteStr->getInitializer())) {
                    if (data->isString()) {
                      annotation += data->getAsString().lower() + " ";
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return (annotation);
}

/**
 * @brief 用于判断是否开启混淆
 *
 * @param flag
 * @param f
 * @param attribute
 * @return true
 * @return false
 */
bool llvm::toObfuscate(bool flag, Function *f,
                       std::string const &attribute) { // 取自原版ollvm项目
  std::string attr = attribute;
  std::string attrNo = "no" + attr;
  // Check if declaration
  if (f->isDeclaration()) {
    return false;
  }
  // Check external linkage
  if (f->hasAvailableExternallyLinkage() != 0) {
    return false;
  }
  // We have to check the nofla flag first
  // Because .find("fla") is true for a string like "fla" or
  // "nofla"
  if (readAnnotate(f).find(attrNo) != std::string::npos) { // 是否禁止开启XXX
    return false;
  }
  // If fla annotations
  if (readAnnotate(f).find(attr) != std::string::npos) { // 是否开启XXX
    return true;
  }
  // If fla flag is set
  if (flag == true) { // 开启PASS
    return true;
  }
  return false;
}

/**
 * @brief 修复PHI指令和逃逸变量
 *
 * @param F
 */
void llvm::fixStack(Function &F) {
  std::vector<PHINode *> origPHI;
  std::vector<Instruction *> origReg;
  BasicBlock &entryBB = F.getEntryBlock();

  // 遍历函数中的每个基本块
  for (BasicBlock &BB : F) {
    // 遍历基本块中的每条指令
    for (Instruction &I : BB) {
      // 如果是 PHI 节点，添加到 origPHI 中
      if (PHINode *PN = dyn_cast<PHINode>(&I)) {
        origPHI.push_back(PN);
      } else if (!(isa<AllocaInst>(&I) && I.getParent() == &entryBB) &&
                 I.isUsedOutsideOfBlock(&BB)) {
        // 如果是寄存器并且不在入口块中，添加到 origReg 中
        origReg.push_back(&I);
      }
    }
  }

  // 将 PHI 节点转换为栈变量
  for (PHINode *PN : origPHI) {
    // 获取插入点
    auto insertPoint = entryBB.getTerminator() != nullptr
                           ? std::optional<BasicBlock::iterator>(
                                 entryBB.getTerminator()->getIterator())
                           : std::nullopt;
    // 调用 DemotePHIToStack 函数
    DemotePHIToStack(PN, insertPoint);
  }

  // 将寄存器变量转换为栈变量
  for (Instruction *I : origReg) {
    // 获取插入点
    auto insertPoint = entryBB.getTerminator() != nullptr
                           ? std::optional<BasicBlock::iterator>(
                                 entryBB.getTerminator()->getIterator())
                           : std::nullopt;
    // 调用 DemoteRegToStack 函数
    DemoteRegToStack(*I, false, insertPoint);
  }
}

/**
 * @brief
 *
 * @param Func
 */
void llvm::FixFunctionConstantExpr(Function *Func) {
  // Replace ConstantExpr with equal instructions
  // Otherwise replacing on Constant will crash the compiler
  for (BasicBlock &BB : *Func) {
    FixBasicBlockConstantExpr(&BB);
  }
}
/**
 * @brief
 *
 * @param BB
 */
void llvm::FixBasicBlockConstantExpr(BasicBlock *BB) {
  // Replace ConstantExpr with equal instructions
  // Otherwise replacing on Constant will crash the compiler
  // Things to note:
  // - Phis must be placed at BB start so CEs must be placed prior to current BB
  assert(!BB->empty() && "BasicBlock is empty!");
  assert((BB->getParent() != NULL) && "BasicBlock must be in a Function!");
  Instruction *FunctionInsertPt =
      &*(BB->getParent()->getEntryBlock().getFirstInsertionPt());
  // Instruction* LocalBBInsertPt=&*(BB.getFirstInsertionPt());
  for (Instruction &I : *BB) {
    if (isa<LandingPadInst>(I) || isa<FuncletPadInst>(I)) {
      continue;
    }
    for (unsigned i = 0; i < I.getNumOperands(); i++) {
      if (ConstantExpr *C = dyn_cast<ConstantExpr>(I.getOperand(i))) {
        Instruction *InsertPt = &I;
        IRBuilder<NoFolder> IRB(InsertPt);
        if (isa<PHINode>(I)) {
          IRB.SetInsertPoint(FunctionInsertPt);
        }
        Instruction *Inst = IRB.Insert(C->getAsInstruction());
        I.setOperand(i, Inst);
      }
    }
  }
}

/**
 * @brief 随机字符填充的字符串
 *
 * @param len
 * @return string
 */
std::string llvm::getrandom_characters(int len) {
  const char first_chars[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
  const char other_chars[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
  std::string str;
  if (len <= 0)
    return "";

  // 第一个字符
  std::uniform_int_distribution<int> first_dist(
      0, sizeof(first_chars) - 2); 
  str.push_back(first_chars[first_dist(get_thread_local_rng())]); // Call anonymous namespaced version

  // 后续字符
  std::uniform_int_distribution<int> other_dist(0, sizeof(other_chars) - 2);
  for (int idx = 1; idx < len; idx++) {
    str.push_back(other_chars[other_dist(get_thread_local_rng())]); // Call anonymous namespaced version
  }
  return str;
}

// 用于缓存从文件读取的字符串的静态变量
static std::vector<std::string> meaningful_strings_cache;
// 用于确保文件只被加载一次的标志
static std::once_flag load_meaningful_strings_flag;
// 字符串文件路径
const char *meaningful_strings_file_path =
    "/home/ljs/code/llvmpass/SsagePass/Obfuscation/src/rand_funcs.txt";

// 辅助函数，用于从文件加载字符串，由 std::call_once 调用
void do_load_meaningful_strings_from_file() {
  auto file_or_err = llvm::MemoryBuffer::getFile(meaningful_strings_file_path);

  if (std::error_code ec = file_or_err.getError()) {
    // 文件读取失败 (例如，文件不存在或无权限)
    // 可以选择性地打印错误信息，例如：
    llvm::errs() << "Warning: Could not open or read meaningful strings file '"
                 << meaningful_strings_file_path << "': " << ec.message()
                 << "\n";
    // 缓存将保持为空，函数将回退到 getrandom_characters
    return;
  }

  std::unique_ptr<llvm::MemoryBuffer> file_buffer =
      std::move(file_or_err.get());
  StringRef buffer_content = file_buffer->getBuffer();

  SmallVector<StringRef, 64> lines; // 预分配一些空间以提高效率
  // 按行分割，不保留空字符串（由连续换行符产生）
  buffer_content.split(lines, '\n', /*MaxSplit=*/-1, /*KeepEmpty=*/false);

  for (StringRef line_ref : lines) {
    std::string line_str =
        line_ref.trim().str(); // 去除行首尾空白并转换为 std::string
    if (!line_str.empty()) {
      meaningful_strings_cache.push_back(line_str);
    }
  }

  // 注意：rand() 的播种 (srand) 通常在程序启动时进行一次。
  // 如果此处未播种，且程序其他地方也未播种，rand() 每次运行可能产生相同的序列。
  // 例如，可以在您的 Pass 插件初始化或主程序开始时调用 srand(time(NULL));
}

/**
 * @brief 随机有意义的字符串
 *
 * @note 尝试读取默认目录下的字符串文件 , 每一行一个字符串 ,
 * 如果不存在则会调用getrandom_characters
 * @return string
 * @todo 可以自定义随机字符串集合
 */
std::string llvm::getMeaningfulRandString() {
  std::call_once(load_meaningful_strings_flag,
                 do_load_meaningful_strings_from_file);
  if (meaningful_strings_cache.empty()) {
    // meaningful_strings_cache 为空，回退到 getrandom_characters
    // 生成 10 到 20 之间的随机长度
    int random_len = get_random_int(10, 20); // 调用匿名命名空间中的 get_random_int
    return llvm::getrandom_characters(random_len); 
  } else {
    std::uniform_int_distribution<size_t> dist(
        0, meaningful_strings_cache.size() - 1);
    return meaningful_strings_cache[dist(get_thread_local_rng())]; // Call anonymous namespaced version
  }
}

/**
 * @brief 随机字符串
 *
 * @param len
 * @param randomStrSource
 * @note 在randomStrSource设置为0时，使用默认的字符集 , 忽视len参数
 * @return string
 */
std::string llvm::rand_str(int len, int randomStrSource_selector) {
  switch (randomStrSource_selector) {
  case 0:                             // 默认字符集
    return getrandom_characters(len); // 已更新为使用 mt19937
  case 1:                             // 来自文件的有意义字符串
    return getMeaningfulRandString(); // 已更新为使用 mt19937 (len
                                      // 参数在此被忽略)
  default:
    return getrandom_characters(len);
  }
}
