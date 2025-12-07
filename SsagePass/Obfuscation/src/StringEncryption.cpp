#include "StringEncryption.h"
#include "Utils.h"
#include "crypto_runtime.h" // For encrypt function

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h" // Important for iterating instructions
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Support/Path.h"

// Runtime linking headers
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/IR/DebugInfo.h"

#include <llvm/ADT/SmallString.h>
#include <random>
#include <string>
#include <vector>
#include <cstdlib>
#include <map>

#define DEBUG_TYPE "strenc"

using namespace llvm;

static cl::opt<bool> OnlyStr("mmonlystr", cl::desc("Encrypt string variable only"), cl::init(true));

// --- Helper Functions ---

static std::vector<uint8_t> getRandomBytes(size_t n) {
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    std::vector<uint8_t> bytes(n);
    for (size_t i = 0; i < n; ++i) bytes[i] = dist(gen);
    return bytes;
}

static void linkRuntime(Module &M) {
    SmallString<256> primaryPath;
#ifdef _WIN32
    const char *homeEnv = getenv("USERPROFILE");
    if (homeEnv) {
        primaryPath.assign(homeEnv);
        sys::path::append(primaryPath, ".ollvm", "crypto_runtime.bc");
    }
#else
    const char *homeEnv = getenv("HOME");
    if (homeEnv) {
        primaryPath.assign(homeEnv);
        sys::path::append(primaryPath, ".ollvm", "crypto_runtime.bc");
    }
#endif
    StringRef secondaryPath = "crypto_runtime.bc";
    Expected<std::unique_ptr<MemoryBuffer>> bufferOrErr = errorCodeToError(std::make_error_code(std::errc::no_such_file_or_directory));

    if (!primaryPath.empty()) {
        if (auto primaryBuffer = MemoryBuffer::getFile(primaryPath)) bufferOrErr = std::move(*primaryBuffer);
    }
    if (!bufferOrErr) {
        if (auto secondaryBuffer = MemoryBuffer::getFile(secondaryPath)) bufferOrErr = std::move(*secondaryBuffer);
    }
    if (!bufferOrErr) {
        consumeError(bufferOrErr.takeError());
        errs() << "[StringEnc] Error: 'crypto_runtime.bc' not found.\n";
        return;
    }

    auto runtimeModuleOrErr = parseBitcodeFile(bufferOrErr.get()->getMemBufferRef(), M.getContext());
    if (Error err = runtimeModuleOrErr.takeError()) {
        handleAllErrors(std::move(err), [&](const ErrorInfoBase &EI) { errs() << "[StringEnc] Error parsing bitcode: " << EI.message() << "\n"; });
        return;
    }
    std::unique_ptr<Module> runtimeModule = std::move(runtimeModuleOrErr.get());
    StripDebugInfo(*runtimeModule);
    
    // Internalize everything except the needed interface
    for (Function &F : *runtimeModule) {
        if (F.getName() != "__get_enc_str" && !F.isDeclaration()) {
            F.setLinkage(GlobalValue::InternalLinkage);
        }
    }

    Linker linker(M);
    if (linker.linkInModule(std::move(runtimeModule))) {
        errs() << "[StringEnc] Error: Failed to link runtime module.\n";
    }
}

// --- ConstantExpr Flattening Helper ---

// Converts ConstantExpr users of GV into actual Instructions in their respective functions.
// This is crucial because we cannot replace a GV with a FunctionCall inside a ConstantExpr.
void flattenConstantExprs(GlobalVariable *GV) {
    std::vector<ConstantExpr*> CEUsers;
    for (User *U : GV->users()) {
        if (ConstantExpr *CE = dyn_cast<ConstantExpr>(U)) {
            CEUsers.push_back(CE);
        }
    }

    for (ConstantExpr *CE : CEUsers) {
        // Find Loop: Find all users of this CE (recursively if needed, but here simple expansion usually works)
        // We find all Instructions that use this CE.
        std::vector<Instruction*> InstUsers;
        std::vector<ConstantExpr*> RecursiveCEs; // Keep track if CEs use CEs
        
        // Simple Recursive Lambda
        std::function<void(User*)> collectInsts = [&](User *U) {
            if (Instruction *I = dyn_cast<Instruction>(U)) {
                InstUsers.push_back(I);
            } else if (ConstantExpr *RecCE = dyn_cast<ConstantExpr>(U)) {
                for (User *RecU : RecCE->users()) {
                    collectInsts(RecU);
                }
            }
        };
        
        for (User *U : CE->users()) {
            collectInsts(U);
        }

        // Now, for each instruction using this CE (or a CE wrapping it), we generate an instruction sequence
        for (Instruction *I : InstUsers) {
            // Create the instruction equivalent of CE before I
            Instruction *NewI = CE->getAsInstruction();
            NewI->insertBefore(I);
            
            // We need to replace the usage in I.
            // Problem: I might be using a parent CE which uses our target CE.
            // The robust way in LLVM passes is usually:
            // "iteratively convert operands that are constant expressions to instructions"
            // Here we assume the common case (direct use or simple GEP) for brevity,
            // but for full strictness, one would run a separate pass to lower ALL ConstantExprs in the module.
            // For now, we replace explicit operands of I that equal CE.
            I->replaceUsesOfWith(CE, NewI);
        }
        
        // Cleanup if CE dead? It will be auto-cleaned by LLVM if unused.
    }
}

// --- Main Pass ---

PreservedAnalyses StringEncryptionPass::run(Module &M, ModuleAnalysisManager &AM) {
    // 1. Link Runtime
    static bool runtimeLinked = false;
    if (!runtimeLinked) {
        linkRuntime(M);
        runtimeLinked = true;
    }

    LLVMContext &Ctx = M.getContext();
    IRBuilder<> Builder(Ctx);

    // 2. Identify String GlobalVariables
    std::vector<GlobalVariable*> targetGVs;
    for (GlobalVariable &GV : M.globals()) {
        if (!GV.hasInitializer() || !GV.isConstant()) continue;
        if (GV.getName().starts_with("llvm.") || GV.getSection().contains("llvm.metadata") || GV.getSection().contains("OBJC")) continue;
        if (OnlyStr && !GV.getName().contains(".str")) continue;
        if (!GV.getValueType()->isArrayTy()) continue; // Only encrypt arrays (standard strings)
        
        ConstantDataArray *arr = dyn_cast<ConstantDataArray>(GV.getInitializer());
        if (!arr || !arr->isString()) continue;
        
        targetGVs.push_back(&GV);
    }

    if (targetGVs.empty()) return PreservedAnalyses::all();

    // 3. Declare Runtime Function
    FunctionCallee DecryptFunc = M.getOrInsertFunction("__get_enc_str", 
        PointerType::getUnqual(Ctx), // returns char* (ptr)
        PointerType::getUnqual(Ctx), // ciphertext (ptr)
        Type::getInt64Ty(Ctx),       // ct_len
        PointerType::getUnqual(Ctx), // aad (ptr)
        Type::getInt64Ty(Ctx),       // aad_len
        PointerType::getUnqual(Ctx), // tag (ptr)
        PointerType::getUnqual(Ctx), // nonce (ptr)
        PointerType::getUnqual(Ctx), // key_p1 (ptr)
        PointerType::getUnqual(Ctx)  // key_p2 (ptr)
    );

    // 4. Process Each String
    for (GlobalVariable *GV : targetGVs) {
        ConstantDataArray *arr = dyn_cast<ConstantDataArray>(GV->getInitializer());
        StringRef rawData = arr->getAsString(); // Includes null terminator if isString() true
        std::vector<uint8_t> plaintext(rawData.begin(), rawData.end());

        // A. Encrypt
        std::string gv_name = GV->getName().str();
        std::vector<uint8_t> aad(gv_name.begin(), gv_name.end());
        std::vector<uint8_t> key = getRandomBytes(32);
        std::vector<uint8_t> nonce = getRandomBytes(24);
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> tag;
        xchacha20_poly1305_encrypt(key, nonce, aad, plaintext, ciphertext, tag);

        // B. MBA Key Components: P1 - P2 = Key
        std::vector<uint8_t> key_p2 = getRandomBytes(32);
        std::vector<uint8_t> key_p1(32);
        for(int i=0; i<32; ++i) key_p1[i] = key[i] + key_p2[i];

        // C. Create Global Constants (Metada)
        auto createGlobal = [&](const std::vector<uint8_t>& data, StringRef suffix) {
            Constant *C = ConstantDataArray::get(Ctx, data);
            auto *NewGV = new GlobalVariable(M, C->getType(), true, GlobalValue::PrivateLinkage, C, GV->getName() + suffix);
            NewGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
            // Decay to i8* for call arguments
              return ConstantExpr::getPointerCast(NewGV, PointerType::getUnqual(Ctx));
        };

        Value *G_Cipher = createGlobal(ciphertext, ".enc");
        Value *G_AAD    = createGlobal(aad, ".aad");
        Value *G_Tag    = createGlobal(tag, ".tag");
        Value *G_Nonce  = createGlobal(nonce, ".nonce");
        Value *G_KeyP1  = createGlobal(key_p1, ".kp1");
        Value *G_KeyP2  = createGlobal(key_p2, ".kp2");
        
        ConstantInt *Len_CT  = ConstantInt::get(Type::getInt64Ty(Ctx), ciphertext.size());
        ConstantInt *Len_AAD = ConstantInt::get(Type::getInt64Ty(Ctx), aad.size());

        // D. Replace Usages
        
        // Step D1: Flatten ConstantExprs logic
        flattenConstantExprs(GV);
        
        // Step D2: Iterate Users (Instruction users only now)
        // We collect them first to avoid iterator invalidation
        std::vector<User*> Users(GV->user_begin(), GV->user_end());
        
        for (User *U : Users) {
            Instruction *Inst = dyn_cast<Instruction>(U);
            if (!Inst) continue; // Should not happen after flatten

            Builder.SetInsertPoint(Inst);
            CallInst *DecCall = Builder.CreateCall(DecryptFunc, {
                G_Cipher, Len_CT, G_AAD, Len_AAD, G_Tag, G_Nonce, G_KeyP1, G_KeyP2
            }, "dec_str");

            // Handle Type Mismatch:
            // GV is [N x i8]*
            // DecCall is i8*
            
            // Common Case 1: GEP(GV, 0, 0) used to get char*
            if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(Inst)) {
                if (GEP->hasAllZeroIndices()) {
                    // This GEP essentially decays array directly to pointer.
                    // We can replace the GEP instruction result with our Call result directly.
                    GEP->replaceAllUsesWith(DecCall);
                    GEP->eraseFromParent();
                    continue;
                }
            }

            // Fallback for strict typing: 
            // Create a BitCast of the Call to the original GV pointer type.
            // This is semantically weird (casting i8* to [N x i8]*) but accepted by LLVM for GEPs.
            Value *CastedCall = Builder.CreateBitCast(DecCall, GV->getType(), "cast_dec");
            Inst->replaceUsesOfWith(GV, CastedCall);
        }
        
        // E. Cleanup
        if (GV->use_empty()) {
            GV->eraseFromParent();
        } else {
            // Should be empty, but if complex ConstantExprs remain, we might fail to replace everything.
            // We empty the initializer to save space.
            GV->setInitializer(ConstantAggregateZero::get(GV->getValueType()));
            GV->setLinkage(GlobalValue::PrivateLinkage); // Hide it
        }
    }

    return PreservedAnalyses::none();
}

StringEncryptionPass *llvm::createStringEncryption(bool flag) {
    return new StringEncryptionPass(flag);
}