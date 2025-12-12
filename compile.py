import os
import sys
import subprocess
import platform
import shutil
import argparse

def find_compiler():
    """自动查找可用的 clang++ 编译器"""
    candidates = ["clang++-21", "clang++"]
    for comp in candidates:
        if shutil.which(comp):
            return comp
    return "clang++"

def find_artifacts(search_root):
    """在指定根目录下搜索插件和静态库"""
    # 常见的构建目录名
    search_dirs = [
        search_root,
        os.path.join(search_root, "build"),
        os.path.join(search_root, "out", "build", "ninja-clang"),
        os.path.join(search_root, "out", "build", "x64-Debug"),
        os.path.join(search_root, "out", "build", "x64-Release"),
        os.path.join(search_root, "out", "build", "RelWithDebInfo"),
    ]

    plugin_path = None
    lib_path = None

    for build_dir in search_dirs:
        if not os.path.exists(build_dir):
            continue
        
        # 1. 查找插件 (OllvmPlugins.so 或 OllvmPlugins.dll)
        # 注意：CMakeLists.txt 中强制后缀为 .so，但在 Windows 上有时可能是 .dll
        candidates = ["OllvmPlugins.so", "OllvmPlugins.dll"]
        for name in candidates:
            p = os.path.join(build_dir, name)
            if os.path.exists(p):
                plugin_path = p
                # 找到插件后，在此构建目录下查找库文件
                
                # 2. 查找 blake3 库
                # 路径通常是 SsagePass/Obfuscation/blake3/c/
                lib_base = os.path.join(build_dir, "SsagePass", "Obfuscation", "blake3", "c")
                
                if os.path.exists(os.path.join(lib_base, "blake3.lib")):
                    lib_path = os.path.join(lib_base, "blake3.lib")
                elif os.path.exists(os.path.join(lib_base, "libblake3.a")):
                    lib_path = os.path.join(lib_base, "libblake3.a")
                
                if plugin_path and lib_path:
                    return plugin_path, lib_path
    
    return plugin_path, lib_path

def get_build_env():
    """配置构建环境变量，添加必要的 DLL 搜索路径"""
    env = os.environ.copy()
    if platform.system() == "Windows":
        # 尝试自动推断 LLVM 和 vcpkg 路径，或者使用硬编码路径
        dll_paths = [
            r"E:\code\lib\llvminstall\bin",
            r"E:\code\lib\vcpkg\installed\x64-windows\bin",
            r"E:\code\lib\vcpkg\installed\x64-windows\debug\bin"
        ]
        current_path = env.get("PATH", "")
        env["PATH"] = os.pathsep.join(dll_paths + [current_path])
    return env

def main():
    parser = argparse.ArgumentParser(description="Compile test with OLLVM plugin")
    parser.add_argument("--build-dir", "-b", help="Path to the build directory (e.g., D:\\test3\\ollvm-plugins)", default=".")
    args = parser.parse_args()

    # 1. 环境检测
    compiler = find_compiler()
    print(f"[+] Using compiler: {compiler}")
    
    # 搜索构建产物
    search_root = os.path.abspath(args.build_dir)
    print(f"[+] Searching for artifacts in: {search_root} ...")
    
    plugin_path, lib_path = find_artifacts(search_root)

    if not plugin_path or not lib_path:
        print(f"[-] Error: Could not find 'OllvmPlugins.so' or 'blake3.lib/libblake3.a'.")
        print(f"    Please build the project first, or specify the correct build directory using --build-dir.")
        if plugin_path:
            print(f"    (Found plugin at: {plugin_path}, but missing library)")
        sys.exit(1)

    print(f"[+] Plugin path: {plugin_path}")
    print(f"[+] Library path: {lib_path}")

    build_env = get_build_env()

    # 2. 定义文件名
    src_file = "test.cpp"
    ir_output = "test.ll"
    exe_output = "charge_test.exe" if platform.system() == "Windows" else "charge_test.out"

    # 3. 生成 LLVM IR
    print("\n[+] Step 1: Generating LLVM IR...")
    cmd_ir = [
        compiler,
        "-emit-llvm",
        "-std=c++23",
        "-g",
        "-fno-omit-frame-pointer",
        "-S", src_file,
        "-o", ir_output
    ]
    try:
        subprocess.run(cmd_ir, check=True, env=build_env)
    except subprocess.CalledProcessError:
        print("[-] Failed to generate IR")
        sys.exit(1)

    # 4. 清理旧文件
    if os.path.exists(exe_output):
        os.remove(exe_output)

    # 5. 编译并链接
    print("\n[+] Step 2: Compiling and Linking...")
    cmd_build = [
        compiler,
        "-v",
        "-g",
        "-std=c++23",
        "-fno-omit-frame-pointer",
        f"-fpass-plugin={plugin_path}",
        src_file,
        "-o", exe_output,
        lib_path
    ]

    if platform.system() != "Windows":
        cmd_build.insert(2, "-no-pie")

    try:
        print(f"Command: {' '.join(cmd_build)}")
        subprocess.run(cmd_build, check=True, env=build_env)
    except subprocess.CalledProcessError:
        print("[-] Compilation failed")
        sys.exit(1)

    # 6. 运行程序
    print(f"\n[+] Step 3: Running {exe_output}...")
    print("-" * 40)
    try:
        run_cmd = [os.path.abspath(exe_output)]
        subprocess.run(run_cmd, check=True, env=build_env)
    except subprocess.CalledProcessError:
        print(f"[-] Execution failed")
    except OSError as e:
        print(f"[-] Execution error: {e}")
    print("-" * 40)

if __name__ == "__main__":
    main()