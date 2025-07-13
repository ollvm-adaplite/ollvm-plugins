import argparse
import os
import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from Crypto.Cipher import ChaCha20_Poly1305
from blake3 import blake3

# --- 常量定义 ---
# 这些节名必须与 LLVM Pass 中设置的完全一致
KEY_SECTION_NAME = ".ic_key"
TEXT_HASH_SECTION_NAME = ".ic_texthash"
FUNC_TABLE_SECTION_NAME = ".ic_functable"
# 新增：函数名列表节
FUNC_NAMES_SECTION_NAME = ".ic_fnames"

# C 结构体大小 (必须与 C++ 代码中的定义匹配)
# struct encrypted_hash { uint8_t[32], uint8_t[24], uint8_t[16] }
ENCRYPTED_HASH_SIZE = 32 + 24 + 16  # 72 bytes
# struct protected_func_info { uint64_t, uint64_t, encrypted_hash }
FUNC_INFO_SIZE = 8 + 8 + ENCRYPTED_HASH_SIZE  # 88 bytes

def encrypt_hash(key: bytes, plaintext_hash: bytes) -> bytes:
    """
    使用给定的密钥和随机生成的 Nonce 加密哈希。
    返回一个 72 字节的 bytes 对象，其布局与 C++ 中的 encrypted_hash 结构体完全匹配。
    """
    nonce = os.urandom(24)  # XChaCha20 需要 24 字节的 nonce
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_hash)
    
    # 按照 C 结构体的顺序打包: ciphertext[32], nonce[24], tag[16]
    return struct.pack(f'<32s24s16s', ciphertext, nonce, tag)

def main(executable_path, debug=False):
    print(f"[*] Processing executable: {executable_path}")

    with open(executable_path, 'r+b') as f:
        elf = ELFFile(f)

        # 1. 查找所有必需的节
        print("[*] Locating required sections...")
        sections = {}
        # 移除了 .text，因为它不再被直接用于哈希
        sec_names_to_find = [KEY_SECTION_NAME, TEXT_HASH_SECTION_NAME, FUNC_TABLE_SECTION_NAME, FUNC_NAMES_SECTION_NAME]
        
        # --- START OF CHANGE ---
        # 核心修复：修改节查找逻辑以匹配带标志的节名 (e.g., ".ic_key,aw")
        # 我们现在遍历所有节，并检查节名是否以我们寻找的名称开头。
        
        # 创建一个待查找节的集合，以便高效地移除已找到的节
        remaining_sections_to_find = set(sec_names_to_find)
        
        for section in elf.iter_sections():
            # 使用 list() 创建副本，以便在迭代时安全地修改集合
            for sec_name_base in list(remaining_sections_to_find):
                # 检查节名是否与基本名称完全匹配，或者以 "基本名称," 开头
                if section.name == sec_name_base or section.name.startswith(sec_name_base + ','):
                    sections[sec_name_base] = section
                    print(f"  - Found '{section.name}' (as '{sec_name_base}') at file offset {section['sh_offset']}, size {section['sh_size']}")
                    remaining_sections_to_find.remove(sec_name_base)
                    break # 已找到，处理下一个节

        # 检查是否所有必需的节都已找到
        if remaining_sections_to_find:
            for sec_name in remaining_sections_to_find:
                print(f"[!] Error: Section '{sec_name}' not found. Is the program compiled with the correct pass?")
            return
        # --- END OF CHANGE ---

        # 2. 从 .ic_fnames 节中读取权威的函数名列表
        print("[*] Reading the authoritative list of function names from pass...")
        names_data = sections[FUNC_NAMES_SECTION_NAME].data()
        # 使用 split(b'\0') 并过滤掉空字符串
        protected_names_set = set(name.decode('utf-8') for name in names_data.split(b'\0') if name)
        print(f"  - Pass has marked {len(protected_names_set)} functions for protection.")

        # 3. 查找符号表，并根据权威列表筛选函数
        print("[*] Locating symbol table and filtering functions...")
        symtab = elf.get_section_by_name('.symtab')
        if not isinstance(symtab, SymbolTableSection):
            print("[!] Error: '.symtab' section not found or is not a symbol table.")
            return

        protected_funcs = []
        # 遍历符号表，只选择那些名字在我们的权威集合中的函数
        for sym in symtab.iter_symbols():
            if sym.name in protected_names_set:
                protected_funcs.append(sym)
        
        # 关键步骤：按函数名排序，与 LLVM Pass 保持一致
        protected_funcs.sort(key=lambda s: s.name)
        print(f"  - Found and sorted {len(protected_funcs)} protected functions from symbol table.")
        if debug:
            for i, sym in enumerate(protected_funcs):
                print(f"    - Index {i}: {sym.name}")


        # 4. 验证函数表空间是否足够 (现在这应该永远是匹配的)
        table_capacity = sections[FUNC_TABLE_SECTION_NAME]['sh_size'] // FUNC_INFO_SIZE
        if table_capacity < len(protected_funcs):
            print(f"[!] FATAL Error: Function table in file has space for {table_capacity} entries, but {len(protected_funcs)} functions were found. This indicates a severe mismatch.")
            return
        if len(protected_names_set) != len(protected_funcs):
             print(f"[!] FATAL Error: The pass specified {len(protected_names_set)} names, but only {len(protected_funcs)} were found in the symbol table.")
             return
        print(f"  - Capacity check passed: Table has space for {table_capacity}, found {len(protected_funcs)}.")


        # 5. 生成主加密密钥
        master_key = os.urandom(32)
        print(f"[*] Generated new master key.")

        # 6. 处理可执行段 (Executable Segment)
        # 修复：不再哈希 .text 节，而是哈希整个可执行的 PT_LOAD 段，
        # 与 C++ 运行时逻辑保持完全一致。
        print("[*] Hashing and encrypting executable segment...")
        exec_segment = None
        for seg in elf.iter_segments():
            # PF_X = 1 (Executable). 我们寻找第一个可加载、可执行的段。
            if seg['p_type'] == 'PT_LOAD' and (seg['p_flags'] & 1):
                exec_segment = seg
                break
        
        if not exec_segment:
            print("[!] FATAL Error: Could not find an executable PT_LOAD segment in the ELF file.")
            return

        # C++ 运行时哈希的是段在内存中的映像 (p_memsz)。
        # OS 加载器会从文件偏移 p_offset 处加载 p_filesz 字节，
        # 然后用 0 填充剩余的 (p_memsz - p_filesz) 字节。
        # 我们必须在 Python 中精确地模拟这个过程。
        f.seek(exec_segment['p_offset'])
        segment_data_from_file = f.read(exec_segment['p_filesz'])
        
        # 使用 ljust 将数据填充到 p_memsz 的长度，不足部分用空字节填充。
        full_segment_data = segment_data_from_file.ljust(exec_segment['p_memsz'], b'\x00')

        text_hash = blake3(full_segment_data).digest()
        
        if debug:
            print(f"    - Found executable segment: offset=0x{exec_segment['p_offset']:x}, filesz={exec_segment['p_filesz']}, memsz={exec_segment['p_memsz']}")
            print(f"    - Hashing {len(full_segment_data)} bytes for the segment.")
            print(f"    - Executable segment hash: {text_hash.hex()}")
            
        encrypted_text_hash_struct = encrypt_hash(master_key, text_hash)

        # 7. 处理所有受保护的函数
        print(f"[*] Hashing and encrypting {len(protected_funcs)} functions...")
        
        # --- START OF CHANGE ---
        # 预分配整个表，并用零填充。这确保了即使某些函数被跳过，
        # 表的大小和索引也是正确的，不会发生错位。
        table_size_in_bytes = len(protected_funcs) * FUNC_INFO_SIZE
        all_funcs_info_bytes = bytearray(table_size_in_bytes)

        processed_count = 0
        for i, sym in enumerate(protected_funcs):
            func_addr = sym['st_value']
            func_size = sym['st_size']
            
            offset = -1
            for seg in elf.iter_segments():
                if seg['p_type'] == 'PT_LOAD':
                    if seg['p_vaddr'] <= func_addr < seg['p_vaddr'] + seg['p_filesz']:
                        offset = func_addr - seg['p_vaddr'] + seg['p_offset']
                        break
            
            # 如果函数有效，则处理它。否则，其在表中的条目将保持为零。
            if offset != -1 and func_size > 0:
                f.seek(offset)
                func_data = f.read(func_size)
                func_hash = blake3(func_data).digest()
                
                if debug:
                    print(f"  - [{i}] Hashing '{sym.name}': Addr=0x{func_addr:x}, Size={func_size}")
                    print(f"    - Plaintext Hash: {func_hash.hex()}")
                
                encrypted_func_hash_struct = encrypt_hash(master_key, func_hash)
                
                func_info_packed = struct.pack(f'<QQ{ENCRYPTED_HASH_SIZE}s', func_addr, func_size, encrypted_func_hash_struct)
                
                # 将打包好的数据放置在 bytearray 的正确位置
                start_pos = i * FUNC_INFO_SIZE
                end_pos = start_pos + FUNC_INFO_SIZE
                all_funcs_info_bytes[start_pos:end_pos] = func_info_packed
                processed_count += 1
            else:
                # 打印警告，但由于我们预分配了数组，索引不会错乱
                print(f"  - WARNING: Skipping function '{sym.name}' (index {i}) due to invalid size or offset. Its entry will be zeroed.")
        
        print(f"  - Processed and packed info for {processed_count} of {len(protected_funcs)} functions.")

        # --- NEW DEBUG BLOCK ---
        if debug:
            print("[*] Verifying bytearray content before writing...")
            # Let's check the problematic index
            target_index = 31
            if len(protected_funcs) > target_index:
                start_pos = target_index * FUNC_INFO_SIZE
                end_pos = start_pos + FUNC_INFO_SIZE
                entry_bytes = all_funcs_info_bytes[start_pos:end_pos]
                
                # Unpack to verify the content of the bytearray itself
                unpacked_addr, unpacked_size = struct.unpack('<QQ', entry_bytes[:16])
                print(f"  - Verification for index {target_index}:")
                print(f"    - Raw bytes in buffer: {entry_bytes.hex()}")
                print(f"    - Unpacked Addr from buffer: 0x{unpacked_addr:x}, Unpacked Size: {unpacked_size}")
                
                # Compare with what we thought we wrote
                original_sym = protected_funcs[target_index]
                if unpacked_addr != original_sym['st_value'] or unpacked_size != original_sym['st_size']:
                    print("    - [!!!] MISMATCH DETECTED IN BYTEARRAY! The data was not packed correctly.")
                else:
                    print("    - [OK] Bytearray content matches expected values.")
        # --- END OF NEW DEBUG BLOCK ---

        # 8. 将所有计算好的数据写回文件
        print("[*] Writing calculated data back to the executable...")
        
        # 写入密钥
        f.seek(sections[KEY_SECTION_NAME]['sh_offset'])
        f.write(master_key)
        print(f"  - Wrote master key to section {KEY_SECTION_NAME}")

        # 写入 .text 哈希
        f.seek(sections[TEXT_HASH_SECTION_NAME]['sh_offset'])
        f.write(encrypted_text_hash_struct)
        print(f"  - Wrote encrypted .text hash to section {TEXT_HASH_SECTION_NAME}")

        # 写入函数信息表
        f.seek(sections[FUNC_TABLE_SECTION_NAME]['sh_offset'])
        f.write(all_funcs_info_bytes)
        # 更新日志消息以反映真实情况
        print(f"  - Wrote {len(all_funcs_info_bytes) // FUNC_INFO_SIZE} entries to section {FUNC_TABLE_SECTION_NAME}")

    print("[+] Activation complete. The executable is now ready to run.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Activates integrity checks in a compiled executable.")
    parser.add_argument("executable", help="Path to the compiled ELF executable.")
    parser.add_argument("--debug", action="store_true", help="Enable detailed debug output.")
    args = parser.parse_args()
    
    if not os.path.exists(args.executable):
        print(f"Error: File not found at '{args.executable}'")
    else:
        main(args.executable, args.debug)
