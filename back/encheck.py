import argparse
import os
import struct
import subprocess
import sys
import shutil
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from Crypto.Cipher import ChaCha20_Poly1305
from blake3 import blake3

# --- 常量定义 ---
# 这些节名必须与 LLVM Pass 中设置的完全一致
KEY_SECTION_NAME = ".ic_key"
TEXT_HASH_SECTION_NAME = ".ic_texthash"
FUNC_TABLE_SECTION_NAME = ".ic_functable"
# 权威信息来源：标记表 (现在使用简化的名称)
MARKER_SECTION_NAME = ".ic_markers"

# C 结构体大小 (必须与 C++ 代码中的定义匹配)
# struct encrypted_hash { uint8_t[32], uint8_t[24], uint8_t[16] }
ENCRYPTED_HASH_SIZE = 32 + 24 + 16  # 72 bytes
# struct protected_func_info { uint64_t, uint64_t, encrypted_hash }
FUNC_INFO_SIZE = 8 + 8 + ENCRYPTED_HASH_SIZE  # 88 bytes
# 新的标记结构体大小: const char* + const void* (两个64位指针)
MARKER_STRUCT_SIZE = 8 + 8 # 16 bytes

def get_string_at_va(elf, va):
    """
    从给定的虚拟地址(VA)在ELF文件中查找并读取一个以 null 结尾的字符串。
    """
    for seg in elf.iter_segments():
        if seg['p_type'] == 'PT_LOAD':
            if seg['p_vaddr'] <= va < seg['p_vaddr'] + seg['p_filesz']:
                offset = va - seg['p_vaddr'] + seg['p_offset']
                elf.stream.seek(offset)
                # 读取一段数据并找到第一个 null 终止符
                # 假设函数名不会太长
                data = elf.stream.read(256) 
                try:
                    return data.split(b'\0', 1)[0].decode('utf-8')
                except UnicodeDecodeError:
                    return None
    return None

def encrypt_hash(key: bytes, plaintext_hash: bytes, aad: bytes = b'') -> bytes:
    """
    使用给定的密钥、随机 Nonce 和 AAD 加密哈希。
    返回一个 72 字节的 bytes 对象，其布局与 C++ 中的 encrypted_hash 结构体完全匹配。
    """
    nonce = os.urandom(24)  # XChaCha20 需要 24 字节的 nonce
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_hash)
    
    # 按照 C 结构体的顺序打包: ciphertext[32], nonce[24], tag[16]
    return struct.pack(f'<32s24s16s', ciphertext, nonce, tag)

def encrypt_blob(key: bytes, plaintext: bytes, aad: bytes = b'') -> bytes:
    """
    使用给定的密钥、随机 Nonce 和 AAD 加密一个数据块。
    返回一个 bytes 对象，其布局为:
    uint64_t plaintext_size | uint8_t nonce[24] | uint8_t tag[16] | uint8_t[] ciphertext
    """
    nonce = os.urandom(24)  # XChaCha20 需要 24 字节的 nonce
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    # 按照 [大小][nonce][tag][密文] 的顺序打包
    return struct.pack(f'<Q24s16s', len(plaintext), nonce, tag) + ciphertext

def main(executable_path, debug=False):
    print(f"[*] Processing executable: {executable_path}")

    # --- 阶段一: 从原始文件中读取标记数据和函数信息 ---
    print("\n--- Phase 1: Reading markers from original executable ---")
    protected_funcs_info = []
    try:
        with open(executable_path, 'rb') as f:
            elf = ELFFile(f)

            # 1a. 查找 .ic_markers 节
            print(f"[*] Locating authoritative '{MARKER_SECTION_NAME}' section...")
            marker_section = elf.get_section_by_name(MARKER_SECTION_NAME)
            if not marker_section:
                print(f"[!] Error: Section '{MARKER_SECTION_NAME}' not found. Is the program compiled with the correct pass?")
                return
            marker_data = marker_section.data()
            print(f"  - Found '{marker_section.name}' at file offset {marker_section['sh_offset']}, size {marker_section['sh_size']}")

            # 1b. 从符号表构建地址到大小的映射
            print("[*] Building address-to-size map from symbol table...")
            symtab = elf.get_section_by_name('.symtab')
            if not isinstance(symtab, SymbolTableSection):
                print("[!] Error: '.symtab' section not found or is not a symbol table.")
                return
            addr_to_symbol = {sym['st_value']: sym for sym in symtab.iter_symbols() if sym['st_info']['type'] == 'STT_FUNC'}
            print(f"  - Mapped {len(addr_to_symbol)} function symbols.")

            # 1c. 解析标记数据以填充 protected_funcs_info
            print(f"[*] Reading function markers from '{MARKER_SECTION_NAME}' data...")
            num_funcs_from_markers = len(marker_data) // MARKER_STRUCT_SIZE
            for i in range(num_funcs_from_markers):
                offset = i * MARKER_STRUCT_SIZE
                name_ptr, addr = struct.unpack('<QQ', marker_data[offset : offset + MARKER_STRUCT_SIZE])
                name = get_string_at_va(elf, name_ptr)
                size = 0
                symbol = addr_to_symbol.get(addr)
                if symbol:
                    size = symbol['st_size']
                if name is None:
                    print(f"  - WARNING: Could not read name for marker at index {i} (Addr: 0x{addr:x}). Skipping.")
                    continue
                protected_funcs_info.append({'name': name, 'addr': addr, 'size': size})

    except FileNotFoundError:
        print(f"Error: File not found at '{executable_path}'")
        return
    except Exception as e:
        print(f"An error occurred during phase 1: {e}")
        return

    # 排序列表，因为现在它已是最终列表
    protected_funcs_info.sort(key=lambda x: x['name'])
    print(f"  - Found and sorted {len(protected_funcs_info)} functions from marker table.")
    if debug:
        for i, info in enumerate(protected_funcs_info):
            print(f"    - Index {i}: {info['name']} (Addr: 0x{info['addr']:x}, Size: {info['size']})")

    # --- 阶段二: 使用 objcopy 移除标记节区 ---
    print(f"\n--- Phase 2: Removing '{MARKER_SECTION_NAME}' section ---")
    objcopy_cmd = 'objcopy'
    if sys.platform == 'win32':
        objcopy_cmd = 'llvm-objcopy.exe'
    
    temp_output_path = executable_path + ".encheck.tmp"

    try:
        cmd = [objcopy_cmd, '--remove-section', MARKER_SECTION_NAME, executable_path, temp_output_path]
        print(f"[*] Running command: {' '.join(cmd)}")
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        
        # 用修改后的文件替换原始文件
        shutil.move(temp_output_path, executable_path)
        print(f"[+] Successfully removed '{MARKER_SECTION_NAME}' section.")

    except FileNotFoundError:
        print(f"[!] FATAL: Command '{objcopy_cmd}' not found. Please ensure it is in your system's PATH.")
        return
    except subprocess.CalledProcessError as e:
        print(f"[!] FATAL: objcopy failed with exit code {e.returncode}.")
        print(f"    STDERR: {e.stderr.strip()}")
        if os.path.exists(temp_output_path):
            os.remove(temp_output_path)
        return
    except Exception as e:
        print(f"An error occurred during phase 2: {e}")
        if os.path.exists(temp_output_path):
            os.remove(temp_output_path)
        return

    # --- 阶段三: 处理修改后的可执行文件 ---
    print(f"\n--- Phase 3: Processing modified executable ---")
    with open(executable_path, 'r+b') as f:
        sections = {}

        # --- AAD 计算逻辑 (现在在修改后的、较小的文件上执行) ---
        f.seek(0)
        file_content = f.read()
        file_size = len(file_content)
        
        mid_index = file_size // 2
        the_byte_val = 0
        found_byte_offset = -1
        for i in range(mid_index, -1, -1):
            if file_content[i] != 0:
                the_byte_val = file_content[i]
                found_byte_offset = i
                break
        
        aad_value = the_byte_val * file_size
        text_section_aad = struct.pack('<Q', aad_value)
        
        if debug:
            print(f"[*] Calculated AAD for .text: byte=0x{the_byte_val:x} at offset {found_byte_offset}, size={file_size}, aad_val={aad_value}")
        
        f.seek(0)
        
        elf = ELFFile(f)

        # 1. 查找所有必需的节 (但不包括 .ic_markers)
        print("[*] Locating required sections in modified file...")
        sec_names_to_find = [KEY_SECTION_NAME, TEXT_HASH_SECTION_NAME, FUNC_TABLE_SECTION_NAME]
        remaining_sections_to_find = set(sec_names_to_find)
        for section in elf.iter_sections():
            for sec_name_base in list(remaining_sections_to_find):
                if section.name.startswith(sec_name_base):
                    sections[sec_name_base] = section
                    print(f"  - Found '{section.name}' (as '{sec_name_base}') at file offset {section['sh_offset']}, size {section['sh_size']}")
                    remaining_sections_to_find.remove(sec_name_base)
                    break
        if remaining_sections_to_find:
            for sec_name in remaining_sections_to_find:
                print(f"[!] Error: Section '{sec_name}' not found in modified file.")
            return

        # 2. 过滤掉无效函数
        print("[*] Filtering out invalid (size=0) functions from the candidate list...")
        valid_funcs_info = [info for info in protected_funcs_info if info['size'] > 0]
        print(f"  - Kept {len(valid_funcs_info)} of {len(protected_funcs_info)} candidates.")
        
        final_table_entry_count = len(valid_funcs_info) + 1
        
        # 3. 验证函数表空间是否足够
        table_section = sections[FUNC_TABLE_SECTION_NAME]
        encryption_overhead = 8 + 24 + 16 # 48 bytes
        plaintext_table_size = final_table_entry_count * FUNC_INFO_SIZE
        required_size = plaintext_table_size + encryption_overhead

        if table_section['sh_size'] < required_size:
            print(f"[!] FATAL: Section '{FUNC_TABLE_SECTION_NAME}' is too small.")
            print(f"    Required: {required_size} bytes, Found: {table_section['sh_size']} bytes.")
            return
        print(f"  - Capacity check passed: Table has enough space for the encrypted blob ({required_size} bytes).")

        # 4. 生成主加密密钥
        master_key = os.urandom(32)
        print(f"[*] Generated new master key.")

        # 5. 处理可执行段
        print("[*] Hashing and encrypting executable segment...")
        exec_segment = next((seg for seg in elf.iter_segments() if seg['p_type'] == 'PT_LOAD' and (seg['p_flags'] & 1)), None)
        
        if not exec_segment:
            print("[!] FATAL Error: Could not find an executable PT_LOAD segment in the ELF file.")
            return

        f.seek(exec_segment['p_offset'])
        segment_data_from_file = f.read(exec_segment['p_filesz'])
        full_segment_data = segment_data_from_file.ljust(exec_segment['p_memsz'], b'\x00')
        text_hash = blake3(full_segment_data).digest()
        encrypted_text_hash_struct = encrypt_hash(master_key, text_hash, aad=text_section_aad)

        # 6. 处理所有受保护的函数
        print(f"[*] Hashing and encrypting {len(valid_funcs_info)} functions...")
        packed_valid_entries = []
        
        for i, info in enumerate(valid_funcs_info):
            func_addr = info['addr']
            func_size = info['size']
            
            file_offset = -1
            for seg in elf.iter_segments():
                if seg['p_type'] == 'PT_LOAD' and seg['p_vaddr'] <= func_addr < seg['p_vaddr'] + seg['p_filesz']:
                    file_offset = func_addr - seg['p_vaddr'] + seg['p_offset']
                    break
            
            if file_offset != -1:
                f.seek(file_offset)
                func_data = f.read(func_size)
                func_hash = blake3(func_data).digest()
                
                if debug:
                    print(f"  - [{i}] Hashing '{info['name']}': Addr=0x{func_addr:x}, Size={func_size}")
                
                aad_data = struct.pack('<QQ', func_addr, func_size)
                encrypted_func_hash_struct = encrypt_hash(master_key, func_hash, aad=aad_data)
                
                func_info_packed = struct.pack(f'<QQ{ENCRYPTED_HASH_SIZE}s', func_addr, func_size, encrypted_func_hash_struct)
                packed_valid_entries.append(func_info_packed)
            else:
                print(f"  - WARNING: Could not find file offset for '{info['name']}' (Addr: 0x{func_addr:x}). Skipping.")

        # 7. 创建最终的数据 Blob
        final_data_blob = b''.join(packed_valid_entries) + (b'\x00' * FUNC_INFO_SIZE)
        print(f"  - Plaintext table size: {len(final_data_blob)} bytes ({len(packed_valid_entries) + 1} entries).")

        # 8. 应用第二层加密保护整个函数表
        print("[*] Applying second layer of encryption to the function table...")
        functable_aad = blake3(encrypted_text_hash_struct).digest()
        encrypted_functable_blob = encrypt_blob(master_key, final_data_blob, aad=functable_aad)
        
        if debug:
            print(f"  - AAD for table (hash of .ic_texthash content): {functable_aad.hex()}")
            print(f"  - Final encrypted table blob size: {len(encrypted_functable_blob)} bytes")

        # 9. 将所有计算好的数据写回文件
        print("[*] Writing calculated data back to the executable...")
        f.seek(sections[KEY_SECTION_NAME]['sh_offset'])
        f.write(master_key)
        print(f"  - Wrote master key to section {KEY_SECTION_NAME}")
        f.seek(sections[TEXT_HASH_SECTION_NAME]['sh_offset'])
        f.write(encrypted_text_hash_struct)
        print(f"  - Wrote encrypted text hash to section {TEXT_HASH_SECTION_NAME}")
        f.seek(sections[FUNC_TABLE_SECTION_NAME]['sh_offset'])
        f.write(encrypted_functable_blob)
        print(f"  - Wrote encrypted function table ({len(encrypted_functable_blob)} bytes) to section {FUNC_TABLE_SECTION_NAME}")

    print("\n[+] Activation complete. The executable is now ready to run.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Activates integrity checks in a compiled executable using a marker table.")
    parser.add_argument("executable", help="Path to the compiled ELF executable.")
    parser.add_argument("--debug", action="store_true", help="Enable detailed debug output.")
    args = parser.parse_args()
    
    if not os.path.exists(args.executable):
        print(f"Error: File not found at '{args.executable}'")
    else:
        main(args.executable, args.debug)
