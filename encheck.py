import argparse
import os
import struct
# 移除了不再需要的 subprocess
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

    with open(executable_path, 'r+b') as f:
        sections = {}

        # --- AAD 计算逻辑 ---
        # 由于我们只是清零节区，文件总大小不变，此处的 AAD 计算是正确的
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

        # 1. 查找所有必需的节
        print("[*] Locating required sections...")
        sec_names_to_find = [KEY_SECTION_NAME, TEXT_HASH_SECTION_NAME, FUNC_TABLE_SECTION_NAME, MARKER_SECTION_NAME]
        remaining_sections_to_find = set(sec_names_to_find)
        for section in elf.iter_sections():
            # 使用一个副本进行迭代，以便安全地从原集合中删除
            for sec_name_base in list(remaining_sections_to_find):
                # 显式检查可能的节名称变体，以提高清晰度
                # 1. 精确匹配 (例如, .ic_key)
                # 2. 匹配只读变体 (例如, .ic_key,a)
                # 3. 匹配旧的可写变体 (例如, .ic_key,aw) - 为了向后兼容
                if section.name == sec_name_base or \
                   section.name == f"{sec_name_base},a" or \
                   section.name == f"{sec_name_base},aw":
                    sections[sec_name_base] = section
                    print(f"  - Found '{section.name}' (as '{sec_name_base}') at file offset {section['sh_offset']}, size {section['sh_size']}")
                    remaining_sections_to_find.remove(sec_name_base)
                    break
        if remaining_sections_to_find:
            for sec_name in remaining_sections_to_find:
                print(f"[!] Error: Section '{sec_name}' not found. Is the program compiled with the correct pass?")
            return

        # 2. 构建从地址到符号的映射，用于快速查找函数大小
        # 这是我们唯一需要符号表的地方
        print("[*] Building address-to-size map from symbol table...")
        symtab = elf.get_section_by_name('.symtab')
        if not isinstance(symtab, SymbolTableSection):
            print("[!] Error: '.symtab' section not found or is not a symbol table.")
            return
        addr_to_symbol = {sym['st_value']: sym for sym in symtab.iter_symbols() if sym['st_info']['type'] == 'STT_FUNC'}
        print(f"  - Mapped {len(addr_to_symbol)} function symbols.")

        # 3. 读取权威的标记表 (.ic_markers)
        print(f"[*] Reading function markers from the authoritative '{MARKER_SECTION_NAME}' section...")
        marker_data = sections[MARKER_SECTION_NAME].data()
        num_funcs_from_markers = len(marker_data) // MARKER_STRUCT_SIZE
        
        protected_funcs_info = []
        for i in range(num_funcs_from_markers):
            offset = i * MARKER_STRUCT_SIZE
            name_ptr, addr = struct.unpack('<QQ', marker_data[offset : offset + MARKER_STRUCT_SIZE])
            
            name = get_string_at_va(elf, name_ptr)
            
            
            # 正确地获取符号及其大小。
            # 首先从字典中获取 Symbol 对象，如果存在，再从中获取大小。
            size = 0
            symbol = addr_to_symbol.get(addr)
            if symbol:
                size = symbol['st_size']
            

            if name is None:
                print(f"  - WARNING: Could not read name for marker at index {i} (Addr: 0x{addr:x}). Skipping.")
                continue
            
            protected_funcs_info.append({'name': name, 'addr': addr, 'size': size})

        # 关键步骤：按函数名排序，与 LLVM Pass 保持完全一致
        protected_funcs_info.sort(key=lambda x: x['name'])
        print(f"  - Found and sorted {len(protected_funcs_info)} functions from marker table.")
        if debug:
            for i, info in enumerate(protected_funcs_info):
                print(f"    - Index {i}: {info['name']} (Addr: 0x{info['addr']:x}, Size: {info['size']})")

        # --- NEW STEP: Filter out invalid functions ---
        print("[*] Filtering out invalid (size=0) functions from the candidate list...")
        valid_funcs_info = [info for info in protected_funcs_info if info['size'] > 0]
        print(f"  - Kept {len(valid_funcs_info)} of {len(protected_funcs_info)} candidates.")
        
        # The final table will contain all valid functions plus one terminator entry.
        final_table_entry_count = len(valid_funcs_info) + 1
        
        # 4. 验证函数表空间是否足够
        table_section = sections[FUNC_TABLE_SECTION_NAME]
        
        # --- FIX: Update size calculation to include encryption overhead ---
        # The final blob is: u64 size + 24B nonce + 16B tag + ciphertext
        encryption_overhead = 8 + 24 + 16 # 48 bytes
        plaintext_table_size = final_table_entry_count * FUNC_INFO_SIZE
        required_size = plaintext_table_size + encryption_overhead

        if table_section['sh_size'] < required_size:
            print(f"[!] FATAL: Section '{FUNC_TABLE_SECTION_NAME}' is too small.")
            print(f"    Required: {required_size} bytes, Found: {table_section['sh_size']} bytes.")
            print(f"    This likely means the number of functions detected by the Pass and the script differ.")
            return
        print(f"  - Capacity check passed: Table has enough space for the encrypted blob ({required_size} bytes).")

        # 5. 生成主加密密钥
        master_key = os.urandom(32)
        print(f"[*] Generated new master key.")

        # 6. 处理可执行段 (逻辑不变)
        print("[*] Hashing and encrypting executable segment...")
        exec_segment = None
        for seg in elf.iter_segments():
            if seg['p_type'] == 'PT_LOAD' and (seg['p_flags'] & 1):
                exec_segment = seg
                break
        
        if not exec_segment:
            print("[!] FATAL Error: Could not find an executable PT_LOAD segment in the ELF file.")
            return

        f.seek(exec_segment['p_offset'])
        segment_data_from_file = f.read(exec_segment['p_filesz'])
        full_segment_data = segment_data_from_file.ljust(exec_segment['p_memsz'], b'\x00')
        text_hash = blake3(full_segment_data).digest()
        # --- MODIFIED: Use the calculated AAD for the text section hash ---
        encrypted_text_hash_struct = encrypt_hash(master_key, text_hash, aad=text_section_aad)

        # 7. 处理所有受保护的函数
        print(f"[*] Hashing and encrypting {len(valid_funcs_info)} functions...")
        
        # --- NEW: Build a list of packed, valid entries ---
        packed_valid_entries = []
        
        for i, info in enumerate(valid_funcs_info):
            func_addr = info['addr']
            func_size = info['size']
            
            # We already filtered, so no need to check for func_size == 0 here.

            # 将虚拟地址转换为文件偏移量
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
                
                # --- FIX: Create AAD from function address and size ---
                aad_data = struct.pack('<QQ', func_addr, func_size)
                encrypted_func_hash_struct = encrypt_hash(master_key, func_hash, aad=aad_data)
                
                # --- IMPORTANT: The address written to the table is the *relative* address ---
                # The runtime will add the base address.
                # The symbol address `func_addr` is already the relative address we need.
                func_info_packed = struct.pack(f'<QQ{ENCRYPTED_HASH_SIZE}s', func_addr, func_size, encrypted_func_hash_struct)
                packed_valid_entries.append(func_info_packed)
            else:
                print(f"  - WARNING: Could not find file offset for '{info['name']}' (Addr: 0x{func_addr:x}). This is unexpected for a valid function and it will be skipped.")

        # --- NEW: Create the final data blob ---
        # Join all valid entries and add a null terminator entry
        final_data_blob = b''.join(packed_valid_entries) + (b'\x00' * FUNC_INFO_SIZE)

        print(f"  - Processed and packed info for {len(packed_valid_entries)} functions.")
        print(f"  - Plaintext table size: {len(final_data_blob)} bytes ({len(packed_valid_entries) + 1} entries).")

        # --- NEW: 应用第二层加密保护整个函数表 ---
        print("[*] Applying second layer of encryption to the function table...")
        # AAD 是 .ic_texthash 节内容的哈希值
        functable_aad = blake3(encrypted_text_hash_struct).digest()
        encrypted_functable_blob = encrypt_blob(master_key, final_data_blob, aad=functable_aad)
        
        if debug:
            print(f"  - AAD for table (hash of .ic_texthash content): {functable_aad.hex()}")
            print(f"  - Final encrypted table blob size: {len(encrypted_functable_blob)} bytes")


        # 8. 将所有计算好的数据写回文件 (逻辑不变)
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

        # 9. 清理步骤: 将不再需要的 .ic_markers 节内容清零
        # 使用同一个、仍然打开的文件句柄 'f' 来完成操作
        print("[*] Attempting to clean up marker section...")

        # 使用更灵活的方式查找标记节区
        marker_section = None
        for section in elf.iter_sections():
            # 匹配任何以 .ic_markers 开头的节区（考虑链接器可能添加的后缀）
            if section.name.startswith(".ic_markers"):
                marker_section = section
                print(f"  - Found marker section: '{section.name}'")
                break

        if marker_section:
            section_offset = marker_section['sh_offset']
            section_size = marker_section['sh_size']
            
            print(f"[*] Cleaning up: Overwriting '{marker_section.name}' section with zeros...")
            print(f"    Section offset: 0x{section_offset:x}, size: {section_size} bytes")
            
            if section_size > 0:
                # 确保我们在当前文件位置进行写入
                f.seek(section_offset)
                zeros = b'\x00' * section_size
                bytes_written = f.write(zeros)
                f.flush()  # 强制刷新到磁盘
                
                # 验证写入是否成功
                f.seek(section_offset)
                verification_data = f.read(section_size)
                if all(b == 0 for b in verification_data):
                    print(f"[+] Successfully zeroed out '{marker_section.name}'. Verified {bytes_written} bytes are now zero.")
                else:
                    print(f"[!] WARNING: Failed to zero out section. First few bytes: {verification_data[:16].hex()}")
                    print("    This might indicate a file permission or caching issue.")
        else:
            print("[!] Warning: Could not find any marker section. Skipping cleanup step.")

    print("[+] Activation complete. The executable is now ready to run.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Activates integrity checks in a compiled executable using a marker table.")
    parser.add_argument("executable", help="Path to the compiled ELF executable.")
    parser.add_argument("--debug", action="store_true", help="Enable detailed debug output.")
    args = parser.parse_args()
    
    if not os.path.exists(args.executable):
        print(f"Error: File not found at '{args.executable}'")
    else:
        main(args.executable, args.debug)
