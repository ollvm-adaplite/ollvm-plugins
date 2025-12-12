import argparse
import os
import struct
import subprocess
import sys
import shutil
from Crypto.Cipher import ChaCha20_Poly1305
from blake3 import blake3

# 尝试导入 ELF 和 PE 处理库
try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    HAS_ELFTOOLS = True
except ImportError:
    HAS_ELFTOOLS = False

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

# --- 常量定义 ---
KEY_SECTION_NAME = ".ic_key"
TEXT_HASH_SECTION_NAME = ".ic_texthash"
FUNC_TABLE_SECTION_NAME = ".ic_functable"
MARKER_SECTION_NAME = ".ic_markers"

# Windows 兼容的短节名
WIN_TEXT_HASH_SEC = ".ic_text"
WIN_FUNC_TABLE_SEC = ".ic_func"
WIN_MARKER_SEC = ".ic_mark"

# C 结构体大小
ENCRYPTED_HASH_SIZE = 32 + 24 + 16  # 72 bytes
FUNC_INFO_SIZE = 8 + 8 + ENCRYPTED_HASH_SIZE  # 88 bytes
MARKER_STRUCT_SIZE = 8 + 8 # 16 bytes

def encrypt_hash(key: bytes, plaintext_hash: bytes, aad: bytes = b'') -> bytes:
    nonce = os.urandom(24)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_hash)
    return struct.pack(f'<32s24s16s', ciphertext, nonce, tag)

def encrypt_blob(key: bytes, plaintext: bytes, aad: bytes = b'') -> bytes:
    nonce = os.urandom(24)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return struct.pack(f'<Q24s16s', len(plaintext), nonce, tag) + ciphertext

def get_function_sizes_via_nm(executable_path):
    sizes = {}
    nm_cmds = ['llvm-nm', 'nm']
    for cmd_name in nm_cmds:
        try:
            cmd = [cmd_name, '--print-size', '--format=bsd', '--numeric-sort', executable_path]
            startupinfo = None
            if sys.platform == 'win32':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.run(cmd, capture_output=True, text=True, startupinfo=startupinfo)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            addr = int(parts[0], 16)
                            size = int(parts[1], 16)
                            type_char = parts[2].upper()
                            if type_char in ('T', 't'): 
                                sizes[addr] = size
                        except ValueError:
                            continue
                return sizes
        except FileNotFoundError:
            continue
    return sizes

def get_function_sizes_pe_pdata(pe):
    sizes = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_EXCEPTION'):
        for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
            start_rva = entry.struct.BeginAddress
            end_rva = entry.struct.EndAddress
            size = end_rva - start_rva
            va = start_rva + pe.OPTIONAL_HEADER.ImageBase
            sizes[va] = size
    return sizes

def process_elf(executable_path, debug):
    if not HAS_ELFTOOLS:
        print("[!] Error: 'pyelftools' is required for ELF files.")
        return False
    print("[*] Detected ELF format.")
    protected_funcs_info = []
    with open(executable_path, 'rb') as f:
        elf = ELFFile(f)
        marker_section = elf.get_section_by_name(MARKER_SECTION_NAME)
        if not marker_section:
            print(f"[!] Error: Section '{MARKER_SECTION_NAME}' not found.")
            return False
        marker_data = marker_section.data()
        symtab = elf.get_section_by_name('.symtab')
        addr_to_size = {}
        if isinstance(symtab, SymbolTableSection):
            for sym in symtab.iter_symbols():
                if sym['st_info']['type'] == 'STT_FUNC':
                    addr_to_size[sym['st_value']] = sym['st_size']
        if not addr_to_size:
            addr_to_size = get_function_sizes_via_nm(executable_path)
        num_funcs = len(marker_data) // MARKER_STRUCT_SIZE
        for i in range(num_funcs):
            offset = i * MARKER_STRUCT_SIZE
            name_ptr, addr = struct.unpack('<QQ', marker_data[offset : offset + MARKER_STRUCT_SIZE])
            name = None
            for seg in elf.iter_segments():
                if seg['p_type'] == 'PT_LOAD':
                    if seg['p_vaddr'] <= name_ptr < seg['p_vaddr'] + seg['p_filesz']:
                        file_off = name_ptr - seg['p_vaddr'] + seg['p_offset']
                        f.seek(file_off)
                        name = f.read(256).split(b'\0', 1)[0].decode('utf-8', errors='ignore')
                        break
            size = addr_to_size.get(addr, 0)
            if name:
                protected_funcs_info.append({'name': name, 'addr': addr, 'size': size})
    return protected_funcs_info

def process_pe(executable_path, debug):
    if not HAS_PEFILE:
        print("[!] Error: 'pefile' is required for PE files.")
        return False
    print("[*] Detected PE format.")
    pe = pefile.PE(executable_path)
    protected_funcs_info = []
    marker_section = None
    target_names = [MARKER_SECTION_NAME, WIN_MARKER_SEC]
    for section in pe.sections:
        name = section.Name.decode().strip('\x00')
        if name in target_names:
            marker_section = section
            break
    if not marker_section:
        print(f"[!] Error: Section '{MARKER_SECTION_NAME}' (or '{WIN_MARKER_SEC}') not found.")
        return False
    marker_data = marker_section.get_data()
    print("[*] Attempting to extract function sizes from .pdata...")
    addr_to_size = get_function_sizes_pe_pdata(pe)
    if not addr_to_size:
        print("[*] .pdata empty or missing. Trying llvm-nm...")
        addr_to_size = get_function_sizes_via_nm(executable_path)
    num_funcs = len(marker_data) // MARKER_STRUCT_SIZE
    image_base = pe.OPTIONAL_HEADER.ImageBase
    temp_funcs = []
    for i in range(num_funcs):
        offset = i * MARKER_STRUCT_SIZE
        name_va, func_va = struct.unpack('<QQ', marker_data[offset : offset + MARKER_STRUCT_SIZE])
        
        if func_va == 0 or name_va == 0:
            continue

        try:
            name_rva = name_va - image_base
            if name_rva < 0 or name_rva > pe.OPTIONAL_HEADER.SizeOfImage:
                continue
            name = pe.get_string_at_rva(name_rva).decode('utf-8', errors='ignore')
        except Exception:
            name = f"func_{func_va:x}"
        
        if not name:
            continue

        size = addr_to_size.get(func_va, 0)
        temp_funcs.append({'name': name, 'addr': func_va, 'size': size})

    if any(f['size'] == 0 for f in temp_funcs):
        print("[*] Some sizes are 0. Using address delta heuristic...")
        sorted_funcs = sorted(temp_funcs, key=lambda x: x['addr'])
        for i in range(len(sorted_funcs)):
            if sorted_funcs[i]['size'] == 0:
                start_addr = sorted_funcs[i]['addr']
                if i < len(sorted_funcs) - 1:
                    end_addr = sorted_funcs[i+1]['addr']
                    estimated_size = end_addr - start_addr
                else:
                    rva = start_addr - image_base
                    sec = pe.get_section_by_rva(rva)
                    if sec:
                        sec_end = image_base + sec.VirtualAddress + sec.Misc_VirtualSize
                        estimated_size = sec_end - start_addr
                    else:
                        estimated_size = 64
                
                if estimated_size > 16 * 1024 * 1024:
                    estimated_size = 64
                
                sorted_funcs[i]['size'] = estimated_size
                if debug: print(f"    - Estimated size for {sorted_funcs[i]['name']}: {estimated_size}")
        protected_funcs_info = sorted_funcs
    else:
        protected_funcs_info = temp_funcs
    pe.close()
    return protected_funcs_info

def main(executable_path, debug=False):
    print(f"[*] Processing executable: {executable_path}")
    is_pe = False
    with open(executable_path, 'rb') as f:
        magic = f.read(4)
        if magic.startswith(b'MZ'):
            is_pe = True
        elif not magic.startswith(b'\x7fELF'):
            print("[!] Unknown file format.")
            return

    if is_pe:
        protected_funcs_info = process_pe(executable_path, debug)
    else:
        protected_funcs_info = process_elf(executable_path, debug)

    if protected_funcs_info is False: return
    valid_funcs_info = [info for info in protected_funcs_info if info['size'] > 0]
    valid_funcs_info.sort(key=lambda x: x['name'])
    print(f"  - Found {len(valid_funcs_info)} valid protected functions.")
    if len(valid_funcs_info) == 0:
        print("[!] No functions to protect. Exiting.")
        return

    # --- Phase 2: Removing/Wiping section ---
    if is_pe:
        # Windows: 安全擦除 (Wipe)
        print(f"\n--- Phase 2: Wiping '{WIN_MARKER_SEC}' section content (Windows Safe Mode) ---")
        try:
            pe = pefile.PE(executable_path)
            marker_section = None
            for section in pe.sections:
                name = section.Name.decode().strip('\x00')
                if name == WIN_MARKER_SEC:
                    marker_section = section
                    break
            
            if marker_section:
                offset = marker_section.PointerToRawData
                size = marker_section.SizeOfRawData
                if offset > 0 and size > 0:
                    pe.close() # 关闭 PE 对象以释放文件句柄
                    with open(executable_path, 'r+b') as f:
                        f.seek(offset)
                        f.write(b'\x00' * size)
                    print(f"[+] Successfully wiped {size} bytes from '{WIN_MARKER_SEC}'.")
                else:
                    print(f"[!] Warning: Section '{WIN_MARKER_SEC}' has invalid offset/size. Skipping wipe.")
                    pe.close()
            else:
                print(f"[!] Warning: Section '{WIN_MARKER_SEC}' not found for wiping.")
                pe.close()
        except Exception as e:
            print(f"[!] Error wiping section: {e}")

    else:
        # Linux: 物理移除 (Remove)
        sec_to_remove = MARKER_SECTION_NAME
        print(f"\n--- Phase 2: Removing '{sec_to_remove}' section ---")
        objcopy_cmd = 'llvm-objcopy'
        if shutil.which(objcopy_cmd) is None:
            objcopy_cmd = 'objcopy'
        
        temp_output_path = executable_path + ".encheck.tmp"
        try:
            cmd = [objcopy_cmd, '--remove-section', sec_to_remove, executable_path, temp_output_path]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            shutil.move(temp_output_path, executable_path)
            print(f"[+] Successfully removed '{sec_to_remove}'.")
        except Exception as e:
            print(f"[!] Error removing section: {e}")
            pass

    print(f"\n--- Phase 3: Processing modified executable ---")
    
    if is_pe:
        try:
            pe = pefile.PE(executable_path)
        except Exception as e:
            print(f"[!] Error parsing modified PE: {e}")
            return
        
        # 1. AAD Calculation
        with open(executable_path, 'rb') as f:
            content = f.read()
        file_size = len(content)
        mid = file_size // 2
        byte_val = 0
        for i in range(mid, -1, -1):
            if content[i] != 0:
                byte_val = content[i]
                break
        aad_value = byte_val * file_size
        text_section_aad = struct.pack('<Q', aad_value)

        # 2. Text Hash
        text_section = None
        for section in pe.sections:
            if section.Name.decode().strip('\x00') == '.text':
                text_section = section
                break
        
        if not text_section:
            print("[!] Error: .text section not found.")
            return

        raw_data = text_section.get_data()
        virt_size = text_section.Misc_VirtualSize
        
        if len(raw_data) >= virt_size:
            hash_data = raw_data[:virt_size]
        else:
            hash_data = raw_data + b'\x00' * (virt_size - len(raw_data))
            
        text_hash = blake3(hash_data).digest()
        
        # 3. Find Sections
        sections_map = {}
        target_sections = [KEY_SECTION_NAME, TEXT_HASH_SECTION_NAME, FUNC_TABLE_SECTION_NAME, WIN_TEXT_HASH_SEC, WIN_FUNC_TABLE_SEC]
        for section in pe.sections:
            name = section.Name.decode().strip('\x00')
            if name in target_sections:
                sections_map[name] = section
        
        def get_section_offset(long_name, short_name):
            sec = sections_map.get(long_name)
            if not sec: sec = sections_map.get(short_name)
            if sec:
                if sec.PointerToRawData == 0:
                    print(f"[!] FATAL: Section '{long_name}' (or '{short_name}') has PointerToRawData=0.")
                    return None
                return sec.PointerToRawData
            return None
            
        key_offset = get_section_offset(KEY_SECTION_NAME, KEY_SECTION_NAME)
        hash_offset = get_section_offset(TEXT_HASH_SECTION_NAME, WIN_TEXT_HASH_SEC)
        table_offset = get_section_offset(FUNC_TABLE_SECTION_NAME, WIN_FUNC_TABLE_SEC)
        
        table_sec = sections_map.get(FUNC_TABLE_SECTION_NAME)
        if not table_sec: table_sec = sections_map.get(WIN_FUNC_TABLE_SEC)
        table_size = table_sec.SizeOfRawData if table_sec else 0

        def read_func_data(addr, size):
            if not hasattr(pe, 'OPTIONAL_HEADER') or not hasattr(pe.OPTIONAL_HEADER, 'ImageBase'):
                 return b'\x00' * size
            rva = addr - pe.OPTIONAL_HEADER.ImageBase
            offset = pe.get_offset_from_rva(rva)
            if offset is None or offset < 0:
                return b'\x00' * size
            try:
                with open(executable_path, 'rb') as f:
                    f.seek(offset)
                    return f.read(size)
            except Exception:
                return b'\x00' * size

    else: # ELF Logic
        with open(executable_path, 'rb') as f:
            elf = ELFFile(f)
            f.seek(0); content = f.read(); file_size = len(content)
            mid = file_size // 2
            byte_val = 0
            for i in range(mid, -1, -1):
                if content[i] != 0:
                    byte_val = content[i]
                    break
            aad_value = byte_val * file_size
            text_section_aad = struct.pack('<Q', aad_value)

            exec_segment = next((seg for seg in elf.iter_segments() if seg['p_type'] == 'PT_LOAD' and (seg['p_flags'] & 1)), None)
            f.seek(exec_segment['p_offset'])
            segment_data = f.read(exec_segment['p_filesz'])
            hash_data = segment_data.ljust(exec_segment['p_memsz'], b'\x00')
            text_hash = blake3(hash_data).digest()

            key_sec = elf.get_section_by_name(KEY_SECTION_NAME)
            hash_sec = elf.get_section_by_name(TEXT_HASH_SECTION_NAME)
            table_sec = elf.get_section_by_name(FUNC_TABLE_SECTION_NAME)
            
            key_offset = key_sec['sh_offset'] if key_sec else None
            hash_offset = hash_sec['sh_offset'] if hash_sec else None
            table_offset = table_sec['sh_offset'] if table_sec else None
            table_size = table_sec['sh_size'] if table_sec else 0
            def read_func_data(addr, size):
                for seg in elf.iter_segments():
                    if seg['p_type'] == 'PT_LOAD' and seg['p_vaddr'] <= addr < seg['p_vaddr'] + seg['p_filesz']:
                        offset = addr - seg['p_vaddr'] + seg['p_offset']
                        with open(executable_path, 'rb') as f:
                            f.seek(offset)
                            return f.read(size)
                return b'\x00' * size

    if key_offset is None or hash_offset is None or table_offset is None:
        print("[!] Error: One or more .ic sections missing or invalid.")
        return

    if key_offset == 0 or hash_offset == 0 or table_offset == 0:
        print("[!] FATAL: One of the section offsets is 0.")
        return

    master_key = os.urandom(32)
    encrypted_text_hash = encrypt_hash(master_key, text_hash, aad=text_section_aad)
    packed_entries = []
    for info in valid_funcs_info:
        func_data = read_func_data(info['addr'], info['size'])
        func_hash = blake3(func_data).digest()
        
        # [FIX] 关键修改：如果是 PE 文件，将 VA 转换为 RVA 存储
        stored_addr = info['addr']
        if is_pe:
            stored_addr = info['addr'] - pe.OPTIONAL_HEADER.ImageBase
            if debug: print(f"[DEBUG] Converted VA 0x{info['addr']:x} to RVA 0x{stored_addr:x} for {info['name']}")

        aad_data = struct.pack('<QQ', stored_addr, info['size'])
        enc_func_hash = encrypt_hash(master_key, func_hash, aad=aad_data)
        
        entry = struct.pack(f'<QQ{ENCRYPTED_HASH_SIZE}s', stored_addr, info['size'], enc_func_hash)
        packed_entries.append(entry)

    final_blob = b''.join(packed_entries) + (b'\x00' * FUNC_INFO_SIZE)
    table_aad = blake3(encrypted_text_hash).digest()
    encrypted_table = encrypt_blob(master_key, final_blob, aad=table_aad)
    if len(encrypted_table) > table_size:
        print(f"[!] FATAL: Table section too small. Need {len(encrypted_table)}, have {table_size}.")
        return
    
    # [IMPORTANT] 在写入文件之前，必须关闭 PE 对象，否则后续的 PE 更新会覆盖掉写入的密钥
    if pe:
        pe.close()

    with open(executable_path, 'r+b') as f:
        f.seek(key_offset)
        f.write(master_key)
        f.seek(hash_offset)
        f.write(encrypted_text_hash)
        f.seek(table_offset)
        f.write(encrypted_table)
    print("[+] Integrity checks activated successfully.")

    # [NEW] 安全地更新 PE 校验和
    # 必须重新加载 PE 文件，这样它才能看到刚才写入的密钥
    if is_pe:
        try:
            print("[*] Updating PE Checksum...")
            pe_final = pefile.PE(executable_path)
            pe_final.OPTIONAL_HEADER.CheckSum = pe_final.generate_checksum()
            pe_final.write(executable_path)
            pe_final.close()
            print("[+] PE Checksum updated successfully.")
        except Exception as e:
            print(f"[!] Warning: Failed to update PE Checksum: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Activates integrity checks.")
    parser.add_argument("executable", help="Path to the executable.")
    parser.add_argument("--debug", action="store_true", help="Enable debug output.")
    args = parser.parse_args()
    if os.path.exists(args.executable):
        main(args.executable, args.debug)
    else:
        print("File not found.")