import struct, sys

exe_path = r'C:\Users\Administrator\Desktop\final - Copy\release\a96tes3m.exe'
with open(exe_path, 'rb') as f:
    data = f.read()

e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
sig = struct.unpack_from('<I', data, e_lfanew)[0]
if sig != 0x4550:
    print('Not a valid PE')
    sys.exit(1)

opt_offset = e_lfanew + 24
magic = struct.unpack_from('<H', data, opt_offset)[0]
is_64 = magic == 0x20B
if is_64:
    num_rva = struct.unpack_from('<I', data, opt_offset + 108)[0]
    import_rva = struct.unpack_from('<I', data, opt_offset + 120)[0]
    import_size = struct.unpack_from('<I', data, opt_offset + 124)[0]
else:
    num_rva = struct.unpack_from('<I', data, opt_offset + 92)[0]
    import_rva = struct.unpack_from('<I', data, opt_offset + 104)[0]
    import_size = struct.unpack_from('<I', data, opt_offset + 108)[0]

print(f'PE Type: {"PE32+" if is_64 else "PE32"}')
print(f'Import Table RVA: {hex(import_rva)}, Size: {import_size}')

num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
opt_size_field = struct.unpack_from('<H', data, e_lfanew + 20)[0]
first_sec_offset = e_lfanew + 24 + opt_size_field

def rva_to_offset(rva):
    for i in range(num_sections):
        sec = first_sec_offset + i * 40
        vsize = struct.unpack_from('<I', data, sec + 8)[0]
        va = struct.unpack_from('<I', data, sec + 12)[0]
        raw_size = struct.unpack_from('<I', data, sec + 16)[0]
        raw_ptr = struct.unpack_from('<I', data, sec + 20)[0]
        if va <= rva < va + max(vsize, raw_size):
            return raw_ptr + (rva - va)
    return None

if import_rva == 0 or import_size == 0:
    print('No import directory')
    sys.exit(1)

imp_offset = rva_to_offset(import_rva)
if imp_offset is None:
    print('Could not resolve import directory offset')
    sys.exit(1)

print(f'Import Directory file offset: {hex(imp_offset)}')
print()
print('=== IMPORTED DLLs AND FUNCTIONS ===')

idx = 0
while True:
    desc_off = imp_offset + idx * 20
    if desc_off + 20 > len(data):
        break
    orig_thunk_rva = struct.unpack_from('<I', data, desc_off)[0]
    name_rva = struct.unpack_from('<I', data, desc_off + 12)[0]
    first_thunk_rva = struct.unpack_from('<I', data, desc_off + 16)[0]

    if name_rva == 0 and orig_thunk_rva == 0 and first_thunk_rva == 0:
        break

    name_off = rva_to_offset(name_rva)
    if name_off:
        name = b''
        while name_off < len(data) and data[name_off] != 0:
            name += bytes([data[name_off]])
            name_off += 1
        dll_name = name.decode('ascii', errors='replace')

        print(f'\n--- {dll_name} ---')

        thunk_rva = orig_thunk_rva if orig_thunk_rva != 0 else first_thunk_rva
        thunk_off = rva_to_offset(thunk_rva)
        if thunk_off is None:
            print('  (could not resolve thunks)')
            idx += 1
            continue

        while True:
            if is_64:
                if thunk_off + 8 > len(data): break
                thunk_val = struct.unpack_from('<Q', data, thunk_off)[0]
                thunk_off += 8
            else:
                if thunk_off + 4 > len(data): break
                thunk_val = struct.unpack_from('<I', data, thunk_off)[0]
                thunk_off += 4

            if thunk_val == 0:
                break

            is_ordinal = (thunk_val & 0x8000000000000000) != 0 if is_64 else (thunk_val & 0x80000000) != 0
            if is_ordinal:
                ordinal = thunk_val & 0xFFFF
                print(f'  ordinal #{ordinal}')
            else:
                hint_name_rva = thunk_val & 0x7FFFFFFFFFFFFFFF if is_64 else thunk_val & 0x7FFFFFFF
                hn_off = rva_to_offset(hint_name_rva)
                if hn_off and hn_off + 2 < len(data):
                    hint = struct.unpack_from('<H', data, hn_off)[0]
                    func_name = b''
                    fn_off = hn_off + 2
                    while fn_off < len(data) and data[fn_off] != 0:
                        func_name += bytes([data[fn_off]])
                        fn_off += 1
                    print(f'  {func_name.decode("ascii", errors="replace")}')
                else:
                    print(f'  (unresolvable rva={hex(thunk_val)})')

    idx += 1
