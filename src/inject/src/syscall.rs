#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::{mem, ptr};
use std::arch::asm;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: *mut std::ffi::c_void,
    pub ObjectName: *mut std::ffi::c_void,
    pub Attributes: u32,
    pub SecurityDescriptor: *mut std::ffi::c_void,
    pub SecurityQualityOfService: *mut std::ffi::c_void,
}

impl OBJECT_ATTRIBUTES {
    pub fn new() -> Self {
        Self {
            Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: ptr::null_mut(),
            ObjectName: ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: ptr::null_mut(),
            SecurityQualityOfService: ptr::null_mut(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CLIENT_ID {
    pub UniqueProcess: *mut std::ffi::c_void,
    pub UniqueThread: *mut std::ffi::c_void,
}

impl CLIENT_ID {
    pub fn new(pid: u32) -> Self {
        Self {
            UniqueProcess: pid as *mut std::ffi::c_void,
            UniqueThread: std::ptr::null_mut(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

impl UNICODE_STRING {
    pub fn new() -> Self {
        Self { Length: 0, MaximumLength: 0, Buffer: ptr::null_mut() }
    }
}

#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub signature: u32,
    pub file_header: IMAGE_FILE_HEADER,
    pub optional_header: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: u32,
}

#[repr(C)]
#[allow(dead_code)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

pub fn get_module_base(name: &str) -> Option<*mut u8> {
    unsafe {
        let peb: *mut u8;
        asm!("mov {}, gs:[0x60]", out(reg) peb);
        let ldr = *(peb.add(0x18) as *const *mut u8);
        let flink = *(ldr.add(0x10) as *const *mut u8);
        let mut entry = flink;
        let head = ldr.add(0x10);
        loop {
            let dll_base = *(entry.add(0x30) as *const *mut u8);
            let name_ptr = *(entry.add(0x60) as *const *mut u16);
            let mut name_buf = [0u16; 16];
            ptr::copy_nonoverlapping(name_ptr, name_buf.as_mut_ptr(), 12);
            let n = String::from_utf16_lossy(&name_buf).to_lowercase();
            if n.contains(&name.to_lowercase()) {
                return Some(dll_base);
            }
            let next = *(entry as *const *mut u8);
            if next == head { break; }
            entry = next;
        }
        None
    }
}

pub fn get_module_base_by_hash(target_hash: u32) -> Option<*mut u8> {
    unsafe {
        let peb: *mut u8;
        asm!("mov {}, gs:[0x60]", out(reg) peb);
        let ldr = *(peb.add(0x18) as *const *mut u8);
        let flink = *(ldr.add(0x10) as *const *mut u8);
        let mut entry = flink;
        let head = ldr.add(0x10);
        loop {
            let dll_base = *(entry.add(0x30) as *const *mut u8);
            let name_ptr = *(entry.add(0x60) as *const *mut u16);
            let mut name_buf = [0u16; 64];
            let mut idx = 0;
            while idx < 64 {
                let c = *name_ptr.add(idx);
                if c == 0 { break; }
                name_buf[idx] = c;
                idx += 1;
            }
            let ascii_buf: Vec<u8> = name_buf[..idx].iter().map(|&c| (c & 0xFF) as u8).collect();
            let mut hash: u32 = 0;
            for &b in &ascii_buf {
                if b == 0 { break; }
                hash = hash.wrapping_mul(31).wrapping_add(b as u32);
            }
            if hash == target_hash {
                return Some(dll_base);
            }
            let next = *(entry as *const *mut u8);
            if next == head { break; }
            entry = next;
        }
        None
    }
}

pub fn resolve_export(dll_base: *mut u8, export_name: &str) -> Option<*mut u8> {
    unsafe {
        let e_magic = core::ptr::read_unaligned(dll_base as *const u16);
        if e_magic != 0x5A4D { return None; }
        let e_lfanew = core::ptr::read_unaligned(dll_base.add(0x3C) as *const i32);
        if e_lfanew <= 0 { return None; }
        let nt = dll_base.add(e_lfanew as usize);
        let sig = core::ptr::read_unaligned(nt as *const u32);
        if sig != 0x00004550 { return None; }
        let file_hdr = nt.add(4);
        let _opt_hdr_size = core::ptr::read_unaligned(file_hdr.add(16) as *const u16) as usize;
        let opt_hdr = nt.add(24);
        let dd0_rva = core::ptr::read_unaligned(opt_hdr.add(112) as *const u32);
        if dd0_rva == 0 { return None; }
        let exp = dll_base.add(dd0_rva as usize);
        let num_funcs = core::ptr::read_unaligned(exp.add(20) as *const u32);
        let num_names = core::ptr::read_unaligned(exp.add(24) as *const u32);
        let addr_funcs_rva = core::ptr::read_unaligned(exp.add(28) as *const u32);
        let addr_names_rva = core::ptr::read_unaligned(exp.add(32) as *const u32);
        let addr_ords_rva = core::ptr::read_unaligned(exp.add(36) as *const u32);
        if num_funcs == 0 || num_names == 0 { return None; }
        if num_funcs > 10000 || num_names > 10000 { return None; }
        let functions = dll_base.add(addr_funcs_rva as usize) as *const u32;
        let names = dll_base.add(addr_names_rva as usize) as *const u32;
        let ordinals = dll_base.add(addr_ords_rva as usize) as *const u16;
        let edir_start = dd0_rva;
        let edir_size = core::ptr::read_unaligned(exp.add(4) as *const u32);
        let edir_end = edir_start + if edir_size > 0 { edir_size } else { 4096 };
        let name_bytes = export_name.as_bytes();
        for i in 0..num_names {
            let name_rva = core::ptr::read_unaligned(names.add(i as usize));
            let name_ptr = dll_base.add(name_rva as usize);
            let mut matched = true;
            for (j, &b) in name_bytes.iter().enumerate() {
                if *(name_ptr.add(j)) != b { matched = false; break; }
            }
            if matched && *(name_ptr.add(name_bytes.len())) == 0 {
                let ord = *ordinals.add(i as usize) as usize;
                if ord >= num_funcs as usize { return None; }
                let func_rva = *functions.add(ord);
                if func_rva >= edir_start && func_rva < edir_end {
                    let fwd_ptr = dll_base.add(func_rva as usize) as *const u8;
                    let mut dot_pos = 0usize;
                    while *fwd_ptr.add(dot_pos) != b'.' && *fwd_ptr.add(dot_pos) != 0 {
                        dot_pos += 1;
                    }
                    if *fwd_ptr.add(dot_pos) == b'.' {
                        let dll_part = core::str::from_utf8_unchecked(
                            core::slice::from_raw_parts(fwd_ptr, dot_pos)
                        );
                        let func_part = core::str::from_utf8_unchecked(
                            core::slice::from_raw_parts(fwd_ptr.add(dot_pos + 1),
                                { let mut e = dot_pos + 1; while *fwd_ptr.add(e) != 0 { e += 1; } e - dot_pos - 1 })
                        );
                        if let Some(fwd_base) = get_module_base(dll_part) {
                            return resolve_export(fwd_base, func_part);
                        }
                        let real_dll = if dll_part.to_lowercase().starts_with("api-ms-win-") {
                            "kernelbase"
                        } else {
                            dll_part
                        };
                        if let Some(fwd_base) = get_module_base(real_dll) {
                            return resolve_export(fwd_base, func_part);
                        }
                    }
                }
                return Some(dll_base.add(func_rva as usize));
            }
        }
        None
    }
}

pub fn resolve_export_by_hash(dll_base: *mut u8, target_hash: u32) -> Option<*mut u8> {
    unsafe {
        let e_magic = core::ptr::read_unaligned(dll_base as *const u16);
        if e_magic != 0x5A4D { return None; }
        let e_lfanew = core::ptr::read_unaligned(dll_base.add(0x3C) as *const i32);
        if e_lfanew <= 0 { return None; }
        let nt = dll_base.add(e_lfanew as usize);
        let sig = core::ptr::read_unaligned(nt as *const u32);
        if sig != 0x00004550 { return None; }
        let opt_hdr = nt.add(24);
        let dd0_rva = core::ptr::read_unaligned(opt_hdr.add(112) as *const u32);
        if dd0_rva == 0 { return None; }
        let exp = dll_base.add(dd0_rva as usize);
        let num_funcs = core::ptr::read_unaligned(exp.add(20) as *const u32);
        let num_names = core::ptr::read_unaligned(exp.add(24) as *const u32);
        let addr_names_rva = core::ptr::read_unaligned(exp.add(32) as *const u32);
        if num_funcs == 0 || num_names == 0 { return None; }
        if num_funcs > 10000 || num_names > 10000 { return None; }
        let addr_funcs_rva = core::ptr::read_unaligned(exp.add(28) as *const u32);
        let addr_ords_rva = core::ptr::read_unaligned(exp.add(36) as *const u32);
        let functions = dll_base.add(addr_funcs_rva as usize) as *const u32;
        let names = dll_base.add(addr_names_rva as usize) as *const u32;
        let ordinals = dll_base.add(addr_ords_rva as usize) as *const u16;
        for i in 0..num_names {
            let name_rva = core::ptr::read_unaligned(names.add(i as usize));
            let name_ptr = dll_base.add(name_rva as usize);
            let mut hash: u32 = 0;
            let mut k = 0;
            loop {
                let b = *name_ptr.add(k);
                if b == 0 { break; }
                hash = hash.wrapping_mul(31).wrapping_add(b as u32);
                k += 1;
            }
            if hash == target_hash {
                let ord = *ordinals.add(i as usize) as usize;
                if ord >= num_funcs as usize { return None; }
                let func_rva = *functions.add(ord);
                return Some(dll_base.add(func_rva as usize));
            }
        }
        None
    }
}
