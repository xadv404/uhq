use std::arch::asm;

use std::ptr;

#[repr(C)]
struct IMAGE_NT_HEADERS64 {
    signature: u32,
    file_header: IMAGE_FILE_HEADER,
    optional_header: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
struct IMAGE_FILE_HEADER {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
struct IMAGE_OPTIONAL_HEADER64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
struct IMAGE_DATA_DIRECTORY {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct IMAGE_EXPORT_DIRECTORY {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
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

pub fn resolve_export(dll_base: *mut u8, export_name: &str) -> Option<*mut u8> {
    unsafe {
        let e_magic = *(dll_base as *const u16);
        let e_lfanew = *(dll_base.add(0x3C) as *const i32);
        if e_magic != 0x5A4D || e_lfanew <= 0 { return None; }
        let nt = dll_base.add(e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt).signature != 0x00004550 { return None; }
        let edir = &(*nt).optional_header.data_directory[0];
        if edir.virtual_address == 0 { return None; }
        let exp = dll_base.add(edir.virtual_address as usize) as *const IMAGE_EXPORT_DIRECTORY;
        let functions = dll_base.add((*exp).address_of_functions as usize) as *const u32;
        let names = dll_base.add((*exp).address_of_names as usize) as *const u32;
        let ordinals = dll_base.add((*exp).address_of_name_ordinals as usize) as *const u16;
        let name_bytes = export_name.as_bytes();
        for i in 0..(*exp).number_of_names {
            let name_ptr = dll_base.add(*names.add(i as usize) as usize);
            let mut matched = true;
            for (j, &b) in name_bytes.iter().enumerate() {
                if *(name_ptr.add(j)) != b { matched = false; break; }
            }
            if matched && *(name_ptr.add(name_bytes.len())) == 0 {
                let ord = *ordinals.add(i as usize) as usize;
                let func_rva = *functions.add(ord);
                return Some(dll_base.add(func_rva as usize));
            }
        }
        None
    }
}
