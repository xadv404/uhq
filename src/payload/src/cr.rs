use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, aead::Aead as _};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const PREFIX_LEN: usize = 3; 

pub fn decrypt_value(encrypted: &[u8], key: &[u8; 32]) -> Result<String, String> {
    // Case 1: v10/v20 format (AES-GCM).
    if encrypted.starts_with(b"v10") || encrypted.starts_with(b"v20") {
    if encrypted.len() < PREFIX_LEN + NONCE_LEN + TAG_LEN {
            return Err(format!("value too short: {} bytes", encrypted.len()));
    }

    let nonce_bytes = &encrypted[PREFIX_LEN..PREFIX_LEN + NONCE_LEN];
    let ciphertext = &encrypted[PREFIX_LEN + NONCE_LEN..];

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "e50")?;

        return String::from_utf8(plaintext).map_err(|_| "e51".into());
}

    // Case 2: Chrome-specific format (like chrome_inner_decrypt in dpflbck.rs).
    if let Some(pt) = chrome_inner_decrypt(encrypted, key) {
        return String::from_utf8(pt).map_err(|_| "e52".into());
}

    // Case 3: Fallback to UTF-8 conversion.
    String::from_utf8(encrypted.to_vec())
        .map_err(|_| "".into())
}

fn chrome_inner_decrypt(encrypted: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    for i in 0..encrypted.len().saturating_sub(61) {
        let flag = encrypted[i];
        if flag != 0x01 && flag != 0x02 && flag != 0x03 {
            continue;
        }
        let iv = &encrypted[i + 1..i + 13];
        let ct_start = i + 13;
        if encrypted.len() < ct_start + 48 {
            continue;
        }
        let ciphertext = &encrypted[ct_start..ct_start + 32];
        let tag = &encrypted[ct_start + 32..ct_start + 48];
        let mut payload = ciphertext.to_vec();
        payload.extend_from_slice(tag);

        let pt = match flag {
            0x01 => aes_gcm_decrypt(key, iv, &payload),
            0x02 => chacha20_decrypt(key, iv, &payload),
            _ => continue,
        };
        if pt.is_some() {
            return pt;
        }
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
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    cipher.decrypt(iv.into(), ciphertext).ok()
}

pub fn hex_fallback(data: &[u8]) -> String {
    format!("[HEX:{}]", data.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

