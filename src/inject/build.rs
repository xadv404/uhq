use std::{env, fs, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));

    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut h = DefaultHasher::new();
    env::var("CARGO_PKG_VERSION").unwrap_or_default().hash(&mut h);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .hash(&mut h);
    std::process::id().hash(&mut h);
    let salt = h.finish() as u32;

    fs::write(
        out_dir.join("api_hash_salt.rs"),
        format!("pub const HASH_SALT: u32 = 0x{:08X};\n", salt),
    )
    .expect("write api_hash_salt.rs");
}
