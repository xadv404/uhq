use rand::Rng;

#[allow(dead_code)]
pub fn get_dynamic_key() -> u64 {
    let proc_id = std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_default();
    let username = std::env::var("USERNAME").unwrap_or_default();
    let combined = format!("{}{}", proc_id, username);
    let mut key: u64 = 0x9E3779B97F4A7C15;
    for b in combined.bytes() {
        key = key.wrapping_mul(0x6C62272E07BB0142).wrapping_add(b as u64);
    }
    key
}

#[allow(dead_code)]
pub fn sleep_jitter(base_ms: u64, jitter_ms: u64) {
    let mut rng = rand::thread_rng();
    let jitter = rng.gen_range(0..jitter_ms);
    std::thread::sleep(std::time::Duration::from_millis(base_ms + jitter));
}

#[allow(dead_code)]
pub fn detect_debugger() -> bool {
    let start = std::time::Instant::now();
    let mut dummy: u64 = 0;
    for i in 0..50000 {
        dummy = dummy.wrapping_add(i);
    }
    let elapsed = start.elapsed();
    elapsed.as_micros() > 8000
}
