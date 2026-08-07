use rand::Rng;

pub fn rotating_decrypt(data: &[u8], keys: &[u8], offset: u8, mask: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (i, &b) in data.iter().enumerate() {
        let k = keys[(offset.wrapping_add(i as u8)) as usize % keys.len()];
        out.push(b ^ k ^ mask);
    }
    out
}

pub fn xor_single(data: &[u8], key: u8, mask: u8) -> Vec<u8> {
    data.iter().map(|&b| b ^ key ^ mask).collect()
}

pub fn xor_crypt(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|b| b ^ key).collect()
}

pub fn reverse_decrypt(data: &[u8], key: u8, mask: u8) -> Vec<u8> {
    let k = (key ^ 0x55) & 0xFF;
    data.iter().rev().map(|&b| b ^ k ^ mask).collect()
}

pub fn feistel_decrypt(data: &[u8], key: u8, mask: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut state = key;
    for &b in data {
        state = (state + 0x9E) & 0xFF;
        let k = ((state << 3) | (state >> 5)) & 0xFF;
        out.push(b ^ k ^ mask);
    }
    out
}

#[allow(dead_code)]
pub fn get_dynamic_key() -> u8 {
    let proc_id = std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_default();
    let username = std::env::var("USERNAME").unwrap_or_default();
    let combined = format!("{}{}", proc_id, username);
    let mut key: u8 = 0;
    for b in combined.bytes() {
        key = key.wrapping_add(b);
    }
    if key == 0 { key = 0x5A; }
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
