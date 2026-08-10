// AUTO-GENERATED POLYMORPHIC JUNK - DO NOT EDIT

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use crate::polymorphic_keys::{
    JUNK_A, JUNK_B, JUNK_MAGIC, JUNK_XOR_CONST, JUNK_MUL_BIG, JUNK_LARGE_XOR,
};

static JUNK_COUNTER: AtomicU64 = AtomicU64::new(0);

#[allow(dead_code)]
pub fn junk_calculate() -> u64 {
    let mut acc: u64 = 0;
    for i in 0..10000 {
        acc = acc.wrapping_add(i as u64);
        acc = acc.wrapping_mul(31);
        acc ^= i as u64;
    }
    acc
}

#[allow(dead_code)]
pub fn junk_transform(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    for (i, &b) in data.iter().enumerate() {
        let mut val = b.wrapping_add(i as u8);
        val = val.rotate_left(3);
        val ^= JUNK_XOR_CONST;
        result.push(val);
    }
    result
}

#[allow(dead_code)]
pub fn junk_validate() -> bool {
    let a: u32 = JUNK_A;
    let b: u32 = JUNK_B;
    let c = a ^ b ^ JUNK_MAGIC;
    c != 0
}

#[allow(dead_code)]
pub fn junk_process(x: i32) -> i32 {
    let mut val = x;
    for _ in 0..100 {
        val = val.wrapping_mul(7);
        val = val.wrapping_add(13);
        val ^= JUNK_XOR_CONST as i32;
        val = val.rotate_left(5);
    }
    val
}

#[allow(dead_code)]
pub fn junk_identity() -> u64 {
    // Returns a build-unique value instead of a static recognizable string
    JUNK_A as u64 ^ JUNK_B as u64 ^ JUNK_MAGIC as u64
}

#[allow(dead_code)]
pub fn junk_hashmap_ops() -> u64 {
    let mut map = HashMap::new();
    for i in 0..1000 {
        map.insert(i, i as u64 ^ JUNK_MUL_BIG);
    }
    let mut sum = 0u64;
    for (_, v) in map.iter() {
        sum = sum.wrapping_add(*v);
    }
    sum
}

#[allow(dead_code)]
pub fn junk_crypto_check() -> bool {
    let key = [
        JUNK_XOR_CONST, JUNK_A as u8, (JUNK_A >> 8) as u8, (JUNK_A >> 16) as u8,
        (JUNK_A >> 24) as u8, JUNK_B as u8, (JUNK_B >> 8) as u8, (JUNK_B >> 16) as u8,
    ];
    let data = [0x49u8, 0x6E, 0x74, 0x65, 0x67, 0x72, 0x69, 0x74, 0x79];
    let mut sum = 0u8;
    for (i, &b) in data.iter().enumerate() {
        sum = sum.wrapping_add(b.wrapping_add(key[i % key.len()]));
    }
    sum != 0
}

#[allow(dead_code)]
pub fn junk_bit_manipulation(val: u64) -> u64 {
    let mut result = val;
    for _ in 0..50 {
        result = result.rotate_left(7);
        result ^= JUNK_LARGE_XOR;
        result = result.wrapping_mul(JUNK_MUL_BIG);
    }
    result
}

#[allow(dead_code)]
pub fn junk_string_processing(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    for &b in bytes {
        out.push(b ^ JUNK_XOR_CONST);
        out.push(b.wrapping_add(1));
    }
    String::from_utf8_lossy(&out).to_string()
}

#[allow(dead_code)]
pub fn junk_counter() -> u64 {
    JUNK_COUNTER.fetch_add(1, Ordering::SeqCst)
}

#[allow(dead_code)]
pub fn junk_floating_point() -> f64 {
    let mut acc = 0.0;
    for i in 1..1000 {
        acc += 1.0 / (i as f64 * i as f64);
    }
    acc.sqrt()
}

#[allow(dead_code)]
pub fn junk_matrix_multiply() -> [[u64; 4]; 4] {
    let a = [[1u64, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]];
    let b = [[16u64, 15, 14, 13], [12, 11, 10, 9], [8, 7, 6, 5], [4, 3, 2, 1]];
    let mut c = [[0u64; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            for k in 0..4 {
                c[i][j] = c[i][j].wrapping_add(a[i][k].wrapping_mul(b[k][j]));
            }
        }
    }
    c
}

#[allow(dead_code)]
pub fn junk_prng(seed: u64) -> u64 {
    let mut state = seed.wrapping_add(JUNK_MUL_BIG);
    for _ in 0..100 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
    }
    state
}

#[allow(dead_code)]
pub fn junk_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for &b in data {
        sum = sum.wrapping_add(b as u32);
    }
    (sum & 0xFFFF) as u16 ^ (JUNK_A & 0xFFFF) as u16
}

#[allow(dead_code)]
pub fn junk_base64_simulate(input: &[u8]) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::new();
    for chunk in input.chunks(3) {
        let mut n: u32 = 0;
        n |= (chunk[0] as u32) << 16;
        if chunk.len() > 1 { n |= (chunk[1] as u32) << 8; }
        if chunk.len() > 2 { n |= chunk[2] as u32; }
        output.push(TABLE[((n >> 18) & 0x3F) as usize]);
        output.push(TABLE[((n >> 12) & 0x3F) as usize]);
        if chunk.len() > 1 { output.push(TABLE[((n >> 6) & 0x3F) as usize]); }
        if chunk.len() > 2 { output.push(TABLE[(n & 0x3F) as usize]); }
    }
    output
}
