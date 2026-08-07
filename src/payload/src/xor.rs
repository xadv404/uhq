#![allow(dead_code)]

pub const KEY: u8 = 0x5A;

fn hex_char(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

pub fn from_hex(hex: &str) -> Vec<u8> {
    let bytes = hex.as_bytes();
    let mut result = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() - 1 {
        result.push((hex_char(bytes[i]) << 4) | hex_char(bytes[i + 1]));
        i += 2;
    }
    result
}

pub fn decode(s: &str) -> String {
    let obf = from_hex(s);
    String::from_utf8(obf.into_iter().map(|b| b ^ KEY).collect()).unwrap_or_default()
}

