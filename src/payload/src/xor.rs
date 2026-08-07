//! AES-256-GCM string decryption for the payload DLL.
//! All plaintext strings are encrypted at build-time (payload/build.rs).
//! This module re-exports the generated helpers.

#![allow(dead_code)]

mod payload_aes_strings {
    include!(concat!(env!("OUT_DIR"), "/payload_aes_strings.rs"));
}

pub use payload_aes_strings::{aes_dec, aes_str};
pub use payload_aes_strings::*;
