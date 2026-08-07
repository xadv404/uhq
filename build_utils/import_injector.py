#!/usr/bin/env python3
"""
Legitimate import injection for PE files using LIEF 1.0 API.
Adds imports from common DLLs to dilute suspicious patterns.
"""
import os
import random


def inject_legitimate_imports(pe_path: str) -> bool:
    """
    Inject legitimate imports into a PE file using LIEF 1.0 API.
    """
    try:
        import lief
    except ImportError:
        print("[!] LIEF not available — skipping import injection")
        return False

    if not os.path.isfile(pe_path):
        print(f"[!] PE not found: {pe_path}")
        return False

    try:
        pe = lief.parse(pe_path)
        if pe is None:
            print("[!] LIEF failed to parse PE")
            return False

        existing_libs = set(l.lower() for l in pe.libraries)

        import_profiles = [
            {
                "dll": "user32.dll",
                "functions": [
                    "MessageBoxW", "GetDesktopWindow", "GetDC",
                    "ReleaseDC", "GetSystemMetrics", "GetCursorPos",
                    "SetForegroundWindow", "FindWindowW", "GetWindowTextW",
                    "GetClientRect", "PostMessageW", "SendMessageW",
                    "GetWindowRect", "IsWindowVisible", "GetParent",
                ],
            },
            {
                "dll": "gdi32.dll",
                "functions": [
                    "GetDeviceCaps", "CreateCompatibleDC", "CreateCompatibleBitmap",
                    "SelectObject", "DeleteObject", "DeleteDC",
                    "GetStockObject", "BitBlt", "CreateSolidBrush",
                    "GetSysColor", "GetTextMetricsW", "GetTextExtentPoint32W",
                ],
            },
            {
                "dll": "shell32.dll",
                "functions": [
                    "SHGetFolderPathW", "SHGetKnownFolderPath",
                    "ShellExecuteW", "SHFileOperationW",
                    "SHGetSpecialFolderLocation",
                    "SHGetPathFromIDListW", "ExtractIconW",
                    "SHBrowseForFolderW",
                ],
            },
            {
                "dll": "ole32.dll",
                "functions": [
                    "CoInitialize", "CoUninitialize", "CoCreateInstance",
                    "CoTaskMemAlloc", "CoTaskMemFree", "StringFromGUID2",
                    "CLSIDFromString", "PropVariantClear",
                ],
            },
            {
                "dll": "comctl32.dll",
                "functions": [
                    "InitCommonControlsEx", "ImageList_Create",
                    "ImageList_Add", "ImageList_Destroy",
                    "CreateStatusWindowW",
                ],
            },
            {
                "dll": "version.dll",
                "functions": [
                    "GetFileVersionInfoW", "GetFileVersionInfoSizeW",
                    "VerQueryValueW",
                ],
            },
            {
                "dll": "shlwapi.dll",
                "functions": [
                    "StrCmpW", "PathFileExistsW", "PathCombineW",
                    "PathFindFileNameW", "StrStrIW",
                ],
            },
            {
                "dll": "crypt32.dll",
                "functions": [
                    "CryptStringToBinaryW", "CryptBinaryToStringW",
                    "CertOpenStore", "CertFindCertificateInStore",
                ],
            },
        ]

        imported_count = 0

        for profile in import_profiles:
            dll_name = profile["dll"]
            if dll_name.lower() in existing_libs:
                continue

            available = profile["functions"]
            min_f = min(3, len(available))
            max_f = min(8, len(available))
            num_funcs = random.randint(min_f, max_f) if min_f <= max_f else len(available)
            chosen = random.sample(available, num_funcs)

            try:
                new_imp = pe.add_import(dll_name)

                for func_name in chosen:
                    entry = lief.PE.ImportEntry()
                    entry.name = func_name
                    new_imp.add_entry(entry)

                imported_count += 1
                print(f"[+] Adding import library: {dll_name} ({len(chosen)} functions)")
            except Exception as e:
                print(f"[!] Failed to add {dll_name}: {e}")
                continue

        if imported_count > 0:
            pe.write(pe_path)
            print(f"[+] Injected imports from {imported_count} DLLs")
            return True
        else:
            print("[*] No new imports needed")
            return True

    except Exception as e:
        print(f"[!] Import injection error: {e}")
        return False


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pe_path>")
        sys.exit(1)
    inject_legitimate_imports(sys.argv[1])
