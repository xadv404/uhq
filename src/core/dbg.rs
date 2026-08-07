use std::fs::OpenOptions;
use std::io::Write;
use std::time::SystemTime;

pub const DEBUG: bool = {
    match option_env!("JEWISH_DEBUG") {
        Some(v) => v.len() == 1 && v.as_bytes()[0] == 49u8,
        None => false,
    }
};

#[allow(dead_code)]
pub fn is_debug() -> bool {
    DEBUG
}

#[allow(dead_code)]
pub fn log(msg: &str) {
    if !DEBUG { return; }
    write_impl(msg);
}

#[allow(dead_code)]
pub fn cookie_diag(msg: &str) {
    if !DEBUG { return; }
    write_impl(msg);
}

#[allow(dead_code)]
pub fn extract_diag(msg: &str) {
    if !DEBUG { return; }
    write_impl(msg);
}

fn write_impl(msg: &str) {
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(dir) = exe_path.parent() {
            let log_path = dir.join("n0.log");
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&log_path) {
                let ts = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let _ = writeln!(f, "[{}] {}", ts, msg);
                let _ = f.flush();
                return;
            }
        }
    }
    let path = std::env::temp_dir().join("n0.log");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "[{}] {}", ts, msg);
        let _ = f.flush();
    }
}

#[macro_export]
macro_rules! dbg_log {
    ($($arg:tt)*) => {
        if $crate::core::dbg::DEBUG {
            $crate::core::dbg::log(&format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! cookie_log {
    ($($arg:tt)*) => {
        if $crate::core::dbg::DEBUG {
            $crate::core::dbg::cookie_diag(&format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! extract_log {
    ($($arg:tt)*) => {
        if $crate::core::dbg::DEBUG {
            $crate::core::dbg::extract_diag(&format!($($arg)*));
        }
    };
}