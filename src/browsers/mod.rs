pub mod chromium;
pub mod gecko;
pub mod common;

use std::panic;

pub fn run() -> Vec<(String, String)> {
    let mut all_files: Vec<(String, String)> = Vec::new();

    let gecko_handle = std::thread::spawn(|| gecko::extract_all());
    let chromium_files = panic::catch_unwind(|| chromium::extract_all()).unwrap_or_default();
    let gecko_files = gecko_handle.join().unwrap_or_default();


    all_files.extend(chromium_files);
    all_files.extend(gecko_files);

    common::zipp::sort_entries(&mut all_files);

    all_files
}
