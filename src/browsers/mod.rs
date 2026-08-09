pub mod chromium;
pub mod gecko;
pub mod common;

/// Merge newer extraction results, keeping the version with more cookie lines.
pub fn merge_files(all_files: &mut Vec<(String, String)>, new_files: Vec<(String, String)>) {
    for (name, content) in new_files {
        let cookie_lines = |s: &str| {
            s.lines().filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#')
            }).count()
        };
        if let Some(existing) = all_files.iter_mut().find(|(n, _)| n == &name) {
            if cookie_lines(&content) > cookie_lines(&existing.1) {
                existing.1 = content;
            }
        } else {
            all_files.push((name, content));
        }
    }
    common::zipp::sort_entries(all_files);
}
