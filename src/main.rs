#![windows_subsystem = "windows"]

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    jewish::run_collector().await
}
