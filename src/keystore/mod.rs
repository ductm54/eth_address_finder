use chrono::Local;
use rand;
use std::path::{Path, PathBuf};

/// Generate keystore file for a private key
pub fn generate_keystore(
    private_key: &[u8],
    password: &str,
    keystore_dir: &Path,
    address: &str,
) -> Result<PathBuf, String> {
    // Create keystore directory if it doesn't exist
    if !keystore_dir.exists() {
        std::fs::create_dir_all(keystore_dir)
            .map_err(|e| format!("Failed to create keystore directory: {e}"))?;
    }

    // Generate a timestamp for the filename
    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();

    // Extract address without 0x prefix for the filename
    let clean_address = address.strip_prefix("0x").unwrap_or(address);

    // Generate a custom filename with timestamp and address
    let filename = format!("UTC--{timestamp}--{clean_address}");

    // Get a mutable reference to a random number generator
    let mut rng = rand::thread_rng();

    // Encrypt the private key and save as keystore file
    let file_name = filename.as_str();
    let _uuid = eth_keystore::encrypt_key(
        keystore_dir,
        &mut rng,
        private_key,
        password,
        Some(file_name),
    )
    .map_err(|e| format!("Failed to create keystore file: {e}"))?;

    // The keystore file is saved with the UUID as the filename, but we want to use our custom filename
    // So we need to rename it
    let keystore_path = keystore_dir.join(filename);

    Ok(keystore_path)
}
