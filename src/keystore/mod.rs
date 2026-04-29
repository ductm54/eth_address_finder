use chrono::Utc;
use rand;
use std::path::{Path, PathBuf};

pub fn generate_keystore(
    private_key: &[u8],
    password: &str,
    keystore_dir: &Path,
    address: &str,
) -> Result<PathBuf, String> {
    if !keystore_dir.exists() {
        std::fs::create_dir_all(keystore_dir)
            .map_err(|e| format!("Failed to create keystore directory: {e}"))?;
    }

    let clean_address = address.strip_prefix("0x").unwrap_or(address).to_lowercase();

    let timestamp = Utc::now().format("%Y-%m-%dT%H-%M-%S%.9fZ").to_string();
    let filename = format!("UTC--{timestamp}--{clean_address}");

    let mut rng = rand::thread_rng();

    eth_keystore::encrypt_key(
        keystore_dir,
        &mut rng,
        private_key,
        password,
        Some(filename.as_str()),
    )
    .map_err(|e| format!("Failed to create keystore file: {e}"))?;

    let keystore_path = keystore_dir.join(&filename);

    let contents = std::fs::read_to_string(&keystore_path)
        .map_err(|e| format!("Failed to read keystore file: {e}"))?;
    let mut keystore: serde_json::Value =
        serde_json::from_str(&contents).map_err(|e| format!("Failed to parse keystore: {e}"))?;
    keystore
        .as_object_mut()
        .ok_or("Invalid keystore JSON")?
        .insert(
            "address".to_string(),
            serde_json::Value::String(clean_address.clone()),
        );
    let updated = serde_json::to_string(&keystore)
        .map_err(|e| format!("Failed to serialize keystore: {e}"))?;
    std::fs::write(&keystore_path, updated)
        .map_err(|e| format!("Failed to write keystore file: {e}"))?;

    Ok(keystore_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keystore_has_address_field_and_standard_filename() {
        let pk_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let pk_bytes = hex::decode(pk_hex).unwrap();
        let address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

        let dir = std::env::temp_dir().join("ks_test_standard_format");
        let _ = std::fs::remove_dir_all(&dir);

        let path = generate_keystore(&pk_bytes, "testpass", &dir, address).unwrap();

        let fname = path.file_name().unwrap().to_str().unwrap();
        assert!(
            fname.starts_with("UTC--"),
            "filename should start with UTC--"
        );
        assert!(
            fname.contains("--f39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
            "filename should end with lowercase address without 0x"
        );
        let parts: Vec<&str> = fname.splitn(3, "--").collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[1].contains('T'), "timestamp should be ISO 8601");

        let content = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            v["address"].as_str().unwrap(),
            "f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
        assert!(v.get("crypto").is_some());
        assert_eq!(v["version"].as_u64().unwrap(), 3);

        let decrypted = eth_keystore::decrypt_key(&path, "testpass").unwrap();
        assert_eq!(decrypted, pk_bytes);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
