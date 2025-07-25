use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use tiny_keccak::{Hasher, Keccak};

/// Generate a random Ethereum private key
pub fn generate_private_key() -> SecretKey {
    SecretKey::new(&mut OsRng)
}

/// Derive Ethereum address from private key
pub fn private_key_to_address(private_key: &SecretKey) -> String {
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, private_key);

    // Convert to uncompressed public key format and skip the first byte (0x04)
    let public_key_bytes = &public_key.serialize_uncompressed()[1..];

    // Hash the public key using Keccak-256
    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(public_key_bytes);
    keccak.finalize(&mut hash);

    // Take the last 20 bytes of the hash as the Ethereum address
    let address = &hash[12..];

    // Convert to hex string with 0x prefix
    format!("0x{}", hex::encode(address))
}

/// Check if an address matches the given prefix and suffix
pub fn address_matches(address: &str, prefix: &Option<String>, suffix: &Option<String>) -> bool {
    // Remove 0x prefix for comparison
    let addr = address.strip_prefix("0x").unwrap_or(address);

    // Check prefix if specified
    if let Some(prefix_str) = prefix {
        if !addr.to_lowercase().starts_with(&prefix_str.to_lowercase()) {
            return false;
        }
    }

    // Check suffix if specified
    if let Some(suffix_str) = suffix {
        if !addr.to_lowercase().ends_with(&suffix_str.to_lowercase()) {
            return false;
        }
    }

    // If we get here, all specified conditions are met
    true
}
