use serde::{Deserialize, Serialize};
use secp256k1::SecretKey;

/// Represents a key pair with private key and public address
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyPair {
    pub private_key: String,
    pub public_address: String,
}

/// Represents a public address entry with keystore file path
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PublicAddressEntry {
    pub public_address: String,
    pub keystore_file: String,
}

/// Represents the results with private keys
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Results {
    pub timestamp: String,
    pub rule: String,
    pub key_pairs: Vec<KeyPair>,
}

/// Represents the results without private keys (for keystore mode)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeystoreResults {
    pub timestamp: String,
    pub rule: String,
    pub addresses: Vec<PublicAddressEntry>,
}

/// Structure to hold a found address and its private key
#[derive(Debug)]
pub struct FoundAddress {
    pub private_key: SecretKey,
    pub address: String,
}
