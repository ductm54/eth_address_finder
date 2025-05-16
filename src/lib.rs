pub mod models;
pub mod crypto;
pub mod cli;
pub mod keystore;
pub mod finder;
pub mod utils;

// Re-export commonly used items
pub use models::{KeyPair, PublicAddressEntry, Results, KeystoreResults, FoundAddress};
pub use crypto::{generate_private_key, private_key_to_address, address_matches};
pub use cli::{Args, get_password, create_rule, print_search_info};
pub use keystore::generate_keystore;
pub use finder::find_addresses_parallel;
pub use utils::{ensure_output_dir, generate_filename, save_results};
