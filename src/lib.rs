pub mod cli;
pub mod crypto;
pub mod finder;
pub mod keystore;
pub mod models;
pub mod utils;

// Re-export commonly used items
pub use cli::{create_rule, get_password, print_search_info, Args};
pub use crypto::{address_matches, generate_private_key, private_key_to_address};
pub use finder::find_addresses_parallel;
pub use keystore::generate_keystore;
pub use models::{FoundAddress, KeyPair, KeystoreResults, PublicAddressEntry, Results};
pub use utils::{ensure_output_dir, generate_filename, save_results};
