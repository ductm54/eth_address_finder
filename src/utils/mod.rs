use chrono::Local;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use crate::models::{KeystoreResults, Results};

/// Create output directory if it doesn't exist
pub fn ensure_output_dir(dir: &str) -> std::io::Result<()> {
    if !Path::new(dir).exists() {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

/// Generate a filename with timestamp and rule
pub fn generate_filename(dir: &str, rule: &str) -> String {
    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    format!("{dir}/eth_addresses_{timestamp}_{rule}.json")
}

/// Save results to a JSON file
pub fn save_results(
    filename: &str,
    results: &Option<Results>,
    keystore_results: &Option<KeystoreResults>,
) -> Result<(), String> {
    match File::create(filename) {
        Ok(mut file) => {
            // Serialize the appropriate results structure
            let json = if let Some(keystore_results) = keystore_results {
                match serde_json::to_string_pretty(keystore_results) {
                    Ok(json) => json,
                    Err(e) => return Err(format!("Error serializing keystore results: {e}")),
                }
            } else if let Some(results) = results {
                match serde_json::to_string_pretty(results) {
                    Ok(json) => json,
                    Err(e) => return Err(format!("Error serializing results: {e}")),
                }
            } else {
                return Err("No results to save".to_string());
            };

            // Write the JSON to the file
            if let Err(e) = file.write_all(json.as_bytes()) {
                return Err(format!("Error writing to file: {e}"));
            }

            println!("Results saved to {filename}");
            Ok(())
        }
        Err(e) => Err(format!("Error creating file: {e}")),
    }
}
