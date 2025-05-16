use std::path::Path;
use std::process;

use chrono::Local;
use clap::Parser;
use dotenv;

use address_finder::{
    Args, KeyPair, PublicAddressEntry, Results, KeystoreResults,
    create_rule, print_search_info, get_password,
    ensure_output_dir, generate_filename, find_addresses_parallel,
    generate_keystore, save_results
};

fn main() {
    // Load environment variables from .env file if it exists
    dotenv::dotenv().ok();

    // Parse command line arguments
    let args = Args::parse();

    // Create a rule string for the filename
    let rule = create_rule(&args.prefix, &args.suffix);

    // Print information about the search
    print_search_info(&args.prefix, &args.suffix, args.count);

    // Ensure output directory exists
    if let Err(e) = ensure_output_dir(&args.output_dir) {
        eprintln!("Error creating output directory: {}", e);
        process::exit(1);
    }

    // Determine keystore directory if keystore option is enabled
    let keystore_dir = if args.keystore {
        let dir = args.keystore_dir.clone().unwrap_or_else(|| format!("{}/keystore", args.output_dir));
        if let Err(e) = ensure_output_dir(&dir) {
            eprintln!("Error creating keystore directory: {}", e);
            process::exit(1);
        }
        Some(dir)
    } else {
        None
    };

    // Get password if keystore option is enabled
    let password = if args.keystore {
        match get_password() {
            Ok(pwd) => Some(pwd),
            Err(e) => {
                eprintln!("Error getting password: {}", e);
                process::exit(1);
            }
        }
    } else {
        None
    };

    // Generate the output filename for JSON results
    let filename = generate_filename(&args.output_dir, &rule);

    // Initialize results based on whether keystore mode is enabled
    let timestamp = Local::now().to_rfc3339();

    let mut standard_results = if !args.keystore {
        Some(Results {
            timestamp: timestamp.clone(),
            rule: rule.clone(),
            key_pairs: Vec::new(),
        })
    } else {
        None
    };

    let mut keystore_results = if args.keystore {
        Some(KeystoreResults {
            timestamp,
            rule: rule.clone(),
            addresses: Vec::new(),
        })
    } else {
        None
    };

    // Find matching addresses in parallel
    println!("Searching for addresses with {} CPU threads...", args.threads);
    let found_addresses = find_addresses_parallel(
        args.count,
        &args.prefix,
        &args.suffix,
        args.threads
    );

    // Process the found addresses
    for found in found_addresses {
        let private_key = found.private_key;
        let address = found.address;
        let private_key_hex = hex::encode(private_key.secret_bytes());

        // If not in keystore mode, add private key to results
        if let Some(results) = &mut standard_results {
            results.key_pairs.push(KeyPair {
                private_key: private_key_hex.clone(),
                public_address: address.clone(),
            });
        }

        // Generate keystore file if requested
        if args.keystore {
            if let (Some(dir), Some(pwd)) = (&keystore_dir, &password) {
                // Convert hex private key back to bytes
                let private_key_bytes = match hex::decode(&private_key_hex) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        eprintln!("Error decoding private key: {}", e);
                        process::exit(1);
                    }
                };

                // Generate keystore file
                match generate_keystore(&private_key_bytes, pwd, Path::new(dir), &address) {
                    Ok(path) => {
                        println!("Keystore file created: {}", path.display());

                        // Add to keystore results
                        if let Some(keystore_results) = &mut keystore_results {
                            keystore_results.addresses.push(PublicAddressEntry {
                                public_address: address.clone(),
                                keystore_file: path.display().to_string(),
                            });
                        }
                    },
                    Err(e) => {
                        eprintln!("Error creating keystore file: {}", e);
                        process::exit(1);
                    }
                }
            }
        }
    }

    // Save results to JSON file
    if let Err(e) = save_results(&filename, &standard_results, &keystore_results) {
        eprintln!("{}", e);
        process::exit(1);
    }
}
