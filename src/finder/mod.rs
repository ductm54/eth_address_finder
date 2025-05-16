use std::sync::{Arc, Mutex};
use rayon::prelude::*;
use num_cpus;

use crate::models::FoundAddress;
use crate::crypto::{generate_private_key, private_key_to_address, address_matches};

/// Find addresses in parallel
pub fn find_addresses_parallel(
    count: usize,
    prefix: &Option<String>,
    suffix: &Option<String>,
    threads: usize
) -> Vec<FoundAddress> {
    // Use the specified number of threads or default to system CPU count
    let thread_count = if threads > 0 {
        threads
    } else {
        num_cpus::get()
    };
    
    // Configure the thread pool
    rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build_global()
        .unwrap();
    
    // Create a shared vector to store results
    let found_addresses = Arc::new(Mutex::new(Vec::new()));
    
    // Create a shared counter for found addresses
    let found_count = Arc::new(Mutex::new(0));
    
    // Process in parallel until we find enough addresses
    println!("Using {} CPU threads for parallel processing", thread_count);
    
    // Each thread will run this closure
    (0..thread_count).into_par_iter().for_each(|_| {
        // Keep generating addresses until we've found enough
        loop {
            // Check if we've already found enough addresses
            {
                let count_lock = found_count.lock().unwrap();
                if *count_lock >= count {
                    break;
                }
            }
            
            // Generate a new private key
            let private_key = generate_private_key();
            
            // Derive the Ethereum address
            let address = private_key_to_address(&private_key);
            
            // Check if the address matches our criteria
            if address_matches(&address, prefix, suffix) {
                // Lock the shared data structures
                let mut found_vec = found_addresses.lock().unwrap();
                let mut count_lock = found_count.lock().unwrap();
                
                // Only add if we still need more addresses
                if *count_lock < count {
                    // Add the found address
                    found_vec.push(FoundAddress {
                        private_key,
                        address,
                    });
                    
                    // Increment the counter
                    *count_lock += 1;
                    
                    // Print progress
                    println!("Found matching address: {} ({}/{})",
                             found_vec.last().unwrap().address,
                             *count_lock,
                             count);
                }
                
                // If we've found enough, break out of the loop
                if *count_lock >= count {
                    break;
                }
            }
        }
    });
    
    // Return the found addresses
    Arc::try_unwrap(found_addresses)
        .expect("There should be no more references to the found_addresses")
        .into_inner()
        .expect("Mutex should not be poisoned")
}
