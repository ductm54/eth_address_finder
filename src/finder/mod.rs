use num_cpus;
use rayon::prelude::*;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::crypto::{address_matches, generate_private_key, private_key_to_address};
use crate::models::FoundAddress;

/// Format duration as hours:minutes:seconds, omitting empty parts
fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

/// Find addresses in parallel
pub fn find_addresses_parallel(
    count: usize,
    prefix: &Option<String>,
    suffix: &Option<String>,
    threads: usize,
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

    // Create a shared counter for total addresses checked
    let total_checked = Arc::new(Mutex::new(0u64));

    // Record start time for speed calculation
    let start_time = Instant::now();
    let start_time_shared = Arc::new(start_time);

    // Process in parallel until we find enough addresses
    println!("Using {thread_count} CPU threads for parallel processing");

    // Clone counters for the progress thread
    let progress_found_count = Arc::clone(&found_count);
    let progress_total_checked = Arc::clone(&total_checked);
    let progress_start_time = Arc::clone(&start_time_shared);

    // Spawn a thread to display progress
    let progress_handle = thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_millis(500)); // Update every 500ms

            let found = {
                let lock = progress_found_count.lock().unwrap();
                *lock
            };

            let checked = {
                let lock = progress_total_checked.lock().unwrap();
                *lock
            };

            if found >= count {
                break;
            }

            let elapsed = progress_start_time.elapsed();
            let speed = if elapsed.as_secs() > 0 {
                checked as f64 / elapsed.as_secs_f64()
            } else {
                0.0
            };

            let time_str = format_duration(elapsed);

            // Use \r to overwrite the current line
            print!("\rProgress: {found} found, {checked} checked, {speed:.0} addr/sec, {time_str}");
            io::stdout().flush().unwrap();
        }
    });

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

            // Increment total checked counter
            {
                let mut checked_lock = total_checked.lock().unwrap();
                *checked_lock += 1;
            }

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
                        address: address.clone(),
                    });

                    // Increment the counter
                    *count_lock += 1;

                    // Clear the progress line and print found address
                    print!("\r");
                    println!(
                        "Found matching address: {} ({}/{})",
                        address, *count_lock, count
                    );
                }

                // If we've found enough, break out of the loop
                if *count_lock >= count {
                    break;
                }
            }
        }
    });

    // Wait for progress thread to finish
    progress_handle.join().unwrap();

    // Clear the progress line and print final stats
    print!("\r");
    let final_checked = {
        let lock = total_checked.lock().unwrap();
        *lock
    };
    let elapsed = start_time.elapsed();
    let final_speed = if elapsed.as_secs() > 0 {
        final_checked as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    let final_time_str = format_duration(elapsed);
    println!(
        "Search completed: {count} addresses found, {final_checked} total checked, {final_speed:.0} addr/sec average, {final_time_str}"
    );

    // Return the found addresses
    Arc::try_unwrap(found_addresses)
        .expect("There should be no more references to the found_addresses")
        .into_inner()
        .expect("Mutex should not be poisoned")
}
