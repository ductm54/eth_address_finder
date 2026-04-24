use num_cpus;
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::crypto::{address_to_hex, IncrementalKeygen, MatchRule};
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
    prefix: &Option<Vec<String>>,
    suffix: &Option<Vec<String>>,
    threads: usize,
) -> Vec<FoundAddress> {
    let thread_count = if threads > 0 {
        threads
    } else {
        num_cpus::get()
    };

    // Use a local pool so callers can invoke this more than once per process
    // (e.g. tests, benchmarks, or library consumers). `build_global` is a
    // one-shot and would panic on the second call.
    let pool = ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .expect("failed to build rayon thread pool");

    let found_addresses = Arc::new(Mutex::new(Vec::with_capacity(count)));
    let found_count = Arc::new(AtomicUsize::new(0));
    let total_checked = Arc::new(AtomicU64::new(0));

    let start_time = Instant::now();

    println!("Using {thread_count} CPU threads for parallel processing");

    let progress_found_count = Arc::clone(&found_count);
    let progress_total_checked = Arc::clone(&total_checked);
    let progress_start_time = start_time;
    let progress_handle = thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(500));
        let found = progress_found_count.load(Ordering::Relaxed);
        if found >= count {
            break;
        }
        let checked = progress_total_checked.load(Ordering::Relaxed);
        let elapsed = progress_start_time.elapsed();
        let speed = if elapsed.as_secs() > 0 {
            checked as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        let time_str = format_duration(elapsed);
        print!("\rProgress: {found} found, {checked} checked, {speed:.0} addr/sec, {time_str}");
        io::stdout().flush().unwrap();
    });

    let prefixes: &[String] = prefix.as_deref().unwrap_or(&[]);
    let suffixes: &[String] = suffix.as_deref().unwrap_or(&[]);
    let rule = match MatchRule::new(prefixes, suffixes) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Invalid prefix/suffix: {e}");
            // Preserve prior behavior of returning an empty set on bad input
            // rather than panicking; main() will save an empty result file.
            return Vec::new();
        }
    };

    // Re-seed each thread's incremental iterator every RESEED_AFTER candidates
    // so that a thread that explored a long dead-end region eventually jumps
    // to a fresh random starting point. Without this, the search is biased
    // toward the neighbourhood of the initial key and could get stuck in a
    // bad area for hard targets. A batch of ~1M keys takes a few seconds at
    // our throughput, so the amortized cost of the reseed scalar-mult is
    // negligible.
    const RESEED_AFTER: u64 = 1_000_000;

    pool.install(|| {
        (0..thread_count).into_par_iter().for_each(|_| {
            let mut kg = IncrementalKeygen::new();
            let mut since_reseed: u64 = 0;
            loop {
                if found_count.load(Ordering::Relaxed) >= count {
                    break;
                }

                let address_bytes = kg.address_bytes();
                total_checked.fetch_add(1, Ordering::Relaxed);

                if rule.matches(&address_bytes) {
                    // Reserve a slot before doing any real work so the final
                    // length of `found_addresses` is exactly `count`.
                    let slot = found_count.fetch_add(1, Ordering::Relaxed);
                    if slot >= count {
                        // Another thread already filled the last slot.
                        found_count.fetch_sub(1, Ordering::Relaxed);
                        break;
                    }
                    let private_key = kg.secret();
                    let address = address_to_hex(&address_bytes);
                    let mut found_vec = found_addresses.lock().unwrap();
                    found_vec.push(FoundAddress {
                        private_key,
                        address: address.clone(),
                    });
                    print!("\r");
                    println!(
                        "Found matching address: {} ({}/{})",
                        address,
                        slot + 1,
                        count
                    );
                }

                kg.advance();
                since_reseed += 1;
                if since_reseed >= RESEED_AFTER {
                    kg = IncrementalKeygen::new();
                    since_reseed = 0;
                }
            }
        });
    });

    progress_handle.join().unwrap();

    print!("\r");
    let final_checked = total_checked.load(Ordering::Relaxed);
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

    Arc::try_unwrap(found_addresses)
        .expect("There should be no more references to the found_addresses")
        .into_inner()
        .expect("Mutex should not be poisoned")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_exactly_count_with_trivial_predicate() {
        // Prefix "0" matches ~1/16 of addresses, so this completes quickly
        // but still exercises the real hot loop and the race-resolution
        // around the last slot.
        let found = find_addresses_parallel(5, &Some(vec!["0".to_string()]), &None, 4);
        assert_eq!(
            found.len(),
            5,
            "expected exactly 5 results, got {}",
            found.len()
        );
        for f in &found {
            let addr = f.address.strip_prefix("0x").unwrap();
            assert!(
                addr.starts_with('0'),
                "address {} does not start with prefix 0",
                f.address
            );
        }
    }
}
