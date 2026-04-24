# Hot-path benchmarks

Machine-specific numbers. Re-run after each optimization phase with `cargo bench --bench hot_path -- --quick`. All numbers are the median of the three reported by criterion.

Throughput = `1 / pipeline_single` on a single thread.

| phase | keygen | derive | match_reject | match_accept | pipeline_single | single-thread addr/sec |
|------|-------:|-------:|-------------:|-------------:|----------------:|-----------------------:|
| baseline (before any fix) | 471 ns | 30.16 µs | 73.3 ns | 73.7 ns | 34.10 µs | ~29,300 |
| + phase 1 (thread-local secp ctx) | 414 ns | 31.37 µs | 70.7 ns | 62.7 ns | 35.30 µs | ~28,300 |
| + phase 2+3 (atomics + local pool) | 457 ns | 29.92 µs | 76.6 ns | 63.7 ns | 29.41 µs | ~34,000 |
| + phase 4 (byte matching, hot path) | 431 ns | 28.92 µs (`derive_bytes`) | 3.04 ns (`rule_reject`) | — | 30.19 µs (`pipeline_single_bytes`) | ~33,100 |
| + phase 7 (incremental point addition) | — | — | 1.72 ns (`rule_reject`) | — | **3.79 µs** (`pipeline_incremental`) | **~264,000** |

### Multi-threaded throughput (after phase 7)

`pipeline_multi_incremental` seeds one `IncrementalKeygen` per thread, then runs 65,536 / N iterations per thread.

| threads | throughput (addr/s) | vs t=1 pre-phase-7 (32.4k) | vs t=1 post-phase-7 |
|--------:|--------------------:|---------------------------:|--------------------:|
| 1 | 251,500 | 7.8× | 1.00× |
| 2 | 463,800 | 14.3× | 1.84× |
| 4 | 730,700 | 22.5× | 2.91× |
| 8 | 770,200 | 23.7× | 3.06× (4-core box, oversubscribed) |

### Multi-threaded throughput (after phase 2+3)

`pipeline_multi` batches 4096 candidates across N threads on a 4-core box.

| threads | throughput (addr/s) | vs t=1 |
|--------:|--------------------:|-------:|
| 1 | 32,440 | 1.00× |
| 2 | 58,400 | 1.80× |
| 4 | 96,900 | 2.99× |
| 8 | 120,200 | 3.70× (oversubscribed on 4 cores) |

## Notes on interpretation

- `derive` dwarfs `keygen` by ~64× — confirms the address derivation path is the bottleneck.
- `match_reject` vs `match_accept` costs the same (both do two `to_lowercase()` allocations regardless of branch).
- `pipeline_single` ≈ `keygen + derive + match_reject`, confirming the hot loop has no other hidden cost.
- **Phase 1 finding:** caching the `Secp256k1<SignOnly>` context via `thread_local!` did not materially move `derive` (30 → 31 µs is within run-to-run noise). The real cost inside `derive` is the scalar multiplication in `PublicKey::from_secret_key`, not context construction — `secp256k1 0.27` appears to share/cache the generator pre-computation internally. The change is still kept because it removes wasted allocation and matches the thread-local pattern we want for future additions, but it is not the speedup lever we hoped for.
- **Corollary:** the single-threaded ceiling is ≈ `1 / derive` ≈ 33k addr/sec regardless of how much we trim around it. Meaningful speedups have to come from either (a) multi-threading (phases 2+3) or (b) replacing the crypto primitive.
- **Phase 4 finding:** `rule_reject` is 3.0 ns — a 25× speedup over `match_reject` (76 ns), but it saves only ~70 ns on a ~30 µs hot loop (≈0.2%). The `derive` cost is almost entirely scalar multiplication; hex-encoding the 20-byte address adds only ~100 ns (`derive` 28.85 µs vs `derive_bytes` 28.92 µs — within noise). The byte-level API is still worth keeping because it removes per-candidate allocations (helpful at high core counts) and it is the correct shape for phase 7's point-addition loop.
- The back-compat `address_matches(&str, ...)` wrapper is now slower than before because it rebuilds a `MatchRule` per call. That's fine — it's no longer on the hot path.
- **Phase 7 (the real win):** replacing the `SecretKey::new() + PublicKey::from_secret_key()` scalar multiplication with an incremental `P ← P + G` point addition drops the per-key cost from ~30 µs to ~3.8 µs (8× on single-thread). Correctness is covered by `incremental_keygen_matches_fresh_derivation`, which at every step cross-checks the fast path against the slow scalar-mult derivation. End-to-end `cargo run -- --prefix abc ...` output has also been spot-verified against `eth_account.Account.from_key` on an independent machine — the first returned private key derives to exactly the claimed public address.
- The finder re-seeds each thread's incremental iterator every 1,000,000 candidates so the search can't get stuck in an unlucky neighbourhood. At current throughput that reseed happens every few seconds of wall-clock per thread.
