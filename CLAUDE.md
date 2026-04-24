# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- Build release binary: `cargo build --release` (binary lands at `target/release/address_finder`)
- Run locally: `cargo run -- --prefix abc --suffix def --count 5 --threads 4` (use `--threads 0` for all cores)
- Tests: `cargo test --verbose` — CI runs this, so keep it green
- Format check: `cargo fmt --all -- --check` (CI-enforced)
- Lint: `cargo clippy --all-targets --all-features -- -D warnings` (CI treats warnings as errors — no `#[allow]` drive-bys)
- Toolchain: pinned to Rust `1.88.0` via `dtolnay/rust-toolchain@1.88.0` in CI; match this locally to avoid spurious lints
- `.env` in the project root is auto-loaded via `dotenv` — same `ETH_*` keys as the CLI flags

## Architecture

Binary crate (`src/main.rs`) + library crate (`src/lib.rs`) sharing the same `address_finder` package. The library re-exports the public surface from each module so `main.rs` imports everything from the crate root rather than from submodules. New public items need a corresponding re-export in `src/lib.rs` to keep this pattern consistent.

Module responsibilities:
- `cli` — `clap` `Args` struct, password prompt (`rpassword`), rule-string formatting. Each arg is wired to both a short/long flag and an `ETH_*` env var; keep those in sync if you add options.
- `crypto` — key generation (`secp256k1` + `OsRng`), address derivation (Keccak-256 over the uncompressed pubkey minus its leading `0x04` byte, last 20 bytes), and case-insensitive prefix/suffix matching.
- `finder` — the hot loop. `find_addresses_parallel` builds a `rayon` global thread pool (`ThreadPoolBuilder::build_global`, which can only be called **once per process**), spawns a progress thread that prints via `\r`, and has each worker loop generating keys until a shared `Mutex<usize>` counter hits the target. Because `build_global` is one-shot, tests that touch this function cannot run in the same process twice.
- `keystore` — wraps `eth_keystore::encrypt_key` and names the output `UTC--<timestamp>--<address>`. Note: the function returns the custom path, but `eth_keystore` actually writes using the filename passed as the `Some(file_name)` arg; the rename comment in the source is misleading.
- `models` — serde structs. Two result shapes: `Results` (includes private keys) and `KeystoreResults` (only addresses + keystore file paths). Keystore mode deliberately omits private keys from JSON.
- `utils` — output-directory creation, timestamped filename generation, and JSON serialization that picks between the two result shapes.

Control flow in `main.rs`: parse args → create rule → optionally prompt for password and create keystore dir → initialize exactly one of the two result structs (keyed off `args.keystore`) → call `find_addresses_parallel` → iterate found addresses, writing either plain key pairs or encrypted keystore files → serialize to `results/eth_addresses_<timestamp>_<rule>.json`. The mutually-exclusive `standard_results` / `keystore_results` Options are the main branching invariant.

## Conventions specific to this repo

- Default thread count is `1`, not `num_cpus::get()`. `--threads 0` is the sentinel for "use all cores."
- Prefix/suffix matching is case-insensitive and strips `0x` before comparing; preserve this if you touch `crypto::address_matches`.
- Errors from `main.rs` use `eprintln!` + `process::exit(1)` rather than `?` / `anyhow`. The library modules return `Result<_, String>` for user-facing errors; keep that style when extending.
- CI builds on Ubuntu, Windows, and macOS — avoid Unix-only path handling.
