# Ethereum Address Finder

A Rust application for generating Ethereum private keys and finding addresses with specific prefixes or suffixes.

## Description

This tool generates random Ethereum private keys and derives their corresponding public addresses. It can search for addresses that match specific patterns (prefix and/or suffix) and save the results to a JSON file. Each run creates a new file with a timestamp in the filename.

## Features

- Generate random Ethereum private keys
- Derive Ethereum addresses from private keys
- Search for addresses with specific prefixes or suffixes
- Save results to JSON files with timestamps
- Generate encrypted keystore files for enhanced security
- Parallel processing for faster address generation and matching
- Configure via command-line arguments or environment variables

## Getting Started

### Prerequisites

- Rust (latest stable version)
- Cargo

### Installation

1. Clone the repository
2. Build the project:

```bash
cargo build --release
```

### Running

Basic usage:

```bash
cargo run -- --prefix abc --suffix def --count 5
```

Using multiple CPU cores for faster processing:

```bash
cargo run -- --prefix abc --suffix def --count 5 --threads 4
```

Using all available CPU cores:

```bash
cargo run -- --prefix abc --suffix def --count 5 --threads 0
```

Or using the compiled binary:

```bash
./target/release/address_finder --prefix abc --suffix def --count 5 --threads 4
```

### Command-line Options

- `-p, --prefix <PREFIX>`: Prefix for Ethereum address (without 0x)
- `-s, --suffix <SUFFIX>`: Suffix for Ethereum address (without 0x)
- `-c, --count <COUNT>`: Number of matching addresses to find (default: 1)
- `-o, --output-dir <OUTPUT_DIR>`: Output directory for result files (default: "results")
- `-e, --keystore`: Generate encrypted keystore files for each private key
- `-k, --keystore-dir <KEYSTORE_DIR>`: Directory for keystore files (defaults to output_dir/keystore)
- `-t, --threads <THREADS>`: Number of CPU cores to use for parallel processing (default: 1)

### Environment Variables

You can also use environment variables instead of command-line arguments:

- `ETH_PREFIX`: Prefix for Ethereum address
- `ETH_SUFFIX`: Suffix for Ethereum address
- `ETH_COUNT`: Number of matching addresses to find
- `ETH_OUTPUT_DIR`: Output directory for result files
- `ETH_KEYSTORE`: Set to any value to enable keystore generation
- `ETH_KEYSTORE_DIR`: Directory for keystore files
- `ETH_THREADS`: Number of CPU cores to use for parallel processing

You can create a `.env` file in the project directory with these variables.

## Output

### JSON Output

The program creates JSON files in the specified output directory (default: "results"). Each file contains:

- Timestamp of when the search was performed
- The rule used for the search (prefix/suffix)
- A list of key pairs (private key and public address)

Example output file (normal mode):

```json
{
  "timestamp": "2023-09-20T15:30:45.123456789Z",
  "rule": "prefix_abc_suffix_def",
  "key_pairs": [
    {
      "private_key": "a1b2c3d4e5f6...",
      "public_address": "0xabc...def"
    },
    ...
  ]
}
```

Example output file (keystore mode):

```json
{
  "timestamp": "2023-09-20T15:30:45.123456789Z",
  "rule": "prefix_abc_suffix_def",
  "addresses": [
    {
      "public_address": "0xabc...def",
      "keystore_file": "results/keystore/UTC--20230920153045--abc...def"
    },
    ...
  ]
}
```

### Keystore Files

When the `--keystore` option is enabled, the program will generate encrypted keystore files in the Ethereum keystore format. These files are compatible with most Ethereum wallets and tools.

The keystore files are saved in the specified keystore directory (default: "results/keystore") with filenames that include a timestamp and the public address:

```
UTC--20230920153045--abc123def456...
```

To generate keystore files, use the `--keystore` flag:

```bash
cargo run -- --prefix abc --suffix def --count 1 -e
```

The program will prompt you to enter and confirm a password, which will be used to encrypt the private keys. This password will be required to access the private keys in the future.

**Important Security Feature**: When keystore mode is enabled, the JSON results file will NOT contain any private keys. Instead, it will only include public addresses and references to the keystore files. This enhances security by ensuring private keys are only stored in encrypted form.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
