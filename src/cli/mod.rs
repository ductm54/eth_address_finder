use clap::Parser;
use rpassword;
use std::io;

/// Validate a hex string for use as an address prefix/suffix. Accepts an
/// optional `0x` prefix, normalizes to lowercase, and rejects anything that
/// can't possibly match an Ethereum address.
fn parse_hex_pattern(s: &str) -> Result<String, String> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    if trimmed.is_empty() {
        return Err("empty hex pattern".to_string());
    }
    if trimmed.len() > 40 {
        return Err(format!(
            "hex pattern longer than 40 characters (got {})",
            trimmed.len()
        ));
    }
    for (idx, c) in trimmed.chars().enumerate() {
        if !c.is_ascii_hexdigit() {
            return Err(format!("non-hex character {c:?} at position {idx}"));
        }
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// Command-line arguments for the application
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Prefix for Ethereum address (without 0x)
    #[arg(short, long, env = "ETH_PREFIX", value_parser = parse_hex_pattern)]
    pub prefix: Option<String>,

    /// Suffix for Ethereum address (without 0x)
    #[arg(short, long, env = "ETH_SUFFIX", value_parser = parse_hex_pattern)]
    pub suffix: Option<String>,

    /// Number of matching addresses to find
    #[arg(short, long, default_value = "1", env = "ETH_COUNT")]
    pub count: usize,

    /// Output directory for result files
    #[arg(short, long, default_value = "results", env = "ETH_OUTPUT_DIR")]
    pub output_dir: String,

    /// Generate keystore files instead of plain JSON
    #[arg(short = 'e', long, env = "ETH_KEYSTORE")]
    pub keystore: bool,

    /// Directory for keystore files (defaults to output_dir/keystore if not specified)
    #[arg(short = 'k', long, env = "ETH_KEYSTORE_DIR")]
    pub keystore_dir: Option<String>,

    /// Number of CPU cores to use for parallel processing (defaults to 1)
    #[arg(short = 't', long, default_value_t = 1, env = "ETH_THREADS")]
    pub threads: usize,
}

/// Get password from user with confirmation
pub fn get_password() -> io::Result<String> {
    println!("Enter password for keystore encryption:");
    let password = rpassword::read_password()?;

    if password.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Password cannot be empty",
        ));
    }

    println!("Confirm password:");
    let confirm_password = rpassword::read_password()?;

    if password != confirm_password {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Passwords do not match",
        ));
    }

    Ok(password)
}

/// Create a rule string for the filename based on prefix and suffix
pub fn create_rule(prefix: &Option<String>, suffix: &Option<String>) -> String {
    match (prefix, suffix) {
        (Some(prefix), Some(suffix)) => format!("prefix_{prefix}_suffix_{suffix}"),
        (Some(prefix), None) => format!("prefix_{prefix}"),
        (None, Some(suffix)) => format!("suffix_{suffix}"),
        (None, None) => "no_rule".to_string(),
    }
}

/// Print information about the search criteria
pub fn print_search_info(prefix: &Option<String>, suffix: &Option<String>, count: usize) {
    println!("Ethereum Address Finder");
    println!("Looking for addresses with:");
    if let Some(prefix) = prefix {
        println!("  Prefix: {prefix}");
    }
    if let Some(suffix) = suffix {
        println!("  Suffix: {suffix}");
    }
    println!("Finding {count} matching addresses...");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_pattern_accepts_valid() {
        assert_eq!(parse_hex_pattern("abc").unwrap(), "abc");
        assert_eq!(parse_hex_pattern("0xABC").unwrap(), "abc");
        assert_eq!(
            parse_hex_pattern("0123456789abcdef").unwrap(),
            "0123456789abcdef"
        );
    }

    #[test]
    fn parse_hex_pattern_rejects_non_hex() {
        assert!(parse_hex_pattern("xyz").is_err());
        assert!(parse_hex_pattern("ab z").is_err());
    }

    #[test]
    fn parse_hex_pattern_rejects_empty() {
        assert!(parse_hex_pattern("").is_err());
        assert!(parse_hex_pattern("0x").is_err());
    }

    #[test]
    fn parse_hex_pattern_rejects_too_long() {
        let too_long = "a".repeat(41);
        assert!(parse_hex_pattern(&too_long).is_err());
    }
}
