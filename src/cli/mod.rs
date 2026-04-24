use clap::Parser;
use rpassword;
use std::io;

/// Validate a single hex segment for use as an address prefix/suffix. Accepts
/// an optional `0x` prefix and normalizes to lowercase.
fn parse_hex_segment(s: &str) -> Result<String, String> {
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
    /// Prefix for Ethereum address (without 0x). Use `|` to pass multiple
    /// alternatives, e.g. `--prefix ab|cd` matches addresses starting with
    /// either `ab` or `cd`.
    #[arg(
        short,
        long,
        env = "ETH_PREFIX",
        value_delimiter = '|',
        value_parser = parse_hex_segment,
    )]
    pub prefix: Option<Vec<String>>,

    /// Suffix for Ethereum address (without 0x). Use `|` to pass multiple
    /// alternatives, e.g. `--suffix 001|002|003`.
    #[arg(
        short,
        long,
        env = "ETH_SUFFIX",
        value_delimiter = '|',
        value_parser = parse_hex_segment,
    )]
    pub suffix: Option<Vec<String>>,

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

/// Create a rule string for the filename based on prefix and suffix. Multiple
/// alternatives are joined with `-` rather than `|`, since pipes aren't
/// filesystem-safe on Windows.
pub fn create_rule(prefix: &Option<Vec<String>>, suffix: &Option<Vec<String>>) -> String {
    let prefix_str = prefix.as_deref().map(|alts| alts.join("-"));
    let suffix_str = suffix.as_deref().map(|alts| alts.join("-"));
    match (prefix_str, suffix_str) {
        (Some(p), Some(s)) => format!("prefix_{p}_suffix_{s}"),
        (Some(p), None) => format!("prefix_{p}"),
        (None, Some(s)) => format!("suffix_{s}"),
        (None, None) => "no_rule".to_string(),
    }
}

/// Print information about the search criteria
pub fn print_search_info(prefix: &Option<Vec<String>>, suffix: &Option<Vec<String>>, count: usize) {
    println!("Ethereum Address Finder");
    println!("Looking for addresses with:");
    if let Some(prefix) = prefix {
        println!("  Prefix: {}", prefix.join(", "));
    }
    if let Some(suffix) = suffix {
        println!("  Suffix: {}", suffix.join(", "));
    }
    println!("Finding {count} matching addresses...");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_segment_accepts_valid() {
        assert_eq!(parse_hex_segment("abc").unwrap(), "abc");
        assert_eq!(parse_hex_segment("0xABC").unwrap(), "abc");
        assert_eq!(
            parse_hex_segment("0123456789abcdef").unwrap(),
            "0123456789abcdef"
        );
    }

    #[test]
    fn parse_hex_segment_rejects_non_hex() {
        assert!(parse_hex_segment("xyz").is_err());
        assert!(parse_hex_segment("ab z").is_err());
    }

    #[test]
    fn parse_hex_segment_rejects_empty() {
        assert!(parse_hex_segment("").is_err());
        assert!(parse_hex_segment("0x").is_err());
    }

    #[test]
    fn parse_hex_segment_rejects_too_long() {
        let too_long = "a".repeat(41);
        assert!(parse_hex_segment(&too_long).is_err());
    }

    #[test]
    fn args_accepts_pipe_separated_suffix() {
        let args = Args::try_parse_from(["prog", "--suffix", "001|002|003"]).unwrap();
        assert_eq!(
            args.suffix,
            Some(vec![
                "001".to_string(),
                "002".to_string(),
                "003".to_string()
            ])
        );
    }

    #[test]
    fn args_accepts_single_suffix() {
        let args = Args::try_parse_from(["prog", "--suffix", "0xDEAD"]).unwrap();
        assert_eq!(args.suffix, Some(vec!["dead".to_string()]));
    }

    #[test]
    fn args_rejects_empty_segment() {
        assert!(Args::try_parse_from(["prog", "--suffix", "001||002"]).is_err());
        assert!(Args::try_parse_from(["prog", "--suffix", "|001"]).is_err());
        assert!(Args::try_parse_from(["prog", "--suffix", "001|"]).is_err());
    }

    #[test]
    fn create_rule_joins_alternatives_with_dash() {
        let p = Some(vec!["ab".to_string(), "cd".to_string()]);
        let s = Some(vec!["01".to_string(), "02".to_string(), "03".to_string()]);
        assert_eq!(create_rule(&p, &s), "prefix_ab-cd_suffix_01-02-03");
        assert_eq!(create_rule(&None, &s), "suffix_01-02-03");
        assert_eq!(create_rule(&p, &None), "prefix_ab-cd");
        assert_eq!(create_rule(&None, &None), "no_rule");
    }
}
