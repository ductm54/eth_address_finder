use clap::Parser;
use rpassword;
use std::io;

/// Command-line arguments for the application
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Prefix for Ethereum address (without 0x)
    #[arg(short, long, env = "ETH_PREFIX")]
    pub prefix: Option<String>,

    /// Suffix for Ethereum address (without 0x)
    #[arg(short, long, env = "ETH_SUFFIX")]
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
