use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "bruteforce-wifi")]
#[command(author = "maxgfr")]
#[command(version = "1.0.0")]
#[command(about = "WiFi bruteforce tool - Educational use only", long_about = None)]
pub struct Args {
    /// Target network index (from scan list)
    #[arg(short, long)]
    pub target: Option<usize>,
    
    /// Number of threads to use (default: CPU count)
    #[arg(short, long)]
    pub threads: Option<usize>,
    
    /// Timeout in seconds for each connection attempt
    #[arg(short, long, default_value = "5")]
    pub timeout: u64,
    
    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,
    
    /// Bruteforce mode
    #[command(subcommand)]
    pub mode: Mode,
}

#[derive(Subcommand)]
pub enum Mode {
    /// Use a wordlist file for bruteforce
    /// 
    /// This mode reads passwords from a file and tests each one against the target network.
    /// Wordlists can be downloaded from various sources online.
    /// 
    /// Example: bruteforce-wifi --target 0 wordlist ./passwords.txt
    Wordlist {
        /// Path to wordlist file
        #[arg(value_name = "FILE")]
        path: PathBuf,
    },
    
    /// Use numeric combinations (e.g., 00000000 to 99999999)
    /// 
    /// This mode generates numeric password combinations and tests each one.
    /// Useful for networks that use numeric passwords (common with some routers).
    /// 
    /// Example: bruteforce-wifi --target 0 numeric --min 4 --max 8
    Numeric {
        /// Minimum number of digits
        #[arg(short, long, default_value = "4")]
        min: usize,
        
        /// Maximum number of digits
        #[arg(short, long, default_value = "8")]
        max: usize,
    },
}
