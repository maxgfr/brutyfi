use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "bruteforce-wifi")]
#[command(author = "maxgfr")]
#[command(version = "2.0.0")]
#[command(about = "WPA/WPA2 offline cracking tool - Educational use only", long_about = None)]
pub struct Args {
    /// Number of threads to use (default: CPU count)
    #[arg(short, long)]
    pub threads: Option<usize>,

    /// Command to execute
    #[command(subcommand)]
    pub mode: Mode,
}

#[derive(Subcommand)]
pub enum Mode {
    /// Crack WPA/WPA2 handshake using offline attack
    ///
    /// Performs offline bruteforce attack against a captured handshake (.cap/.pcap or .json).
    /// Much faster than online attacks (5,000-50,000 passwords/second).
    ///
    /// Example: bruteforce-wifi crack wordlist capture.cap --ssid MyNetwork passwords.txt
    Crack {
        /// Crack method
        #[command(subcommand)]
        method: CrackMethod,
    },
}

#[derive(Subcommand)]
pub enum CrackMethod {
    /// Crack using a wordlist file
    ///
    /// Tests passwords from a file against the captured handshake.
    ///
    /// Example: bruteforce-wifi crack wordlist handshake.cap --ssid MyNetwork rockyou.txt
    Wordlist {
        /// Path to handshake file (.cap or .json)
        #[arg(value_name = "HANDSHAKE")]
        handshake: PathBuf,

        /// Network SSID (required for .cap files)
        #[arg(long)]
        ssid: Option<String>,

        /// Path to wordlist file
        #[arg(value_name = "WORDLIST")]
        wordlist: PathBuf,
    },

    /// Crack using numeric combinations
    ///
    /// Generates and tests numeric passwords (e.g., 12345678).
    /// Useful for routers with default numeric passwords.
    ///
    /// Example: bruteforce-wifi crack numeric handshake.cap --ssid MyNetwork --min 8 --max 8
    Numeric {
        /// Path to handshake file (.cap or .json)
        #[arg(value_name = "HANDSHAKE")]
        handshake: PathBuf,

        /// Network SSID (required for .cap files)
        #[arg(long)]
        ssid: Option<String>,

        /// Minimum number of digits
        #[arg(short, long, default_value = "8")]
        min: usize,

        /// Maximum number of digits
        #[arg(short, long, default_value = "8")]
        max: usize,
    },
}
