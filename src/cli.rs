use clap::{Parser, Subcommand, Args as ClapArgs};
use std::path::PathBuf;


#[derive(Parser)]
#[command(name = "bruteforce-wifi")]
#[command(author = "maxgfr")]
#[command(version = "2.0.0")]
#[command(about = "WPA/WPA2 offline cracking tool - Educational use only")]
#[command(long_about = r#"
📡 Bruteforce WiFi - All-in-One WiFi Security Tool

WORKFLOW:
  1. Capture handshake: bruteforce-wifi capture -i en0 -c 10 -s "MyNetwork"
  2. Crack password:    bruteforce-wifi crack numeric capture.cap --min 8 --max 8

⚠️  macOS LIMITATION: Apple Silicon does NOT support packet injection.
    Deauth attacks will NOT work. You must manually reconnect a device
    to capture the WPA handshake.

For educational purposes only. Only use on networks you own or have permission to test.
"#)]
pub struct Args {
    /// Number of threads to use for cracking (default: CPU count)
    #[arg(short, long, global = true)]
    pub threads: Option<usize>,

    #[command(subcommand)]
    pub mode: Mode,
}

#[derive(Subcommand)]
pub enum Mode {
    /// Fast scan of WiFi networks on all channels
    ///
    /// Scans 22 channels (2.4GHz: 1-13, 5GHz: 36,40,44,48,149,153,157,161,165).
    /// Takes ~5 seconds. Shows SSID, BSSID, channel, signal, and security info.
    /// Requires root/sudo privileges.
    ///
    /// Examples:
    ///   bruteforce-wifi scan -i en0
    Scan(ScanArgs),

    /// Capture WiFi traffic to a .cap file
    ///
    /// Puts interface in monitor mode and captures packets.
    /// Requires root/sudo privileges.
    ///
    /// ⚠️  On macOS: Deauth attacks do NOT work. You must manually
    /// disconnect and reconnect a device to trigger the handshake.
    ///
    /// Examples:
    ///   bruteforce-wifi capture -i en0 -c 10 -s "MyNetwork" -o capture.cap
    ///   bruteforce-wifi capture -i en0 --channel 36 --bssid AA:BB:CC:DD:EE:FF -v
    Capture(CaptureArgs),

    /// Crack WPA/WPA2 handshake using offline attack
    ///
    /// Performs offline bruteforce attack against a captured handshake.
    /// Much faster than online attacks (5,000-50,000 passwords/second).
    ///
    /// Examples:
    ///   bruteforce-wifi crack wordlist capture.cap passwords.txt
    ///   bruteforce-wifi crack numeric capture.cap --min 8 --max 8
    Crack {
        #[command(subcommand)]
        method: CrackMethod,
    },
}

#[derive(ClapArgs)]
pub struct ScanArgs {
    /// WiFi interface to scan on (e.g., en0 on macOS, wlan0 on Linux)
    #[arg(short, long)]
    pub interface: String,
}

#[derive(ClapArgs)]
pub struct CaptureArgs {
    /// WiFi interface to capture on (e.g., en0 on macOS, wlan0 on Linux)
    #[arg(short, long)]
    pub interface: String,

    /// Lock to a specific channel (recommended for better capture)
    ///
    /// 2.4GHz: 1-14
    /// 5GHz: 36-48, 52-64 (DFS), 100-144 (DFS), 149-165, 169-177
    #[arg(short, long)]
    pub channel: Option<u32>,

    /// Target network SSID (name)
    #[arg(short, long)]
    pub ssid: Option<String>,

    /// Target AP MAC address (BSSID) - more precise than SSID
    ///
    /// Format: AA:BB:CC:DD:EE:FF
    #[arg(short, long)]
    pub bssid: Option<String>,

    /// Output capture file
    #[arg(short, long, default_value = "capture.cap")]
    pub output: String,

    /// Capture duration in seconds (optional, runs until Ctrl+C if not set)
    #[arg(short, long)]
    pub duration: Option<u64>,

    /// Verbose mode - show all detected beacons and packet statistics
    #[arg(short, long)]
    pub verbose: bool,

    /// Disable deauth attacks (passive capture only)
    #[arg(long)]
    pub no_deauth: bool,
}

#[derive(Subcommand)]
pub enum CrackMethod {
    /// Crack using a wordlist file
    ///
    /// Tests passwords from a file against the captured handshake.
    ///
    /// Example: bruteforce-wifi crack wordlist capture.cap rockyou.txt
    Wordlist {
        /// Path to handshake file (.cap or .json)
        #[arg(value_name = "HANDSHAKE")]
        handshake: PathBuf,

        /// Network SSID (optional - auto-detected from .cap if possible)
        #[arg(long)]
        ssid: Option<String>,

        /// Path to wordlist file
        #[arg(value_name = "WORDLIST")]
        wordlist: PathBuf,
    },

    /// Crack using numeric combinations
    ///
    /// Generates and tests numeric passwords (e.g., 12345678).
    /// Perfect for routers with default numeric passwords (TP-Link, D-Link).
    ///
    /// Example: bruteforce-wifi crack numeric capture.cap --min 8 --max 8
    Numeric {
        /// Path to handshake file (.cap or .json)
        #[arg(value_name = "HANDSHAKE")]
        handshake: PathBuf,

        /// Network SSID (optional - auto-detected from .cap if possible)
        #[arg(long)]
        ssid: Option<String>,

        /// Minimum number of digits
        #[arg(short = 'n', long, default_value = "8")]
        min: usize,

        /// Maximum number of digits
        #[arg(short = 'x', long, default_value = "8")]
        max: usize,
    },
}
