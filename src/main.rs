mod cli;
mod bruteforce;
mod password_gen;
mod handshake;
mod crypto;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;

use cli::{Args, Mode, CrackMethod};
use bruteforce::{BruteforceConfig, bruteforce_wordlist, bruteforce_numeric};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("\n{}", "📡 Bruteforce WiFi v2.0.0".bold().cyan());
    println!("{}\n", "WPA/WPA2 offline cracking tool - Educational use only".dimmed());

    match args.mode {
        Mode::Crack { method } => {
            let config = BruteforceConfig {
                threads: args.threads.unwrap_or_else(num_cpus::get),
            };
            handle_crack_mode(method, &config).await?;
        }
    }

    Ok(())
}

/// Handle crack mode - offline bruteforce against handshake
async fn handle_crack_mode(method: CrackMethod, config: &BruteforceConfig) -> Result<()> {
    let result = match method {
        CrackMethod::Wordlist { handshake, ssid, wordlist } => {
            println!("{}", "\n🔓 Starting wordlist attack...".cyan());
            bruteforce_wordlist(config, &handshake, ssid.as_deref(), &wordlist).await?
        }
        CrackMethod::Numeric { handshake, ssid, min, max } => {
            println!("{}", "\n🔢 Starting numeric combination attack...".cyan());
            bruteforce_numeric(config, &handshake, ssid.as_deref(), min, max).await?
        }
    };

    // Display results
    println!();
    match result.password {
        Some(password) => {
            println!("{} {}", "✓ Password found:".bold().green(), password.bold().cyan());
            println!("{}", "  Save this password securely!".yellow());
            println!("\n{}", "Statistics:".bold());
            println!("  Attempts: {}", result.attempts.to_string().cyan());
            println!("  Duration: {:.2}s", result.duration_secs);
            println!("  Speed: {:.0} passwords/second", result.passwords_per_second.to_string().green());
        }
        None => {
            println!("{}", "✗ Password not found in the provided range/wordlist".red());
            println!("\n{}", "Statistics:".bold());
            println!("  Attempts: {}", result.attempts.to_string().cyan());
            println!("  Duration: {:.2}s", result.duration_secs);
            println!("  Speed: {:.0} passwords/second", result.passwords_per_second);

            println!("\n{}", "💡 Tips:".bold().yellow());
            println!("  - Try a larger wordlist (e.g., rockyou.txt)");
            println!("  - Check if the password uses special characters");
            println!("  - Verify the handshake file is valid");
        }
    }

    Ok(())
}
