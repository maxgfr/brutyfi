mod cli;
mod wifi;
mod bruteforce;
mod password_gen;
mod platform;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;

use cli::{Args, Mode};
use wifi::WifiScanner;
use bruteforce::{BruteforceConfig, bruteforce_wordlist, bruteforce_numeric};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    println!("\n{}", "📡 Bruteforce WiFi v1.0.0".bold().cyan());
    println!("{}\n", "WiFi bruteforce tool - Educational use only".dimmed());
    
    // Scan for available networks using WifiScanner
    println!("{}", "Scanning for WiFi networks...".yellow());
    let scanner = WifiScanner::new()?;
    let networks = scanner.scan()?;
    
    if networks.is_empty() {
        println!("{}", "No WiFi networks found!".red());
        return Ok(());
    }
    
    // Display networks with numeric confidence scores
    println!("\n{}", "Available networks:".bold().green());
    scanner.display_networks(&networks);
    
    // Show top 3 most likely numeric password networks
    let likely_numeric = scanner.get_most_likely_numeric(&networks, 3);
    if !likely_numeric.is_empty() {
        println!("{}", "Top 3 networks most likely to have numeric passwords:".bold().yellow());
        for (idx, network) in likely_numeric.iter().enumerate() {
            let confidence = (network.numeric_confidence() * 100.0) as u32;
            println!("  {}. {} - Confidence: {}%", 
                (idx + 1).to_string().cyan(),
                network.ssid.bold(),
                confidence.to_string().green()
            );
        }
        println!();
    }
    
    // Select target network
    let target_index = if let Some(index) = args.target {
        if index >= networks.len() {
            println!("{}", "Invalid network index!".red());
            return Ok(());
        }
        index
    } else {
        println!("{}", "Select target network index:".bold());
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let index: usize = input.trim().parse()?;
        if index >= networks.len() {
            println!("{}", "Invalid network index!".red());
            return Ok(());
        }
        index
    };
    
    let target = &networks[target_index];
    let confidence = (target.numeric_confidence() * 100.0) as u32;
    
    println!("\n{}", format!("Target: {} ({})", target.ssid, target.security).bold().yellow());
    if target.likely_numeric {
        println!("{}", format!("  Numeric password likelihood: {}%", confidence).green());
    }
    
    // Configure bruteforce
    let config = BruteforceConfig {
        ssid: target.ssid.clone(),
        bssid: target.bssid.clone(),
        threads: args.threads.unwrap_or(num_cpus::get()),
        timeout: args.timeout,
        verbose: args.verbose,
    };
    
    // Execute bruteforce based on mode
    let result = match args.mode {
        Mode::Wordlist { path } => {
            println!("{}", "\n🔓 Starting wordlist attack...".cyan());
            bruteforce_wordlist(&config, &path).await?
        }
        Mode::Numeric { min, max } => {
            println!("{}", "\n🔢 Starting numeric combination attack...".cyan());
            bruteforce_numeric(&config, min, max).await?
        }
    };
    
    // Display results
    match result.password {
        Some(password) => {
            println!("\n{} {}", "✓ Password found:".bold().green(), password.bold().cyan());
            println!("{}", "  Save this password securely!".yellow());
            println!("\nStatistics:");
            println!("  Attempts: {}", result.attempts.to_string().cyan());
            println!("  Duration: {:.2}s", result.duration_secs);
            println!("  Speed: {:.0} attempts/second", result.passwords_per_second);
        }
        None => {
            println!("\n{}", "✗ Password not found in the provided range/wordlist".red());
            println!("\nStatistics:");
            println!("  Attempts: {}", result.attempts.to_string().cyan());
            println!("  Duration: {:.2}s", result.duration_secs);
            println!("  Speed: {:.0} attempts/second", result.passwords_per_second);
        }
    }
    
    Ok(())
}
