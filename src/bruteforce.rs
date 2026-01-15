/*!
 * Offline WPA/WPA2 bruteforce engine
 *
 * This module implements high-performance offline password cracking
 * against captured WPA/WPA2 handshakes.
 *
 * Performance optimizations:
 * - Parallel password testing with Rayon
 * - Efficient batch processing
 * - Lock-free progress tracking
 * - Minimal allocations
 */

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::crypto;
use crate::handshake::Handshake;
use crate::password_gen::ParallelPasswordGenerator;

/// Bruteforce configuration
pub struct BruteforceConfig {
    pub threads: usize,
}

/// Bruteforce result
pub struct BruteforceResult {
    pub password: Option<String>,
    pub attempts: u64,
    pub duration_secs: f64,
    pub passwords_per_second: f64,
}

/// Offline bruteforce engine for WPA/WPA2 handshakes
pub struct OfflineBruteForcer {
    handshake: Handshake,
    threads: usize,
    attempts: Arc<AtomicU64>,
    found: Arc<AtomicBool>,
}

impl OfflineBruteForcer {
    pub fn new(handshake: Handshake, threads: usize) -> Result<Self> {
        // Configure rayon thread pool
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .stack_size(4 * 1024 * 1024)
            .build_global()
            .ok();

        Ok(Self {
            handshake,
            threads,
            attempts: Arc::new(AtomicU64::new(0)),
            found: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Test a single password against the handshake
    #[inline(always)]
    fn test_password(&self, password: &str) -> bool {
        self.attempts.fetch_add(1, Ordering::Relaxed);

        crypto::verify_password(
            password,
            &self.handshake.ssid,
            &self.handshake.ap_mac,
            &self.handshake.client_mac,
            &self.handshake.anonce,
            &self.handshake.snonce,
            &self.handshake.eapol_frame,
            &self.handshake.mic,
            self.handshake.key_version,
        )
    }

    /// Bruteforce using numeric passwords
    pub fn crack_numeric(&self, min_length: usize, max_length: usize) -> Result<Option<String>> {
        println!("🚀 Starting offline WPA/WPA2 crack");
        println!("📝 SSID: {}", self.handshake.ssid);
        println!("🔢 Range: {}-{} digits", min_length, max_length);
        println!("🧵 Using {} threads\n", self.threads);

        let start_time = Instant::now();
        let found_password: Arc<parking_lot::Mutex<Option<String>>> =
            Arc::new(parking_lot::Mutex::new(None));

        // Process each length
        for length in min_length..=max_length {
            if self.found.load(Ordering::Acquire) {
                break;
            }

            let generator = ParallelPasswordGenerator::new(length, self.threads);
            let total = generator.total_combinations();

            println!("Testing {} combinations ({} digits)...", total, length);

            let pb = ProgressBar::new(total);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}) {eta} {msg}")
                    .unwrap()
                    .progress_chars("█▓▒░-"),
            );

            // Process batches in parallel
            for batch in generator.batches() {
                if self.found.load(Ordering::Acquire) {
                    break;
                }

                let found_ref = Arc::clone(&self.found);
                let found_password_ref = Arc::clone(&found_password);

                // Parallel password testing
                let result = batch.par_iter().find_any(|password| {
                    if found_ref.load(Ordering::Relaxed) {
                        return false;
                    }

                    if self.test_password(password) {
                        found_ref.store(true, Ordering::Release);
                        *found_password_ref.lock() = Some(password.to_string());
                        true
                    } else {
                        false
                    }
                });

                pb.inc(batch.len() as u64);

                if result.is_some() {
                    break;
                }

                // Update throughput
                let elapsed = start_time.elapsed().as_secs_f64();
                let current_attempts = self.attempts.load(Ordering::Relaxed);
                let throughput = current_attempts as f64 / elapsed;
                pb.set_message(format!("{:.0} pwd/s", throughput));
            }

            pb.finish_with_message("Done");

            if self.found.load(Ordering::Acquire) {
                break;
            }
        }

        let elapsed = start_time.elapsed();
        let attempts = self.attempts.load(Ordering::Relaxed);
        let rate = attempts as f64 / elapsed.as_secs_f64();

        println!("\n📊 Performance Statistics:");
        println!("   Total attempts: {}", attempts);
        println!("   Time elapsed: {:.2}s", elapsed.as_secs_f64());
        println!("   Average rate: {:.0} passwords/second", rate);

        let result = found_password.lock().clone();
        Ok(result)
    }

    /// Bruteforce using wordlist
    pub fn crack_wordlist(&self, passwords: Vec<String>) -> Result<Option<String>> {
        println!("🚀 Starting offline WPA/WPA2 crack");
        println!("📝 SSID: {}", self.handshake.ssid);
        println!("📋 Wordlist size: {}", passwords.len());
        println!("🧵 Using {} threads\n", self.threads);

        let pb = ProgressBar::new(passwords.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}) {eta} {msg}")
                .unwrap()
                .progress_chars("█▓▒░-"),
        );

        let start_time = Instant::now();
        let found_password: Arc<parking_lot::Mutex<Option<String>>> =
            Arc::new(parking_lot::Mutex::new(None));

        let found_ref = Arc::clone(&self.found);
        let found_password_ref = Arc::clone(&found_password);

        // Parallel processing with optimal chunk size
        let chunk_size = (passwords.len() / (self.threads * 12)).max(100).min(10000);

        passwords.par_chunks(chunk_size).find_any(|chunk| {
            for password in chunk.iter() {
                if found_ref.load(Ordering::Relaxed) {
                    return false;
                }

                if self.test_password(password) {
                    found_ref.store(true, Ordering::Release);
                    *found_password_ref.lock() = Some(password.to_string());
                    pb.inc(chunk.len() as u64);
                    return true;
                }
            }
            pb.inc(chunk.len() as u64);

            // Update throughput
            let elapsed = start_time.elapsed().as_secs_f64();
            let current_attempts = self.attempts.load(Ordering::Relaxed);
            let throughput = current_attempts as f64 / elapsed;
            pb.set_message(format!("{:.0} pwd/s", throughput));

            false
        });

        pb.finish_with_message("Done");

        let elapsed = start_time.elapsed();
        let attempts = self.attempts.load(Ordering::Relaxed);
        let rate = attempts as f64 / elapsed.as_secs_f64();

        println!("\n📊 Performance Statistics:");
        println!("   Total attempts: {}", attempts);
        println!("   Time elapsed: {:.2}s", elapsed.as_secs_f64());
        println!("   Average rate: {:.0} passwords/second", rate);

        let result = found_password.lock().clone();
        Ok(result)
    }

    /// Get current attempt count
    pub fn attempts(&self) -> u64 {
        self.attempts.load(Ordering::Relaxed)
    }
}

/// Bruteforce using a wordlist file (wrapper for compatibility)
/// Load handshake from either .cap or .json file
fn load_handshake(path: &std::path::Path, ssid: Option<&str>) -> Result<Handshake> {
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    let handshake = match extension.to_lowercase().as_str() {
        "cap" | "pcap" => {
            use crate::handshake::parse_cap_file;
            parse_cap_file(path, ssid).context("Failed to parse .cap file")?
        }
        _ => {
            // Default to JSON format
            Handshake::load_from_file(path).context("Failed to load handshake file")?
        }
    };

    Ok(handshake)
}

pub async fn bruteforce_wordlist(
    config: &BruteforceConfig,
    handshake_path: &std::path::Path,
    ssid: Option<&str>,
    wordlist_path: &std::path::Path,
) -> Result<BruteforceResult> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    // Load handshake from .cap or .json
    let handshake = load_handshake(handshake_path, ssid)?;

    handshake.display();
    println!();

    // Load wordlist
    let file = File::open(wordlist_path)
        .with_context(|| format!("Failed to open wordlist: {}", wordlist_path.display()))?;

    let reader = BufReader::new(file);
    let passwords: Vec<String> = reader
        .lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.trim().is_empty())
        .filter(|line| line.len() >= 8 && line.len() <= 63) // WPA password length constraints
        .map(|line| line.trim().to_string())
        .collect();

    println!(
        "✓ Loaded {} valid passwords from wordlist\n",
        passwords.len()
    );

    // Create bruteforcer
    let forcer = OfflineBruteForcer::new(handshake, config.threads)?;

    let start_time = Instant::now();
    let result = forcer.crack_wordlist(passwords)?;
    let elapsed = start_time.elapsed();
    let attempts = forcer.attempts();
    let rate = attempts as f64 / elapsed.as_secs_f64();

    Ok(BruteforceResult {
        password: result,
        attempts,
        duration_secs: elapsed.as_secs_f64(),
        passwords_per_second: rate,
    })
}

/// Bruteforce using numeric combinations (wrapper for compatibility)
pub async fn bruteforce_numeric(
    config: &BruteforceConfig,
    handshake_path: &std::path::Path,
    ssid: Option<&str>,
    min_digits: usize,
    max_digits: usize,
) -> Result<BruteforceResult> {
    // Load handshake from .cap or .json
    let handshake = load_handshake(handshake_path, ssid)?;

    handshake.display();
    println!();

    // Create bruteforcer
    let forcer = OfflineBruteForcer::new(handshake, config.threads)?;

    let start_time = Instant::now();
    let result = forcer.crack_numeric(min_digits, max_digits)?;
    let elapsed = start_time.elapsed();
    let attempts = forcer.attempts();
    let rate = attempts as f64 / elapsed.as_secs_f64();

    Ok(BruteforceResult {
        password: result,
        attempts,
        duration_secs: elapsed.as_secs_f64(),
        passwords_per_second: rate,
    })
}
