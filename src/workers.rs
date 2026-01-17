/*!
 * Background workers for async operations
 *
 * These workers handle long-running tasks in background threads
 * and communicate progress back to the GUI via channels.
 */

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use bruteforce_wifi::{parse_cap_file, scan_networks, OfflineBruteForcer, WifiNetwork};

/// Scan result from background worker
#[derive(Debug, Clone)]
pub enum ScanResult {
    Success(Vec<WifiNetwork>),
    PartialSuccess {
        networks: Vec<WifiNetwork>,
        warning: String,
    },
    Error(String),
}

/// Capture progress from background worker
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum CaptureProgress {
    Started,
    Log(String),
    PacketsCaptured(u64),
    EapolDetected {
        message_type: u8,
        ap_mac: String,
        client_mac: String,
    },
    HandshakeComplete {
        ssid: String,
    },
    Error(String),
    Finished {
        output_file: String,
        packets: u64,
    },
    Stopped,
}

/// Crack progress from background worker
#[derive(Debug, Clone)]
pub enum CrackProgress {
    Started { total: u64 },
    Progress { current: u64, total: u64, rate: f64 },
    Log(String),
    Found(String),
    NotFound,
    Error(String),
}

/// Capture state for controlling the capture process
#[allow(dead_code)]
pub struct CaptureState {
    pub running: Arc<AtomicBool>,
    pub packets_count: Arc<AtomicU64>,
}

#[allow(dead_code)]
impl CaptureState {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
            packets_count: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Crack state for controlling the crack process
pub struct CrackState {
    pub running: Arc<AtomicBool>,
    pub attempts: Arc<AtomicU64>,
    #[allow(dead_code)]
    pub found: Arc<AtomicBool>,
}

impl CrackState {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
            attempts: Arc::new(AtomicU64::new(0)),
            found: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Wordlist crack worker data
pub struct WordlistCrackParams {
    pub handshake_path: PathBuf,
    pub ssid: Option<String>,
    pub wordlist_path: PathBuf,
    pub threads: usize,
}

/// Numeric crack worker data
pub struct NumericCrackParams {
    pub handshake_path: PathBuf,
    pub ssid: Option<String>,
    pub min_digits: usize,
    pub max_digits: usize,
    pub threads: usize,
}

/// Scan networks in background
pub fn scan_networks_async(interface: String) -> ScanResult {
    match scan_networks(&interface) {
        Ok(networks) => {
            if networks.is_empty() {
                ScanResult::Error("No networks found".to_string())
            } else {
                // Compact duplicate networks (same SSID, different channels/BSSIDs)
                let compacted_networks = bruteforce_wifi::compact_duplicate_networks(networks);

                // Check if BSSIDs are missing (Location Services issue)
                let has_bssids = compacted_networks.iter().any(|n| !n.bssid.is_empty());
                if !has_bssids {
                    ScanResult::PartialSuccess {
                        networks: compacted_networks,
                        warning: "Location Services permission required to access WiFi BSSIDs. Enable it in System Settings > Privacy & Security > Location Services.".to_string()
                    }
                } else {
                    ScanResult::Success(compacted_networks)
                }
            }
        }
        Err(e) => ScanResult::Error(e.to_string()),
    }
}

/// Capture parameters
pub struct CaptureParams {
    pub interface: String,
    pub channel: Option<u32>,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub output_file: String,
}

/// Run capture in background with progress updates
pub async fn capture_async(
    params: CaptureParams,
    state: Arc<CaptureState>,
    progress_tx: tokio::sync::mpsc::UnboundedSender<CaptureProgress>,
) -> CaptureProgress {
    use bruteforce_wifi::CaptureOptions;

    let _ = progress_tx.send(CaptureProgress::Started);
    let _ = progress_tx.send(CaptureProgress::Log(
        "Starting packet capture...".to_string(),
    ));

    // Clone output_file before moving params
    let output_file = params.output_file.clone();
    let interface = params.interface.clone();
    let ssid = params.ssid.clone();
    let bssid = params.bssid.clone();

    // Pre-flight checks
    let _ = progress_tx.send(CaptureProgress::Log(format!(
        "Checking interface {}...",
        interface
    )));

    // Verify interface exists
    let interface_check = interface.clone();
    let check_result = tokio::task::spawn_blocking(move || {
        use pcap::Device;
        let devices = Device::list().unwrap_or_default();
        devices.iter().any(|d| d.name == interface_check)
    })
    .await;

    match check_result {
        Ok(true) => {
            let _ = progress_tx.send(CaptureProgress::Log(format!(
                "Interface {} found",
                interface
            )));
        }
        Ok(false) => {
            let error_msg = format!(
                "Interface '{}' not found. Available interfaces: run 'ifconfig' to list them. On macOS, WiFi is usually 'en0'.",
                interface
            );
            let _ = progress_tx.send(CaptureProgress::Error(error_msg.clone()));
            return CaptureProgress::Error(error_msg);
        }
        Err(e) => {
            let error_msg = format!("Failed to check interfaces: {}", e);
            let _ = progress_tx.send(CaptureProgress::Error(error_msg.clone()));
            return CaptureProgress::Error(error_msg);
        }
    }

    let _ = progress_tx.send(CaptureProgress::Log(
        "Attempting to enable monitor mode...".to_string(),
    ));

    // Run capture in blocking thread
    let result = tokio::task::spawn_blocking(move || {
        // Build capture options inside the blocking thread
        let options = CaptureOptions {
            interface: &interface,
            channel: params.channel,
            ssid: ssid.as_deref(),
            bssid: bssid.as_deref(),
            output_file: &params.output_file,
            duration: None,  // Run until stopped
            no_deauth: true, // macOS doesn't support deauth
        };

        // Try to capture, with better error messages
        match bruteforce_wifi::capture_traffic(options) {
            Ok(()) => Ok(()),
            Err(e) => {
                let error_str = e.to_string();
                // Provide more helpful error messages
                if error_str.contains("permission denied") || error_str.contains("Operation not permitted") {
                    Err(anyhow::anyhow!(
                        "Permission denied. Make sure to run with sudo: sudo ./target/release/bruteforce-wifi"
                    ))
                } else if error_str.contains("monitor mode") || error_str.contains("rfmon") {
                    Err(anyhow::anyhow!(
                        "Monitor mode not supported on this interface. On macOS, you may need to disconnect from WiFi first (Option+Click WiFi icon > Disconnect)."
                    ))
                } else if error_str.contains("device") || error_str.contains("interface") {
                    Err(anyhow::anyhow!(
                        "Failed to open interface. Try: 1) Run with sudo, 2) Disconnect from WiFi, 3) Check if en0 is the correct interface."
                    ))
                } else {
                    Err(e)
                }
            }
        }
    })
    .await;

    match result {
        Ok(Ok(())) => {
            let _ = progress_tx.send(CaptureProgress::Log(
                "Capture completed successfully".to_string(),
            ));
            CaptureProgress::Finished {
                output_file,
                packets: state.packets_count.load(Ordering::Relaxed),
            }
        }
        Ok(Err(e)) => {
            let error_msg = e.to_string();
            let _ = progress_tx.send(CaptureProgress::Log(format!(
                "Capture error: {}",
                error_msg
            )));
            CaptureProgress::Error(error_msg)
        }
        Err(e) => {
            let error_msg = format!("Task failed: {}", e);
            let _ = progress_tx.send(CaptureProgress::Log(error_msg.clone()));
            CaptureProgress::Error(error_msg)
        }
    }
}

/// Run wordlist crack in background with progress updates
/// Note: This function is kept for reference but crack_wordlist_optimized is preferred
#[allow(dead_code)]
pub async fn crack_wordlist_async(
    params: WordlistCrackParams,
    state: Arc<CrackState>,
    progress_tx: tokio::sync::mpsc::UnboundedSender<CrackProgress>,
) -> CrackProgress {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    // Load handshake with panic protection
    let _ = progress_tx.send(CrackProgress::Log("Loading handshake...".to_string()));
    let handshake = match std::panic::catch_unwind(|| {
        parse_cap_file(&params.handshake_path, params.ssid.as_deref())
    }) {
        Ok(Ok(h)) => {
            let _ = progress_tx.send(CrackProgress::Log(format!(
                "Handshake loaded: SSID={}",
                h.ssid
            )));
            h
        }
        Ok(Err(e)) => return CrackProgress::Error(format!("Failed to parse handshake: {}", e)),
        Err(panic_err) => {
            return CrackProgress::Error(format!(
                "Panic while parsing handshake: {:?}",
                panic_err
                    .downcast_ref::<String>()
                    .map(|s| s.as_str())
                    .or_else(|| panic_err.downcast_ref::<&str>().copied())
                    .unwrap_or("Unknown panic")
            ))
        }
    };

    // Load wordlist
    let _ = progress_tx.send(CrackProgress::Log(format!(
        "Loading wordlist from {}...",
        params.wordlist_path.display()
    )));
    let file = match File::open(&params.wordlist_path) {
        Ok(f) => f,
        Err(e) => return CrackProgress::Error(format!("Failed to open wordlist: {}", e)),
    };

    let reader = BufReader::new(file);
    let passwords: Vec<String> = reader
        .lines()
        .map_while(Result::ok)
        .filter(|line| !line.trim().is_empty())
        .filter(|line| line.len() >= 8 && line.len() <= 63)
        .map(|line| line.trim().to_string())
        .collect();

    if passwords.is_empty() {
        return CrackProgress::Error("No valid passwords in wordlist".to_string());
    }

    let total = passwords.len() as u64;
    let _ = progress_tx.send(CrackProgress::Log(format!("Loaded {} passwords", total)));
    let _ = progress_tx.send(CrackProgress::Started { total });

    // Create bruteforcer
    let forcer = match OfflineBruteForcer::new(handshake, params.threads) {
        Ok(f) => f,
        Err(e) => return CrackProgress::Error(e.to_string()),
    };

    let _ = progress_tx.send(CrackProgress::Log(format!(
        "Starting crack with {} threads...",
        params.threads
    )));

    // Run crack with progress updates
    let start = std::time::Instant::now();
    // Larger chunks reduce overhead and improve cache locality
    let chunk_size = (passwords.len() / (params.threads * 4)).clamp(500, 50000);

    use rayon::prelude::*;
    let found_password: Arc<parking_lot::Mutex<Option<String>>> =
        Arc::new(parking_lot::Mutex::new(None));
    let found_flag = Arc::new(AtomicBool::new(false));

    let found_password_clone = Arc::clone(&found_password);
    let _result = passwords.par_chunks(chunk_size).find_any(|chunk| {
        if found_flag.load(Ordering::Acquire) || !state.running.load(Ordering::Relaxed) {
            return false;
        }

        for password in chunk.iter() {
            // Check for found flag with Acquire ordering to ensure we see the latest value
            if found_flag.load(Ordering::Acquire) || !state.running.load(Ordering::Relaxed) {
                return false;
            }

            let current = state.attempts.fetch_add(1, Ordering::Relaxed);

            // Send progress every 5000 attempts (reduced from 1000 to improve performance)
            if current.is_multiple_of(5000) {
                let elapsed = start.elapsed().as_secs_f64();
                let rate = if elapsed > 0.0 {
                    current as f64 / elapsed
                } else {
                    0.0
                };
                let _ = progress_tx.send(CrackProgress::Progress {
                    current,
                    total,
                    rate,
                });
            }

            if bruteforce_wifi::verify_password(
                password,
                &forcer.handshake.ssid,
                &forcer.handshake.ap_mac,
                &forcer.handshake.client_mac,
                &forcer.handshake.anonce,
                &forcer.handshake.snonce,
                &forcer.handshake.eapol_frame,
                &forcer.handshake.mic,
                forcer.handshake.key_version,
            ) {
                // Store the found password BEFORE setting the flag
                *found_password_clone.lock() = Some(password.to_string());
                // Use Release ordering to ensure password is visible before flag
                found_flag.store(true, Ordering::Release);
                return true;
            }
        }
        false
    });

    // Check if password was found or stopped
    if found_flag.load(Ordering::Acquire) {
        let result = found_password.lock().clone();
        if let Some(password) = result {
            let _ = progress_tx.send(CrackProgress::Log(format!("Password found: {}", password)));
            return CrackProgress::Found(password);
        }
    }

    if !state.running.load(Ordering::Relaxed) {
        return CrackProgress::Error("Stopped by user".to_string());
    }

    let _ = progress_tx.send(CrackProgress::Log(
        "Password not found in wordlist".to_string(),
    ));
    CrackProgress::NotFound
}

/// Run numeric crack in background with progress updates
/// Note: This function is kept for reference but crack_numeric_optimized is preferred
#[allow(dead_code)]
pub async fn crack_numeric_async(
    params: NumericCrackParams,
    state: Arc<CrackState>,
    progress_tx: tokio::sync::mpsc::UnboundedSender<CrackProgress>,
) -> CrackProgress {
    use bruteforce_wifi::password_gen::ParallelPasswordGenerator;
    use rayon::prelude::*;

    // Load handshake with panic protection
    let _ = progress_tx.send(CrackProgress::Log("Loading handshake...".to_string()));
    let handshake = match std::panic::catch_unwind(|| {
        parse_cap_file(&params.handshake_path, params.ssid.as_deref())
    }) {
        Ok(Ok(h)) => {
            let _ = progress_tx.send(CrackProgress::Log(format!(
                "Handshake loaded: SSID={}",
                h.ssid
            )));
            h
        }
        Ok(Err(e)) => return CrackProgress::Error(format!("Failed to parse handshake: {}", e)),
        Err(panic_err) => {
            return CrackProgress::Error(format!(
                "Panic while parsing handshake: {:?}",
                panic_err
                    .downcast_ref::<String>()
                    .map(|s| s.as_str())
                    .or_else(|| panic_err.downcast_ref::<&str>().copied())
                    .unwrap_or("Unknown panic")
            ))
        }
    };

    // Calculate total
    let mut total: u64 = 0;
    for len in params.min_digits..=params.max_digits {
        total += 10u64.pow(len as u32);
    }

    let _ = progress_tx.send(CrackProgress::Log(format!(
        "Testing {} combinations ({}-{} digits)",
        total, params.min_digits, params.max_digits
    )));
    let _ = progress_tx.send(CrackProgress::Started { total });

    let _ = progress_tx.send(CrackProgress::Log(format!(
        "Starting crack with {} threads...",
        params.threads
    )));

    // Run crack with progress updates
    let start = std::time::Instant::now();
    let found_password: Arc<parking_lot::Mutex<Option<String>>> =
        Arc::new(parking_lot::Mutex::new(None));
    let found_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Process each length
    for length in params.min_digits..=params.max_digits {
        if found_flag.load(std::sync::atomic::Ordering::Acquire)
            || !state.running.load(std::sync::atomic::Ordering::Relaxed)
        {
            break;
        }

        let generator = ParallelPasswordGenerator::new(length, params.threads);

        // Process batches in parallel
        for batch in generator.batches() {
            if found_flag.load(std::sync::atomic::Ordering::Acquire)
                || !state.running.load(std::sync::atomic::Ordering::Relaxed)
            {
                break;
            }

            let found_ref = Arc::clone(&found_flag);
            let found_password_ref = Arc::clone(&found_password);
            let state_ref = Arc::clone(&state);

            // Parallel password testing
            let _result = batch.par_iter().find_any(|password| {
                // Check for found flag with Acquire ordering to ensure we see the latest value
                if found_ref.load(std::sync::atomic::Ordering::Acquire)
                    || !state_ref.running.load(std::sync::atomic::Ordering::Relaxed)
                {
                    return false;
                }

                let current = state_ref
                    .attempts
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                // Send progress every 5000 attempts (reduced from 1000 to improve performance)
                if current.is_multiple_of(5000) {
                    let elapsed = start.elapsed().as_secs_f64();
                    let rate = if elapsed > 0.0 {
                        current as f64 / elapsed
                    } else {
                        0.0
                    };
                    let _ = progress_tx.send(CrackProgress::Progress {
                        current,
                        total,
                        rate,
                    });
                }

                if bruteforce_wifi::verify_password(
                    password,
                    &handshake.ssid,
                    &handshake.ap_mac,
                    &handshake.client_mac,
                    &handshake.anonce,
                    &handshake.snonce,
                    &handshake.eapol_frame,
                    &handshake.mic,
                    handshake.key_version,
                ) {
                    // Store the found password BEFORE setting the flag
                    *found_password_ref.lock() = Some(password.to_string());
                    // Use Release ordering to ensure password is visible before flag
                    found_ref.store(true, std::sync::atomic::Ordering::Release);
                    return true;
                }

                false
            });

            if found_flag.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
        }
    }

    // Check if password was found or stopped
    if found_flag.load(std::sync::atomic::Ordering::Acquire) {
        let result = found_password.lock().clone();
        if let Some(password) = result {
            let _ = progress_tx.send(CrackProgress::Log(format!("Password found: {}", password)));
            return CrackProgress::Found(password);
        }
    }

    if !state.running.load(std::sync::atomic::Ordering::Relaxed) {
        return CrackProgress::Error("Stopped by user".to_string());
    }

    let _ = progress_tx.send(CrackProgress::Log(
        "Password not found in range".to_string(),
    ));
    CrackProgress::NotFound
}
