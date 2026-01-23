/*!
 * Hashcat + hcxtools integration for GPU-accelerated cracking
 *
 * This module provides integration with external tools:
 * - hcxpcapngtool: Convert PCAP to hashcat format (.22000)
 * - hashcat: GPU-accelerated password cracking
 *
 * This can be 10-100x faster than native CPU cracking on supported GPUs.
 */

use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn find_hashcat_binary() -> Option<String> {
    let candidates = [
        "hashcat",
        "/opt/homebrew/bin/hashcat",
        "/usr/local/bin/hashcat",
        "/opt/local/bin/hashcat",
        "/usr/bin/hashcat",
    ];

    for bin in candidates {
        if Command::new(bin)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Some(bin.to_string());
        }
    }

    None
}

fn find_hcxpcapngtool_binary() -> Option<String> {
    let candidates = [
        "hcxpcapngtool",
        "/opt/homebrew/bin/hcxpcapngtool",
        "/usr/local/bin/hcxpcapngtool",
        "/opt/local/bin/hcxpcapngtool",
        "/usr/bin/hcxpcapngtool",
    ];

    for bin in candidates {
        if Command::new(bin)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Some(bin.to_string());
        }
    }

    None
}

/// Format speed in human-readable format (H/s, KH/s, MH/s, GH/s)
fn format_speed(speed: f64) -> String {
    if speed >= 1_000_000_000.0 {
        format!("{:.2} GH/s", speed / 1_000_000_000.0)
    } else if speed >= 1_000_000.0 {
        format!("{:.2} MH/s", speed / 1_000_000.0)
    } else if speed >= 1_000.0 {
        format!("{:.2} KH/s", speed / 1_000.0)
    } else {
        format!("{:.0} H/s", speed)
    }
}

/// Format number with thousands separator (1234567 -> "1,234,567")
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();

    for (count, c) in s.chars().rev().enumerate() {
        if count > 0 && count % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }

    result.chars().rev().collect()
}

fn parse_speed_line(line: &str) -> Option<(u64, String)> {
    if !line.contains("Speed.#") {
        return None;
    }

    let speed_part = line.split(':').nth(1)?.trim();
    let mut parts = speed_part.split_whitespace();
    let value_str = parts.next()?;
    let unit = parts.next().unwrap_or("H/s");

    let value: f64 = value_str.parse().ok()?;
    let multiplier = if unit.starts_with("GH/") {
        1_000_000_000.0
    } else if unit.starts_with("MH/") {
        1_000_000.0
    } else if unit.starts_with("KH/") {
        1_000.0
    } else {
        1.0
    };

    let total = (value * multiplier).round() as u64;
    Some((total, format_speed(total as f64)))
}

fn parse_progress_percent(line: &str) -> Option<f64> {
    if !line.contains("Progress") {
        return None;
    }
    let start = line.find('(')? + 1;
    let end = line[start..].find('%')? + start;
    let percent_str = &line[start..end];
    percent_str.trim().parse::<f64>().ok()
}

fn parse_u64_clean(value: &str) -> Option<u64> {
    let cleaned = value.trim().replace(',', "");
    cleaned.parse::<u64>().ok()
}

fn parse_progress_counts(line: &str) -> Option<(u64, u64, f64)> {
    if !line.contains("Progress") {
        return None;
    }

    let after = line.split(':').nth(1)?.trim();
    let counts_part = after.split_whitespace().next()?;
    let (current_str, total_str) = counts_part.split_once('/')?;
    let current = parse_u64_clean(current_str)?;
    let total = parse_u64_clean(total_str)?;

    let percent = if let Some(start) = after.find('(') {
        let end = after[start..].find('%')? + start;
        after[start + 1..end].trim().parse::<f64>().ok()?
    } else {
        0.0
    };

    Some((current, total, percent))
}

fn parse_keyspace(line: &str) -> Option<u64> {
    if !line.contains("Keyspace") {
        return None;
    }
    let after = line.split(':').nth(1)?.trim();
    if let Some((_, total_str)) = after.split_once('/') {
        let total_part = total_str.split_whitespace().next().unwrap_or(total_str);
        return parse_u64_clean(total_part);
    }
    parse_u64_clean(after)
}

fn parse_restore_point(line: &str) -> Option<(u64, u64)> {
    if !line.contains("Restore.Point") {
        return None;
    }
    let after = line.split(':').nth(1)?.trim();
    let mut parts = after.split('/');
    let current = parse_u64_clean(parts.next()?)?;
    let total = parts.next()?.split_whitespace().next()?.to_string();
    let total = parse_u64_clean(&total)?;
    Some((current, total))
}

fn parse_cracked_password(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Ignore device/status lines
    if trimmed.contains("Device #")
        || trimmed.contains("OpenCL API")
        || trimmed.contains("METAL API")
        || trimmed.contains("Backend Device")
    {
        return None;
    }

    // WPA 22000 format: WPA*02*...:password
    if trimmed.starts_with("WPA*02*") && trimmed.contains(':') {
        if let Some(password) = trimmed.split(':').next_back() {
            let password = password.trim();
            if password.len() >= 8 && password.len() <= 63 && !password.contains('*') {
                return Some(password.to_string());
            }
        }
        return None;
    }

    // Generic hash:password format (left side likely hex)
    if let Some((left, right)) = trimmed.rsplit_once(':') {
        let left = left.trim();
        let right = right.trim();
        if right.len() >= 8 && right.len() <= 63 {
            let is_hex = left.len() >= 32 && left.chars().all(|c| c.is_ascii_hexdigit());
            if is_hex {
                return Some(right.to_string());
            }
        }
    }

    None
}

/// Check if hcxpcapngtool is installed
pub fn is_hcxtools_installed() -> bool {
    find_hcxpcapngtool_binary().is_some()
}

/// Check if hashcat is installed
pub fn is_hashcat_installed() -> bool {
    find_hashcat_binary().is_some()
}

/// Check if both tools are available
pub fn are_external_tools_available() -> (bool, bool) {
    (is_hcxtools_installed(), is_hashcat_installed())
}

/// Get hashcat version info
pub fn get_hashcat_version() -> Option<String> {
    let bin = find_hashcat_binary()?;
    Command::new(bin)
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
}

/// Detect available hashcat devices and return optimal device type
/// Returns: 3 for CPU+GPU (best), 2 for GPU only, 1 for CPU only
pub fn detect_optimal_device_type() -> u8 {
    let Some(bin) = find_hashcat_binary() else {
        return 2;
    };

    let output = Command::new(bin).arg("-I").output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Check if GPU is available (Metal or OpenCL)
        if stdout.contains("Type...........: GPU") || stdout.contains("Metal Info:") {
            // Try CPU+GPU first (level 3) for maximum performance
            // If it doesn't work, the app will fallback automatically
            // Note: On some macOS configs, only GPU-only (-D 2) works
            return 3; // CPU+GPU for maximum performance
        }

        // Check if CPU is available
        if stdout.contains("Type...........: CPU") {
            return 1; // CPU only
        }
    }

    // Fallback to GPU only if detection unclear
    2
}

/// Convert PCAP/CAP file to hashcat 22000 format using hcxpcapngtool
pub fn convert_to_hashcat_format(pcap_path: &Path) -> Result<PathBuf> {
    // Generate unique output path in /tmp directory
    let filename = pcap_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("capture");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let output_path = PathBuf::from(format!("/tmp/{}_{}.22000", filename, ts));

    let Some(bin) = find_hcxpcapngtool_binary() else {
        return Err(anyhow!("hcxpcapngtool not found. Please install hcxtools."));
    };

    let output = Command::new(bin)
        .arg("-o")
        .arg(&output_path)
        .arg(pcap_path)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let details = if !stderr.trim().is_empty() {
            stderr.trim().to_string()
        } else if !stdout.trim().is_empty() {
            stdout.trim().to_string()
        } else {
            "No handshake found in capture file".to_string()
        };
        return Err(anyhow!(
            "hcxpcapngtool failed: {}. Ensure the capture contains a valid WPA handshake or PMKID.",
            details
        ));
    }

    // Check if output file was created and is not empty
    if !output_path.exists() {
        return Err(anyhow!(
            "No valid WPA handshake or PMKID found in the capture file"
        ));
    }

    let metadata = std::fs::metadata(&output_path)?;
    if metadata.len() == 0 {
        std::fs::remove_file(&output_path).ok();
        return Err(anyhow!(
            "No valid WPA handshake or PMKID found in the capture file"
        ));
    }

    Ok(output_path)
}

/// Hashcat attack mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashcatAttackMode {
    /// Straight dictionary attack
    Dictionary = 0,
    /// Brute-force / mask attack
    BruteForce = 3,
}

/// Hashcat cracking parameters
#[derive(Debug, Clone)]
pub struct HashcatParams {
    pub hash_file: PathBuf,
    pub attack_mode: HashcatAttackMode,
    /// For dictionary attack: path to wordlist
    pub wordlist: Option<PathBuf>,
    /// For brute-force: mask pattern (e.g., "?d?d?d?d?d?d?d?d" for 8 digits)
    pub mask: Option<String>,
    /// Minimum password length (for incremental mask attack)
    pub min_length: Option<usize>,
    /// Maximum password length (for incremental mask attack)
    pub max_length: Option<usize>,
    /// Enable status output
    pub status: bool,
    /// Workload profile (1=Low, 2=Default, 3=High, 4=Nightmare)
    pub workload: u8,
    /// Device types: 1=CPU, 2=GPU, 3=CPU+GPU
    pub device_types: u8,
}

impl HashcatParams {
    /// Create params for numeric brute-force attack
    pub fn numeric(hash_file: PathBuf, min_digits: usize, max_digits: usize) -> Self {
        // Build mask for numeric-only attack
        let mask = "?d".repeat(max_digits);

        Self {
            hash_file,
            attack_mode: HashcatAttackMode::BruteForce,
            wordlist: None,
            mask: Some(mask),
            min_length: Some(min_digits),
            max_length: Some(max_digits),
            status: true,
            workload: 3,
            device_types: detect_optimal_device_type(), // Auto-detect: 2=GPU, 1=CPU
        }
    }

    /// Create params for wordlist attack
    pub fn wordlist(hash_file: PathBuf, wordlist: PathBuf) -> Self {
        Self {
            hash_file,
            attack_mode: HashcatAttackMode::Dictionary,
            wordlist: Some(wordlist),
            mask: None,
            min_length: None,
            max_length: None,
            status: true,
            workload: 3,
            device_types: detect_optimal_device_type(), // Auto-detect: 2=GPU, 1=CPU
        }
    }
}

/// Result from hashcat execution
#[derive(Debug, Clone)]
pub enum HashcatResult {
    /// Password found
    Found(String),
    /// Password not found (exhausted search space)
    NotFound,
    /// Error occurred
    Error(String),
    /// User stopped the process
    Stopped,
}

/// Progress information from hashcat
#[derive(Debug, Clone)]
pub struct HashcatProgress {
    pub status: String,
    pub progress_percent: f64,
    pub speed: String,
    pub rate_per_sec: f64,
    pub current_attempts: u64,
    pub total_attempts: u64,
    pub recovered: String,
    pub time_estimated: String,
}

/// Run hashcat and return the result
/// This is a blocking operation - should be run in a separate thread
pub fn run_hashcat(
    params: &HashcatParams,
    progress_callback: impl Fn(HashcatProgress) + Send,
    stop_flag: &std::sync::atomic::AtomicBool,
) -> HashcatResult {
    use std::io::{BufRead, BufReader};
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    // Note: stop_flag being false means user requested stop
    // We don't check it before starting, only during execution

    let hashcat_bin = match find_hashcat_binary() {
        Some(bin) => bin,
        None => {
            return HashcatResult::Error(
                "hashcat not found. Please install hashcat and try again.".to_string(),
            )
        }
    };

    let mut cmd = Command::new(hashcat_bin);

    // WPA/WPA2 mode
    cmd.arg("-m").arg("22000");

    // Attack mode
    cmd.arg("-a").arg((params.attack_mode as u8).to_string());

    // Hash file
    cmd.arg(&params.hash_file);

    // Attack-specific options
    match params.attack_mode {
        HashcatAttackMode::Dictionary => {
            if let Some(ref wordlist) = params.wordlist {
                cmd.arg(wordlist);
            }
        }
        HashcatAttackMode::BruteForce => {
            if let Some(ref mask) = params.mask {
                cmd.arg(mask);
            }
            if let (Some(min), Some(max)) = (params.min_length, params.max_length) {
                cmd.arg("--increment");
                cmd.arg("--increment-min").arg(min.to_string());
                cmd.arg("--increment-max").arg(max.to_string());
            }
        }
    }

    // Status and performance options
    if params.status {
        cmd.arg("--status");
        cmd.arg("--status-timer").arg("1");
    }

    cmd.arg("-w").arg(params.workload.to_string());

    // Device selection: CPU+GPU for maximum performance
    cmd.arg("-D").arg(params.device_types.to_string());

    // Potfile path in /tmp to avoid conflicts
    // CRITICAL: Remove old potfile to avoid returning cached results
    let potfile_path = "/tmp/brutyfi_hashcat.potfile";
    let _ = std::fs::remove_file(potfile_path); // Ignore error if file doesn't exist
    cmd.arg("--potfile-path").arg(potfile_path);

    // NOTE: --force removed as it can cause "No devices found/left" error
    // on some macOS configurations with Metal/OpenCL

    // Set up pipes
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return HashcatResult::Error(format!("Failed to start hashcat: {}", e)),
    };

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    let (stdout_tx, stdout_rx) = mpsc::channel::<String>();
    let (stderr_tx, stderr_rx) = mpsc::channel::<String>();

    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            let _ = stdout_tx.send(line);
        }
    });

    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            let _ = stderr_tx.send(line);
        }
    });

    let mut stderr_output: Vec<String> = Vec::new();
    let mut retry_gpu_only = false;
    let mut last_speed: Option<String> = None;
    let mut last_progress: Option<f64> = None;
    let mut last_rate_per_sec: f64 = 0.0;
    let mut last_attempts: Option<(u64, u64)> = None;

    // Send initial status
    progress_callback(HashcatProgress {
        status: "Starting hashcat...".to_string(),
        progress_percent: 0.0,
        speed: "Initializing...".to_string(),
        rate_per_sec: 0.0,
        current_attempts: 0,
        total_attempts: 0,
        recovered: "0/1".to_string(),
        time_estimated: "Unknown".to_string(),
    });

    loop {
        // Check stop flag frequently
        if !stop_flag.load(Ordering::Acquire) {
            let _ = child.kill();
            let _ = child.wait();
            return HashcatResult::Stopped;
        }

        while let Ok(line) = stdout_rx.try_recv() {
            if let Some(password) = parse_cracked_password(&line) {
                progress_callback(HashcatProgress {
                    status: "Password found!".to_string(),
                    progress_percent: 100.0,
                    speed: "Done".to_string(),
                    rate_per_sec: last_rate_per_sec,
                    current_attempts: last_attempts.map(|a| a.0).unwrap_or(0),
                    total_attempts: last_attempts.map(|a| a.1).unwrap_or(0),
                    recovered: "1/1".to_string(),
                    time_estimated: "Complete".to_string(),
                });
                let _ = child.kill();
                let _ = child.wait();
                return HashcatResult::Found(password);
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some((per_sec, speed_fmt)) = parse_speed_line(trimmed) {
                last_speed = Some(speed_fmt.clone());
                last_rate_per_sec = per_sec as f64;
                progress_callback(HashcatProgress {
                    status: format!("Cracking: {} passwords/sec", format_number(per_sec)),
                    progress_percent: last_progress.unwrap_or(0.0),
                    speed: speed_fmt,
                    rate_per_sec: last_rate_per_sec,
                    current_attempts: last_attempts.map(|a| a.0).unwrap_or(0),
                    total_attempts: last_attempts.map(|a| a.1).unwrap_or(0),
                    recovered: "0/1".to_string(),
                    time_estimated: "Working...".to_string(),
                });
                continue;
            }

            if let Some((current, total, percent)) = parse_progress_counts(trimmed) {
                last_progress = Some(percent / 100.0);
                last_attempts = Some((current, total));
                progress_callback(HashcatProgress {
                    status: "Cracking in progress...".to_string(),
                    progress_percent: percent / 100.0,
                    speed: last_speed
                        .clone()
                        .unwrap_or_else(|| "Working...".to_string()),
                    rate_per_sec: last_rate_per_sec,
                    current_attempts: current,
                    total_attempts: total,
                    recovered: "0/1".to_string(),
                    time_estimated: "Working...".to_string(),
                });
                continue;
            }

            if let Some(percent) = parse_progress_percent(trimmed) {
                last_progress = Some(percent / 100.0);
                progress_callback(HashcatProgress {
                    status: "Cracking in progress...".to_string(),
                    progress_percent: percent / 100.0,
                    speed: last_speed
                        .clone()
                        .unwrap_or_else(|| "Working...".to_string()),
                    rate_per_sec: last_rate_per_sec,
                    current_attempts: last_attempts.map(|a| a.0).unwrap_or(0),
                    total_attempts: last_attempts.map(|a| a.1).unwrap_or(0),
                    recovered: "0/1".to_string(),
                    time_estimated: "Working...".to_string(),
                });
                continue;
            }

            if let Some((current, total)) = parse_restore_point(trimmed) {
                last_attempts = Some((current, total));
                progress_callback(HashcatProgress {
                    status: "Cracking in progress...".to_string(),
                    progress_percent: last_progress.unwrap_or(0.0),
                    speed: last_speed
                        .clone()
                        .unwrap_or_else(|| "Working...".to_string()),
                    rate_per_sec: last_rate_per_sec,
                    current_attempts: current,
                    total_attempts: total,
                    recovered: "0/1".to_string(),
                    time_estimated: "Working...".to_string(),
                });
                continue;
            }

            if let Some(total) = parse_keyspace(trimmed) {
                let current = last_attempts.map(|a| a.0).unwrap_or(0);
                last_attempts = Some((current, total));
                progress_callback(HashcatProgress {
                    status: "Cracking in progress...".to_string(),
                    progress_percent: last_progress.unwrap_or(0.0),
                    speed: last_speed
                        .clone()
                        .unwrap_or_else(|| "Working...".to_string()),
                    rate_per_sec: last_rate_per_sec,
                    current_attempts: current,
                    total_attempts: total,
                    recovered: "0/1".to_string(),
                    time_estimated: "Working...".to_string(),
                });
                continue;
            }

            progress_callback(HashcatProgress {
                status: trimmed.to_string(),
                progress_percent: last_progress.unwrap_or(0.0),
                speed: last_speed
                    .clone()
                    .unwrap_or_else(|| "Working...".to_string()),
                rate_per_sec: last_rate_per_sec,
                current_attempts: last_attempts.map(|a| a.0).unwrap_or(0),
                total_attempts: last_attempts.map(|a| a.1).unwrap_or(0),
                recovered: "0/1".to_string(),
                time_estimated: "Unknown".to_string(),
            });
        }

        while let Ok(line) = stderr_rx.try_recv() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            stderr_output.push(trimmed.to_string());

            if trimmed.contains("No devices found/left") {
                if params.device_types == 3 {
                    retry_gpu_only = true;
                    progress_callback(HashcatProgress {
                        status: "CPU+GPU mode failed, retrying with GPU-only...".to_string(),
                        progress_percent: 0.0,
                        speed: "Retrying...".to_string(),
                        rate_per_sec: 0.0,
                        current_attempts: 0,
                        total_attempts: 0,
                        recovered: "0/1".to_string(),
                        time_estimated: "Unknown".to_string(),
                    });
                } else {
                    let _ = child.kill();
                    let _ = child.wait();
                    return HashcatResult::Error(
                        "No devices found/left. Hashcat could not access a usable GPU.".to_string(),
                    );
                }
            }

            if let Some((per_sec, speed_fmt)) = parse_speed_line(trimmed) {
                last_speed = Some(speed_fmt.clone());
                last_rate_per_sec = per_sec as f64;
                progress_callback(HashcatProgress {
                    status: format!("Cracking: {} passwords/sec", format_number(per_sec)),
                    progress_percent: last_progress.unwrap_or(0.0),
                    speed: speed_fmt,
                    rate_per_sec: last_rate_per_sec,
                    current_attempts: last_attempts.map(|a| a.0).unwrap_or(0),
                    total_attempts: last_attempts.map(|a| a.1).unwrap_or(0),
                    recovered: "0/1".to_string(),
                    time_estimated: "Working...".to_string(),
                });
                continue;
            }

            if let Some((current, total, percent)) = parse_progress_counts(trimmed) {
                last_progress = Some(percent / 100.0);
                last_attempts = Some((current, total));
                progress_callback(HashcatProgress {
                    status: "Cracking in progress...".to_string(),
                    progress_percent: percent / 100.0,
                    speed: last_speed
                        .clone()
                        .unwrap_or_else(|| "Working...".to_string()),
                    rate_per_sec: last_rate_per_sec,
                    current_attempts: current,
                    total_attempts: total,
                    recovered: "0/1".to_string(),
                    time_estimated: "Working...".to_string(),
                });
                continue;
            }

            if let Some(percent) = parse_progress_percent(trimmed) {
                last_progress = Some(percent / 100.0);
                progress_callback(HashcatProgress {
                    status: "Cracking in progress...".to_string(),
                    progress_percent: percent / 100.0,
                    speed: last_speed
                        .clone()
                        .unwrap_or_else(|| "Working...".to_string()),
                    rate_per_sec: last_rate_per_sec,
                    current_attempts: last_attempts.map(|a| a.0).unwrap_or(0),
                    total_attempts: last_attempts.map(|a| a.1).unwrap_or(0),
                    recovered: "0/1".to_string(),
                    time_estimated: "Working...".to_string(),
                });
                continue;
            }

            if let Some((current, total)) = parse_restore_point(trimmed) {
                last_attempts = Some((current, total));
                progress_callback(HashcatProgress {
                    status: "Cracking in progress...".to_string(),
                    progress_percent: last_progress.unwrap_or(0.0),
                    speed: last_speed
                        .clone()
                        .unwrap_or_else(|| "Working...".to_string()),
                    rate_per_sec: last_rate_per_sec,
                    current_attempts: current,
                    total_attempts: total,
                    recovered: "0/1".to_string(),
                    time_estimated: "Working...".to_string(),
                });
                continue;
            }

            if let Some(total) = parse_keyspace(trimmed) {
                let current = last_attempts.map(|a| a.0).unwrap_or(0);
                last_attempts = Some((current, total));
                progress_callback(HashcatProgress {
                    status: "Cracking in progress...".to_string(),
                    progress_percent: last_progress.unwrap_or(0.0),
                    speed: last_speed
                        .clone()
                        .unwrap_or_else(|| "Working...".to_string()),
                    rate_per_sec: last_rate_per_sec,
                    current_attempts: current,
                    total_attempts: total,
                    recovered: "0/1".to_string(),
                    time_estimated: "Working...".to_string(),
                });
                continue;
            }

            progress_callback(HashcatProgress {
                status: trimmed.to_string(),
                progress_percent: last_progress.unwrap_or(0.0),
                speed: last_speed
                    .clone()
                    .unwrap_or_else(|| "Working...".to_string()),
                rate_per_sec: last_rate_per_sec,
                current_attempts: last_attempts.map(|a| a.0).unwrap_or(0),
                total_attempts: last_attempts.map(|a| a.1).unwrap_or(0),
                recovered: "0/1".to_string(),
                time_estimated: "Unknown".to_string(),
            });
        }

        if retry_gpu_only {
            let _ = child.kill();
            let _ = child.wait();
            let mut new_params = params.clone();
            new_params.device_types = 2;
            return run_hashcat(&new_params, progress_callback, stop_flag);
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                // Process exited
                if status.success() || status.code() == Some(1) {
                    // Check potfile or --show for results
                    let potfile_path = "/tmp/brutyfi_hashcat.potfile";

                    // Use the same hashcat binary that was found earlier
                    let Some(hashcat_bin_show) = find_hashcat_binary() else {
                        return HashcatResult::Error(
                            "hashcat binary not found for --show command".to_string(),
                        );
                    };

                    let mut show_cmd = Command::new(hashcat_bin_show);
                    show_cmd
                        .arg("-m")
                        .arg("22000")
                        .arg(&params.hash_file)
                        .arg("--potfile-path")
                        .arg(potfile_path)
                        .arg("--show")
                        .arg("--quiet");

                    let show_output = show_cmd.output();

                    match show_output {
                        Ok(output) => {
                            // Log stderr if there are any errors from --show
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            if !stderr.trim().is_empty() {
                                eprintln!("Hashcat --show stderr: {}", stderr.trim());
                            }

                            let stdout = String::from_utf8_lossy(&output.stdout);
                            for line in stdout.lines() {
                                let line = line.trim();
                                if !line.is_empty() && line.contains(':') {
                                    if let Some(password) = line.split(':').next_back() {
                                        let password = password.trim();
                                        if password.len() >= 8
                                            && password.len() <= 63
                                            && !password.contains('*')
                                        {
                                            return HashcatResult::Found(password.to_string());
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to execute hashcat --show: {}", e);
                        }
                    }

                    return HashcatResult::NotFound;
                }

                let error_msg = if !stderr_output.is_empty() {
                    format!(
                        "Hashcat exited with code {:?}\n\nError details:\n{}",
                        status.code(),
                        stderr_output.join("\n")
                    )
                } else {
                    format!("Hashcat exited with code: {:?}", status.code())
                };
                return HashcatResult::Error(error_msg);
            }
            Ok(None) => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return HashcatResult::Error(format!("Failed to wait for hashcat: {}", e)),
        }
    }
}
/// Full hashcat workflow: PCAP -> convert -> crack
pub fn crack_with_hashcat(
    pcap_path: &Path,
    params_builder: impl FnOnce(PathBuf) -> HashcatParams,
    progress_callback: impl Fn(HashcatProgress) + Send,
    stop_flag: &std::sync::atomic::AtomicBool,
) -> Result<HashcatResult> {
    // Step 1: Convert PCAP to hashcat format
    let hash_file = convert_to_hashcat_format(pcap_path)?;

    // Step 2: Build params with the converted file
    let params = params_builder(hash_file.clone());

    // Step 3: Run hashcat
    let result = run_hashcat(&params, progress_callback, stop_flag);

    // Cleanup: optionally remove the .22000 file
    // std::fs::remove_file(&hash_file).ok();

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_detection() {
        let (hcx, hashcat) = are_external_tools_available();
        println!("hcxtools installed: {}", hcx);
        println!("hashcat installed: {}", hashcat);
    }

    #[test]
    fn test_numeric_mask() {
        let params = HashcatParams::numeric(PathBuf::from("test.22000"), 8, 10);
        assert_eq!(params.mask, Some("?d?d?d?d?d?d?d?d?d?d".to_string()));
        assert_eq!(params.min_length, Some(8));
        assert_eq!(params.max_length, Some(10));
    }
}
