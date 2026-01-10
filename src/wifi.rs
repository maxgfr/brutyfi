/*!
 * WiFi network scanning and display with intelligent numeric password detection
 */

use anyhow::{Result, Context};
use std::fmt;
use std::process::Command;

/// WiFi network information with intelligent detection
#[derive(Debug, Clone)]
pub struct WifiNetwork {
    /// Network SSID (name)
    pub ssid: String,
    /// Network BSSID (MAC address)
    pub bssid: String,
    /// Signal strength in dBm
    pub rssi: i32,
    /// WiFi channel
    pub channel: u32,
    /// Security type (e.g., WPA2, WEP, Open)
    pub security: String,
    /// Signal strength percentage (0-100)
    pub signal_strength: f64,
    /// Whether this network is likely to use a numeric-only password
    pub likely_numeric: bool,
}

impl WifiNetwork {
    /// Detect if this network is likely to use a numeric-only password
    /// Based on common router patterns (TP-Link, D-Link, etc.)
    pub fn detect_numeric_password_likelihood(&mut self) {
        let ssid_lower = self.ssid.to_lowercase();

        // Common router brands that use numeric passwords by default
        let numeric_indicators = [
            "tp-link", "tplink", "tp_link",
            "d-link", "dlink",
            "netgear",
            "linksys",
            "asus",
            "belkin",
            "zyxel",
            "huawei",
            "sagem",
            "technicolor",
            "sfr",
            "bbox",
            "livebox",
            "orange",
            "freebox",
            "bouygues",
            "numericable",
        ];

        // Check if SSID contains known brands
        let has_brand = numeric_indicators.iter().any(|&brand| ssid_lower.contains(brand));

        // Check if SSID ends with digits (common pattern like "Network_1234")
        let ends_with_digits = self.ssid.chars().rev().take(4).all(|c| c.is_numeric());

        // Check if SSID is purely numeric (like "12345678")
        let is_pure_numeric = self.ssid.chars().all(|c| c.is_numeric());

        // Check if BSSID starts with known manufacturer OUI (first 6 chars)
        // TP-Link OUIs: 14:CC:20, F4:EC:38, 50:C7:BF, etc.
        let tplink_oui = ["14:cc:20", "f4:ec:38", "50:c7:bf", "c0:25:e9", "a4:2b:b0", "84:16:f9"];
        let has_tplink_mac = tplink_oui.iter().any(|&oui| {
            self.bssid.to_lowercase().starts_with(oui)
        });

        // Additional OUIs for common router manufacturers
        let other_ouis = [
            "00:1a:2b", "00:1e:58", // D-Link
            "00:0f:66", "00:14:6c", // Netgear
            "00:15:6d", "00:17:3f", // Linksys
            "00:04:5a", "00:0c:e5", // ASUS
            "00:1b:63", "00:1c:df", // Belkin
            "00:1e:40", "00:1e:58", // Zyxel
            "00:e0:fc", "00:1a:4d", // Huawei
            "00:1a:1c", "00:1a:1b", // Sagem
            "00:1a:1e", "00:1a:1f", // Technicolor
        ];
        let has_known_router_mac = other_ouis.iter().any(|&oui| {
            self.bssid.to_lowercase().starts_with(oui)
        });

        // Check for common patterns like "WIFI_XXXX", "BOX_XXXX"
        let has_pattern = ssid_lower.contains("wifi_") ||
                         ssid_lower.contains("box_") ||
                         ssid_lower.contains("home_") ||
                         ssid_lower.contains("network_");

        self.likely_numeric = has_brand || ends_with_digits || has_tplink_mac ||
                            has_known_router_mac || is_pure_numeric || has_pattern;
    }

    /// Get a confidence score for numeric password likelihood (0.0 to 1.0)
    pub fn numeric_confidence(&self) -> f32 {
        let mut score: f32 = 0.0;
        let ssid_lower = self.ssid.to_lowercase();

        // SSID is purely numeric - highest confidence
        if self.ssid.chars().all(|c| c.is_numeric()) {
            score += 0.9;
        }

        // Ends with 4+ digits
        if self.ssid.chars().rev().take(4).all(|c| c.is_numeric()) {
            score += 0.7;
        }

        // Contains known brand
        let numeric_indicators = [
            "tp-link", "tplink", "tp_link", "d-link", "dlink",
            "netgear", "linksys", "asus", "belkin", "zyxel", "huawei",
            "sagem", "technicolor", "sfr", "bbox", "livebox", "orange",
            "freebox", "bouygues", "numericable",
        ];
        if numeric_indicators.iter().any(|&brand| ssid_lower.contains(brand)) {
            score += 0.6;
        }

        // Known router MAC
        let tplink_oui = ["14:cc:20", "f4:ec:38", "50:c7:bf", "c0:25:e9", "a4:2b:b0", "84:16:f9"];
        if tplink_oui.iter().any(|&oui| self.bssid.to_lowercase().starts_with(oui)) {
            score += 0.8;
        }

        // Common patterns
        if ssid_lower.contains("wifi_") || ssid_lower.contains("box_") ||
           ssid_lower.contains("home_") || ssid_lower.contains("network_") {
            score += 0.5;
        }

        score.min(1.0)
    }
}

impl fmt::Display for WifiNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<30} {:<18} {:>6} dBm  Ch {:>2}  {}",
            self.ssid, self.bssid, self.rssi, self.channel, self.security
        )
    }
}

/// WiFi scanner with intelligent detection
pub struct WifiScanner;

impl WifiScanner {
    pub fn new() -> Result<Self> {
        Ok(WifiScanner)
    }

    /// Scan for available WiFi networks
    pub fn scan(&self) -> Result<Vec<WifiNetwork>> {
        let networks = scan_networks_sync()?;
        
        // Detect numeric password likelihood for each network
        let mut networks = networks;
        for network in &mut networks {
            network.detect_numeric_password_likelihood();
        }

        Ok(networks)
    }

    /// Filter networks likely to have numeric passwords
    pub fn filter_numeric_likely(networks: &[WifiNetwork]) -> Vec<WifiNetwork> {
        networks.iter()
            .filter(|n| n.likely_numeric)
            .cloned()
            .collect()
    }

    /// Display networks in a formatted table with confidence scores
    pub fn display_networks(&self, networks: &[WifiNetwork]) {
        if networks.is_empty() {
            println!("No networks found.");
            return;
        }

        println!("\n{:<4} {:<30} {:<18} {:<10} {:<6} {:<20} {:<12}",
                 "#", "SSID", "BSSID", "Signal", "Ch", "Security", "Numeric?");
        println!("{}", "─".repeat(110));

        for (idx, network) in networks.iter().enumerate() {
            let indicator = if network.likely_numeric {
                let confidence = (network.numeric_confidence() * 100.0) as u32;
                format!("✓ {}%", confidence)
            } else {
                String::new()
            };
            
            let ssid_display = if network.ssid.len() > 28 {
                format!("{}...", &network.ssid[..25])
            } else {
                network.ssid.clone()
            };
            
            println!(
                "{:<4} {:<30} {:<18} {:>6} dBm  Ch {:>2}  {:<20} {:<12}",
                idx + 1,
                ssid_display,
                &network.bssid,
                network.rssi,
                network.channel,
                &network.security,
                indicator
            );
        }
        println!();
    }

    /// Display networks sorted by numeric likelihood (most likely first)
    pub fn display_networks_sorted(&self, networks: &[WifiNetwork]) {
        if networks.is_empty() {
            println!("No networks found.");
            return;
        }

        let mut sorted_networks: Vec<(usize, &WifiNetwork)> = networks.iter()
            .enumerate()
            .collect();
        
        // Sort by numeric confidence (descending)
        sorted_networks.sort_by(|a, b| {
            b.1.numeric_confidence().partial_cmp(&a.1.numeric_confidence()).unwrap()
        });

        println!("\n{:<4} {:<30} {:<18} {:<10} {:<6} {:<20} {:<12}",
                 "#", "SSID", "BSSID", "Signal", "Ch", "Security", "Numeric?");
        println!("{}", "─".repeat(110));

        for (display_idx, (_original_idx, network)) in sorted_networks.iter().enumerate() {
            let indicator = if network.likely_numeric {
                let confidence = (network.numeric_confidence() * 100.0) as u32;
                format!("✓ {}%", confidence)
            } else {
                String::new()
            };
            
            let ssid_display = if network.ssid.len() > 28 {
                format!("{}...", &network.ssid[..25])
            } else {
                network.ssid.clone()
            };
            
            println!(
                "{:<4} {:<30} {:<18} {:>6} dBm  Ch {:>2}  {:<20} {:<12}",
                display_idx + 1,
                ssid_display,
                &network.bssid,
                network.rssi,
                network.channel,
                &network.security,
                indicator
            );
        }
        println!();
    }

    /// Get most likely numeric password networks
    pub fn get_most_likely_numeric<'a>(&self, networks: &'a [WifiNetwork], limit: usize) -> Vec<&'a WifiNetwork> {
        let mut sorted: Vec<&WifiNetwork> = networks.iter()
            .filter(|n| n.likely_numeric)
            .collect();

        sorted.sort_by(|a, b| {
            b.numeric_confidence().partial_cmp(&a.numeric_confidence()).unwrap()
        });

        sorted.into_iter().take(limit).collect()
    }
}

/// Scan for available WiFi networks (synchronous version)
fn scan_networks_sync() -> Result<Vec<WifiNetwork>> {
    // Try different methods based on OS
    #[cfg(target_os = "macos")]
    {
        scan_networks_macos()
    }

    #[cfg(target_os = "linux")]
    {
        scan_networks_linux()
    }

    #[cfg(target_os = "windows")]
    {
        scan_networks_windows()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(anyhow::anyhow!("Unsupported operating system"))
    }
}

/// Scan WiFi networks on macOS using the airport command
#[cfg(target_os = "macos")]
fn scan_networks_macos() -> Result<Vec<WifiNetwork>> {
    let output = Command::new("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport")
        .arg("-s")
        .output()
        .context("Failed to scan WiFi networks")?;
    
    if !output.status.success() {
        return Err(anyhow::anyhow!("Airport scan failed"));
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_airport_output(&stdout)
}

/// Scan WiFi networks on Linux using nmcli or iwlist
#[cfg(target_os = "linux")]
fn scan_networks_linux() -> Result<Vec<WifiNetwork>> {
    // Try nmcli first
    let output = Command::new("nmcli")
        .args(["-t", "-f", "SSID,BSSID,SIGNAL,SECURITY,CHAN", "device", "wifi", "list"])
        .output()
        .context("Failed to scan WiFi networks with nmcli");
    
    if output.is_ok() {
        let stdout = String::from_utf8_lossy(&output.unwrap().stdout);
        return parse_nmcli_output(&stdout);
    }
    
    // Fallback to iwlist
    let output = Command::new("iwlist")
        .args(["scan"])
        .output()
        .context("Failed to scan WiFi networks with iwlist")?;
    
    if !output.status.success() {
        return Err(anyhow::anyhow!("WiFi scan failed"));
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_iwlist_output(&stdout)
}

/// Scan WiFi networks on Windows using netsh
#[cfg(target_os = "windows")]
fn scan_networks_windows() -> Result<Vec<WifiNetwork>> {
    let output = Command::new("netsh")
        .args(["wlan", "show", "networks", "mode=bssid"])
        .output()
        .context("Failed to scan WiFi networks with netsh")?;
    
    if !output.status.success() {
        return Err(anyhow::anyhow!("WiFi scan failed"));
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_netsh_output(&stdout)
}

/// Parse airport command output (macOS)
#[cfg(target_os = "macos")]
fn parse_airport_output(output: &str) -> Result<Vec<WifiNetwork>> {
    let mut networks = Vec::new();
    let lines: Vec<&str> = output.lines().collect();

    // Skip header line
    for line in lines.iter().skip(1) {
        if line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 6 {
            let ssid = parts[0].to_string();
            let bssid = parts[1].to_string();
            let rssi = parts[2].parse::<i32>().unwrap_or(-100);
            let channel = parts[3].parse::<u32>().unwrap_or(0);
            let security = parts[6..].join(" ");
            let signal_strength = ((rssi + 100) as f64 / 70.0 * 100.0).max(0.0).min(100.0);

            networks.push(WifiNetwork {
                ssid,
                bssid,
                rssi,
                channel,
                security,
                signal_strength,
                likely_numeric: false,
            });
        }
    }

    Ok(networks)
}

/// Parse nmcli output (Linux)
#[cfg(target_os = "linux")]
fn parse_nmcli_output(output: &str) -> Result<Vec<WifiNetwork>> {
    let mut networks = Vec::new();
    
    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }
        
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 5 {
            continue;
        }
        
        let ssid = parts[0].to_string();
        let bssid = parts[1].to_string();
        let signal_strength: f64 = parts[2].parse().unwrap_or(0.0);
        let rssi = (-100 + (signal_strength / 2.0)) as i32; // Convert percentage to dBm
        let security = parts[3].to_string();
        let channel: u32 = parts[4].parse().unwrap_or(1);
        
        networks.push(WifiNetwork {
            ssid,
            bssid,
            rssi,
            channel,
            security,
            signal_strength,
            likely_numeric: false,
        });
    }
    
    Ok(networks)
}

/// Parse iwlist output (Linux fallback)
#[cfg(target_os = "linux")]
fn parse_iwlist_output(output: &str) -> Result<Vec<WifiNetwork>> {
    let mut networks = Vec::new();
    let mut current_network = WifiNetwork {
        ssid: String::new(),
        bssid: String::new(),
        rssi: -100,
        channel: 1,
        security: String::new(),
        signal_strength: 0.0,
        likely_numeric: false,
    };
    
    for line in output.lines() {
        let line = line.trim();
        
        if line.starts_with("Cell") {
            if !current_network.ssid.is_empty() {
                networks.push(current_network.clone());
            }
            current_network = WifiNetwork {
                ssid: String::new(),
                bssid: String::new(),
                rssi: -100,
                channel: 1,
                security: String::new(),
                signal_strength: 0.0,
                likely_numeric: false,
            };
        } else if line.starts_with("ESSID:") {
            if let Some(ssid) = line.split('"').nth(1) {
                current_network.ssid = ssid.to_string();
            }
        } else if line.starts_with("Address:") {
            if let Some(addr) = line.split(':').nth(1) {
                current_network.bssid = addr.trim().to_string();
            }
        } else if line.contains("Signal level") {
            if let Some(level) = line.split('=').nth(1) {
                if let Some(dbm) = level.split(' ').next() {
                    if let Ok(rssi) = dbm.trim().parse::<i32>() {
                        current_network.rssi = rssi;
                        current_network.signal_strength = ((rssi + 100) as f64 / 70.0 * 100.0).max(0.0).min(100.0);
                    }
                }
            }
        } else if line.contains("Encryption key:") {
            if line.contains("on") {
                current_network.security = "WPA/WPA2".to_string();
            } else {
                current_network.security = "Open".to_string();
            }
        }
    }
    
    if !current_network.ssid.is_empty() {
        networks.push(current_network);
    }
    
    Ok(networks)
}

/// Parse netsh output (Windows)
#[cfg(target_os = "windows")]
fn parse_netsh_output(output: &str) -> Result<Vec<WifiNetwork>> {
    let mut networks = Vec::new();
    let mut current_ssid = String::new();
    let mut current_bssid = String::new();
    let mut current_signal = -100i32;
    let mut current_channel = 0u32;
    let mut current_security = String::new();

    for line in output.lines() {
        let line = line.trim();

        if line.starts_with("SSID") && !line.contains("BSSID") {
            if let Some(ssid) = line.split(':').nth(1) {
                current_ssid = ssid.trim().to_string();
            }
        } else if line.starts_with("BSSID") {
            if let Some(bssid) = line.split(':').nth(1) {
                current_bssid = bssid.trim().to_string();
            }
        } else if line.starts_with("Signal") {
            if let Some(signal_str) = line.split(':').nth(1) {
                let signal_str = signal_str.trim().replace("%", "");
                if let Ok(signal) = signal_str.parse::<i32>() {
                    // Convert percentage to dBm (rough approximation)
                    current_signal = -100 + signal / 2;
                }
            }
        } else if line.starts_with("Channel") {
            if let Some(channel_str) = line.split(':').nth(1) {
                if let Ok(channel) = channel_str.trim().parse::<u32>() {
                    current_channel = channel;
                }
            }
        } else if line.starts_with("Authentication") {
            if let Some(auth) = line.split(':').nth(1) {
                current_security = auth.trim().to_string();
            }

            // When we hit authentication, we have all info for this network
            if !current_ssid.is_empty() && !current_bssid.is_empty() {
                let signal_strength = ((current_signal + 100) as f64 / 70.0 * 100.0).max(0.0).min(100.0);
                networks.push(WifiNetwork {
                    ssid: current_ssid.clone(),
                    bssid: current_bssid.clone(),
                    rssi: current_signal,
                    channel: current_channel,
                    security: current_security.clone(),
                    signal_strength,
                    likely_numeric: false,
                });

                // Reset for next network
                current_ssid.clear();
                current_bssid.clear();
            }
        }
    }

    Ok(networks)
}

/// Scan for available WiFi networks (async wrapper for backward compatibility)
pub async fn scan_networks() -> Result<Vec<WifiNetwork>> {
    scan_networks_sync()
}
