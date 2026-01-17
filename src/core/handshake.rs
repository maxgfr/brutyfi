/*!
 * WPA/WPA2 Handshake capture and parsing
 *
 * This module handles the capture and parsing of WPA/WPA2 4-way handshakes.
 * The handshake contains all the information needed to bruteforce the password offline.
 */

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// WPA/WPA2 4-way handshake data structure
///
/// Contains all necessary information to bruteforce a WPA/WPA2 password offline:
/// - SSID and BSSID (network identifiers)
/// - AP and client MAC addresses
/// - ANonce and SNonce (random nonces from the handshake)
/// - MIC (Message Integrity Code to verify password)
/// - EAPOL frame for MIC calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    /// Network SSID (used in PMK derivation)
    pub ssid: String,

    /// AP MAC address (BSSID)
    pub ap_mac: [u8; 6],

    /// Client/Station MAC address
    pub client_mac: [u8; 6],

    /// Authenticator Nonce (from AP)
    pub anonce: [u8; 32],

    /// Supplicant Nonce (from client)
    pub snonce: [u8; 32],

    /// Message Integrity Code (to verify password correctness)
    pub mic: Vec<u8>,

    /// EAPOL frame (with MIC field zeroed) for MIC calculation
    pub eapol_frame: Vec<u8>,

    /// Key version (1 = HMAC-MD5, 2 = HMAC-SHA1, 3 = AES-CMAC)
    pub key_version: u8,
}

impl Handshake {
    /// Load handshake from file
    pub fn load_from_file(path: &std::path::Path) -> Result<Self> {
        let json = std::fs::read_to_string(path).context("Failed to read handshake file")?;
        let handshake: Handshake =
            serde_json::from_str(&json).context("Failed to parse handshake file")?;
        Ok(handshake)
    }
}

/// Parse .pcap file to extract WPA/WPA2 handshake
///
/// This function reads a pcap file (captured with airodump-ng, wireshark, etc.)
/// and extracts the WPA/WPA2 4-way handshake EAPOL frames.
pub fn parse_cap_file(path: &std::path::Path, ssid: Option<&str>) -> Result<Handshake> {
    // Use pcap crate directly instead of pcap_parser to ensure compatibility
    // with how we write the file (using libpcap via pcap crate)
    let mut pcap =
        pcap::Capture::from_file(path).map_err(|e| anyhow!("Failed to open pcap file: {:?}", e))?;

    let mut eapol_packets: Vec<EapolPacket> = Vec::new();
    let mut bssid_ssid_map: std::collections::HashMap<[u8; 6], String> =
        std::collections::HashMap::new();

    // Read all packets
    while let Ok(packet) = pcap.next_packet() {
        // Try to extract EAPOL
        if let Some(eapol) = extract_eapol_from_packet(packet.data) {
            eapol_packets.push(eapol);
        }

        // Try to extract SSID and BSSID from Beacon
        if let Some((bssid, extracted_ssid)) = extract_bssid_ssid_from_beacon(packet.data) {
            bssid_ssid_map.insert(bssid, extracted_ssid);
        }
    }

    if eapol_packets.is_empty() {
        return Err(anyhow!("No EAPOL packets found in .pcap file"));
    }

    // Build handshake from EAPOL packets with map lookup
    build_handshake_from_eapol(&eapol_packets, ssid, &bssid_ssid_map)
}

/// Extract BSSID and SSID from Beacon frame
fn extract_bssid_ssid_from_beacon(data: &[u8]) -> Option<([u8; 6], String)> {
    // Skip radiotap
    if data.len() < 50 {
        return None;
    }
    let radiotap_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if data.len() < radiotap_len + 24 {
        return None;
    }

    let frame = &data[radiotap_len..];

    // Frame Control: Check for Management frames (Type 0)
    // Beacon = Type 0, Subtype 8 (0x80)
    // Probe Response = Type 0, Subtype 5 (0x50)
    let fc = frame[0];
    let f_type = (fc >> 2) & 0x3;
    let f_subtype = (fc >> 4) & 0xF;

    // Must be management frame (type 0)
    if f_type != 0 {
        return None;
    }

    // Must be Beacon (subtype 8) or Probe Response (subtype 5)
    if f_subtype != 8 && f_subtype != 5 {
        return None;
    }

    // BSSID is Addr3 (offset 16)
    let bssid: [u8; 6] = frame[16..22].try_into().ok()?;

    // Body starts at 24 (Header) + 12 (Fixed Params) = 36
    let mut i = 36;
    while i < frame.len() {
        if i + 2 > frame.len() {
            break;
        }
        let id = frame[i];
        let len = frame[i + 1] as usize;
        let val_start = i + 2;
        let val_end = val_start + len;

        if val_end > frame.len() {
            break;
        }

        if id == 0 {
            // SSID
            if let Ok(s) = std::str::from_utf8(&frame[val_start..val_end]) {
                return Some((bssid, s.to_string()));
            }
        }
        i = val_end;
    }

    None
}

/// EAPOL packet structure
#[derive(Debug, Clone)]
pub struct EapolPacket {
    pub ap_mac: [u8; 6],
    pub client_mac: [u8; 6],
    pub anonce: Option<[u8; 32]>,
    pub snonce: Option<[u8; 32]>,
    pub mic: Option<Vec<u8>>,
    pub eapol_data: Vec<u8>,
    pub key_version: u8,
    pub message_type: u8, // 1=M1, 2=M2, 3=M3, 4=M4
    pub replay_counter: u64,
}

/// Extract EAPOL packet from raw packet data
pub fn extract_eapol_from_packet(data: &[u8]) -> Option<EapolPacket> {
    // Check minimum packet size (radiotap + 802.11 + LLC + EAPOL)
    if data.len() < 100 {
        return None;
    }

    // Skip radiotap header (variable length)
    let radiotap_len = if data.len() >= 4 {
        u16::from_le_bytes([data[2], data[3]]) as usize
    } else {
        return None;
    };

    if data.len() < radiotap_len + 24 {
        return None;
    }

    let ieee80211_data = &data[radiotap_len..];

    // Check for 802.11 data frame (type 2)
    let frame_control = u16::from_le_bytes([ieee80211_data[0], ieee80211_data[1]]);
    let frame_type = (frame_control >> 2) & 0x3;
    if frame_type != 2 {
        return None;
    }

    // Extract ToDS and FromDS flags from frame control
    let to_ds = (frame_control & 0x0100) != 0; // Bit 8
    let from_ds = (frame_control & 0x0200) != 0; // Bit 9

    // Extract MAC addresses from 802.11 header
    let addr1: [u8; 6] = ieee80211_data[4..10].try_into().ok()?;
    let addr2: [u8; 6] = ieee80211_data[10..16].try_into().ok()?;
    let _addr3: [u8; 6] = ieee80211_data[16..22].try_into().ok()?;

    // Determine AP and client MAC based on ToDS/FromDS flags
    // Infrastructure mode (STA <-> AP):
    // - FromDS=1, ToDS=0 (AP → STA/M1,M3): Addr1=Client, Addr2=BSSID(AP), Addr3=SA(AP)
    // - FromDS=0, ToDS=1 (STA → AP/M2,M4): Addr1=BSSID(AP), Addr2=Client, Addr3=DA(AP)
    let (ap_mac, client_mac) = match (to_ds, from_ds) {
        (false, true) => (addr2, addr1), // AP → Client (M1, M3)
        (true, false) => (addr1, addr2), // Client → AP (M2, M4)
        _ => return None,                // Other combinations not expected for EAPOL
    };

    // Skip to LLC/SNAP header (after 802.11 header + QoS if present)
    let has_qos = (frame_control >> 4) & 0xF == 8;
    let header_len = if has_qos { 26 } else { 24 };

    if ieee80211_data.len() < header_len + 8 {
        return None;
    }

    let llc_data = &ieee80211_data[header_len..];

    // Check for EAPOL (LLC: AA AA 03 00 00 00 88 8E)
    if llc_data.len() < 8 || llc_data[0..8] != [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E] {
        return None;
    }

    let eapol_data = &llc_data[8..];
    if eapol_data.len() < 4 {
        return None;
    }

    // Parse EAPOL length to truncate any trailer/padding
    // Byte 2-3: Packet Body Length
    let body_len = u16::from_be_bytes([eapol_data[2], eapol_data[3]]) as usize;
    let total_len = 4 + body_len;

    if eapol_data.len() < total_len {
        return None;
    }

    // Truncate to exact EAPOL length
    let eapol_data = &eapol_data[..total_len];

    // Parse EAPOL-Key frame
    // Byte 0: Protocol Version
    // Byte 1: Packet Type (3 = EAPOL-Key)
    if eapol_data[1] != 3 {
        return None;
    }

    // Key Information field at offset 5-6
    let key_info = u16::from_be_bytes([eapol_data[5], eapol_data[6]]);
    let key_version = (key_info & 0x07) as u8;

    // Replay Counter (8 bytes) at offset 9
    if eapol_data.len() < 17 {
        return None;
    }
    let replay_counter_bytes: [u8; 8] = match eapol_data[9..17].try_into() {
        Ok(bytes) => bytes,
        Err(_) => return None, // Malformed packet
    };
    let replay_counter = u64::from_be_bytes(replay_counter_bytes);

    // Determine message type from key_info flags
    let key_mic_flag = (key_info & 0x100) != 0;
    let key_ack_flag = (key_info & 0x80) != 0;
    let install_flag = (key_info & 0x40) != 0;
    // Secure bit used to distinguish M2 from M4 (sometimes)
    // but relying on just flags can be tricky.
    // M2 usually has Secure=0, M4 has Secure=1.
    // However, for cracking we need SNonce. M2 MUST have SNonce.

    // Simplification for our purpose:
    // M1: Ack=1, Mic=0
    // M2: Ack=0, Mic=1 (Context: Client->AP)
    // M3: Ack=1, Mic=1
    // M4: Ack=0, Mic=1 (Context: Client->AP, typically secure=1)

    let message_type = match (key_ack_flag, key_mic_flag, install_flag) {
        (true, false, false) => 1, // M1: ANonce from AP
        (false, true, false) => {
            // Distinguishing M2 from M4 is hard with just flags.
            // We'll verify later if it has SNonce (required for M2).
            // For now, let's look at the data length or other fields if needed,
            // but we can mark it as M2 (candidate) or check Secure bit if we parsed it.
            // Let's assume it's M2 if we see these flags, extract logic handles content.
            // But to avoid the unreachable pattern warning, we remove M4 line or distinguish.

            // If we assume M2/M4 have same flags, they map to '2' here (or we check secure bit).
            let secure_flag = (key_info & 0x200) != 0;
            if secure_flag {
                4
            } else {
                2
            }
        }
        (true, true, true) => 3, // M3: ANonce from AP (retransmit)
        // (false, true, false) => 4,  // Removed as it overlaps with M2 case above
        _ => return None,
    };

    // Extract nonces and MIC
    let mut anonce: Option<[u8; 32]> = None;
    let mut snonce: Option<[u8; 32]> = None;
    let mut mic: Option<Vec<u8>> = None;

    // ANonce at offset 17 (for M1 and M3)
    if (message_type == 1 || message_type == 3) && eapol_data.len() >= 49 {
        anonce = Some(eapol_data[17..49].try_into().ok()?);
    }

    // SNonce at offset 17 (for M2)
    if message_type == 2 && eapol_data.len() >= 49 {
        snonce = Some(eapol_data[17..49].try_into().ok()?);
    }

    // MIC at offset 81 (16 bytes) - present in M2, M3, M4
    if key_mic_flag && eapol_data.len() >= 97 {
        mic = Some(eapol_data[81..97].to_vec());
    }

    Some(EapolPacket {
        ap_mac,
        client_mac,
        anonce,
        snonce,
        mic,
        eapol_data: eapol_data.to_vec(),
        key_version,
        message_type,
        replay_counter,
    })
}

/// Build complete handshake from EAPOL packets
fn build_handshake_from_eapol(
    packets: &[EapolPacket],
    ssid: Option<&str>,
    bssid_map: &std::collections::HashMap<[u8; 6], String>,
) -> Result<Handshake> {
    // Collect all potential M2 candidates along with their indices
    let m2_candidates: Vec<(usize, &EapolPacket)> = packets
        .iter()
        .enumerate()
        .filter(|(_, p)| p.message_type == 2 && p.snonce.is_some() && p.mic.is_some())
        .collect();

    if m2_candidates.is_empty() {
        return Err(anyhow!("Message 2 (SNonce + MIC) not found in handshake"));
    }

    // Iterate through all M2 candidates to find one with a matching M1
    for (m2_index, m2) in m2_candidates {
        // Find the last M1 (ANonce) that appears BEFORE this M2.
        // This handles retransmissions: M1(A) -> M1(B) -> M2(resp B).
        // We want M1(B), which is the latest one before M2 (and matches Replay Counter).
        let m1_opt = packets[0..m2_index].iter().rev().find(|p| {
            p.message_type == 1 && p.anonce.is_some()
                 && p.ap_mac == m2.ap_mac       // Ensure it's the same session
                 && p.client_mac == m2.client_mac
                 && p.replay_counter == m2.replay_counter
        }); // CRITICAL: Match replay counter

        if let Some(m1) = m1_opt {
            // Found a valid pair! Extract values with proper error handling
            let ap_mac = m1.ap_mac;
            let client_mac = m2.client_mac;

            // These should always be Some due to filter, but handle gracefully
            let anonce = match m1.anonce {
                Some(n) => n,
                None => continue, // Skip to next M2 candidate
            };
            let snonce = match m2.snonce {
                Some(n) => n,
                None => continue,
            };
            let mic = match &m2.mic {
                Some(m) => m.clone(),
                None => continue,
            };
            let key_version = m2.key_version;

            // Use M2 EAPOL frame with MIC zeroed
            let mut eapol_frame = m2.eapol_data.clone();
            if eapol_frame.len() >= 97 {
                // Zero out MIC field (offset 81, length 16)
                for item in eapol_frame.iter_mut().take(97).skip(81) {
                    *item = 0;
                }
            }

            // Determine SSID
            // Priority:
            // 1. SSID provided by user (forces override)
            // 2. SSID found in beacon matching BSSID
            // 3. Error

            let ssid_str = if let Some(s) = ssid {
                // Check if it matches detected (just for warning)
                if let Some(detected) = bssid_map.get(&ap_mac) {
                    if s != detected {
                        println!("\n⚠️  WARNING: Provided SSID '{}' does not match the SSID '{}' broadcasted by the target AP ({:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X})",
                            s, detected, ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
                        println!("   Using provided SSID. If cracking fails, rely on the detected SSID.\n");
                    }
                }
                s.to_string()
            } else {
                match bssid_map.get(&ap_mac) {
                    Some(s) => {
                        println!("✨ Auto-detected SSID for target AP: {}", s);
                        s.clone()
                    },
                    None => return Err(anyhow!("SSID not found for target AP ({:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}). Please provide --ssid.",
                        ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]))
                 }
            };

            return Ok(Handshake {
                ssid: ssid_str,
                ap_mac,
                client_mac,
                anonce,
                snonce,
                mic,
                eapol_frame,
                key_version,
            });
        }
    }

    // If we reach here, we found M2(s) but no matching M1s
    Err(anyhow!("Found valid Message 2 packets, but could not find any corresponding Message 1 (Replay Counter mismatch)"))
}
