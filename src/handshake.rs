/*!
 * WPA/WPA2 Handshake capture and parsing
 *
 * This module handles the capture and parsing of WPA/WPA2 4-way handshakes.
 * The handshake contains all the information needed to bruteforce the password offline.
 */

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;

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
    /// Create a new handshake from captured data
    pub fn new(
        ssid: String,
        ap_mac: [u8; 6],
        client_mac: [u8; 6],
        anonce: [u8; 32],
        snonce: [u8; 32],
        mic: Vec<u8>,
        eapol_frame: Vec<u8>,
        key_version: u8,
    ) -> Self {
        Self {
            ssid,
            ap_mac,
            client_mac,
            anonce,
            snonce,
            mic,
            eapol_frame,
            key_version,
        }
    }

    /// Save handshake to file (JSON format for simplicity)
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .context("Failed to serialize handshake")?;
        std::fs::write(path, json)
            .context("Failed to write handshake file")?;
        Ok(())
    }

    /// Load handshake from file
    pub fn load_from_file(path: &std::path::Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)
            .context("Failed to read handshake file")?;
        let handshake: Handshake = serde_json::from_str(&json)
            .context("Failed to parse handshake file")?;
        Ok(handshake)
    }

    /// Display handshake information
    pub fn display(&self) {
        println!("WPA/WPA2 Handshake Information:");
        println!("  SSID: {}", self.ssid);
        println!("  AP MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.ap_mac[0], self.ap_mac[1], self.ap_mac[2],
            self.ap_mac[3], self.ap_mac[4], self.ap_mac[5]);
        println!("  Client MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.client_mac[0], self.client_mac[1], self.client_mac[2],
            self.client_mac[3], self.client_mac[4], self.client_mac[5]);
        println!("  Key Version: {}", self.key_version);
        println!("  MIC Length: {} bytes", self.mic.len());
    }
}

/// Parse .cap file to extract WPA/WPA2 handshake
///
/// This function reads a pcap file (captured with airodump-ng, wireshark, etc.)
/// and extracts the WPA/WPA2 4-way handshake EAPOL frames.
pub fn parse_cap_file(path: &std::path::Path, ssid: Option<&str>) -> Result<Handshake> {
    use pcap_parser::*;
    use pcap_parser::traits::PcapReaderIterator;
    use std::io::Cursor;

    let mut file = File::open(path)
        .context("Failed to open .cap file")?;

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .context("Failed to read .cap file")?;

    let mut cursor = Cursor::new(buffer);
    let mut reader = LegacyPcapReader::new(65536, &mut cursor)
        .map_err(|e| anyhow!("Failed to parse pcap file: {:?}", e))?;

    let mut eapol_packets: Vec<EapolPacket> = Vec::new();

    // Read all packets and extract EAPOL frames
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::Legacy(packet) => {
                        if let Some(eapol) = extract_eapol_from_packet(&packet.data) {
                            eapol_packets.push(eapol);
                        }
                    }
                    PcapBlockOwned::LegacyHeader(_) => {},
                    PcapBlockOwned::NG(_) => {},
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => break,
            Err(e) => return Err(anyhow!("Error reading pcap: {:?}", e)),
        }
    }

    if eapol_packets.is_empty() {
        return Err(anyhow!("No EAPOL packets found in .cap file"));
    }

    // Build handshake from EAPOL packets
    build_handshake_from_eapol(&eapol_packets, ssid)
}

/// EAPOL packet structure
#[derive(Debug, Clone)]
struct EapolPacket {
    ap_mac: [u8; 6],
    client_mac: [u8; 6],
    anonce: Option<[u8; 32]>,
    snonce: Option<[u8; 32]>,
    mic: Option<Vec<u8>>,
    eapol_data: Vec<u8>,
    key_version: u8,
    message_type: u8, // 1=M1, 2=M2, 3=M3, 4=M4
}

/// Extract EAPOL packet from raw packet data
fn extract_eapol_from_packet(data: &[u8]) -> Option<EapolPacket> {
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

    // Extract MAC addresses from 802.11 header
    // Address 1: Receiver, Address 2: Transmitter, Address 3: BSSID
    let addr1: [u8; 6] = ieee80211_data[4..10].try_into().ok()?;
    let addr2: [u8; 6] = ieee80211_data[10..16].try_into().ok()?;
    let addr3: [u8; 6] = ieee80211_data[16..22].try_into().ok()?;

    // Determine AP and client MAC
    let (ap_mac, client_mac) = if addr3 == addr1 {
        (addr1, addr2) // AP to Client
    } else {
        (addr2, addr1) // Client to AP
    };

    // Skip to LLC/SNAP header (after 802.11 header + QoS if present)
    let has_qos = (frame_control >> 4) & 0xF == 8;
    let header_len = if has_qos { 26 } else { 24 };

    if ieee80211_data.len() < header_len + 8 {
        return None;
    }

    let llc_data = &ieee80211_data[header_len..];

    // Check for EAPOL (LLC: AA AA 03 00 00 00 88 8E)
    if llc_data.len() < 8 || &llc_data[0..8] != &[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E] {
        return None;
    }

    let eapol_data = &llc_data[8..];
    if eapol_data.len() < 95 {
        return None;
    }

    // Parse EAPOL-Key frame
    // Byte 0: Protocol Version
    // Byte 1: Packet Type (3 = EAPOL-Key)
    if eapol_data[1] != 3 {
        return None;
    }

    // Key Information field at offset 5-6
    let key_info = u16::from_be_bytes([eapol_data[5], eapol_data[6]]);
    let key_version = (key_info & 0x07) as u8;

    // Determine message type from key_info flags
    let key_mic_flag = (key_info & 0x100) != 0;
    let key_ack_flag = (key_info & 0x80) != 0;
    let install_flag = (key_info & 0x40) != 0;

    let message_type = match (key_ack_flag, key_mic_flag, install_flag) {
        (true, false, false) => 1, // M1: ANonce from AP
        (false, true, false) => 2,  // M2: SNonce from client
        (true, true, true) => 3,    // M3: ANonce from AP (retransmit)
        (false, true, false) => 4,  // M4: Final ACK from client
        _ => return None,
    };

    // Extract nonces and MIC
    let mut anonce: Option<[u8; 32]> = None;
    let mut snonce: Option<[u8; 32]> = None;
    let mut mic: Option<Vec<u8>> = None;

    // ANonce at offset 17 (for M1 and M3)
    if message_type == 1 || message_type == 3 {
        if eapol_data.len() >= 49 {
            anonce = Some(eapol_data[17..49].try_into().ok()?);
        }
    }

    // SNonce at offset 17 (for M2)
    if message_type == 2 {
        if eapol_data.len() >= 49 {
            snonce = Some(eapol_data[17..49].try_into().ok()?);
        }
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
    })
}

/// Build complete handshake from EAPOL packets
fn build_handshake_from_eapol(packets: &[EapolPacket], ssid: Option<&str>) -> Result<Handshake> {
    // Find M1 (ANonce) and M2 (SNonce + MIC)
    let m1 = packets.iter()
        .find(|p| p.message_type == 1 && p.anonce.is_some())
        .ok_or_else(|| anyhow!("Message 1 (ANonce) not found in handshake"))?;

    let m2 = packets.iter()
        .find(|p| p.message_type == 2 && p.snonce.is_some() && p.mic.is_some())
        .ok_or_else(|| anyhow!("Message 2 (SNonce + MIC) not found in handshake"))?;

    // Extract data
    let ap_mac = m1.ap_mac;
    let client_mac = m2.client_mac;
    let anonce = m1.anonce.unwrap();
    let snonce = m2.snonce.unwrap();
    let mic = m2.mic.clone().unwrap();
    let key_version = m2.key_version;

    // Use M2 EAPOL frame with MIC zeroed
    let mut eapol_frame = m2.eapol_data.clone();
    if eapol_frame.len() >= 97 {
        // Zero out MIC field (offset 81, length 16)
        for i in 81..97 {
            eapol_frame[i] = 0;
        }
    }

    // Get SSID
    let ssid = ssid
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!(
            "SSID required for WPA/WPA2 cracking.\n\
             Use: bruteforce-wifi crack <method> <file.cap> --ssid <SSID>"
        ))?;

    Ok(Handshake {
        ssid,
        ap_mac,
        client_mac,
        anonce,
        snonce,
        mic,
        eapol_frame,
        key_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_serialization() {
        let handshake = Handshake::new(
            "TestNetwork".to_string(),
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0u8; 32],
            [1u8; 32],
            vec![0xAB; 16],
            vec![0x02; 121],
            2,
        );

        // Test JSON serialization
        let json = serde_json::to_string(&handshake).unwrap();
        let deserialized: Handshake = serde_json::from_str(&json).unwrap();

        assert_eq!(handshake.ssid, deserialized.ssid);
        assert_eq!(handshake.ap_mac, deserialized.ap_mac);
    }
}
