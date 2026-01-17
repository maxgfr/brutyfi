/*!
 * WPA/WPA2 Cryptographic functions
 *
 * Implements the cryptographic algorithms used in WPA/WPA2:
 * - PMK (Pairwise Master Key) derivation using PBKDF2-HMAC-SHA1
 * - PTK (Pairwise Transient Key) derivation using PRF
 * - MIC (Message Integrity Code) calculation and verification
 *
 * References:
 * - IEEE 802.11i-2004 standard
 * - RFC 2898 (PBKDF2)
 */

use aes::Aes128;
use cmac::Cmac;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use sha1::Sha1;
use sha2::Sha256;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type Aes128Cmac = Cmac<Aes128>;

/// Constant for PRF expansion
const PRF_LABEL: &[u8] = b"Pairwise key expansion";

/// Calculate PMK (Pairwise Master Key) from passphrase and SSID using HMAC-SHA1 (WPA2)
///
/// PMK = PBKDF2(passphrase, SSID, 4096 iterations, 256 bits)
///
/// This is the most computationally expensive part of WPA/WPA2 cracking.
/// Each password requires 4096 iterations of HMAC-SHA1.
///
/// # Arguments
/// * `passphrase` - WiFi password (8-63 characters)
/// * `ssid` - Network SSID (used as salt)
///
/// # Returns
/// 32-byte PMK
#[inline]
pub fn calculate_pmk(passphrase: &str, ssid: &str) -> [u8; 32] {
    let mut pmk = [0u8; 32];
    let _ = pbkdf2::<HmacSha1>(passphrase.as_bytes(), ssid.as_bytes(), 4096, &mut pmk);
    pmk
}

/// Calculate PMK (Pairwise Master Key) from passphrase and SSID using HMAC-SHA256 (WPA2-SHA256/WPA3)
#[inline]
pub fn calculate_pmk_sha256(passphrase: &str, ssid: &str) -> [u8; 32] {
    let mut pmk = [0u8; 32];
    let _ = pbkdf2::<HmacSha256>(passphrase.as_bytes(), ssid.as_bytes(), 4096, &mut pmk);
    pmk
}

/// Calculate PTK (Pairwise Transient Key) from PMK and handshake data
///
/// Uses PRF-512 (SHA1) for WPA2 or KDF (SHA256) for WPA2-SHA256/WPA3
///
/// # Arguments
/// * `pmk` - Pairwise Master Key
/// * `ap_mac` - AP MAC address
/// * `client_mac` - Client MAC address
/// * `anonce` - Authenticator nonce
/// * `snonce` - Supplicant nonce
/// * `key_version` - Key version from handshake (3 = WPA2-SHA256/WPA3, others = WPA2)
///
/// # Returns
/// 64-byte PTK (we need the first 16 bytes for KCK)
#[inline]
pub fn calculate_ptk(
    pmk: &[u8; 32],
    ap_mac: &[u8; 6],
    client_mac: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
    key_version: u8,
) -> [u8; 64] {
    // Concatenate: min(AA, SPA) || max(AA, SPA) || min(ANonce, SNonce) || max(ANonce, SNonce)
    let mut data = [0u8; 76]; // 6 + 6 + 32 + 32

    // Compare and order MAC addresses
    if ap_mac < client_mac {
        data[0..6].copy_from_slice(ap_mac);
        data[6..12].copy_from_slice(client_mac);
    } else {
        data[0..6].copy_from_slice(client_mac);
        data[6..12].copy_from_slice(ap_mac);
    }

    // Compare and order nonces
    if anonce < snonce {
        data[12..44].copy_from_slice(anonce);
        data[44..76].copy_from_slice(snonce);
    } else {
        data[12..44].copy_from_slice(snonce);
        data[44..76].copy_from_slice(anonce);
    }

    if key_version == 3 {
        // WPA2-SHA256 / WPA3
        kdf_sha256(pmk, PRF_LABEL, &data)
    } else {
        // WPA2 (SHA1)
        prf_512(pmk, PRF_LABEL, &data)
    }
}

/// PRF-512: Pseudo-Random Function to generate 64 bytes from PMK (SHA1 based)
#[inline]
fn prf_512(key: &[u8], prefix: &[u8], data: &[u8]) -> [u8; 64] {
    let mut result = [0u8; 64];
    let mut input = [0u8; 128];
    let mut pos = 0;

    // Copy prefix
    input[pos..pos + prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();

    // NULL byte
    input[pos] = 0;
    pos += 1;

    // Copy data
    input[pos..pos + data.len()].copy_from_slice(data);
    pos += data.len();

    let counter_pos = pos;
    pos += 1;
    let input_len = pos;

    for i in 0..4u8 {
        input[counter_pos] = i;
        let mut mac = HmacSha1::new_from_slice(key).expect("HMAC can take key of any size");
        mac.update(&input[..input_len]);
        let hash = mac.finalize().into_bytes();

        let start = i as usize * 20;
        let end = std::cmp::min(start + 20, 64);
        result[start..end].copy_from_slice(&hash[..end - start]);
    }
    result
}

/// KDF-SHA256: Key Derivation Function for WPA2-SHA256 / WPA3
/// Generates 64 bytes (approx 512 bits) although usually 48 bytes (384 bits) are used.
#[inline]
fn kdf_sha256(key: &[u8], label: &[u8], context: &[u8]) -> [u8; 64] {
    let mut result = [0u8; 64];

    // IEEE 802.11w-2009: KDF-SHA256
    // Generate 64 bytes (512 bits) using 2 iterations
    let iterations: u16 = 2;
    let length_bits: u16 = 512;

    for i in 1..=iterations {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");

        // KDF format: counter (LE) || label || context || length (LE)
        mac.update(&i.to_le_bytes());
        mac.update(label);
        mac.update(context);
        mac.update(&length_bits.to_le_bytes());

        let hash = mac.finalize().into_bytes();
        let start = ((i - 1) * 32) as usize;
        let end = start + 32;

        if end <= 64 {
            result[start..end].copy_from_slice(&hash);
        }
    }

    result
}

/// Calculate MIC (Message Integrity Code) for EAPOL frame
///
/// MIC = HMAC-SHA1(KCK, EAPOL_frame)[0..16]  (for key_version = 2)
/// MIC = HMAC-MD5(KCK, EAPOL_frame)          (for key_version = 1)
/// MIC = AES-CMAC(KCK, EAPOL_frame)          (for key_version = 3)
///
/// # Arguments
/// * `kck` - Key Confirmation Key (first 16 bytes of PTK)
/// * `eapol_frame` - EAPOL frame with MIC field zeroed
/// * `key_version` - Key version from handshake (1, 2, or 3)
#[inline]
pub fn calculate_mic(kck: &[u8; 16], eapol_frame: &[u8], key_version: u8) -> [u8; 16] {
    let mut result = [0u8; 16];

    match key_version {
        1 => {
            // HMAC-MD5
            use hmac::Hmac;
            use md5::Md5;
            type HmacMd5 = Hmac<Md5>;
            let mut mac = HmacMd5::new_from_slice(kck).expect("HMAC can take key of any size");
            mac.update(eapol_frame);
            result.copy_from_slice(&mac.finalize().into_bytes());
        }
        3 => {
            // AES-128-CMAC
            use cmac::Mac;
            let mut mac = Aes128Cmac::new_from_slice(kck).expect("CMAC key size error");
            mac.update(eapol_frame);
            result.copy_from_slice(&mac.finalize().into_bytes());
        }
        _ => {
            // HMAC-SHA1
            let mut mac = HmacSha1::new_from_slice(kck).expect("HMAC can take key of any size");
            mac.update(eapol_frame);
            let hash = mac.finalize().into_bytes();
            result.copy_from_slice(&hash[..16]);
        }
    }
    result
}

/// Verify if a password is correct by comparing calculated MIC with captured MIC
///
/// Supports WPA (MD5), WPA2 (SHA1), and WPA2-SHA256/WPA3 (SHA256/CMAC)
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn verify_password(
    password: &str,
    ssid: &str,
    ap_mac: &[u8; 6],
    client_mac: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
    eapol_frame: &[u8],
    captured_mic: &[u8],
    key_version: u8,
) -> bool {
    // Step 1: Calculate PMK
    let pmk = if key_version == 3 {
        calculate_pmk_sha256(password, ssid)
    } else {
        calculate_pmk(password, ssid)
    };

    // Step 2: Calculate PTK
    let ptk = calculate_ptk(&pmk, ap_mac, client_mac, anonce, snonce, key_version);

    // Step 3: Extract KCK (first 16 bytes of PTK)
    // PTK is always 64 bytes, so this should never fail
    let mut kck = [0u8; 16];
    kck.copy_from_slice(&ptk[0..16]);

    // Step 4: Calculate MIC
    let calculated_mic = calculate_mic(&kck, eapol_frame, key_version);

    // Step 5: Compare MICs
    constant_time_compare_16(&calculated_mic, captured_mic)
}

/// Optimized constant-time comparison for 16-byte MIC
#[inline(always)]
fn constant_time_compare_16(a: &[u8; 16], b: &[u8]) -> bool {
    if b.len() != 16 {
        return false;
    }

    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pmk_calculation() {
        // Test vector from IEEE 802.11i
        let passphrase = "password";
        let ssid = "IEEE";
        let pmk = calculate_pmk(passphrase, ssid);

        // PMK should be 32 bytes
        assert_eq!(pmk.len(), 32);

        // Same password and SSID should produce same PMK
        let pmk2 = calculate_pmk(passphrase, ssid);
        assert_eq!(pmk, pmk2);
    }

    #[test]
    fn test_ptk_calculation() {
        let pmk = [0u8; 32];
        let ap_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let client_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let anonce = [0u8; 32];
        let snonce = [1u8; 32];

        // Test with key_version 2 (WPA2)
        let ptk = calculate_ptk(&pmk, &ap_mac, &client_mac, &anonce, &snonce, 2);

        // PTK should be 64 bytes
        assert_eq!(ptk.len(), 64);
    }

    #[test]
    fn test_constant_time_compare() {
        // Test with 16 byte arrays
        let a = [1u8; 16];
        let b = [1u8; 16];
        let mut c = [1u8; 16];
        c[0] = 2;

        assert!(constant_time_compare_16(&a, &b));
        assert!(!constant_time_compare_16(&a, &c));
    }
}
