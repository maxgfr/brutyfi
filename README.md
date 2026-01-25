# BrutiFi 🔐

> Modern desktop application for WPA/WPA2 security testing on macOS with real-time feedback

[![Release](https://github.com/maxgfr/bruteforce-wifi/actions/workflows/release.yml/badge.svg)](https://github.com/maxgfr/bruteforce-wifi/releases)
[![CI](https://github.com/maxgfr/bruteforce-wifi/actions/workflows/ci.yml/badge.svg)](https://github.com/maxgfr/bruteforce-wifi/actions)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**⚠️ EDUCATIONAL USE ONLY - UNAUTHORIZED ACCESS IS ILLEGAL ⚠️**

A high-performance macOS desktop GUI application for testing WPA/WPA2 password security through offline bruteforce attacks. Built with Rust and Iced, featuring dual cracking engines (Native CPU and Hashcat GPU) for maximum performance.

## ✨ Features

### Core Capabilities

- 🖥️ **Modern Desktop GUI** - Built with Iced framework for smooth, native experience
- 🚀 **Dual Cracking Engines**:
  - **Native CPU**: Custom PBKDF2 implementation with Rayon parallelism (~10K-100K passwords/sec)
  - **Hashcat GPU**: 10-100x faster acceleration with automatic device detection
- 📡 **WiFi Network Scanning** - Real-time discovery with channel detection
- 🎯 **Handshake Capture** - EAPOL frame analysis with visual progress indicators
- 🔑 **Dual Attack Modes**:
  - 🔢 Numeric bruteforce (PIN codes: 8-12 digits)
  - 📋 Wordlist attacks (rockyou.txt, custom lists)
- 📊 **Live Progress** - Real-time speed metrics, attempt counters, and ETA
- 🔒 **100% Offline** - No data transmitted anywhere

### Platform Support
- 🍎 **macOS Native** - Apple Silicon and Intel support

## 📦 Installation

### macOS

#### Quick Installation

1. Download the DMG from the latest release (Apple Silicon or Intel).
2. Open the DMG and drag **BrutiFi.app** to **Applications**.
3. Launch the app — macOS will ask for the admin (root) password at startup to enable capture.

#### Remove Quarantine Attribute (Required for GitHub downloads)

When downloading from GitHub, macOS adds a quarantine attribute. You must remove it to launch the app:

```bash
xattr -dr com.apple.quarantine /Applications/BrutiFi.app
```

> This removes security warnings, but WiFi capture in monitor mode still requires root privileges on macOS.

### From Source

```bash
git clone https://github.com/maxgfr/bruteforce-wifi.git
cd bruteforce-wifi
cargo build --release
./target/release/bruteforce-wifi
```

## 🚀 Usage

### Complete Workflow

```text
1. Scan Networks → 2. Select Target → 3. Capture Handshake → 4. Crack Password
```

### Step 1: Scan for Networks

Launch the app and click "Scan Networks" to discover nearby WiFi networks:

- **SSID** (network name)
- **Channel number**
- **Signal strength**
- **Security type** (WPA/WPA2)

### Step 2: Select & Capture Handshake

Select a network → Click "Continue to Capture"

**Before capturing:**

1. **Choose output location**: Click "Choose Location" to save the .pcap file
   - Default: `capture.pcap` in current directory
   - Recommended: Save to Documents or Desktop for easy access
2. **Disconnect from WiFi** (macOS only):
   - Option+Click WiFi icon → "Disconnect"
   - This improves capture reliability

Then click "Start Capture"

The app monitors for the WPA/WPA2 4-way handshake:

- ✅ **M1** - ANonce (from AP)
- ✅ **M2** - SNonce + MIC (from client)
- 🎉 **Handshake Complete!**

> **macOS Note**: Deauth attacks don't work on Apple Silicon. Manually reconnect a device to trigger the handshake (turn WiFi off/on on your phone).

### Step 3: Crack Password

Navigate to "Crack" tab:

#### Engine Selection

- **Native CPU**: Software-only cracking, works everywhere
- **Hashcat GPU**: Requires hashcat + hcxtools installed, 10-100x faster

#### Attack Methods

- **Numeric Attack**: Tests PIN codes (e.g., 00000000-99999999)
- **Wordlist Attack**: Tests passwords from files like rockyou.txt

#### Real-time Stats

- Progress bar with percentage
- Current attempts / Total
- Passwords per second
- Live logs (copyable)

## 🛠️ Development

### Prerequisites

- **Rust 1.70+**: Install via [rustup](https://rustup.rs/)
- **Xcode Command Line Tools**: `xcode-select --install`

### Build Commands

```bash
# Development build with fast compile times
cargo build

# Optimized release build
cargo build --release

# Run the app
cargo run --release

# Format code (enforced by CI)
cargo fmt --all

# Lint code (enforced by CI)
cargo clippy --all-targets --all-features -- -D warnings

# Run tests
cargo test
```

### Build macOS DMG (Local)

You can build a macOS DMG installer locally from the source code:

```bash
# Build DMG (automatically detects architecture)
./scripts/build_dmg.sh
```

This will create:
- `BrutiFi-{VERSION}-macOS-arm64.dmg` (Apple Silicon)
- `BrutiFi-{VERSION}-macOS-arm64.dmg.sha256` (checksum)

**Note**: The application is signed with ad-hoc signing by default, which is sufficient for local use and testing. No additional code signing is required.

### Optional: Hashcat Integration

For GPU-accelerated cracking, install:

```bash
brew install hashcat hcxtools
```

## 🔐 Security & Legal

### Disclaimer

#### Educational Use Only

This tool is for educational and authorized testing only.

✅ **Legal Uses:**

- Testing your own WiFi network security
- Authorized penetration testing with written permission
- Security research and education
- CTF competitions and challenges

❌ **Illegal Activities:**

- Unauthorized access to networks you don't own
- Intercepting communications without permission
- Any malicious or unauthorized use

**Unauthorized access to computer networks is a criminal offense** in most jurisdictions (CFAA in USA, Computer Misuse Act in UK, etc.). Always obtain explicit written permission before testing.

## 🙏 Acknowledgments & inspiration

This project was inspired by several groundbreaking tools in the WiFi security space:

- [AirJack](https://github.com/rtulke/AirJack) - As `brutifi` but in a Python-based CLI
- [Aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) - Industry-standard WiFi
- [Pyrit](https://github.com/JPaulMora/Pyrit) - Pre-computed tables for WPA-PSK attacks
- [Cowpatty](https://github.com/joswr1ght/cowpatty) - Early WPA-PSK cracking implementation

These tools demonstrated the feasibility of offline WPA/WPA2 password attacks and inspired the creation of a modern, user-friendly desktop application.

Special thanks to the following libraries and tools:

- [Iced](https://github.com/iced-rs/iced) - Cross-platform GUI framework
- [Rayon](https://github.com/rayon-rs/rayon) - Data parallelism library
- [pcap-rs](https://github.com/rust-pcap/pcap) - Rust bindings for libpcap
- [Hashcat](https://github.com/hashcat/hashcat) - GPU-accelerated password recovery
- [hcxtools](https://github.com/ZerBea/hcxtools) - Wireless security auditing tools

## 📄 License

[MIT License](LICENSE) - Use at your own risk
