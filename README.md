# BrutiFi 🔐

> Modern desktop application for WPA/WPA2 security testing with real-time feedback

[![Release](https://github.com/maxgfr/bruteforce-wifi/actions/workflows/release.yml/badge.svg)](https://github.com/maxgfr/bruteforce-wifi/releases)
[![CI](https://github.com/maxgfr/bruteforce-wifi/actions/workflows/ci.yml/badge.svg)](https://github.com/maxgfr/bruteforce-wifi/actions)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**⚠️ EDUCATIONAL USE ONLY - UNAUTHORIZED ACCESS IS ILLEGAL ⚠️**

A high-performance, cross-platform desktop GUI application for testing WPA/WPA2 password security through offline bruteforce attacks. Built with Rust and Iced, featuring dual cracking engines (Native CPU and Hashcat GPU) for maximum performance.

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
- 🍎 **macOS Native** - Apple Silicon support
- 🪟 **Windows Ready** - Full Npcap support
- 🐧 **Linux Compatible** - libpcap integration

## 📦 Installation

### macOS

#### Download Pre-built Binary

```bash
# Apple Silicon (M1/M2/M3/M4) - Recommended
curl -LO https://github.com/maxgfr/bruteforce-wifi/releases/latest/download/BrutiFi-*-macOS-arm64.dmg

# Intel x86_64
curl -LO https://github.com/maxgfr/bruteforce-wifi/releases/latest/download/BrutiFi-*-macOS-x86_64.dmg
```

#### Running from the DMG

```bash
hdiutil attach BrutiFi-*-macOS-*.dmg
cp -R "/Volumes/BrutiFi/BrutiFi.app" /Applications/BrutiFi.app
xattr -dr com.apple.quarantine /Applications/BrutiFi.app
sudo /Applications/BrutiFi.app/Contents/MacOS/brutifi
```

#### Build from Source (Recommended for Development)

```bash
git clone https://github.com/maxgfr/bruteforce-wifi.git
cd bruteforce-wifi
cargo build --release

# Run locally
sudo ./target/release/brutifi
```

### Windows

```powershell
Invoke-WebRequest -Uri "https://github.com/maxgfr/bruteforce-wifi/releases/latest/download/WiFi-Bruteforce-Windows-x64.zip" -OutFile "WiFi-Bruteforce.zip"
Expand-Archive WiFi-Bruteforce.zip
cd WiFi-Bruteforce
.\bruteforce-wifi.exe
```

**Prerequisites**: Install [Npcap](https://npcap.com/) (modern alternative to WinPcap)

### Linux

```bash
# Install dependencies
sudo apt install libpcap-dev libxkbcommon-dev libwayland-dev

# Clone and build
git clone https://github.com/maxgfr/bruteforce-wifi.git
cd bruteforce-wifi
cargo build --release
sudo ./target/release/bruteforce-wifi
```

### From Source (All Platforms)

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
- **macOS**: Xcode Command Line Tools
- **Linux**: `sudo apt install libpcap-dev libxkbcommon-dev libwayland-dev`
- **Windows**: [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/) + Npcap SDK

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

### Optional: Hashcat Integration

For GPU-accelerated cracking, install:

```bash
# macOS
brew install hashcat hcxtools

# Linux
sudo apt install hashcat hcxtools

# Windows
# Download from https://hashcat.net/hashcat/
# Download hcxtools from https://github.com/ZerBea/hcxtools
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
