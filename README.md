# WiFi Bruteforce Tool 🔐

> Modern desktop application for WPA/WPA2 security testing with real-time feedback

[![Release](https://github.com/maxgfr/bruteforce-wifi/actions/workflows/release.yml/badge.svg)](https://github.com/maxgfr/bruteforce-wifi/releases)
[![CI](https://github.com/maxgfr/bruteforce-wifi/actions/workflows/ci.yml/badge.svg)](https://github.com/maxgfr/bruteforce-wifi/actions)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**⚠️ EDUCATIONAL USE ONLY - UNAUTHORIZED ACCESS IS ILLEGAL ⚠️**

A high-performance, cross-platform desktop GUI application for testing WPA/WPA2 password security through offline bruteforce attacks.

## ✨ Features

- 🖥️ **Modern Desktop GUI** - Built with Iced framework for smooth UX
- 🚀 **Blazing Fast** - Multithreading parallelism with Rayon
- 📡 **WiFi Network Scanning** - Real-time discovery with BSSID/channel detection
- 🎯 **Handshake Capture** - EAPOL frame analysis with visual progress
- 🔑 **Dual Attack Modes**:
  - 🔢 Numeric bruteforce (PIN codes: 8-12 digits)
  - 📋 Wordlist attacks (rockyou.txt, custom lists)
- 📊 **Live Progress** - Real-time speed metrics and ETA
- 🍎 **macOS Native** - Automatic Location Services integration  
- 🪟 **Windows Ready** - Full WinPcap support
- 🔒 **100% Offline** - No data transmitted anywhere

## 📦 Installation

### macOS

Download the latest DMG from [Releases](https://github.com/maxgfr/bruteforce-wifi/releases):

```bash
# Apple Silicon (M1/M2/M3/M4) - Recommended
curl -LO https://github.com/maxgfr/bruteforce-wifi/releases/latest/download/WiFi-Bruteforce-macOS-arm64.dmg

# Intel x86_64
curl -LO https://github.com/maxgfr/bruteforce-wifi/releases/latest/download/WiFi-Bruteforce-macOS-x86_64.dmg
```

**Setup Location Services** (required for BSSID access):
1. Open the DMG and drag to Applications
2. Launch the app - macOS will prompt for Location Services permission
3. Click "Allow" to enable WiFi BSSID scanning

> **Tip**: If the prompt doesn't appear, manually enable in:  
> `System Settings → Privacy & Security → Location Services → WiFi Bruteforce`

**Running Unsigned Applications on macOS**:

Since this app is not signed with an Apple Developer certificate, you'll need to bypass Gatekeeper:

1. **First launch attempt**: Right-click (or Control-click) the app → Select "Open"
2. **If you see "damaged" error**:

   ```bash
   # Remove quarantine attribute
   xattr -d com.apple.quarantine /Applications/WiFi-Bruteforce.app
   
   # If that doesn't work, remove all extended attributes
   xattr -cr /Applications/WiFi-Bruteforce.app
   ```

**Alternative: Build from source** (avoids signing issues):
```bash
git clone https://github.com/maxgfr/bruteforce-wifi.git
cd bruteforce-wifi
cargo build --release
sudo ./target/release/bruteforce-wifi
```

### Windows

Download the ZIP from [Releases](https://github.com/maxgfr/bruteforce-wifi/releases):

```powershell
Invoke-WebRequest -Uri "https://github.com/maxgfr/bruteforce-wifi/releases/latest/download/WiFi-Bruteforce-Windows-x64.zip" -OutFile "WiFi-Bruteforce.zip"
Expand-Archive WiFi-Bruteforce.zip
cd WiFi-Bruteforce
.\bruteforce-wifi.exe
```

**Prerequisites**: Install [Npcap](https://npcap.com/) (modern alternative to WinPcap)

### From Source

```bash
git clone https://github.com/maxgfr/bruteforce-wifi.git
cd bruteforce-wifi
cargo build --release
./target/release/bruteforce-wifi
```

## 🚀 Usage

### Complete Workflow

```
1. Scan Networks → 2. Select Target → 3. Capture Handshake → 4. Crack Password
```

#### 1. **Scan for Networks**

Launch the app and click "Scan Networks" to discover nearby WiFi networks with full details:
- SSID (network name)
- BSSID (MAC address)
- Channel number
- Signal strength
- Security type (WPA/WPA2)

#### 2. **Select & Capture**

Select a network → Click "Continue to Capture"

**Before capturing:**
1. **Choose output location**: Click "Choose Location" to save the .pcap file where you want
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

#### 3. **Crack Password**

Navigate to "Crack" tab:
- **Numeric Attack**: Tests PIN codes (e.g., 00000000-99999999)
- **Wordlist Attack**: Tests passwords from files like rockyou.txt

Real-time stats:
- Progress bar with percentage
- Current attempts / Total
- Passwords per second
- Live logs

## 🛠️ Development

### Prerequisites

- **Rust 1.70+**: Install via [rustup](https://rustup.rs/)
- **macOS**: Xcode Command Line Tools
- **Linux**: `sudo apt install libpcap-dev libxkbcommon-dev libwayland-dev`
- **Windows**: [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/) + WinPcap SDK

### Build Commands

```bash
# Development build with fast compile times
cargo build

# Optimized release build
cargo build --release

# Run the app
cargo run --release

# Format code (enforced by CI)
cargo fmt

# Lint code (enforced by CI)
cargo clippy --all-targets --all-features -- -D warnings

# Run tests
cargo test
```


## 🔒 Security & Legal

### Disclaimer

**THIS TOOL IS FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

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

## 🙏 Acknowledgments

- [Iced](https://github.com/iced-rs/iced) - Cross-platform GUI framework
- [Rayon](https://github.com/rayon-rs/rayon) - Data parallelism library
- [libpcap](https://www.tcpdump.org/) - Packet capture library
- [pcap-rs](https://github.com/rust-pcap/pcap) - Rust bindings for libpcap

## 📄 License

[MIT License](LICENSE) - Use at your own risk