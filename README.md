# 📡 Bruteforce WiFi

<div align="center">

**⚠️ EDUCATIONAL USE ONLY - UNAUTHORIZED ACCESS IS ILLEGAL ⚠️**

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-macOS%20|%20Linux%20|%20Windows-lightgrey.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**WiFi bruteforce tool - Educational purposes only**

**Performance:** 695M passwords/sec generation | 2000-5000+ pwd/sec bruteforce | **14x faster** 🚀

</div>

---

## 📚 Table of Contents

- [Quick Start](#-quick-start)
- [Features](#-features)
- [Performance](#-performance-benchmarks)
- [Usage](#-usage)
- [Building from Source](#-building-from-source)
- [GitHub Actions & Release](#-github-actions--release)
- [Homebrew Installation](#-homebrew-installation)
- [Security & Legal](#-security--legal)
- [Troubleshooting](#-troubleshooting)

---

## ⚡ Quick Start

### Installation

#### Option 1: Homebrew (macOS/Linux)

```bash
brew tap maxgfr/tap
brew install bruteforce-wifi
```

#### Option 2: From Source (Recommended for best performance)

```bash
# Install Rust if you haven't already
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone and build
git clone https://github.com/maxgfr/bruteforce-wifi.git
cd bruteforce-wifi
cargo build --release

# Binary will be at: target/release/bruteforce-wifi
```

#### Option 3: Ultra-Optimized Build (14x faster!)

```bash
# Build with CPU-specific optimizations for maximum performance
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

### Basic Usage

```bash
# Interactive mode (recommended)
sudo bruteforce-wifi wordlist ./passwords.txt

# Target specific network with numeric combinations (8 digits)
sudo bruteforce-wifi --target 0 numeric --min 8 --max 8

# Show help
bruteforce-wifi --help
```

---

## 🎯 Features

### Two Attack Modes

1. **Wordlist Attack** - Test passwords from a file
   - Supports any text file with one password per line
   - Can use wordlists downloaded from the web
   - Parallel processing for faster testing

2. **Numeric Combination Attack** - Generate and test numeric passwords
   - Generate combinations from 00000000 to 99999999 (configurable range)
   - Useful for networks with numeric passwords
   - Highly optimized for performance

### Intelligent Detection

- 🧠 **Auto-detects WiFi networks** likely to use numeric passwords
  - Recognizes TP-Link, D-Link, Netgear, Sagem, Technicolor, Livebox, Freebox, and more
  - Detects manufacturer MAC addresses (OUI)
  - Identifies common SSID patterns (WIFI_XXXX, BOX_XXXX, etc.)
  - Provides confidence scores for numeric password likelihood
  - Displays top 3 most likely networks

### Cross-Platform Support

- ✅ **macOS** (10.15+ Catalina or later)
- ✅ **Linux** (NetworkManager or wpa_supplicant)
- ✅ **Windows** (10/11)

### Performance

- 🚀 **1000-2400+ passwords/second** (hardware-dependent)
- 🚀 **Adaptive batch sizing** - Dynamically adjusts for optimal throughput
- 🚀 **SIMD-friendly** - Optimized for vectorization
- 🚀 **Cache-optimized** - Data structures designed for L2 cache efficiency
- 🚀 **Lock-free algorithms** - Zero contention with atomic operations
- 🚀 **Memory efficient** - Minimal allocations with parking_lot mutexes
- 🚀 **Work-stealing parallelism** - Perfect CPU utilization with Rayon
- 🚀 **Multi-threaded processing** - Uses all CPU cores by default
- 🚀 **Real-time progress tracking** - Throughput statistics and ETA

---

## 🎮 Usage

### Interactive Mode

```bash
sudo bruteforce-wifi wordlist ./passwords.txt
```

This will:
1. Scan for available WiFi networks
2. Display a list of networks with signal strength and security info
3. Prompt you to select a target network
4. Start the bruteforce attack
5. Display results

### Target Specific Network

```bash
# Target network at index 0 with wordlist
sudo bruteforce-wifi --target 0 wordlist ./passwords.txt

# Target network at index 0 with numeric combinations (8 digits)
sudo bruteforce-wifi --target 0 numeric --min 8 --max 8
```

### Numeric Combination Examples

```bash
# Test 4-digit combinations (0000-9999)
sudo bruteforce-wifi --target 0 numeric --min 4 --max 4

# Test 8-digit combinations (00000000-99999999)
sudo bruteforce-wifi --target 0 numeric --min 8 --max 8

# Test range from 6 to 8 digits
sudo bruteforce-wifi --target 0 numeric --min 6 --max 8
```

### Wordlist Examples

```bash
# Use a wordlist file
sudo bruteforce-wifi --target 0 wordlist ./my_passwords.txt

# Use a downloaded wordlist (e.g., from SecLists)
sudo bruteforce-wifi --target 0 wordlist ./rockyou.txt
```

### Advanced Options

```bash
# Use specific number of threads
sudo bruteforce-wifi --target 0 --threads 16 wordlist ./passwords.txt

# Verbose output
sudo bruteforce-wifi --target 0 --verbose numeric --min 8 --max 8

# Set timeout for each connection attempt
sudo bruteforce-wifi --target 0 --timeout 10 wordlist ./passwords.txt
```

---

## 🔧 Command-Line Options

```
Usage: bruteforce-wifi [OPTIONS] <MODE>

Arguments:
  <MODE>  Bruteforce mode [possible values: wordlist, numeric]

Options:
  -t, --target <INDEX>       Target network index (from scan list)
  -j, --threads <NUM>        Number of threads to use (default: CPU count)
  -T, --timeout <SECONDS>    Timeout in seconds for each connection attempt [default: 5]
  -v, --verbose              Verbose output
  -h, --help                 Print help
  -V, --version              Print version
```

### Wordlist Mode

```
bruteforce-wifi wordlist <FILE>

Arguments:
  <FILE>  Path to wordlist file
```

### Numeric Mode

```
bruteforce-wifi numeric [OPTIONS]

Options:
  -m, --min <DIGITS>  Minimum number of digits [default: 4]
  -M, --max <DIGITS>  Maximum number of digits [default: 8]
```

---

## 🏗️ Building from Source

### Prerequisites

- **Rust 1.70+** (https://rustup.rs)
- **sudo/root access** (for WiFi operations)

### Build

```bash
# Standard build
cargo build --release

# Binary will be at: target/release/bruteforce-wifi
```

### Install System-Wide (Optional)

```bash
# macOS/Linux
sudo cp target/release/bruteforce-wifi /usr/local/bin/

# Linux without sudo (using capabilities)
sudo setcap cap_net_admin+ep /usr/local/bin/bruteforce-wifi
```

---

## 🎯 Cas d'Usage Typique : TP-Link avec Mot de Passe 8 Chiffres

### Contexte

Les routeurs **TP-Link** (et autres marques similaires) sont livrés avec un mot de passe WiFi **par défaut de 8 chiffres numériques**. Ces mots de passe sont imprimés sur une étiquette au dos du routeur.

**Pourquoi c'est pertinent ?**

- ✅ **Très courant** : Millions de routeurs TP-Link, D-Link, Netgear vendus
- ✅ **Rarement changé** : Beaucoup d'utilisateurs gardent le mot de passe par défaut
- ✅ **Espace réduit** : Seulement 100 millions de combinaisons (00000000-99999999)
- ✅ **Bruteforce faisable** : Avec les optimisations, c'est réaliste

### Détection Automatique

L'outil **détecte automatiquement** les réseaux TP-Link :

```bash
sudo bruteforce-wifi wordlist /dev/null
```

Vous verrez :

```text
Available networks:
#    SSID                           BSSID              Signal     Ch   Security             Numeric?
────────────────────────────────────────────────────────────────────────────────────────────────────
1    TP-Link_5GHz                   14:CC:20:XX:XX:XX    -45 dBm  Ch 6   WPA2                 ✓ 80%
2    D-Link_2.4G                    00:1A:2B:XX:XX:XX    -55 dBm  Ch 11  WPA2                 ✓ 60%
3    MyHomeWiFi                     AA:BB:CC:XX:XX:XX    -60 dBm  Ch 1   WPA2

Top 3 networks most likely to have numeric passwords:
  1. TP-Link_5GHz - Confidence: 80%
  2. D-Link_2.4G - Confidence: 60%
```

**Critères de détection :**

- 🔍 Nom contenant "TP-Link", "D-Link", "Netgear", etc.
- 🔍 Adresse MAC (OUI) des fabricants connus
  - TP-Link : `14:CC:20`, `F4:EC:38`, `50:C7:BF`, etc.
  - D-Link : `00:1A:2B`, `00:1E:58`
  - Et 20+ autres fabricants
- 🔍 Patterns dans le SSID (WIFI_XXXX, BOX_XXXX, etc.)

### Exemple Pratique

```bash
# 1. Scanner les réseaux (détection automatique TP-Link)
sudo bruteforce-wifi wordlist /dev/null
# Ctrl+C après avoir vu la liste

# 2. Lancer le bruteforce sur le réseau TP-Link détecté (index 0)
sudo bruteforce-wifi --target 0 numeric --min 8 --max 8
```


### Pourquoi 8 Chiffres ?

Format typique TP-Link : `12345678`, `87654321`, `00112233`, etc.

- ✅ Facile à imprimer sur étiquette
- ✅ Facile à taper (clavier numérique)
- ✅ "Sécurisé" selon les fabricants (100M combinaisons)
- ❌ **Mais bruteforçable** avec cet outil optimisé !

### Protection Recommandée

Si vous avez un routeur TP-Link ou similaire :

1. ✅ **Changez le mot de passe immédiatement**
2. ✅ Utilisez au moins 12 caractères alphanumériques
3. ✅ Activez WPA3 si disponible
4. ✅ Désactivez WPS

---

## 📊 Performance Benchmarks

### Tested on Apple M1 (8 cores)

```text
Password Generation:  695,510,894 passwords/second
Binary Size:          1.0 MB (optimized)
Bruteforce Speed:     2000-5000+ attempts/second (hardware-dependent)
```

---

## 🔧 GitHub Actions & Release

Ce projet utilise GitHub Actions pour automatiser les releases et la mise à jour Homebrew.

### Workflow de Release (`.github/workflows/release.yml`)

Lors d'un push de tag `v*`, le workflow:

1. **Build multi-plateforme**
   - Linux x86_64
   - macOS x86_64
   - macOS ARM64 (Apple Silicon)

2. **Génération automatique**
   - Création des archives `.tar.gz`
   - Calcul des checksums SHA256
   - Upload des artifacts

3. **Création de la release**
   - Notes de release formatées
   - Binaires pour chaque plateforme
   - Fichiers SHA256SUMS

### Créer une Release

```bash
# 1. Update version dans Cargo.toml si nécessaire
# 2. Commit les changements
git add .
git commit -m "Release v1.0.0"
git push origin master

# 3. Créer et pusher le tag
git tag v1.0.0
git push origin v1.0.0
```

Le workflow GitHub Actions se déclenche automatiquement et crée la release !

### Workflow Homebrew (`.github/workflows/update-bruteforce-wifi.yml`)

Déclenché automatiquement après publication d'une release:

1. Télécharge les binaires de la release
2. Calcule les SHA256 pour chaque plateforme
3. Met à jour la formule Homebrew dans `maxgfr/homebrew-tap`
4. Commit et push automatiquement

**Configuration requise**: Secret `HOMEBREW_TAP_TOKEN` avec permissions `repo`

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
- ⚠️ Heavy fines ($10,000+)
- ⚠️ Imprisonment (up to 10 years)

**This tool is for:**
- ✅ Testing YOUR OWN networks
- ✅ Educational purposes
- ✅ Authorized security testing

**NOT for:**
- ❌ Unauthorized access
- ❌ Malicious purposes

**The author is NOT responsible for misuse.**

---

## 📄 License

MIT License - Educational purposes only

See [LICENSE](LICENSE) for details.
