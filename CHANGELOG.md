# Changelog

All notable changes to this project will be documented in this file.

## [1.6.0](https://github.com/maxgfr/brutyfi/compare/v1.5.0...v1.6.0) (2026-01-18)


### ✨ Features

* rename project to BrutyFi and update related references ([296950f](https://github.com/maxgfr/brutyfi/commit/296950f30af779435edefd7f0c11720426660ddb))

## [1.5.0](https://github.com/maxgfr/bruteforce-wifi/compare/v1.4.2...v1.5.0) (2026-01-18)


### ✨ Features

* enhance channel detection and logging during traffic capture ([83a7c8f](https://github.com/maxgfr/bruteforce-wifi/commit/83a7c8f0924db257c3f70855964c0eede745839a))
* update file handling to support .pcap format and enhance capture file selection ([31155c2](https://github.com/maxgfr/bruteforce-wifi/commit/31155c2e9f1cc79ccd794b86137e0781a0de1cce))

## [1.4.2](https://github.com/maxgfr/bruteforce-wifi/compare/v1.4.1...v1.4.2) (2026-01-17)


### 🐛 Bug Fixes

* replace filter and next with find for improved readability in digit extraction ([0357ecc](https://github.com/maxgfr/bruteforce-wifi/commit/0357ecc05545b5fd8501076c0d2cdf6793c83c1b))

## [1.4.1](https://github.com/maxgfr/bruteforce-wifi/compare/v1.4.0...v1.4.1) (2026-01-17)


### 🐛 Bug Fixes

* improve app bundle signing process and update capture instructions for macOS ([e6f68a0](https://github.com/maxgfr/bruteforce-wifi/commit/e6f68a04e91905c96c8ebefdbfe2fee0bbec970f))

## [1.4.0](https://github.com/maxgfr/bruteforce-wifi/compare/v1.3.3...v1.4.0) (2026-01-17)


### ✨ Features

* **macOS:** add launcher script for root privileges and update binary naming ([46a5b64](https://github.com/maxgfr/bruteforce-wifi/commit/46a5b648f1c30b6e5b59037db4e23fa699dd5cab))

## [1.3.3](https://github.com/maxgfr/bruteforce-wifi/compare/v1.3.2...v1.3.3) (2026-01-17)


### 🐛 Bug Fixes

* **ci:** ensure push trigger is defined for main branch ([2994b0e](https://github.com/maxgfr/bruteforce-wifi/commit/2994b0ec1b04e3d51aa3a571dcf72e6534f8f0ed))


### ♻️ Code Refactoring

* **ci,release:** remove push trigger from CI and update semantic-release setup ([49f6a13](https://github.com/maxgfr/bruteforce-wifi/commit/49f6a1353d22d8fef6d3a000409fafdc7b7adb36))

## [1.3.2](https://github.com/maxgfr/bruteforce-wifi/compare/v1.3.1...v1.3.2) (2026-01-17)


### ♻️ Code Refactoring

* **ci:** streamline Clippy command and improve capture logic for non-Windows systems ([5863eb5](https://github.com/maxgfr/bruteforce-wifi/commit/5863eb50c4f6bb28ab282554fb9a5b78873df3e7))

## [1.3.1](https://github.com/maxgfr/bruteforce-wifi/compare/v1.3.0...v1.3.1) (2026-01-17)


### ♻️ Code Refactoring

* **ui,core,ci:** unify scan and capture screens with performance improvements ([a6d4221](https://github.com/maxgfr/bruteforce-wifi/commit/a6d4221375efdbd3a345c748a0317ba0766a9b8f))

## [1.3.0](https://github.com/maxgfr/bruteforce-wifi/compare/v1.2.0...v1.3.0) (2026-01-17)


### ✨ Features

* Enhance CI workflow, improve error handling, and optimize performance across multiple modules ([c66c7cc](https://github.com/maxgfr/bruteforce-wifi/commit/c66c7ccf29741304b05d59315d87b24964974c6c))

## [1.2.0](https://github.com/maxgfr/bruteforce-wifi/compare/v1.1.0...v1.2.0) (2026-01-17)


### ✨ Features

* Enhance handshake loading with panic protection in cracking functions ([2944092](https://github.com/maxgfr/bruteforce-wifi/commit/29440929111b7eb85fcd5bb1e12cbec171d1ffee))
* Implement optimized background workers for password cracking ([e0257c1](https://github.com/maxgfr/bruteforce-wifi/commit/e0257c1dc11e0e7b33b603b213940c50d93de50c))

## [1.1.0](https://github.com/maxgfr/bruteforce-wifi/compare/v1.0.0...v1.1.0) (2026-01-16)


### ✨ Features

* Update dependencies and enhance network scanning functionality ([dc02c1c](https://github.com/maxgfr/bruteforce-wifi/commit/dc02c1c3baf5244eca84544eb5c1bd6f6e9112f6))

## 1.0.0 (2026-01-15)


### ✨ Features

* Add Crack Screen for WPA/WPA2 password cracking ([ce77dd6](https://github.com/maxgfr/bruteforce-wifi/commit/ce77dd6b9e433520dd85711b3837b7f9c0af384a))
* Add direct .pcap file parsing and simplify architecture ([bef5afd](https://github.com/maxgfr/bruteforce-wifi/commit/bef5afd5a5a95e5d804d005ac8d85d9be4266152))
* Add native ARM64 support and improve capture logging ([a42e55c](https://github.com/maxgfr/bruteforce-wifi/commit/a42e55c5216a1affb1bfbae3a3f7bd7246d1b92e))
* Implement CLI for WiFi bruteforce tool with wordlist and numeric modes ([5eb116a](https://github.com/maxgfr/bruteforce-wifi/commit/5eb116aa68b4049eee58bf45de0745fb40800f51))
* Update CLI to target networks by SSID instead of index ([40ddee6](https://github.com/maxgfr/bruteforce-wifi/commit/40ddee648765f2a566c6d292abf826781f9ea21b))


### ⚡ Performance Improvements

* Optimize crypto operations for offline WPA/WPA2 cracking ([33a6669](https://github.com/maxgfr/bruteforce-wifi/commit/33a66697aca4b2fd5031d04d8a68dae4aad74a88))

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and uses [Conventional Commits](https://www.conventionalcommits.org/).
