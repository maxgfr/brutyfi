/*!
 * Main application state and logic
 *
 * Manages the application state machine and handles all messages.
 */

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use iced::time;
use iced::widget::{button, column, container, horizontal_rule, row, text, text_editor};
use iced::{clipboard, Element, Length, Subscription, Task, Theme};
use pcap::Device;
use serde::{Deserialize, Serialize};

use crate::screens::{CrackEngine, CrackMethod, CrackScreen, HandshakeProgress, ScanCaptureScreen};
use crate::theme::colors;
use crate::workers::{
    self, CaptureParams, CaptureState, CrackState, NumericCrackParams, ScanResult,
    WordlistCrackParams,
};
use crate::workers_optimized;
use brutifi::WifiNetwork;

/// Application screens
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screen {
    #[default]
    ScanCapture,
    Crack,
}

/// Application messages
#[derive(Debug, Clone)]
pub enum Message {
    // Navigation
    GoToScanCapture,
    GoToCrack,

    // Scan & Capture screen
    StartScan,
    StopScan,
    ResetScanState,
    ScanComplete(ScanResult),
    SelectNetwork(usize),
    SelectChannel(String),
    InterfaceSelected(String),
    BrowseCaptureFile,
    CaptureFileSelected(Option<PathBuf>),
    DownloadCapturedPcap,
    SaveCapturedPcap(Option<PathBuf>),
    DisconnectWifi,
    WifiDisconnectResult(Result<(), String>),
    CopyLogsToClipboard,
    StartCapture,
    StopCapture,
    CaptureProgress(workers::CaptureProgress),
    #[allow(dead_code)]
    EnableAdminMode,

    // Crack screen
    UseCapturedFileToggled(bool),
    HandshakePathChanged(String),
    EngineChanged(CrackEngine),
    MethodChanged(CrackMethod),
    MinDigitsChanged(String),
    MaxDigitsChanged(String),
    WordlistPathChanged(String),
    BrowseHandshake,
    BrowseWordlist,
    HandshakeSelected(Option<PathBuf>),
    WordlistSelected(Option<PathBuf>),
    StartCrack,
    StopCrack,
    CrackProgress(workers::CrackProgress),
    CopyPassword,
    CopyLogs,
    LogsEditorAction(text_editor::Action),
    #[allow(dead_code)]
    ReturnToNormalMode,

    // General
    Tick,
}

/// Main application state
pub struct BruteforceApp {
    screen: Screen,
    scan_capture_screen: ScanCaptureScreen,
    crack_screen: CrackScreen,
    is_root: bool,
    capture_state: Option<Arc<CaptureState>>,
    capture_progress_rx: Option<tokio::sync::mpsc::UnboundedReceiver<workers::CaptureProgress>>,
    crack_state: Option<Arc<CrackState>>,
    crack_progress_rx: Option<tokio::sync::mpsc::UnboundedReceiver<workers::CrackProgress>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedState {
    version: u32,
    scan: PersistedScanState,
    capture: PersistedCaptureState,
    crack: PersistedCrackState,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedScanState {
    networks: Vec<WifiNetwork>,
    selected_network: Option<usize>,
    selected_interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedCaptureState {
    target_network: Option<WifiNetwork>,
    output_file: String,
    handshake_complete: bool,
    packets_captured: u64,
    last_saved_capture_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedCrackState {
    handshake_path: String,
    use_captured_file: bool,
    ssid: String,
    engine: CrackEngine,
    method: CrackMethod,
    min_digits: String,
    max_digits: String,
    wordlist_path: String,
    threads: usize,
}

impl BruteforceApp {
    pub fn new(is_root: bool) -> (Self, Task<Message>) {
        let interface_list = list_interfaces();
        let selected_interface = choose_default_interface(&interface_list);

        #[cfg(target_os = "macos")]
        {
            let mut app = Self {
                screen: Screen::ScanCapture,
                scan_capture_screen: ScanCaptureScreen {
                    interface_list,
                    selected_interface,
                    ..ScanCaptureScreen::default()
                },
                crack_screen: CrackScreen::default(),
                is_root,
                capture_state: None,
                capture_progress_rx: None,
                crack_state: None,
                crack_progress_rx: None,
            };

            if let Some(persisted) = load_persisted_state() {
                app.apply_persisted_state(persisted);
            }

            if let Ok(screen) = std::env::var("BRUTIFI_START_SCREEN") {
                if screen.eq_ignore_ascii_case("crack") {
                    app.screen = Screen::Crack;
                } else if screen.eq_ignore_ascii_case("scan")
                    || screen.eq_ignore_ascii_case("capture")
                {
                    app.screen = Screen::ScanCapture;
                }
            }

            if let Ok(path) = std::env::var("BRUTIFI_HANDSHAKE_PATH") {
                if !path.is_empty() {
                    app.crack_screen.handshake_path = path;
                }
            }

            if let Ok(ssid) = std::env::var("BRUTIFI_SSID") {
                if !ssid.is_empty() {
                    app.crack_screen.ssid = ssid;
                }
            }

            if let Ok(val) = std::env::var("BRUTIFI_USE_CAPTURED") {
                app.crack_screen.use_captured_file = val == "1" || val.eq_ignore_ascii_case("true");
            }

            if let Ok(path) = std::env::var("BRUTIFI_WORDLIST_PATH") {
                if !path.is_empty() {
                    app.crack_screen.wordlist_path = path;
                }
            }

            let auto_capture = std::env::var("BRUTIFI_AUTO_CAPTURE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);

            // Optional auto-capture
            if auto_capture
                && is_root
                && app.screen == Screen::ScanCapture
                && app.scan_capture_screen.target_network.is_some()
            {
                (app, Task::done(Message::StartCapture))
            } else {
                (app, Task::none())
            }
        }

        #[cfg(not(target_os = "macos"))]
        {
            let mut app = Self {
                screen: Screen::ScanCapture,
                scan_capture_screen: ScanCaptureScreen {
                    interface_list,
                    selected_interface,
                    ..ScanCaptureScreen::default()
                },
                crack_screen: CrackScreen::default(),
                is_root,
                capture_state: None,
                capture_progress_rx: None,
                crack_state: None,
                crack_progress_rx: None,
            };

            if let Some(persisted) = load_persisted_state() {
                app.apply_persisted_state(persisted);
            }

            (app, Task::none())
        }
    }

    pub fn theme(&self) -> Theme {
        Theme::Dark
    }

    pub fn subscription(&self) -> Subscription<Message> {
        // Poll for capture and crack progress updates
        // Reduced from 100ms to 50ms for more responsive UI while maintaining performance
        if self.capture_progress_rx.is_some() || self.crack_progress_rx.is_some() {
            time::every(std::time::Duration::from_millis(50)).map(|_| Message::Tick)
        } else {
            Subscription::none()
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            // Navigation
            Message::GoToScanCapture => {
                self.screen = Screen::ScanCapture;
                Task::none()
            }
            Message::GoToCrack => {
                // Stop capture if currently capturing
                if self.scan_capture_screen.is_capturing {
                    if let Some(ref state) = self.capture_state {
                        state.stop();
                    }
                    self.scan_capture_screen.is_capturing = false;
                    self.capture_state = None;
                    self.capture_progress_rx = None;

                    // Add log message about stopping capture
                    self.scan_capture_screen
                        .log_messages
                        .push("⏹️ Capture stopped (navigated to crack screen)".to_string());
                    if self.scan_capture_screen.log_messages.len() > 50 {
                        self.scan_capture_screen.log_messages.remove(0);
                    }
                    let logs_text = self.scan_capture_screen.log_messages.join("\n");
                    self.scan_capture_screen.logs_content =
                        text_editor::Content::with_text(&logs_text);

                    self.persist_state();
                }

                #[cfg(target_os = "macos")]
                if self.is_root {
                    let mut envs = Vec::new();
                    envs.push(("BRUTIFI_START_SCREEN", "crack".to_string()));
                    if !self.scan_capture_screen.output_file.is_empty() {
                        envs.push((
                            "BRUTIFI_HANDSHAKE_PATH",
                            self.scan_capture_screen.output_file.clone(),
                        ));
                    }
                    if let Some(ref network) = self.scan_capture_screen.target_network {
                        if !network.ssid.is_empty() {
                            envs.push(("BRUTIFI_SSID", network.ssid.clone()));
                        }
                    }
                    envs.push((
                        "BRUTIFI_USE_CAPTURED",
                        if self.crack_screen.use_captured_file {
                            "1".to_string()
                        } else {
                            "0".to_string()
                        },
                    ));
                    if !self.crack_screen.wordlist_path.is_empty() {
                        envs.push((
                            "BRUTIFI_WORDLIST_PATH",
                            self.crack_screen.wordlist_path.clone(),
                        ));
                    }

                    if crate::relaunch_as_user(&envs) {
                        std::process::exit(0);
                    }

                    self.crack_screen.error_message = Some(
                        "Failed to return to normal mode. Please restart the app manually."
                            .to_string(),
                    );
                }

                // Set handshake path from capture only if using captured file
                if self.crack_screen.use_captured_file {
                    if let Some(ref saved) = self.scan_capture_screen.last_saved_capture_path {
                        if !saved.is_empty() {
                            self.crack_screen.handshake_path = saved.clone();
                        }
                    } else if !self.scan_capture_screen.output_file.is_empty() {
                        self.crack_screen.handshake_path =
                            self.scan_capture_screen.output_file.clone();
                    }
                }
                // Set SSID from captured network
                if let Some(ref network) = self.scan_capture_screen.target_network {
                    self.crack_screen.ssid = network.ssid.clone();
                }

                // Only reset crack screen state if NOT currently cracking AND no results to show
                // This preserves logs when navigating back to the crack screen after a crack
                let has_results = self.crack_screen.found_password.is_some()
                    || self.crack_screen.password_not_found
                    || self.crack_screen.error_message.is_some();

                if !self.crack_screen.is_cracking && !has_results {
                    self.crack_screen.error_message = None;
                    self.crack_screen.found_password = None;
                    self.crack_screen.password_not_found = false;
                    self.crack_screen.current_attempts = 0;
                    self.crack_screen.progress = 0.0;
                    self.crack_screen.log_messages.clear();
                    self.crack_screen.logs_content = text_editor::Content::new();
                }

                self.screen = Screen::Crack;
                Task::none()
            }

            // Scan & Capture screen
            Message::StartScan => {
                self.scan_capture_screen.is_scanning = true;
                self.scan_capture_screen.error_message = None;

                let interface = self.scan_capture_screen.selected_interface.clone();
                Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || workers::scan_networks_async(interface))
                            .await
                            .unwrap_or(ScanResult::Error("Task failed".to_string()))
                    },
                    Message::ScanComplete,
                )
            }
            Message::StopScan => {
                self.scan_capture_screen.is_scanning = false;
                Task::none()
            }
            Message::ResetScanState => {
                if let Some(ref state) = self.capture_state {
                    state.stop();
                }
                self.capture_state = None;
                self.capture_progress_rx = None;

                let interface_list = self.scan_capture_screen.interface_list.clone();
                let selected_interface = self.scan_capture_screen.selected_interface.clone();
                self.scan_capture_screen = ScanCaptureScreen {
                    interface_list,
                    selected_interface,
                    ..ScanCaptureScreen::default()
                };
                self.persist_state();
                Task::none()
            }
            Message::ScanComplete(result) => {
                self.scan_capture_screen.is_scanning = false;
                match result {
                    ScanResult::Success(networks) => {
                        self.scan_capture_screen.networks = networks;
                        self.scan_capture_screen.selected_network = None;
                    }
                    ScanResult::Error(msg) => {
                        self.scan_capture_screen.error_message = Some(msg);
                    }
                }
                self.persist_state();
                Task::none()
            }
            Message::SelectNetwork(idx) => {
                self.scan_capture_screen.selected_network = Some(idx);
                // Also set target network for capture
                if let Some(network) = self.scan_capture_screen.networks.get(idx) {
                    self.scan_capture_screen.target_network = Some(network.clone());
                    self.scan_capture_screen.handshake_progress = HandshakeProgress::default();
                    self.scan_capture_screen.handshake_complete = false;
                    // Reset bits captured
                    self.scan_capture_screen.packets_captured = 0;

                    // Extract available channels from the network
                    let channels: Vec<String> = network
                        .channel
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect();

                    self.scan_capture_screen.available_channels = channels.clone();

                    // Auto-select first channel if multiple
                    if channels.len() == 1 {
                        self.scan_capture_screen.selected_channel = Some(channels[0].clone());
                    } else {
                        self.scan_capture_screen.selected_channel = None;
                    }
                }
                self.persist_state();
                Task::none()
            }
            Message::SelectChannel(channel) => {
                self.scan_capture_screen.selected_channel = Some(channel);
                Task::none()
            }
            Message::InterfaceSelected(interface) => {
                self.scan_capture_screen.selected_interface = interface;
                self.persist_state();
                Task::none()
            }
            Message::BrowseCaptureFile => {
                let current_path = PathBuf::from(&self.scan_capture_screen.output_file);
                let dir = current_path.parent().map(|p| p.to_path_buf());
                let filename = current_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("handshake.pcap")
                    .to_string();

                Task::perform(
                    async move {
                        let mut dialog = rfd::AsyncFileDialog::new()
                            .set_title("Choose Capture Output Location")
                            .add_filter("PCAP Files", &["pcap", "cap"])
                            .set_file_name(&filename);

                        if let Some(d) = dir {
                            dialog = dialog.set_directory(d);
                        }

                        dialog
                            .save_file()
                            .await
                            .map(|handle| handle.path().to_path_buf())
                    },
                    Message::CaptureFileSelected,
                )
            }
            Message::DownloadCapturedPcap => Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .set_title("Save Captured PCAP")
                        .add_filter("PCAP files", &["pcap"])
                        .set_file_name("capture.pcap")
                        .save_file()
                        .await
                        .map(|handle| handle.path().to_path_buf())
                },
                Message::SaveCapturedPcap,
            ),
            Message::CaptureFileSelected(path) => {
                if let Some(path) = path {
                    let path_str = path.to_string_lossy().to_string();
                    eprintln!("[DEBUG] Capture file selected: {}", path_str);
                    self.scan_capture_screen.output_file = path_str.clone();
                    self.scan_capture_screen
                        .log_messages
                        .push(format!("📁 Output file: {}", path_str));
                    if self.scan_capture_screen.log_messages.len() > 50 {
                        self.scan_capture_screen.log_messages.remove(0);
                    }
                    let logs_text = self.scan_capture_screen.log_messages.join("\n");
                    self.scan_capture_screen.logs_content =
                        text_editor::Content::with_text(&logs_text);
                }
                self.persist_state();
                Task::none()
            }
            Message::SaveCapturedPcap(path) => {
                if let Some(dest) = path {
                    let src = PathBuf::from(&self.scan_capture_screen.output_file);
                    if src.exists() {
                        if let Err(e) = fs::copy(&src, &dest) {
                            self.scan_capture_screen.error_message =
                                Some(format!("Failed to save capture: {}", e));
                        } else {
                            self.scan_capture_screen.last_saved_capture_path =
                                Some(dest.display().to_string());
                            if self.crack_screen.use_captured_file {
                                self.crack_screen.handshake_path = dest.display().to_string();
                            }
                            self.scan_capture_screen
                                .log_messages
                                .push(format!("✅ Capture saved to {}", dest.display()));
                            if self.scan_capture_screen.log_messages.len() > 50 {
                                self.scan_capture_screen.log_messages.remove(0);
                            }
                            let logs_text = self.scan_capture_screen.log_messages.join("\n");
                            self.scan_capture_screen.logs_content =
                                text_editor::Content::with_text(&logs_text);
                        }
                    } else {
                        self.scan_capture_screen.error_message =
                            Some(format!("Capture file not found: {}", src.display()));
                    }
                }
                self.persist_state();
                Task::none()
            }
            Message::CopyLogsToClipboard => {
                let logs_text = self.scan_capture_screen.log_messages.join("\n");
                if !logs_text.is_empty() {
                    // On macOS, clipboard::write may fail when running as root
                    // Use pbcopy as a more reliable fallback
                    #[cfg(target_os = "macos")]
                    {
                        use std::io::Write;
                        use std::process::{Command, Stdio};

                        if let Ok(mut child) = Command::new("pbcopy").stdin(Stdio::piped()).spawn()
                        {
                            if let Some(mut stdin) = child.stdin.take() {
                                let _ = stdin.write_all(logs_text.as_bytes());
                            }
                            let _ = child.wait();
                            self.scan_capture_screen
                                .log_messages
                                .push("📋 Logs copied to clipboard".to_string());
                            if self.scan_capture_screen.log_messages.len() > 50 {
                                self.scan_capture_screen.log_messages.remove(0);
                            }
                            let new_logs_text = self.scan_capture_screen.log_messages.join("\n");
                            self.scan_capture_screen.logs_content =
                                text_editor::Content::with_text(&new_logs_text);
                            return Task::none();
                        }
                    }

                    // Fallback to Iced clipboard (works on non-macOS or if pbcopy fails)
                    return clipboard::write(logs_text);
                }
                Task::none()
            }
            Message::DisconnectWifi => Task::perform(
                async {
                    tokio::task::spawn_blocking(|| -> Result<(), String> {
                        brutifi::disconnect_wifi().map_err(|e| e.to_string())
                    })
                    .await
                    .unwrap_or_else(|e| Err(e.to_string()))
                },
                Message::WifiDisconnectResult,
            ),
            Message::WifiDisconnectResult(result) => {
                match result {
                    Ok(()) => {
                        self.scan_capture_screen.error_message = None;
                        self.scan_capture_screen
                            .log_messages
                            .push("🔌 WiFi disconnected successfully".to_string());

                        // Wait a moment then verify disconnection worked
                        // This ensures the UI reflects the actual WiFi state
                        self.scan_capture_screen
                            .log_messages
                            .push("✓ You can now start capture".to_string());
                    }
                    Err(err) => {
                        self.scan_capture_screen.error_message = Some(err.clone());
                        self.scan_capture_screen
                            .log_messages
                            .push(format!("❌ Disconnect failed: {}", err));
                    }
                }
                if self.scan_capture_screen.log_messages.len() > 50 {
                    self.scan_capture_screen.log_messages.remove(0);
                }
                let logs_text = self.scan_capture_screen.log_messages.join("\n");
                self.scan_capture_screen.logs_content = text_editor::Content::with_text(&logs_text);
                Task::none()
            }
            Message::StartCapture => {
                let network = match self.scan_capture_screen.target_network.clone() {
                    Some(network) => network,
                    None => {
                        self.scan_capture_screen.error_message =
                            Some("No target network selected".to_string());
                        return Task::none();
                    }
                };

                // Simplified: Just log if WiFi is connected (warning, not blocking)
                if let Some(ssid) = brutifi::wifi_connected_ssid() {
                    self.scan_capture_screen
                        .log_messages
                        .push(format!("⚠️ Warning: WiFi connected to '{}'. Consider disconnecting for better capture.", ssid));
                }

                // Check if running as root
                if !self.is_root {
                    #[cfg(target_os = "macos")]
                    {
                        self.scan_capture_screen.error_message =
                            Some("Requesting admin privileges for capture...".to_string());
                        self.persist_state();
                        let envs = self.build_relaunch_envs_for_capture(true);
                        if crate::relaunch_as_root_with_env(&envs) {
                            std::process::exit(0);
                        }
                        self.scan_capture_screen.error_message = Some(
                                "Failed to request admin privileges. Please try again or launch with sudo."
                                    .to_string(),
                            );
                        return Task::none();
                    }

                    #[cfg(not(target_os = "macos"))]
                    {
                        self.scan_capture_screen.error_message = Some(
                                "Capture requires admin privileges. Please restart the app as Administrator."
                                    .to_string(),
                            );
                        return Task::none();
                    }
                }

                self.scan_capture_screen.is_capturing = true;
                self.scan_capture_screen.error_message = None;
                self.scan_capture_screen.packets_captured = 0;
                self.scan_capture_screen.handshake_progress = HandshakeProgress::default();
                self.persist_state();

                let state = Arc::new(CaptureState::new());
                self.capture_state = Some(state.clone());

                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                self.capture_progress_rx = Some(rx);

                // Use selected channel if available, otherwise use first channel from network
                let channel_str = self
                    .scan_capture_screen
                    .selected_channel
                    .clone()
                    .or_else(|| {
                        // Fallback: take first channel from network
                        network
                            .channel
                            .split(',')
                            .next()
                            .map(|s| s.trim().to_string())
                    });

                let channel = channel_str.and_then(|ch| {
                    // Try to parse channel number
                    // This handles "36", "36 (5GHz)", "Channel 6", etc.
                    ch.split(|c: char| !c.is_ascii_digit())
                        .find(|s| !s.is_empty())
                        .and_then(|s| s.parse::<u32>().ok())
                });

                // Check if channel was successfully parsed
                if channel.is_none() {
                    self.scan_capture_screen.error_message = Some(
                        format!("Could not detect channel from network info (channel field: '{}'). Please rescan.", network.channel)
                    );
                    self.scan_capture_screen.is_capturing = false;
                    return Task::none();
                }

                // Warn if multiple channels available but none selected
                if self.scan_capture_screen.available_channels.len() > 1
                    && self.scan_capture_screen.selected_channel.is_none()
                {
                    self.scan_capture_screen.error_message = Some(
                        "Multiple channels available. Please select a channel before starting capture.".to_string()
                    );
                    self.scan_capture_screen.is_capturing = false;
                    return Task::none();
                }

                // Log channel selection
                let selected_ch_str = self
                    .scan_capture_screen
                    .selected_channel
                    .as_deref()
                    .unwrap_or("auto");
                eprintln!(
                    "[DEBUG] Starting capture on channel: {:?} (selected: '{}', network raw: '{}')",
                    channel, selected_ch_str, network.channel
                );

                let params = CaptureParams {
                    interface: self.scan_capture_screen.selected_interface.clone(),
                    channel,
                    ssid: Some(network.ssid.clone()),
                    output_file: self.scan_capture_screen.output_file.clone(),
                };

                Task::perform(
                    workers::capture_async(params, state, tx),
                    Message::CaptureProgress,
                )
            }
            Message::StopCapture => {
                if let Some(ref state) = self.capture_state {
                    state.stop();
                }
                self.scan_capture_screen.is_capturing = false;
                self.capture_progress_rx = None;
                self.persist_state();
                Task::none()
            }
            Message::CaptureProgress(progress) => {
                match progress {
                    workers::CaptureProgress::Log(msg) => {
                        self.scan_capture_screen.log_messages.push(msg);
                        // Keep only last 50 messages
                        if self.scan_capture_screen.log_messages.len() > 50 {
                            self.scan_capture_screen.log_messages.remove(0);
                        }
                        let logs_text = self.scan_capture_screen.log_messages.join("\n");
                        self.scan_capture_screen.logs_content =
                            text_editor::Content::with_text(&logs_text);
                    }
                    workers::CaptureProgress::HandshakeComplete { ssid } => {
                        self.scan_capture_screen.handshake_complete = true;
                        self.scan_capture_screen.handshake_progress.m1_received = true;
                        self.scan_capture_screen.handshake_progress.m2_received = true;
                        self.scan_capture_screen.is_capturing = false;
                        self.scan_capture_screen
                            .log_messages
                            .push(format!("✅ Handshake captured for '{}'", ssid));
                        let logs_text = self.scan_capture_screen.log_messages.join("\n");
                        self.scan_capture_screen.logs_content =
                            text_editor::Content::with_text(&logs_text);
                        self.persist_state();

                        #[cfg(target_os = "macos")]
                        if self.is_root {
                            let envs = self.build_relaunch_envs_for_capture(false);
                            if crate::relaunch_as_user(&envs) {
                                std::process::exit(0);
                            }
                        }
                    }
                    workers::CaptureProgress::Error(msg) => {
                        self.scan_capture_screen.error_message = Some(msg.clone());
                        self.scan_capture_screen.is_capturing = false;
                        self.scan_capture_screen
                            .log_messages
                            .push(format!("❌ Error: {}", msg));
                        let logs_text = self.scan_capture_screen.log_messages.join("\n");
                        self.scan_capture_screen.logs_content =
                            text_editor::Content::with_text(&logs_text);
                        self.persist_state();
                    }
                    workers::CaptureProgress::Finished {
                        output_file,
                        packets,
                    } => {
                        self.scan_capture_screen.output_file = output_file;
                        self.scan_capture_screen.packets_captured = packets;
                        self.scan_capture_screen.is_capturing = false;
                        self.persist_state();
                    }
                    _ => {}
                }
                Task::none()
            }
            Message::EnableAdminMode => {
                #[cfg(target_os = "macos")]
                {
                    if !self.is_root {
                        if crate::relaunch_as_root() {
                            std::process::exit(0);
                        }

                        self.scan_capture_screen.error_message = Some(
                            "Failed to request admin privileges. Please try again or launch with sudo."
                                .to_string(),
                        );
                    }
                }

                #[cfg(not(target_os = "macos"))]
                {
                    self.scan_capture_screen.error_message =
                        Some("Please restart the app with Administrator privileges.".to_string());
                }

                Task::none()
            }

            // Crack screen
            Message::UseCapturedFileToggled(enabled) => {
                self.crack_screen.use_captured_file = enabled;
                if enabled {
                    // Auto-populate from scan_capture screen
                    if let Some(ref saved) = self.scan_capture_screen.last_saved_capture_path {
                        if !saved.is_empty() {
                            self.crack_screen.handshake_path = saved.clone();
                        } else {
                            self.crack_screen.handshake_path =
                                self.scan_capture_screen.output_file.clone();
                        }
                    } else {
                        self.crack_screen.handshake_path =
                            self.scan_capture_screen.output_file.clone();
                    }
                }
                self.persist_state();
                Task::none()
            }
            Message::HandshakePathChanged(path) => {
                self.crack_screen.handshake_path = path;
                self.persist_state();
                Task::none()
            }
            Message::EngineChanged(engine) => {
                self.crack_screen.engine = engine;
                self.persist_state();
                Task::none()
            }
            Message::MethodChanged(method) => {
                self.crack_screen.method = method;
                self.persist_state();
                Task::none()
            }
            Message::MinDigitsChanged(val) => {
                if val.is_empty() || val.parse::<usize>().is_ok() {
                    self.crack_screen.min_digits = val;
                    self.persist_state();
                }
                Task::none()
            }
            Message::MaxDigitsChanged(val) => {
                if val.is_empty() || val.parse::<usize>().is_ok() {
                    self.crack_screen.max_digits = val;
                    self.persist_state();
                }
                Task::none()
            }
            Message::WordlistPathChanged(path) => {
                self.crack_screen.wordlist_path = path;
                self.persist_state();
                Task::none()
            }
            Message::BrowseHandshake => Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .add_filter("Capture files", &["cap", "pcap", "pcapng", "json"])
                        .set_title("Select Handshake File")
                        .pick_file()
                        .await
                        .map(|f| f.path().to_path_buf())
                },
                Message::HandshakeSelected,
            ),
            Message::BrowseWordlist => Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .add_filter("Wordlist files", &["txt", "lst"])
                        .set_title("Select Wordlist File")
                        .pick_file()
                        .await
                        .map(|f| f.path().to_path_buf())
                },
                Message::WordlistSelected,
            ),
            Message::HandshakeSelected(path) => {
                if let Some(p) = path {
                    let path_str = p.display().to_string();
                    eprintln!("[DEBUG] Handshake file selected: {}", path_str);
                    self.crack_screen.handshake_path = path_str.clone();
                    self.crack_screen.use_captured_file = false;
                    self.crack_screen
                        .log_messages
                        .push(format!("📁 Handshake file: {}", path_str));
                    if self.crack_screen.log_messages.len() > 50 {
                        self.crack_screen.log_messages.remove(0);
                    }
                    let logs_text = self.crack_screen.log_messages.join("\n");
                    self.crack_screen.logs_content = text_editor::Content::with_text(&logs_text);
                }
                self.persist_state();
                Task::none()
            }
            Message::WordlistSelected(path) => {
                if let Some(p) = path {
                    let path_str = p.display().to_string();
                    eprintln!("[DEBUG] Wordlist file selected: {}", path_str);
                    self.crack_screen.wordlist_path = path_str.clone();
                    self.crack_screen
                        .log_messages
                        .push(format!("📁 Wordlist file: {}", path_str));
                    if self.crack_screen.log_messages.len() > 50 {
                        self.crack_screen.log_messages.remove(0);
                    }
                    let logs_text = self.crack_screen.log_messages.join("\n");
                    self.crack_screen.logs_content = text_editor::Content::with_text(&logs_text);
                }
                self.persist_state();
                Task::none()
            }
            Message::StartCrack => {
                // Validate handshake file exists
                let handshake_path = PathBuf::from(&self.crack_screen.handshake_path);
                if !handshake_path.exists() {
                    self.crack_screen.error_message = Some(format!(
                        "Handshake file not found: {}",
                        self.crack_screen.handshake_path
                    ));
                    return Task::none();
                }

                // Validate wordlist file exists for wordlist method
                if self.crack_screen.method == CrackMethod::Wordlist {
                    let wordlist_path = PathBuf::from(&self.crack_screen.wordlist_path);
                    if !wordlist_path.exists() {
                        self.crack_screen.error_message = Some(format!(
                            "Wordlist file not found: {}",
                            self.crack_screen.wordlist_path
                        ));
                        return Task::none();
                    }
                }

                // Validate numeric range for numeric method
                if self.crack_screen.method == CrackMethod::Numeric {
                    let min_digits = self.crack_screen.min_digits.parse::<usize>().unwrap_or(8);
                    let max_digits = self.crack_screen.max_digits.parse::<usize>().unwrap_or(8);

                    if !(1..=63).contains(&min_digits) {
                        self.crack_screen.error_message =
                            Some("Min digits must be between 1 and 63".to_string());
                        return Task::none();
                    }

                    if !(1..=63).contains(&max_digits) {
                        self.crack_screen.error_message =
                            Some("Max digits must be between 1 and 63".to_string());
                        return Task::none();
                    }

                    if min_digits > max_digits {
                        self.crack_screen.error_message =
                            Some("Min digits cannot be greater than max digits".to_string());
                        return Task::none();
                    }
                }

                self.crack_screen.is_cracking = true;
                self.crack_screen.error_message = None;
                self.crack_screen.found_password = None;
                self.crack_screen.password_not_found = false;
                self.crack_screen.current_attempts = 0;
                self.crack_screen.progress = 0.0;
                self.crack_screen.status_message = "Starting...".to_string();
                self.crack_screen.log_messages.clear();

                // Add initial log messages with configuration info
                self.crack_screen.log_messages.push(format!(
                    "🚀 Starting crack for: {}",
                    self.crack_screen.handshake_path
                ));
                self.crack_screen.log_messages.push(format!(
                    "📊 Engine: {:?} | Method: {:?}",
                    self.crack_screen.engine, self.crack_screen.method
                ));
                if !self.crack_screen.ssid.is_empty() {
                    self.crack_screen
                        .log_messages
                        .push(format!("📡 Target SSID: {}", self.crack_screen.ssid));
                }
                let logs_text = self.crack_screen.log_messages.join("\n");
                self.crack_screen.logs_content = text_editor::Content::with_text(&logs_text);

                let state = Arc::new(CrackState::new());
                self.crack_state = Some(state.clone());

                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                self.crack_progress_rx = Some(rx);

                match self.crack_screen.method {
                    CrackMethod::Numeric => {
                        // Check if using hashcat engine
                        if self.crack_screen.engine == CrackEngine::Hashcat {
                            let params = workers::HashcatCrackParams {
                                handshake_path,
                                wordlist_path: None,
                                min_digits: Some(self.crack_screen.min_digits.parse().unwrap_or(8)),
                                max_digits: Some(self.crack_screen.max_digits.parse().unwrap_or(8)),
                                is_numeric: true,
                            };

                            // Calculate total
                            let mut total: u64 = 0;
                            for len in params.min_digits.unwrap()..=params.max_digits.unwrap() {
                                total += 10u64.pow(len as u32);
                            }
                            self.crack_screen.total_attempts = total;

                            Task::perform(
                                workers::crack_hashcat_async(params, state, tx),
                                Message::CrackProgress,
                            )
                        } else {
                            // Native CPU cracking
                            let params = NumericCrackParams {
                                handshake_path,
                                ssid: if self.crack_screen.ssid.is_empty() {
                                    None
                                } else {
                                    Some(self.crack_screen.ssid.clone())
                                },
                                min_digits: self.crack_screen.min_digits.parse().unwrap_or(8),
                                max_digits: self.crack_screen.max_digits.parse().unwrap_or(8),
                                threads: self.crack_screen.threads,
                            };

                            // Calculate total
                            let mut total: u64 = 0;
                            for len in params.min_digits..=params.max_digits {
                                total += 10u64.pow(len as u32);
                            }
                            self.crack_screen.total_attempts = total;

                            Task::perform(
                                workers_optimized::crack_numeric_optimized(params, state, tx),
                                Message::CrackProgress,
                            )
                        }
                    }
                    CrackMethod::Wordlist => {
                        // Check if using hashcat engine
                        if self.crack_screen.engine == CrackEngine::Hashcat {
                            let params = workers::HashcatCrackParams {
                                handshake_path,
                                wordlist_path: Some(PathBuf::from(
                                    &self.crack_screen.wordlist_path,
                                )),
                                min_digits: None,
                                max_digits: None,
                                is_numeric: false,
                            };

                            Task::perform(
                                workers::crack_hashcat_async(params, state, tx),
                                Message::CrackProgress,
                            )
                        } else {
                            // Native CPU cracking
                            let params = WordlistCrackParams {
                                handshake_path,
                                ssid: if self.crack_screen.ssid.is_empty() {
                                    None
                                } else {
                                    Some(self.crack_screen.ssid.clone())
                                },
                                wordlist_path: PathBuf::from(&self.crack_screen.wordlist_path),
                                threads: self.crack_screen.threads,
                            };

                            Task::perform(
                                workers_optimized::crack_wordlist_optimized(params, state, tx),
                                Message::CrackProgress,
                            )
                        }
                    }
                }
            }
            Message::StopCrack => {
                if let Some(ref state) = self.crack_state {
                    state.stop();
                }
                self.crack_screen.is_cracking = false;
                self.crack_screen.status_message = "Stopped".to_string();
                self.crack_progress_rx = None;
                Task::none()
            }
            Message::CrackProgress(progress) => {
                match progress {
                    workers::CrackProgress::Started { total } => {
                        self.crack_screen.total_attempts = total;
                        self.crack_screen.status_message = "Cracking...".to_string();
                    }
                    workers::CrackProgress::Progress {
                        current,
                        total,
                        rate,
                    } => {
                        self.crack_screen.current_attempts = current;
                        self.crack_screen.total_attempts = total;
                        self.crack_screen.rate = rate;
                        self.crack_screen.progress = if total > 0 {
                            current as f32 / total as f32
                        } else {
                            0.0
                        };
                    }
                    workers::CrackProgress::Log(msg) => {
                        self.crack_screen.log_messages.push(msg);
                        // Keep only last 50 logs
                        if self.crack_screen.log_messages.len() > 50 {
                            self.crack_screen.log_messages.remove(0);
                        }
                        let logs_text = self.crack_screen.log_messages.join("\n");
                        self.crack_screen.logs_content =
                            text_editor::Content::with_text(&logs_text);
                    }
                    workers::CrackProgress::Found(password) => {
                        // Drain any remaining log messages from the channel before closing
                        if let Some(ref mut rx) = self.crack_progress_rx {
                            while let Ok(remaining) = rx.try_recv() {
                                if let workers::CrackProgress::Log(msg) = remaining {
                                    self.crack_screen.log_messages.push(msg);
                                }
                            }
                        }

                        self.crack_screen
                            .log_messages
                            .push(format!("✅ Password found: {}", password));
                        if self.crack_screen.log_messages.len() > 50 {
                            self.crack_screen.log_messages.remove(0);
                        }
                        let logs_text = self.crack_screen.log_messages.join("\n");
                        self.crack_screen.logs_content =
                            text_editor::Content::with_text(&logs_text);

                        self.crack_screen.found_password = Some(password);
                        self.crack_screen.status_message = "Password found!".to_string();
                        self.crack_screen.progress = 1.0;
                        self.crack_screen.is_cracking = false;
                        self.crack_progress_rx = None;
                    }
                    workers::CrackProgress::NotFound => {
                        // Drain any remaining log messages from the channel before closing
                        if let Some(ref mut rx) = self.crack_progress_rx {
                            while let Ok(remaining) = rx.try_recv() {
                                if let workers::CrackProgress::Log(msg) = remaining {
                                    self.crack_screen.log_messages.push(msg);
                                }
                            }
                        }

                        self.crack_screen
                            .log_messages
                            .push("❌ Password not found - all combinations exhausted".to_string());
                        if self.crack_screen.log_messages.len() > 50 {
                            self.crack_screen.log_messages.remove(0);
                        }
                        let logs_text = self.crack_screen.log_messages.join("\n");
                        self.crack_screen.logs_content =
                            text_editor::Content::with_text(&logs_text);

                        self.crack_screen.status_message = "Password not found".to_string();
                        self.crack_screen.progress = 1.0;
                        self.crack_screen.password_not_found = true;
                        self.crack_screen.is_cracking = false;
                        self.crack_progress_rx = None;
                    }
                    workers::CrackProgress::Error(msg) => {
                        // Drain any remaining log messages from the channel before closing
                        if let Some(ref mut rx) = self.crack_progress_rx {
                            while let Ok(remaining) = rx.try_recv() {
                                if let workers::CrackProgress::Log(msg) = remaining {
                                    self.crack_screen.log_messages.push(msg);
                                }
                            }
                        }

                        self.crack_screen
                            .log_messages
                            .push(format!("❌ Error: {}", msg));
                        if self.crack_screen.log_messages.len() > 50 {
                            self.crack_screen.log_messages.remove(0);
                        }
                        let logs_text = self.crack_screen.log_messages.join("\n");
                        self.crack_screen.logs_content =
                            text_editor::Content::with_text(&logs_text);

                        self.crack_screen.error_message = Some(msg);
                        self.crack_screen.status_message = "Error occurred".to_string();
                        self.crack_screen.is_cracking = false;
                        self.crack_progress_rx = None;
                    }
                }
                Task::none()
            }
            Message::CopyPassword => {
                if let Some(ref password) = self.crack_screen.found_password {
                    // On macOS, clipboard::write may fail when running as root
                    // Use pbcopy as a more reliable fallback
                    #[cfg(target_os = "macos")]
                    {
                        use std::io::Write;
                        use std::process::{Command, Stdio};

                        if let Ok(mut child) = Command::new("pbcopy").stdin(Stdio::piped()).spawn()
                        {
                            if let Some(mut stdin) = child.stdin.take() {
                                let _ = stdin.write_all(password.as_bytes());
                            }
                            let _ = child.wait();
                            return Task::none();
                        }
                    }

                    // Fallback to Iced clipboard
                    return clipboard::write(password.clone());
                }
                Task::none()
            }
            Message::CopyLogs => {
                let logs_text = self.crack_screen.log_messages.join("\n");
                if !logs_text.is_empty() {
                    // On macOS, clipboard::write may fail when running as root
                    // Use pbcopy as a more reliable fallback
                    #[cfg(target_os = "macos")]
                    {
                        use std::io::Write;
                        use std::process::{Command, Stdio};

                        if let Ok(mut child) = Command::new("pbcopy").stdin(Stdio::piped()).spawn()
                        {
                            if let Some(mut stdin) = child.stdin.take() {
                                let _ = stdin.write_all(logs_text.as_bytes());
                            }
                            let _ = child.wait();
                            self.crack_screen
                                .log_messages
                                .push("📋 Logs copied to clipboard".to_string());
                            if self.crack_screen.log_messages.len() > 50 {
                                self.crack_screen.log_messages.remove(0);
                            }
                            let new_logs_text = self.crack_screen.log_messages.join("\n");
                            self.crack_screen.logs_content =
                                text_editor::Content::with_text(&new_logs_text);
                            return Task::none();
                        }
                    }

                    // Fallback to Iced clipboard (works on non-macOS or if pbcopy fails)
                    return clipboard::write(logs_text);
                }
                Task::none()
            }
            Message::LogsEditorAction(action) => {
                match self.screen {
                    Screen::Crack => {
                        self.crack_screen.logs_content.perform(action);
                    }
                    Screen::ScanCapture => {
                        self.scan_capture_screen.logs_content.perform(action);
                    }
                }
                Task::none()
            }
            Message::ReturnToNormalMode => {
                #[cfg(target_os = "macos")]
                {
                    if self.is_root {
                        let mut envs = Vec::new();
                        envs.push(("BRUTIFI_START_SCREEN", "crack".to_string()));
                        if !self.crack_screen.handshake_path.is_empty() {
                            envs.push((
                                "BRUTIFI_HANDSHAKE_PATH",
                                self.crack_screen.handshake_path.clone(),
                            ));
                        }
                        if !self.crack_screen.ssid.is_empty() {
                            envs.push(("BRUTIFI_SSID", self.crack_screen.ssid.clone()));
                        }
                        envs.push((
                            "BRUTIFI_USE_CAPTURED",
                            if self.crack_screen.use_captured_file {
                                "1".to_string()
                            } else {
                                "0".to_string()
                            },
                        ));
                        if !self.crack_screen.wordlist_path.is_empty() {
                            envs.push((
                                "BRUTIFI_WORDLIST_PATH",
                                self.crack_screen.wordlist_path.clone(),
                            ));
                        }

                        if crate::relaunch_as_user(&envs) {
                            std::process::exit(0);
                        }

                        self.crack_screen.error_message = Some(
                            "Failed to return to normal mode. Please restart the app manually."
                                .to_string(),
                        );
                    }
                }

                Task::none()
            }
            Message::Tick => {
                let mut messages = Vec::new();

                // Poll for capture progress
                if let Some(ref mut rx) = self.capture_progress_rx {
                    while let Ok(progress) = rx.try_recv() {
                        messages.push(Message::CaptureProgress(progress));
                    }
                }

                // Poll for crack progress
                if let Some(ref mut rx) = self.crack_progress_rx {
                    while let Ok(progress) = rx.try_recv() {
                        messages.push(Message::CrackProgress(progress));
                    }
                }

                if !messages.is_empty() {
                    return Task::batch(messages.into_iter().map(Task::done));
                }
                Task::none()
            }
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        // Root warning banner
        let root_warning = if !self.is_root {
            Some(
                container(
                    row![
                        text("ℹ ").size(14).color(colors::TEXT_DIM),
                        text("Capture requires root. Crack works without permissions.")
                            .size(12)
                            .color(colors::TEXT_DIM),
                    ]
                    .align_y(iced::Alignment::Center)
                    .padding([6, 15]),
                )
                .width(Length::Fill)
                .style(|_| container::Style {
                    background: Some(iced::Background::Color(iced::Color::from_rgba(
                        0.5, 0.5, 0.5, 0.1,
                    ))),
                    border: iced::Border {
                        color: colors::TEXT_DIM,
                        width: 1.0,
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            )
        } else {
            None
        };

        // Navigation header - simplified to 2 steps
        let nav = container(
            row![
                nav_button("1. Scan & Capture", Screen::ScanCapture, self.screen),
                text("→").size(16).color(colors::TEXT_DIM),
                nav_button("2. Crack", Screen::Crack, self.screen),
            ]
            .spacing(15)
            .align_y(iced::Alignment::Center)
            .padding([10, 20]),
        )
        .width(Length::Fill)
        .style(|_| container::Style {
            background: Some(iced::Background::Color(colors::SURFACE)),
            ..Default::default()
        });

        // Current screen content
        let content = match self.screen {
            Screen::ScanCapture => self.scan_capture_screen.view(self.is_root),
            Screen::Crack => self.crack_screen.view(self.is_root),
        };

        let mut main_col = column![nav, horizontal_rule(1)];
        if let Some(warning) = root_warning {
            main_col = main_col.push(warning);
        }
        main_col = main_col.push(content);

        main_col.into()
    }

    fn apply_persisted_state(&mut self, state: PersistedState) {
        if !state.scan.selected_interface.is_empty() {
            self.scan_capture_screen.selected_interface = state.scan.selected_interface;
        }
        self.scan_capture_screen.networks = state.scan.networks;
        self.scan_capture_screen.selected_network = state
            .scan
            .selected_network
            .filter(|idx| *idx < self.scan_capture_screen.networks.len());
        self.scan_capture_screen.target_network = state.capture.target_network;
        if self.scan_capture_screen.target_network.is_none() {
            if let Some(idx) = self.scan_capture_screen.selected_network {
                if let Some(net) = self.scan_capture_screen.networks.get(idx) {
                    self.scan_capture_screen.target_network = Some(net.clone());
                }
            }
        }
        if !state.capture.output_file.is_empty() {
            self.scan_capture_screen.output_file = state.capture.output_file;
        }
        self.scan_capture_screen.handshake_complete = state.capture.handshake_complete;
        if self.scan_capture_screen.handshake_complete {
            self.scan_capture_screen.handshake_progress.m1_received = true;
            self.scan_capture_screen.handshake_progress.m2_received = true;
        }
        self.scan_capture_screen.packets_captured = state.capture.packets_captured;
        self.scan_capture_screen.last_saved_capture_path = state.capture.last_saved_capture_path;

        if let Some(path) = self.scan_capture_screen.last_saved_capture_path.clone() {
            if self.scan_capture_screen.log_messages.is_empty() {
                self.scan_capture_screen
                    .log_messages
                    .push(format!("✅ Last saved capture: {}", path));
            }
        }

        if !state.crack.handshake_path.is_empty() {
            self.crack_screen.handshake_path = state.crack.handshake_path;
        }
        self.crack_screen.use_captured_file = state.crack.use_captured_file;
        self.crack_screen.ssid = state.crack.ssid;
        self.crack_screen.engine = state.crack.engine;
        self.crack_screen.method = state.crack.method;
        if !state.crack.min_digits.is_empty() {
            self.crack_screen.min_digits = state.crack.min_digits;
        }
        if !state.crack.max_digits.is_empty() {
            self.crack_screen.max_digits = state.crack.max_digits;
        }
        if !state.crack.wordlist_path.is_empty() {
            self.crack_screen.wordlist_path = state.crack.wordlist_path;
        }
        if state.crack.threads > 0 {
            self.crack_screen.threads = state.crack.threads;
        }
    }

    fn persist_state(&self) {
        let state = PersistedState {
            version: 1,
            scan: PersistedScanState {
                networks: self.scan_capture_screen.networks.clone(),
                selected_network: self.scan_capture_screen.selected_network,
                selected_interface: self.scan_capture_screen.selected_interface.clone(),
            },
            capture: PersistedCaptureState {
                target_network: self.scan_capture_screen.target_network.clone(),
                output_file: self.scan_capture_screen.output_file.clone(),
                handshake_complete: self.scan_capture_screen.handshake_complete,
                packets_captured: self.scan_capture_screen.packets_captured,
                last_saved_capture_path: self.scan_capture_screen.last_saved_capture_path.clone(),
            },
            crack: PersistedCrackState {
                handshake_path: self.crack_screen.handshake_path.clone(),
                use_captured_file: self.crack_screen.use_captured_file,
                ssid: self.crack_screen.ssid.clone(),
                engine: self.crack_screen.engine,
                method: self.crack_screen.method,
                min_digits: self.crack_screen.min_digits.clone(),
                max_digits: self.crack_screen.max_digits.clone(),
                wordlist_path: self.crack_screen.wordlist_path.clone(),
                threads: self.crack_screen.threads,
            },
        };

        if let Err(err) = save_persisted_state(&state) {
            eprintln!("[WARN] Failed to save state: {}", err);
        }
    }

    #[cfg(target_os = "macos")]
    fn build_relaunch_envs_for_capture(&self, auto_capture: bool) -> Vec<(&'static str, String)> {
        let mut envs = Vec::new();
        envs.push(("BRUTIFI_START_SCREEN", "scan".to_string()));
        if auto_capture {
            envs.push(("BRUTIFI_AUTO_CAPTURE", "1".to_string()));
        }
        envs
    }
}

fn list_interfaces() -> Vec<String> {
    let mut interfaces: Vec<String> = Device::list()
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.name)
        .collect();
    interfaces.sort();
    interfaces.dedup();
    if interfaces.is_empty() {
        interfaces.push("en0".to_string());
    }
    interfaces
}

fn choose_default_interface(interfaces: &[String]) -> String {
    if interfaces.iter().any(|name| name.as_str() == "en0") {
        return "en0".to_string();
    }
    if let Some(name) = interfaces.iter().find(|name| name.as_str() == "wlan0") {
        return name.clone();
    }
    if let Some(name) = interfaces
        .iter()
        .find(|name| name.as_str().starts_with("wl"))
    {
        return name.clone();
    }
    interfaces
        .first()
        .cloned()
        .unwrap_or_else(|| "en0".to_string())
}

fn state_file_path() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    if home.is_empty() {
        return None;
    }
    let dir = PathBuf::from(home).join(".brutifi");
    if fs::create_dir_all(&dir).is_err() {
        return None;
    }
    Some(dir.join("state.json"))
}

fn load_persisted_state() -> Option<PersistedState> {
    let path = state_file_path()?;
    let data = fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn save_persisted_state(state: &PersistedState) -> std::io::Result<()> {
    if let Some(path) = state_file_path() {
        let data = serde_json::to_string_pretty(state).unwrap_or_default();
        fs::write(path, data)?;
    }
    Ok(())
}

/// Navigation button helper
fn nav_button(label: &str, target: Screen, current: Screen) -> Element<'_, Message> {
    let is_active = target == current;
    let color = if is_active {
        colors::PRIMARY
    } else {
        colors::TEXT_DIM
    };

    let msg = match target {
        Screen::ScanCapture => Message::GoToScanCapture,
        Screen::Crack => Message::GoToCrack,
    };

    button(text(label).size(14).color(color))
        .padding([8, 12])
        .style(move |_, status| {
            let bg = match status {
                iced::widget::button::Status::Hovered => {
                    Some(iced::Background::Color(colors::SURFACE_HOVER))
                }
                _ if is_active => Some(iced::Background::Color(iced::Color::from_rgba(
                    0.18, 0.55, 0.34, 0.2,
                ))),
                _ => None,
            };
            iced::widget::button::Style {
                background: bg,
                text_color: color,
                border: iced::Border {
                    radius: 4.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            }
        })
        .on_press(msg)
        .into()
}
