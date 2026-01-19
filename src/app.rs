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

use crate::screens::{CrackEngine, CrackMethod, CrackScreen, HandshakeProgress, ScanCaptureScreen};
use crate::theme::colors;
use crate::workers::{
    self, CaptureParams, CaptureState, CrackState, NumericCrackParams, ScanResult,
    WordlistCrackParams,
};
use crate::workers_optimized;

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
    ScanComplete(ScanResult),
    SelectNetwork(usize),
    InterfaceSelected(String),
    BrowseCaptureFile,
    CaptureFileSelected(Option<PathBuf>),
    DownloadCapturedPcap,
    SaveCapturedPcap(Option<PathBuf>),
    StartCapture,
    StopCapture,
    CaptureProgress(workers::CaptureProgress),
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

impl BruteforceApp {
    pub fn new(is_root: bool) -> (Self, Task<Message>) {
        let interface_list = list_interfaces();
        let selected_interface = choose_default_interface(&interface_list);
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

        #[cfg(target_os = "macos")]
        {
            if let Ok(screen) = std::env::var("BRUTIFI_START_SCREEN") {
                if screen.eq_ignore_ascii_case("crack") {
                    app.screen = Screen::Crack;
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
        }

        (app, Task::none())
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
                // Set handshake path from capture
                if !self.scan_capture_screen.output_file.is_empty() {
                    self.crack_screen.handshake_path = self.scan_capture_screen.output_file.clone();
                }
                // Set SSID from captured network
                if let Some(ref network) = self.scan_capture_screen.target_network {
                    self.crack_screen.ssid = network.ssid.clone();
                }

                // Reset crack screen state
                self.crack_screen.error_message = None;
                self.crack_screen.found_password = None;
                self.crack_screen.password_not_found = false;
                self.crack_screen.current_attempts = 0;
                self.crack_screen.progress = 0.0;
                self.crack_screen.log_messages.clear();
                self.crack_screen.logs_content = text_editor::Content::new();

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
                }
                Task::none()
            }
            Message::InterfaceSelected(interface) => {
                self.scan_capture_screen.selected_interface = interface;
                Task::none()
            }
            Message::BrowseCaptureFile => Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .set_title("Save Capture File")
                        .add_filter("Capture Files", &["pcap", "pcap"])
                        .set_file_name("handshake.pcap")
                        .save_file()
                        .await
                        .map(|handle| handle.path().to_path_buf())
                },
                Message::CaptureFileSelected,
            ),
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
                    self.scan_capture_screen.output_file = path.to_string_lossy().to_string();
                }
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
                            self.scan_capture_screen
                                .log_messages
                                .push(format!("✅ Capture saved to {}", dest.display()));
                            if self.scan_capture_screen.log_messages.len() > 50 {
                                self.scan_capture_screen.log_messages.remove(0);
                            }
                        }
                    } else {
                        self.scan_capture_screen.error_message =
                            Some(format!("Capture file not found: {}", src.display()));
                    }
                }
                Task::none()
            }
            Message::StartCapture => {
                if let Some(ref network) = self.scan_capture_screen.target_network {
                    // Check if running as root
                    if !self.is_root {
                        self.scan_capture_screen.error_message = Some(
                            "Capture requires admin privileges. Click 'Enable Admin Mode' in this screen, or run with sudo."
                                .to_string(),
                        );
                        return Task::none();
                    }

                    self.scan_capture_screen.is_capturing = true;
                    self.scan_capture_screen.error_message = None;
                    self.scan_capture_screen.packets_captured = 0;
                    self.scan_capture_screen.handshake_progress = HandshakeProgress::default();

                    let state = Arc::new(CaptureState::new());
                    self.capture_state = Some(state.clone());

                    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                    self.capture_progress_rx = Some(rx);

                    // Parse channel from network (robust)
                    let channel = network.channel.split(',').next().and_then(|ch| {
                        // Try to find the first sequence of digits
                        // This handles "36 (5GHz)", "Channel 6", "1", etc.
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

                    // Log channel selection
                    eprintln!(
                        "[DEBUG] Starting capture on channel: {:?} (raw: '{}')",
                        channel, network.channel
                    );

                    // Warn if multiple channels detected
                    if network.channel.contains(',') {
                        self.scan_capture_screen.error_message = Some(
                            format!("Multiple channels detected ({}). Using channel {}. If capture fails, disconnect from WiFi and rescan.", 
                                network.channel, channel.unwrap())
                        );
                    }

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
                } else {
                    self.scan_capture_screen.error_message =
                        Some("No target network selected".to_string());
                    Task::none()
                }
            }
            Message::StopCapture => {
                if let Some(ref state) = self.capture_state {
                    state.stop();
                }
                self.scan_capture_screen.is_capturing = false;
                self.capture_progress_rx = None;
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
                    }
                    workers::CaptureProgress::HandshakeComplete { ssid } => {
                        self.scan_capture_screen.handshake_complete = true;
                        self.scan_capture_screen.is_capturing = false;
                        self.scan_capture_screen
                            .log_messages
                            .push(format!("✅ Handshake captured for '{}'", ssid));
                    }
                    workers::CaptureProgress::Error(msg) => {
                        self.scan_capture_screen.error_message = Some(msg.clone());
                        self.scan_capture_screen.is_capturing = false;
                        self.scan_capture_screen
                            .log_messages
                            .push(format!("❌ Error: {}", msg));
                    }
                    workers::CaptureProgress::Finished {
                        output_file,
                        packets,
                    } => {
                        self.scan_capture_screen.output_file = output_file;
                        self.scan_capture_screen.packets_captured = packets;
                        self.scan_capture_screen.is_capturing = false;
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
                    self.crack_screen.handshake_path = self.scan_capture_screen.output_file.clone();
                }
                Task::none()
            }
            Message::HandshakePathChanged(path) => {
                self.crack_screen.handshake_path = path;
                Task::none()
            }
            Message::EngineChanged(engine) => {
                self.crack_screen.engine = engine;
                Task::none()
            }
            Message::MethodChanged(method) => {
                self.crack_screen.method = method;
                Task::none()
            }
            Message::MinDigitsChanged(val) => {
                if val.is_empty() || val.parse::<usize>().is_ok() {
                    self.crack_screen.min_digits = val;
                }
                Task::none()
            }
            Message::MaxDigitsChanged(val) => {
                if val.is_empty() || val.parse::<usize>().is_ok() {
                    self.crack_screen.max_digits = val;
                }
                Task::none()
            }
            Message::WordlistPathChanged(path) => {
                self.crack_screen.wordlist_path = path;
                Task::none()
            }
            Message::BrowseHandshake => Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .add_filter("Capture files", &["pcap", "pcap", "json"])
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
                    self.crack_screen.handshake_path = p.display().to_string();
                }
                Task::none()
            }
            Message::WordlistSelected(path) => {
                if let Some(p) = path {
                    self.crack_screen.wordlist_path = p.display().to_string();
                }
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
                self.crack_screen.logs_content = text_editor::Content::new();

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
                        self.crack_screen.found_password = Some(password);
                        self.crack_screen.status_message = "Password found!".to_string();
                        self.crack_screen.progress = 1.0;
                        self.crack_screen.is_cracking = false;
                        self.crack_progress_rx = None;
                    }
                    workers::CrackProgress::NotFound => {
                        self.crack_screen.status_message = "Password not found".to_string();
                        self.crack_screen.progress = 1.0;
                        self.crack_screen.password_not_found = true;
                        self.crack_screen.is_cracking = false;
                        self.crack_progress_rx = None;
                    }
                    workers::CrackProgress::Error(msg) => {
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
                    return clipboard::write(password.clone());
                }
                Task::none()
            }
            Message::CopyLogs => {
                let logs_text = self.crack_screen.log_messages.join("\n");
                if !logs_text.is_empty() {
                    return clipboard::write(logs_text);
                }
                Task::none()
            }
            Message::LogsEditorAction(action) => {
                self.crack_screen.logs_content.perform(action);
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
