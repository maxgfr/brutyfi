/*!
 * Capture handlers
 *
 * Handles packet capture operations.
 */

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use iced::Task;

use crate::app::BruteforceApp;
use crate::messages::Message;
use crate::screens::HandshakeProgress;
use crate::workers::{self, CaptureParams, CaptureProgress, CaptureState};

impl BruteforceApp {
    /// Browse for capture file location
    pub fn handle_browse_capture_file(&self) -> Task<Message> {
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

    /// Handle capture file selection
    pub fn handle_capture_file_selected(&mut self, path: Option<PathBuf>) -> Task<Message> {
        if let Some(path) = path {
            let path_str = path.to_string_lossy().to_string();
            eprintln!("[DEBUG] Capture file selected: {}", path_str);
            self.scan_capture_screen.output_file = path_str.clone();
            self.add_capture_log(format!("📁 Output file: {}", path_str));
        }
        self.persist_state();
        Task::none()
    }

    /// Download captured PCAP file
    pub fn handle_download_captured_pcap(&self) -> Task<Message> {
        Task::perform(
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
        )
    }

    /// Save captured PCAP to selected location
    pub fn handle_save_captured_pcap(&mut self, path: Option<PathBuf>) -> Task<Message> {
        if let Some(dest) = path {
            let src = PathBuf::from(&self.scan_capture_screen.output_file);
            if src.exists() {
                if let Err(e) = fs::copy(&src, &dest) {
                    self.scan_capture_screen.error_message =
                        Some(format!("Failed to save capture: {}", e));
                } else {
                    self.scan_capture_screen.last_saved_capture_path =
                        Some(dest.display().to_string());
                    self.crack_screen.handshake_path = dest.display().to_string();
                    self.add_capture_log(format!("✅ Capture saved to {}", dest.display()));
                }
            } else {
                self.scan_capture_screen.error_message =
                    Some(format!("Capture file not found: {}", src.display()));
            }
        }
        self.persist_state();
        Task::none()
    }

    /// Disconnect from WiFi
    pub fn handle_disconnect_wifi(&self) -> Task<Message> {
        Task::perform(
            async {
                tokio::task::spawn_blocking(|| -> Result<(), String> {
                    brutifi::disconnect_wifi().map_err(|e| e.to_string())
                })
                .await
                .unwrap_or_else(|e| Err(e.to_string()))
            },
            Message::WifiDisconnectResult,
        )
    }

    /// Handle WiFi disconnect result
    pub fn handle_wifi_disconnect_result(&mut self, result: Result<(), String>) -> Task<Message> {
        match result {
            Ok(()) => {
                self.scan_capture_screen.error_message = None;
                self.add_capture_log("🔌 WiFi disconnected successfully".to_string());
                self.add_capture_log("✓ You can now start capture".to_string());
            }
            Err(err) => {
                self.scan_capture_screen.error_message = Some(err.clone());
                self.add_capture_log(format!("❌ Disconnect failed: {}", err));
            }
        }
        Task::none()
    }

    /// Start packet capture
    pub fn handle_start_capture(&mut self) -> Task<Message> {
        let network = match self.scan_capture_screen.target_network.clone() {
            Some(network) => network,
            None => {
                self.scan_capture_screen.error_message =
                    Some("No target network selected".to_string());
                return Task::none();
            }
        };

        // Warn if WiFi is connected
        if let Some(ssid) = brutifi::wifi_connected_ssid() {
            self.add_capture_log(format!(
                "⚠️ Warning: WiFi connected to '{}'. Consider disconnecting for better capture.",
                ssid
            ));
        }

        // Check if running as root
        if !self.is_root {
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

        self.scan_capture_screen.is_capturing = true;
        self.scan_capture_screen.error_message = None;
        self.scan_capture_screen.packets_captured = 0;
        self.scan_capture_screen.handshake_progress = HandshakeProgress::default();
        self.persist_state();

        let state = Arc::new(CaptureState::new());
        self.capture_state = Some(state.clone());

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.capture_progress_rx = Some(rx);

        // Get channel to capture on
        let channel_str = self
            .scan_capture_screen
            .selected_channel
            .clone()
            .or_else(|| {
                network
                    .channel
                    .split(',')
                    .next()
                    .map(|s| s.trim().to_string())
            });

        let channel = channel_str.and_then(|ch| {
            ch.split(|c: char| !c.is_ascii_digit())
                .find(|s| !s.is_empty())
                .and_then(|s| s.parse::<u32>().ok())
        });

        if channel.is_none() {
            self.scan_capture_screen.error_message = Some(format!(
                "Could not detect channel from network info (channel field: '{}'). Please rescan.",
                network.channel
            ));
            self.scan_capture_screen.is_capturing = false;
            return Task::none();
        }

        if self.scan_capture_screen.available_channels.len() > 1
            && self.scan_capture_screen.selected_channel.is_none()
        {
            self.scan_capture_screen.error_message = Some(
                "Multiple channels available. Please select a channel before starting capture."
                    .to_string(),
            );
            self.scan_capture_screen.is_capturing = false;
            return Task::none();
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
    }

    /// Stop packet capture
    pub fn handle_stop_capture(&mut self) -> Task<Message> {
        if let Some(ref state) = self.capture_state {
            state.stop();
        }
        self.scan_capture_screen.is_capturing = false;
        self.capture_progress_rx = None;
        self.persist_state();
        Task::none()
    }

    /// Handle capture progress updates
    pub fn handle_capture_progress(&mut self, progress: CaptureProgress) -> Task<Message> {
        match progress {
            CaptureProgress::Log(msg) => {
                self.add_capture_log(msg);
            }
            CaptureProgress::HandshakeComplete { ssid } => {
                self.scan_capture_screen.handshake_complete = true;
                self.scan_capture_screen.handshake_progress.m1_received = true;
                self.scan_capture_screen.handshake_progress.m2_received = true;
                self.scan_capture_screen.is_capturing = false;
                self.add_capture_log(format!("✅ Handshake captured for '{}'", ssid));
                self.persist_state();

                if self.is_root {
                    let envs = self.build_relaunch_envs_for_capture(false);
                    if crate::relaunch_as_user(&envs) {
                        std::process::exit(0);
                    }
                }
            }
            CaptureProgress::Error(msg) => {
                self.scan_capture_screen.error_message = Some(msg.clone());
                self.scan_capture_screen.is_capturing = false;
                self.add_capture_log(format!("❌ Error: {}", msg));
                self.persist_state();
            }
            CaptureProgress::Finished {
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

    /// Enable admin mode
    pub fn handle_enable_admin_mode(&mut self) -> Task<Message> {
        if !self.is_root {
            if crate::relaunch_as_root() {
                std::process::exit(0);
            }

            self.scan_capture_screen.error_message = Some(
                "Failed to request admin privileges. Please try again or launch with sudo."
                    .to_string(),
            );
        }

        Task::none()
    }

    /// Helper to add a log message to capture screen
    pub(crate) fn add_capture_log(&mut self, msg: String) {
        self.scan_capture_screen.log_messages.push(msg);
        if self.scan_capture_screen.log_messages.len() > 50 {
            self.scan_capture_screen.log_messages.remove(0);
        }
    }
}
