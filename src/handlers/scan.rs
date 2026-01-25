/*!
 * Scan handlers
 *
 * Handles WiFi network scanning operations.
 */

use iced::Task;

use crate::app::BruteforceApp;
use crate::messages::Message;
use crate::screens::HandshakeProgress;
use crate::workers::{self, ScanResult};

impl BruteforceApp {
    /// Start network scanning
    pub fn handle_start_scan(&mut self) -> Task<Message> {
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

    /// Stop network scanning
    pub fn handle_stop_scan(&mut self) -> Task<Message> {
        self.scan_capture_screen.is_scanning = false;
        Task::none()
    }

    /// Handle scan completion
    pub fn handle_scan_complete(&mut self, result: ScanResult) -> Task<Message> {
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

    /// Handle network selection
    pub fn handle_select_network(&mut self, idx: usize) -> Task<Message> {
        self.scan_capture_screen.selected_network = Some(idx);

        if let Some(network) = self.scan_capture_screen.networks.get(idx) {
            self.scan_capture_screen.target_network = Some(network.clone());
            self.scan_capture_screen.handshake_progress = HandshakeProgress::default();
            self.scan_capture_screen.handshake_complete = false;
            self.scan_capture_screen.packets_captured = 0;

            // Extract available channels from the network
            let channels: Vec<String> = network
                .channel
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();

            self.scan_capture_screen.available_channels = channels.clone();

            // Auto-select first channel if only one
            if channels.len() == 1 {
                self.scan_capture_screen.selected_channel = Some(channels[0].clone());
            } else {
                self.scan_capture_screen.selected_channel = None;
            }
        }

        self.persist_state();
        Task::none()
    }

    /// Handle channel selection
    pub fn handle_select_channel(&mut self, channel: String) -> Task<Message> {
        self.scan_capture_screen.selected_channel = Some(channel);
        Task::none()
    }

    /// Handle interface selection
    pub fn handle_interface_selected(&mut self, interface: String) -> Task<Message> {
        self.scan_capture_screen.selected_interface = interface;
        self.persist_state();
        Task::none()
    }
}
