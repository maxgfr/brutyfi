/*!
 * General handlers
 *
 * Handles general application operations like tick.
 */

use iced::Task;

use crate::app::BruteforceApp;
use crate::messages::Message;

impl BruteforceApp {
    /// Return to normal (non-root) mode
    pub fn handle_return_to_normal_mode(&mut self) -> Task<Message> {
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
                "Failed to return to normal mode. Please restart the app manually.".to_string(),
            );
        }

        Task::none()
    }

    /// Handle tick for polling progress channels
    pub fn handle_tick(&mut self) -> Task<Message> {
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
