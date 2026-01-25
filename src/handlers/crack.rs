/*!
 * Crack handlers
 *
 * Handles password cracking operations.
 */

use std::path::PathBuf;
use std::sync::Arc;

use iced::{clipboard, Task};

use crate::app::BruteforceApp;
use crate::messages::Message;
use crate::screens::{CrackEngine, CrackMethod};
use crate::workers::{self, CrackProgress, CrackState, NumericCrackParams, WordlistCrackParams};
use crate::workers_optimized;

impl BruteforceApp {
    /// Handle handshake path change
    pub fn handle_handshake_path_changed(&mut self, path: String) -> Task<Message> {
        self.crack_screen.handshake_path = path;
        self.persist_state();
        Task::none()
    }

    /// Handle engine change
    pub fn handle_engine_changed(&mut self, engine: CrackEngine) -> Task<Message> {
        self.crack_screen.engine = engine;
        self.persist_state();
        Task::none()
    }

    /// Handle method change
    pub fn handle_method_changed(&mut self, method: CrackMethod) -> Task<Message> {
        self.crack_screen.method = method;
        self.persist_state();
        Task::none()
    }

    /// Handle min digits change
    pub fn handle_min_digits_changed(&mut self, val: String) -> Task<Message> {
        if val.is_empty() || val.parse::<usize>().is_ok() {
            self.crack_screen.min_digits = val;
            self.persist_state();
        }
        Task::none()
    }

    /// Handle max digits change
    pub fn handle_max_digits_changed(&mut self, val: String) -> Task<Message> {
        if val.is_empty() || val.parse::<usize>().is_ok() {
            self.crack_screen.max_digits = val;
            self.persist_state();
        }
        Task::none()
    }

    /// Handle wordlist path change
    pub fn handle_wordlist_path_changed(&mut self, path: String) -> Task<Message> {
        self.crack_screen.wordlist_path = path;
        self.persist_state();
        Task::none()
    }

    /// Browse for handshake file
    pub fn handle_browse_handshake(&self) -> Task<Message> {
        Task::perform(
            async {
                rfd::AsyncFileDialog::new()
                    .add_filter("Capture files", &["cap", "pcap", "pcapng", "json"])
                    .set_title("Select Handshake File")
                    .pick_file()
                    .await
                    .map(|f| f.path().to_path_buf())
            },
            Message::HandshakeSelected,
        )
    }

    /// Browse for wordlist file
    pub fn handle_browse_wordlist(&self) -> Task<Message> {
        Task::perform(
            async {
                rfd::AsyncFileDialog::new()
                    .add_filter("Wordlist files", &["txt", "lst"])
                    .set_title("Select Wordlist File")
                    .pick_file()
                    .await
                    .map(|f| f.path().to_path_buf())
            },
            Message::WordlistSelected,
        )
    }

    /// Handle handshake file selection
    pub fn handle_handshake_selected(&mut self, path: Option<PathBuf>) -> Task<Message> {
        if let Some(p) = path {
            let path_str = p.display().to_string();
            eprintln!("[DEBUG] Handshake file selected: {}", path_str);
            self.crack_screen.handshake_path = path_str.clone();
            self.add_crack_log(format!("📁 Handshake file: {}", path_str));

            // Extract SSID from the handshake file
            match brutifi::parse_cap_file(&p, None) {
                Ok(handshake) => {
                    self.crack_screen.ssid = handshake.ssid.clone();
                    self.add_crack_log(format!("📡 Detected SSID: {}", handshake.ssid));
                    eprintln!("[DEBUG] Extracted SSID from handshake: {}", handshake.ssid);
                }
                Err(e) => {
                    eprintln!("[DEBUG] Failed to parse handshake file: {}", e);
                    self.add_crack_log(format!("⚠️ Could not extract SSID: {}", e));
                }
            }
        }
        self.persist_state();
        Task::none()
    }

    /// Handle wordlist file selection
    pub fn handle_wordlist_selected(&mut self, path: Option<PathBuf>) -> Task<Message> {
        if let Some(p) = path {
            let path_str = p.display().to_string();
            eprintln!("[DEBUG] Wordlist file selected: {}", path_str);
            self.crack_screen.wordlist_path = path_str.clone();
            self.add_crack_log(format!("📁 Wordlist file: {}", path_str));
        }
        self.persist_state();
        Task::none()
    }

    /// Start cracking process
    pub fn handle_start_crack(&mut self) -> Task<Message> {
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

        // Validate numeric range
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

        // Initialize cracking state
        self.crack_screen.is_cracking = true;
        self.crack_screen.error_message = None;
        self.crack_screen.found_password = None;
        self.crack_screen.password_not_found = false;
        self.crack_screen.current_attempts = 0;
        self.crack_screen.progress = 0.0;
        self.crack_screen.status_message = "Starting...".to_string();
        self.crack_screen.log_messages.clear();

        // Add initial log messages
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

        let state = Arc::new(CrackState::new());
        self.crack_state = Some(state.clone());

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.crack_progress_rx = Some(rx);

        match self.crack_screen.method {
            CrackMethod::Numeric => self.start_numeric_crack(handshake_path, state, tx),
            CrackMethod::Wordlist => self.start_wordlist_crack(handshake_path, state, tx),
        }
    }

    fn start_numeric_crack(
        &mut self,
        handshake_path: PathBuf,
        state: Arc<CrackState>,
        tx: tokio::sync::mpsc::UnboundedSender<CrackProgress>,
    ) -> Task<Message> {
        if self.crack_screen.engine == CrackEngine::Hashcat {
            let params = workers::HashcatCrackParams {
                handshake_path,
                wordlist_path: None,
                min_digits: Some(self.crack_screen.min_digits.parse().unwrap_or(8)),
                max_digits: Some(self.crack_screen.max_digits.parse().unwrap_or(8)),
                is_numeric: true,
            };

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

    fn start_wordlist_crack(
        &mut self,
        handshake_path: PathBuf,
        state: Arc<CrackState>,
        tx: tokio::sync::mpsc::UnboundedSender<CrackProgress>,
    ) -> Task<Message> {
        if self.crack_screen.engine == CrackEngine::Hashcat {
            let params = workers::HashcatCrackParams {
                handshake_path,
                wordlist_path: Some(PathBuf::from(&self.crack_screen.wordlist_path)),
                min_digits: None,
                max_digits: None,
                is_numeric: false,
            };

            Task::perform(
                workers::crack_hashcat_async(params, state, tx),
                Message::CrackProgress,
            )
        } else {
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

    /// Stop cracking process
    pub fn handle_stop_crack(&mut self) -> Task<Message> {
        if let Some(ref state) = self.crack_state {
            state.stop();
        }
        self.crack_screen.is_cracking = false;
        self.crack_screen.status_message = "Stopped".to_string();
        self.crack_progress_rx = None;
        Task::none()
    }

    /// Handle crack progress updates
    pub fn handle_crack_progress(&mut self, progress: CrackProgress) -> Task<Message> {
        match progress {
            CrackProgress::Started { total } => {
                self.crack_screen.total_attempts = total;
                self.crack_screen.status_message = "Cracking...".to_string();
            }
            CrackProgress::Progress {
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
            CrackProgress::Log(msg) => {
                self.add_crack_log(msg);
            }
            CrackProgress::Found(password) => {
                self.drain_crack_logs();
                self.add_crack_log(format!("✅ Password found: {}", password));
                self.crack_screen.found_password = Some(password);
                self.crack_screen.status_message = "Password found!".to_string();
                self.crack_screen.progress = 1.0;
                self.crack_screen.is_cracking = false;
                self.crack_progress_rx = None;
            }
            CrackProgress::NotFound => {
                self.drain_crack_logs();
                self.add_crack_log(
                    "❌ Password not found - all combinations exhausted".to_string(),
                );
                self.crack_screen.status_message = "Password not found".to_string();
                self.crack_screen.progress = 1.0;
                self.crack_screen.password_not_found = true;
                self.crack_screen.is_cracking = false;
                self.crack_progress_rx = None;
            }
            CrackProgress::Error(msg) => {
                self.drain_crack_logs();
                self.add_crack_log(format!("❌ Error: {}", msg));
                self.crack_screen.error_message = Some(msg);
                self.crack_screen.status_message = "Error occurred".to_string();
                self.crack_screen.is_cracking = false;
                self.crack_progress_rx = None;
            }
        }
        Task::none()
    }

    /// Copy password to clipboard
    pub fn handle_copy_password(&self) -> Task<Message> {
        if let Some(ref password) = self.crack_screen.found_password {
            use std::io::Write;
            use std::process::{Command, Stdio};

            if let Ok(mut child) = Command::new("pbcopy").stdin(Stdio::piped()).spawn() {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(password.as_bytes());
                }
                let _ = child.wait();
                return Task::none();
            }

            return clipboard::write(password.clone());
        }
        Task::none()
    }

    /// Helper to add a log message to crack screen
    fn add_crack_log(&mut self, msg: String) {
        self.crack_screen.log_messages.push(msg);
        if self.crack_screen.log_messages.len() > 50 {
            self.crack_screen.log_messages.remove(0);
        }
    }

    /// Drain remaining log messages from channel
    fn drain_crack_logs(&mut self) {
        if let Some(ref mut rx) = self.crack_progress_rx {
            while let Ok(remaining) = rx.try_recv() {
                if let CrackProgress::Log(msg) = remaining {
                    self.crack_screen.log_messages.push(msg);
                }
            }
        }
    }
}
