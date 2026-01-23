/*!
 * Crack Screen
 *
 * Handles WPA/WPA2 password cracking.
 * Supports both numeric and wordlist attacks.
 * Can use native CPU cracking or external GPU tools (hashcat + hcxtools).
 */

use iced::widget::{
    button, checkbox, column, container, horizontal_space, pick_list, row, text, text_editor,
    text_input,
};
use iced::{Element, Length};

use crate::app::Message;
use crate::theme::{self, colors};
use serde::{Deserialize, Serialize};

/// Cracking engine selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CrackEngine {
    #[default]
    Native,
    Hashcat,
}

impl std::fmt::Display for CrackEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CrackEngine::Native => write!(f, "Native (CPU)"),
            CrackEngine::Hashcat => write!(f, "Hashcat (GPU) ⚡"),
        }
    }
}

/// Crack method selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CrackMethod {
    #[default]
    Numeric,
    Wordlist,
}

impl std::fmt::Display for CrackMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CrackMethod::Numeric => write!(f, "Numeric (digits only)"),
            CrackMethod::Wordlist => write!(f, "Wordlist"),
        }
    }
}

/// Crack screen state
#[derive(Debug)]
pub struct CrackScreen {
    pub handshake_path: String,
    pub use_captured_file: bool,
    pub ssid: String,
    pub engine: CrackEngine,
    pub method: CrackMethod,
    pub min_digits: String,
    pub max_digits: String,
    pub wordlist_path: String,
    pub threads: usize,
    pub is_cracking: bool,
    pub progress: f32,
    pub current_attempts: u64,
    pub total_attempts: u64,
    pub rate: f64,
    pub found_password: Option<String>,
    pub password_not_found: bool,
    pub error_message: Option<String>,
    pub status_message: String,
    pub log_messages: Vec<String>,
    pub logs_content: iced::widget::text_editor::Content,
    pub hashcat_available: bool,
    pub hcxtools_available: bool,
}

impl Default for CrackScreen {
    fn default() -> Self {
        // Check external tools availability
        let (hcxtools, hashcat) = brutifi::are_external_tools_available();

        Self {
            handshake_path: "/tmp/capture.pcap".to_string(),
            use_captured_file: true,
            ssid: String::new(),
            engine: CrackEngine::Native,
            method: CrackMethod::Numeric,
            min_digits: "8".to_string(),
            max_digits: "8".to_string(),
            wordlist_path: String::new(),
            threads: num_cpus::get(),
            is_cracking: false,
            progress: 0.0,
            current_attempts: 0,
            total_attempts: 0,
            rate: 0.0,
            found_password: None,
            password_not_found: false,
            error_message: None,
            status_message: "Ready to crack".to_string(),
            log_messages: Vec::new(),
            logs_content: iced::widget::text_editor::Content::new(),
            hashcat_available: hashcat,
            hcxtools_available: hcxtools,
        }
    }
}

impl CrackScreen {
    pub fn view(&self, is_root: bool) -> Element<'_, Message> {
        let title = text("Crack Password").size(28).color(colors::TEXT);

        let subtitle = text("Bruteforce WPA/WPA2 password from captured handshake")
            .size(14)
            .color(colors::TEXT_DIM);

        let root_warning = if is_root && cfg!(target_os = "macos") {
            Some(
                container(
                    column![
                        text("File access limited in admin mode")
                            .size(12)
                            .color(colors::TEXT),
                        text("Capture will automatically return to normal mode once finished.")
                            .size(10)
                            .color(colors::TEXT_DIM),
                    ]
                    .spacing(6),
                )
                .padding(10)
                .style(theme::card_style),
            )
        } else {
            None
        };

        // Engine selection (Native vs Hashcat)
        let engine_options: Vec<CrackEngine> = if self.hashcat_available && self.hcxtools_available
        {
            vec![CrackEngine::Native, CrackEngine::Hashcat]
        } else {
            vec![CrackEngine::Native]
        };

        let engine_warning = if !self.hashcat_available || !self.hcxtools_available {
            let missing = match (self.hcxtools_available, self.hashcat_available) {
                (false, false) => "hcxtools and hashcat not found",
                (false, true) => "hcxtools not found",
                (true, false) => "hashcat not found",
                _ => "",
            };
            Some(
                text(format!(
                    "💡 {} - Install for GPU acceleration (10-100x faster)",
                    missing
                ))
                .size(11)
                .color(colors::WARNING),
            )
        } else {
            None
        };

        let mut engine_picker = column![
            text("Cracking Engine").size(13).color(colors::TEXT),
            pick_list(engine_options, Some(self.engine), Message::EngineChanged,)
                .padding(10)
                .width(Length::Fill),
        ]
        .spacing(6);

        if let Some(warning) = engine_warning {
            engine_picker = engine_picker.push(warning);
        }

        // Engine info card
        let engine_info: Element<Message> = match self.engine {
            CrackEngine::Native => container(
                column![
                    text("CPU-based cracking").size(13).color(colors::TEXT),
                    text(format!(
                        "Uses {} CPU threads for parallel password testing",
                        self.threads
                    ))
                    .size(11)
                    .color(colors::TEXT_DIM),
                ]
                .spacing(4)
                .padding(10),
            )
            .style(theme::card_style)
            .into(),
            CrackEngine::Hashcat => container(
                column![
                    row![text("⚡ GPU-accelerated cracking")
                        .size(13)
                        .color(colors::SUCCESS),],
                    text("Uses hashcat + hcxtools for maximum speed")
                        .size(11)
                        .color(colors::TEXT_DIM),
                    text("Converts PCAP → .22000 format → hashcat mode 22000")
                        .size(10)
                        .color(colors::TEXT_DIM),
                ]
                .spacing(4)
                .padding(10),
            )
            .style(theme::card_style)
            .into(),
        };

        // Handshake file input
        let mut handshake_input = column![
            text("Handshake File").size(13).color(colors::TEXT),
            checkbox(
                "Use captured file from Capture screen",
                self.use_captured_file
            )
            .on_toggle(Message::UseCapturedFileToggled)
            .size(14),
        ]
        .spacing(6);

        // Only show file browse when NOT using captured file
        if !self.use_captured_file {
            handshake_input = handshake_input.push(
                row![
                    text_input("Browse for .cap file", &self.handshake_path)
                        .on_input(Message::HandshakePathChanged)
                        .padding(10)
                        .size(14)
                        .width(Length::Fill),
                    button(text("Browse").size(13))
                        .padding([10, 15])
                        .style(theme::secondary_button_style)
                        .on_press(Message::BrowseHandshake),
                ]
                .spacing(10),
            );
        }

        // Method selection
        let method_picker = column![
            text("Attack Method").size(13).color(colors::TEXT),
            pick_list(
                vec![CrackMethod::Numeric, CrackMethod::Wordlist],
                Some(self.method),
                Message::MethodChanged,
            )
            .padding(10)
            .width(Length::Fill),
        ]
        .spacing(6);

        // Method-specific options
        let method_options: Element<Message> = match self.method {
            CrackMethod::Numeric => container(
                column![
                    text("Numeric Attack Options").size(14).color(colors::TEXT),
                    text("Tests all numeric combinations (e.g., 00000000 to 99999999)")
                        .size(12)
                        .color(colors::TEXT_DIM),
                    row![
                        column![
                            text("Min Digits").size(12).color(colors::TEXT_DIM),
                            text_input("8", &self.min_digits)
                                .on_input(Message::MinDigitsChanged)
                                .padding(10)
                                .size(14)
                                .width(Length::Fixed(100.0)),
                        ]
                        .spacing(4),
                        column![
                            text("Max Digits").size(12).color(colors::TEXT_DIM),
                            text_input("8", &self.max_digits)
                                .on_input(Message::MaxDigitsChanged)
                                .padding(10)
                                .size(14)
                                .width(Length::Fixed(100.0)),
                        ]
                        .spacing(4),
                        horizontal_space(),
                    ]
                    .spacing(20)
                    .align_y(iced::Alignment::End),
                ]
                .spacing(10)
                .padding(15),
            )
            .style(theme::card_style)
            .into(),
            CrackMethod::Wordlist => container(
                column![
                    text("Wordlist Attack Options").size(14).color(colors::TEXT),
                    text("Tests passwords from a wordlist file (e.g., rockyou.txt)")
                        .size(12)
                        .color(colors::TEXT_DIM),
                    row![
                        text_input("Select a wordlist file...", &self.wordlist_path)
                            .on_input(Message::WordlistPathChanged)
                            .padding(10)
                            .size(14)
                            .width(Length::Fill),
                        button(text("Browse").size(13))
                            .padding([10, 15])
                            .style(theme::secondary_button_style)
                            .on_press(Message::BrowseWordlist),
                    ]
                    .spacing(10),
                ]
                .spacing(10)
                .padding(15),
            )
            .style(theme::card_style)
            .into(),
        };

        // Threads configuration (only show for native engine)
        let threads_config: Option<Element<Message>> = if self.engine == CrackEngine::Native {
            Some(
                column![text(format!(
                    "Threads: {} (optimized for your CPU)",
                    self.threads
                ))
                .size(13)
                .color(colors::TEXT_DIM)]
                .into(),
            )
        } else {
            None
        };

        // Progress display
        let progress_display =
            if self.is_cracking || self.found_password.is_some() || self.current_attempts > 0 {
                let progress_bar = container(
                    container(text(""))
                        .width(Length::FillPortion((self.progress * 100.0) as u16))
                        .height(Length::Fixed(8.0))
                        .style(|_| container::Style {
                            background: Some(iced::Background::Color(colors::PRIMARY)),
                            border: iced::Border {
                                radius: 4.0.into(),
                                ..Default::default()
                            },
                            ..Default::default()
                        }),
                )
                .width(Length::Fill)
                .height(Length::Fixed(8.0))
                .style(|_| container::Style {
                    background: Some(iced::Background::Color(colors::SURFACE)),
                    border: iced::Border {
                        radius: 4.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                });

                Some(
                    container(
                        column![
                            row![
                                text(&self.status_message).size(13).color(colors::TEXT),
                                horizontal_space(),
                                text(format!("{:.1}%", self.progress * 100.0))
                                    .size(13)
                                    .color(colors::TEXT_DIM),
                            ],
                            progress_bar,
                            row![
                                horizontal_space(),
                                text(format!("{:.0} passwords/sec", self.rate))
                                    .size(12)
                                    .color(colors::SECONDARY),
                            ],
                        ]
                        .spacing(8)
                        .padding(15),
                    )
                    .style(theme::card_style),
                )
            } else {
                None
            };

        // Result display
        let result_display = if let Some(ref password) = self.found_password {
            Some(
                container(
                    column![
                        text("Password Found!").size(18).color(colors::SUCCESS),
                        container(
                            row![
                                text(password).size(24).color(colors::TEXT),
                                horizontal_space(),
                                button(text("Copy").size(13))
                                    .padding([8, 15])
                                    .style(theme::secondary_button_style)
                                    .on_press(Message::CopyPassword),
                            ]
                            .align_y(iced::Alignment::Center)
                            .padding(15)
                        )
                        .style(|_| container::Style {
                            background: Some(iced::Background::Color(iced::Color::from_rgba(
                                0.18, 0.80, 0.44, 0.2
                            ))),
                            border: iced::Border {
                                color: colors::SUCCESS,
                                width: 2.0,
                                radius: 6.0.into(),
                            },
                            ..Default::default()
                        }),
                    ]
                    .spacing(10)
                    .padding(15),
                )
                .style(theme::card_style),
            )
        } else if self.password_not_found {
            Some(
                container(
                    column![
                        text("Password Not Found").size(18).color(colors::DANGER),
                        container(
                            text("The password was not found in the tested combinations")
                                .size(14)
                                .color(colors::TEXT)
                        )
                        .padding(15)
                        .style(|_| container::Style {
                            background: Some(iced::Background::Color(iced::Color::from_rgba(
                                0.86, 0.21, 0.27, 0.2
                            ))),
                            border: iced::Border {
                                color: colors::DANGER,
                                width: 2.0,
                                radius: 6.0.into(),
                            },
                            ..Default::default()
                        }),
                    ]
                    .spacing(10)
                    .padding(15),
                )
                .style(theme::card_style),
            )
        } else {
            None
        };

        // Error display
        let error_display = self.error_message.as_ref().map(|msg| {
            container(
                text(format!("Error: {}", msg))
                    .size(13)
                    .color(colors::DANGER),
            )
            .padding(10)
            .style(|_| container::Style {
                background: Some(iced::Background::Color(iced::Color::from_rgba(
                    0.86, 0.21, 0.27, 0.15,
                ))),
                border: iced::Border {
                    color: colors::DANGER,
                    width: 1.0,
                    radius: 6.0.into(),
                },
                ..Default::default()
            })
        });

        // Control buttons
        let crack_btn = if self.is_cracking {
            button(
                row![text("⟳").size(18), text("Stop Cracking").size(14),]
                    .spacing(8)
                    .align_y(iced::Alignment::Center),
            )
            .padding([12, 24])
            .style(theme::danger_button_style)
            .on_press(Message::StopCrack)
        } else {
            let can_start = match self.method {
                CrackMethod::Numeric => !self.handshake_path.is_empty(),
                CrackMethod::Wordlist => {
                    !self.handshake_path.is_empty() && !self.wordlist_path.is_empty()
                }
            };

            if can_start {
                button(text("Start Cracking").size(14))
                    .padding([12, 24])
                    .style(theme::primary_button_style)
                    .on_press(Message::StartCrack)
            } else {
                button(text("Start Cracking").size(14))
                    .padding([12, 24])
                    .style(theme::secondary_button_style)
            }
        };

        let back_btn = button(text("Back to Scan").size(14))
            .padding([10, 20])
            .style(theme::secondary_button_style)
            .on_press(Message::GoToScanCapture);

        // Logs display
        let logs_display = if !self.log_messages.is_empty() {
            let header = row![
                text("Logs").size(13).color(colors::TEXT),
                horizontal_space(),
                button(text("Copy logs").size(11))
                    .padding([6, 10])
                    .style(theme::secondary_button_style)
                    .on_press(Message::CopyLogs),
            ];

            Some(
                container(
                    column![
                        header,
                        text_editor(&self.logs_content)
                            .on_action(Message::LogsEditorAction)
                            .padding(8)
                            .size(11)
                            .height(Length::Fixed(150.0))
                    ]
                    .spacing(8)
                    .padding(15),
                )
                .style(theme::card_style),
            )
        } else {
            None
        };

        // Build layout
        let mut content = column![
            title,
            subtitle,
            engine_picker,
            engine_info,
            handshake_input,
            method_picker,
            method_options,
        ]
        .spacing(15);

        if let Some(warning) = root_warning {
            content = content.push(warning);
        }

        if let Some(threads) = threads_config {
            content = content.push(threads);
        }

        if let Some(progress) = progress_display {
            content = content.push(progress);
        }

        if let Some(result) = result_display {
            content = content.push(result);
        }

        if let Some(logs) = logs_display {
            content = content.push(logs);
        }

        if let Some(error) = error_display {
            content = content.push(error);
        }

        content = content.push(row![back_btn, horizontal_space(), crack_btn,].spacing(10));

        container(iced::widget::scrollable(content.padding(20)))
            .width(Length::Fill)
            .height(Length::Fill)
            .style(|_| container::Style {
                background: Some(iced::Background::Color(colors::BACKGROUND)),
                ..Default::default()
            })
            .into()
    }
}
