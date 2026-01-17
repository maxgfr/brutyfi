/*!
 * Combined Scan & Capture Screen
 *
 * Unified screen for WiFi network scanning and handshake capture.
 * Shows network list on the left, capture panel on the right.
 */

use iced::widget::{
    button, column, container, horizontal_rule, horizontal_space, row, scrollable, text, Column,
};
use iced::{Element, Length};

use crate::app::Message;
use crate::theme::{self, colors};
use bruteforce_wifi::WifiNetwork;

/// EAPOL message tracking
#[derive(Debug, Clone, Default)]
pub struct HandshakeProgress {
    pub m1_received: bool,
    pub m2_received: bool,
    pub m3_received: bool,
    pub m4_received: bool,
    pub last_ap_mac: String,
    pub last_client_mac: String,
}

impl HandshakeProgress {
    pub fn is_complete(&self) -> bool {
        self.m1_received && self.m2_received
    }
}

/// Combined Scan & Capture screen state
#[derive(Debug, Clone)]
pub struct ScanCaptureScreen {
    // Scan state
    pub networks: Vec<WifiNetwork>,
    pub selected_network: Option<usize>,
    pub is_scanning: bool,
    pub location_services_warning: bool,

    // Capture state
    pub target_network: Option<WifiNetwork>,
    #[allow(dead_code)]
    pub interface: String,
    pub output_file: String,
    pub is_capturing: bool,
    pub packets_captured: u64,
    pub handshake_progress: HandshakeProgress,
    pub handshake_complete: bool,

    // Shared
    pub error_message: Option<String>,
    #[allow(dead_code)]
    pub log_messages: Vec<String>,
}

impl Default for ScanCaptureScreen {
    fn default() -> Self {
        Self {
            networks: Vec::new(),
            selected_network: None,
            is_scanning: false,
            location_services_warning: false,
            target_network: None,
            interface: "en0".to_string(),
            output_file: "capture.cap".to_string(),
            is_capturing: false,
            packets_captured: 0,
            handshake_progress: HandshakeProgress::default(),
            handshake_complete: false,
            error_message: None,
            log_messages: Vec::new(),
        }
    }
}

impl ScanCaptureScreen {
    pub fn view(&self) -> Element<'_, Message> {
        // Left panel: Network list
        let left_panel = self.view_network_list();

        // Right panel: Capture
        let right_panel = self.view_capture_panel();

        // Main layout: two columns
        let content = row![left_panel, right_panel,]
            .spacing(15)
            .height(Length::Fill);

        container(content.padding(20))
            .width(Length::Fill)
            .height(Length::Fill)
            .style(|_| container::Style {
                background: Some(iced::Background::Color(colors::BACKGROUND)),
                ..Default::default()
            })
            .into()
    }

    fn view_network_list(&self) -> Element<'_, Message> {
        let title = text("WiFi Networks").size(20).color(colors::TEXT);

        // Scan button
        let scan_btn = if self.is_scanning {
            button(
                row![text("Scanning...").size(13),]
                    .spacing(6)
                    .align_y(iced::Alignment::Center),
            )
            .padding([8, 16])
            .style(theme::secondary_button_style)
            .on_press(Message::StopScan)
        } else {
            button(text("Scan").size(13))
                .padding([8, 16])
                .style(theme::primary_button_style)
                .on_press(Message::StartScan)
        };

        let header = row![title, horizontal_space(), scan_btn,].align_y(iced::Alignment::Center);

        // Location Services Warning (compact)
        let location_warning = if self.location_services_warning {
            Some(
                container(
                    text("Location Services required for BSSIDs")
                        .size(11)
                        .color(colors::WARNING),
                )
                .padding([6, 10])
                .style(|_| container::Style {
                    background: Some(iced::Background::Color(iced::Color::from_rgba(
                        0.95, 0.77, 0.06, 0.15,
                    ))),
                    border: iced::Border {
                        color: colors::WARNING,
                        width: 1.0,
                        radius: 4.0.into(),
                    },
                    ..Default::default()
                }),
            )
        } else {
            None
        };

        // Network list
        let network_list: Element<Message> = if self.networks.is_empty() {
            if self.is_scanning {
                container(text("Scanning...").size(13).color(colors::TEXT_DIM))
                    .center_x(Length::Fill)
                    .center_y(Length::Fill)
                    .into()
            } else {
                container(
                    column![
                        text("No networks").size(14).color(colors::TEXT_DIM),
                        text("Click Scan to discover WiFi networks")
                            .size(11)
                            .color(colors::TEXT_DIM),
                    ]
                    .spacing(4)
                    .align_x(iced::Alignment::Center),
                )
                .center_x(Length::Fill)
                .center_y(Length::Fill)
                .into()
            }
        } else {
            let items: Vec<Element<Message>> = self
                .networks
                .iter()
                .enumerate()
                .map(|(idx, network)| {
                    let is_selected = self.selected_network == Some(idx);

                    let security_color = if network.security.contains("WPA3") {
                        colors::DANGER
                    } else if network.security.contains("WPA") {
                        colors::PRIMARY
                    } else if network.security.contains("None") {
                        colors::SUCCESS
                    } else {
                        colors::TEXT_DIM
                    };

                    let signal_icon = if let Ok(rssi) = network.signal_strength.parse::<i32>() {
                        if rssi > -50 {
                            "Strong"
                        } else if rssi > -70 {
                            "Medium"
                        } else {
                            "Weak"
                        }
                    } else {
                        "?"
                    };

                    let item_style = if is_selected {
                        theme::network_item_selected_style
                    } else {
                        theme::network_item_style
                    };

                    button(
                        container(
                            row![
                                column![
                                    text(network.ssid.clone()).size(13).color(if is_selected {
                                        colors::SUCCESS
                                    } else {
                                        colors::TEXT
                                    }),
                                    text(format!("Ch {} | {}", network.channel, signal_icon))
                                        .size(10)
                                        .color(colors::TEXT_DIM),
                                ]
                                .spacing(2),
                                horizontal_space(),
                                text(network.security.clone())
                                    .size(10)
                                    .color(security_color),
                            ]
                            .align_y(iced::Alignment::Center)
                            .padding(8),
                        )
                        .style(item_style),
                    )
                    .padding(0)
                    .style(|_, _| button::Style {
                        background: None,
                        ..Default::default()
                    })
                    .on_press(Message::SelectNetwork(idx))
                    .into()
                })
                .collect();

            scrollable(Column::with_children(items).spacing(4).width(Length::Fill))
                .height(Length::Fill)
                .into()
        };

        let network_count = if !self.networks.is_empty() {
            Some(
                text(format!("{} networks", self.networks.len()))
                    .size(11)
                    .color(colors::TEXT_DIM),
            )
        } else {
            None
        };

        let mut content = column![header,].spacing(10);

        if let Some(warning) = location_warning {
            content = content.push(warning);
        }

        content = content.push(
            container(network_list)
                .height(Length::Fill)
                .width(Length::Fill)
                .style(theme::card_style)
                .padding(8),
        );

        if let Some(count) = network_count {
            content = content.push(count);
        }

        container(content)
            .width(Length::FillPortion(2))
            .height(Length::Fill)
            .into()
    }

    fn view_capture_panel(&self) -> Element<'_, Message> {
        let title = text("Capture Handshake").size(20).color(colors::TEXT);

        // Network selector - simplified without pick_list
        let network_selector: Element<Message> = if self.target_network.is_none() {
            container(
                text("Select a network from the list on the left")
                    .size(12)
                    .color(colors::TEXT_DIM),
            )
            .padding(10)
            .style(theme::card_style)
            .into()
        } else {
            container(text("Network selected").size(12).color(colors::SUCCESS))
                .padding(10)
                .style(theme::card_style)
                .into()
        };

        // Target info
        let target_info = self.target_network.as_ref().map(|network| {
            container(
                column![
                    row![
                        text("SSID: ").size(11).color(colors::TEXT_DIM),
                        text(&network.ssid).size(11).color(colors::TEXT),
                    ],
                    row![
                        text("BSSID: ").size(11).color(colors::TEXT_DIM),
                        text(if network.bssid.is_empty() {
                            "Hidden"
                        } else {
                            &network.bssid
                        })
                        .size(11)
                        .color(colors::TEXT),
                    ],
                    row![
                        text("Channel: ").size(11).color(colors::TEXT_DIM),
                        text(&network.channel).size(11).color(colors::TEXT),
                        text(" | Security: ").size(11).color(colors::TEXT_DIM),
                        text(&network.security).size(11).color(colors::PRIMARY),
                    ],
                ]
                .spacing(2),
            )
            .padding(10)
            .style(theme::card_style)
        });

        // Handshake progress (compact)
        let handshake_status = {
            let hp = &self.handshake_progress;

            let step_style = |received: bool| {
                move |_: &_| container::Style {
                    background: Some(iced::Background::Color(if received {
                        iced::Color::from_rgba(0.18, 0.80, 0.44, 0.2)
                    } else {
                        colors::SURFACE
                    })),
                    border: iced::Border {
                        color: if received {
                            colors::SUCCESS
                        } else {
                            colors::BORDER
                        },
                        width: 1.0,
                        radius: 4.0.into(),
                    },
                    ..Default::default()
                }
            };

            let m1_color = if hp.m1_received {
                colors::SUCCESS
            } else {
                colors::TEXT_DIM
            };
            let m2_color = if hp.m2_received {
                colors::SUCCESS
            } else {
                colors::TEXT_DIM
            };
            let m3_color = if hp.m3_received {
                colors::SUCCESS
            } else {
                colors::TEXT_DIM
            };
            let m4_color = if hp.m4_received {
                colors::SUCCESS
            } else {
                colors::TEXT_DIM
            };

            let status_text = if self.handshake_complete {
                text("Handshake captured!").size(12).color(colors::SUCCESS)
            } else if hp.is_complete() {
                text("M1+M2 ready for cracking!")
                    .size(12)
                    .color(colors::SUCCESS)
            } else {
                text("Waiting for handshake...")
                    .size(12)
                    .color(colors::TEXT_DIM)
            };

            container(
                column![
                    text("4-Way Handshake").size(11).color(colors::TEXT_DIM),
                    row![
                        container(text("M1").size(12).color(m1_color))
                            .padding([6, 10])
                            .style(step_style(hp.m1_received)),
                        text("→").size(14).color(colors::TEXT_DIM),
                        container(text("M2").size(12).color(m2_color))
                            .padding([6, 10])
                            .style(step_style(hp.m2_received)),
                        text("→").size(14).color(colors::TEXT_DIM),
                        container(text("M3").size(12).color(m3_color))
                            .padding([6, 10])
                            .style(step_style(hp.m3_received)),
                        text("→").size(14).color(colors::TEXT_DIM),
                        container(text("M4").size(12).color(m4_color))
                            .padding([6, 10])
                            .style(step_style(hp.m4_received)),
                    ]
                    .spacing(6)
                    .align_y(iced::Alignment::Center),
                    status_text,
                ]
                .spacing(8),
            )
            .padding(10)
            .style(theme::card_style)
        };

        // Capture status
        let capture_status = if self.is_capturing {
            container(
                row![
                    text("Capturing...").size(12).color(colors::SUCCESS),
                    horizontal_space(),
                    text(format!("{} packets", self.packets_captured))
                        .size(12)
                        .color(colors::TEXT),
                ]
                .align_y(iced::Alignment::Center),
            )
            .padding(10)
            .style(|_| container::Style {
                background: Some(iced::Background::Color(iced::Color::from_rgba(
                    0.18, 0.80, 0.44, 0.1,
                ))),
                border: iced::Border {
                    color: colors::SUCCESS,
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            })
        } else {
            container(text("Ready to capture").size(12).color(colors::TEXT_DIM))
                .padding(10)
                .style(theme::card_style)
        };

        // Error display
        let error_display = self.error_message.as_ref().map(|msg| {
            container(text(msg).size(11).color(colors::DANGER))
                .padding(8)
                .style(|_| container::Style {
                    background: Some(iced::Background::Color(iced::Color::from_rgba(
                        0.86, 0.21, 0.27, 0.15,
                    ))),
                    border: iced::Border {
                        color: colors::DANGER,
                        width: 1.0,
                        radius: 4.0.into(),
                    },
                    ..Default::default()
                })
        });

        // Instructions (compact)
        let instructions = container(
            column![
                text("How to capture:").size(11).color(colors::TEXT),
                text("1. Start capture below")
                    .size(10)
                    .color(colors::TEXT_DIM),
                text("2. On another device, reconnect to the network")
                    .size(10)
                    .color(colors::TEXT_DIM),
                text("3. Handshake will be captured automatically")
                    .size(10)
                    .color(colors::TEXT_DIM),
            ]
            .spacing(2),
        )
        .padding(10)
        .style(|_| container::Style {
            background: Some(iced::Background::Color(iced::Color::from_rgba(
                0.5, 0.5, 0.5, 0.1,
            ))),
            border: iced::Border {
                color: colors::BORDER,
                width: 1.0,
                radius: 4.0.into(),
            },
            ..Default::default()
        });

        // Control buttons
        let capture_btn = if self.is_capturing {
            button(text("Stop Capture").size(13))
                .padding([10, 20])
                .style(theme::danger_button_style)
                .on_press(Message::StopCapture)
        } else {
            let can_capture = self.target_network.is_some();
            let btn = button(text("Start Capture").size(13))
                .padding([10, 20])
                .style(theme::primary_button_style);
            if can_capture {
                btn.on_press(Message::StartCapture)
            } else {
                btn
            }
        };

        let continue_btn = if self.handshake_complete || self.handshake_progress.is_complete() {
            Some(
                button(text("Continue to Crack").size(13))
                    .padding([10, 20])
                    .style(theme::primary_button_style)
                    .on_press(Message::GoToCrack),
            )
        } else {
            None
        };

        // Build layout
        let mut content = column![title, horizontal_rule(1), network_selector,].spacing(10);

        if let Some(info) = target_info {
            content = content.push(info);
        }

        content = content.push(handshake_status);
        content = content.push(capture_status);

        if let Some(error) = error_display {
            content = content.push(error);
        }

        content = content.push(instructions);

        let mut button_row = row![capture_btn,].spacing(10);
        if let Some(btn) = continue_btn {
            button_row = button_row.push(btn);
        }
        content = content.push(button_row);

        container(content)
            .width(Length::FillPortion(3))
            .height(Length::Fill)
            .into()
    }
}
