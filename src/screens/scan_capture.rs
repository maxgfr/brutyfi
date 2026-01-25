/*!
 * Combined Scan & Capture Screen
 *
 * Unified screen for WiFi network scanning and handshake capture.
 * Shows network list on the left, capture panel on the right.
 */

use iced::widget::{
    button, column, container, horizontal_rule, horizontal_space, pick_list, row, scrollable, text,
    Column,
};
use iced::{Element, Length, Theme};

use crate::messages::Message;
use crate::theme::{self, colors};
use brutifi::WifiNetwork;

/// EAPOL message tracking
#[derive(Debug, Clone, Default)]
pub struct HandshakeProgress {
    pub m1_received: bool,
    pub m2_received: bool,
}

impl HandshakeProgress {
    pub fn is_complete(&self) -> bool {
        self.m1_received && self.m2_received
    }
}

/// Combined Scan & Capture screen state
#[derive(Debug)]
pub struct ScanCaptureScreen {
    // Scan state
    pub networks: Vec<WifiNetwork>,
    pub selected_network: Option<usize>,
    pub is_scanning: bool,
    pub interface_list: Vec<String>,
    pub selected_interface: String,

    // Capture state
    pub target_network: Option<WifiNetwork>,
    pub output_file: String,
    pub is_capturing: bool,
    pub packets_captured: u64,
    pub handshake_progress: HandshakeProgress,
    pub handshake_complete: bool,

    // Shared
    pub error_message: Option<String>,
    pub log_messages: Vec<String>,
    pub last_saved_capture_path: Option<String>,

    // Channel selection for multi-channel networks
    pub available_channels: Vec<String>,
    pub selected_channel: Option<String>,
}

impl Default for ScanCaptureScreen {
    fn default() -> Self {
        Self {
            networks: Vec::new(),
            selected_network: None,
            is_scanning: false,
            interface_list: Vec::new(),
            selected_interface: "en0".to_string(),
            target_network: None,
            output_file: "/tmp/capture.pcap".to_string(),
            is_capturing: false,
            packets_captured: 0,
            handshake_progress: HandshakeProgress::default(),
            handshake_complete: false,
            error_message: None,
            log_messages: Vec::new(),
            last_saved_capture_path: None,
            available_channels: Vec::new(),
            selected_channel: None,
        }
    }
}

impl ScanCaptureScreen {
    pub fn view(&self, is_root: bool) -> Element<'_, Message> {
        // Left panel: Network list
        let left_panel = self.view_network_list();

        // Right panel: Capture
        let right_panel = self.view_capture_panel(is_root);

        // Main layout: two columns
        let content = row![left_panel, right_panel,]
            .spacing(15)
            .height(Length::Fill);

        container(content.padding(20))
            .width(Length::Fill)
            .height(Length::Fill)
            .style(|_: &Theme| container::Style {
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

        let reset_btn = button(text("Reset").size(13))
            .padding([8, 16])
            .style(theme::secondary_button_style)
            .on_press(Message::ResetScanState);

        let header = row![
            title,
            horizontal_space(),
            reset_btn,
            horizontal_space().width(10),
            scan_btn,
        ]
        .align_y(iced::Alignment::Center);

        let interface_picker: Element<Message> = if self.interface_list.is_empty() {
            container(text("No interfaces found").size(11).color(colors::TEXT_DIM)).into()
        } else {
            let options = self.interface_list.clone();
            pick_list(
                options,
                Some(self.selected_interface.clone()),
                Message::InterfaceSelected,
            )
            .placeholder("Select interface")
            .into()
        };

        let interface_row = row![
            text("Interface").size(11).color(colors::TEXT_DIM),
            interface_picker,
        ]
        .spacing(10)
        .align_y(iced::Alignment::Center);

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

        let mut content = column![header, interface_row].spacing(10);

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

    fn view_capture_panel(&self, _is_root: bool) -> Element<'_, Message> {
        let title = text("Capture Handshake").size(20).color(colors::TEXT);
        let handshake_done = self.handshake_complete || self.handshake_progress.is_complete();

        // ========== NETWORK INFO BLOCK ==========
        let network_info_block: Element<'_, Message> = if let Some(network) = &self.target_network {
            // Build column elements
            let mut col_elements: Vec<Element<Message>> = vec![
                row![
                    text("Network:")
                        .size(11)
                        .color(colors::TEXT_DIM)
                        .width(Length::Fixed(80.0)),
                    text(&network.ssid).size(12).color(colors::TEXT),
                ]
                .spacing(8)
                .into(),
                row![
                    text("Channel:")
                        .size(11)
                        .color(colors::TEXT_DIM)
                        .width(Length::Fixed(80.0)),
                    text(&network.channel).size(11).color(colors::TEXT),
                ]
                .spacing(8)
                .into(),
                row![
                    text("Security:")
                        .size(11)
                        .color(colors::TEXT_DIM)
                        .width(Length::Fixed(80.0)),
                    text(&network.security).size(11).color(colors::PRIMARY),
                ]
                .spacing(8)
                .into(),
            ];

            // Add channel selector if multiple channels
            if self.available_channels.len() > 1 {
                col_elements.push(horizontal_rule(1).into());
                col_elements.push(
                    text("Select channel to monitor:")
                        .size(10)
                        .color(colors::TEXT_DIM)
                        .into(),
                );
                col_elements.push(
                    pick_list(
                        self.available_channels.as_slice(),
                        self.selected_channel.as_ref(),
                        Message::SelectChannel,
                    )
                    .placeholder("Choose channel...")
                    .width(Length::Fill)
                    .into(),
                );
            }

            col_elements.push(horizontal_rule(1).into());
            col_elements.push(
                row![
                    text("Output file:")
                        .size(11)
                        .color(colors::TEXT_DIM)
                        .width(Length::Fixed(80.0)),
                    text(&self.output_file).size(10).color(colors::SUCCESS),
                ]
                .spacing(8)
                .into(),
            );
            col_elements.push(
                button(text("Change location").size(11))
                    .padding([5, 10])
                    .style(theme::secondary_button_style)
                    .on_press(Message::BrowseCaptureFile)
                    .into(),
            );

            container(column(col_elements).spacing(6))
                .padding(12)
                .width(Length::Fill)
                .style(theme::card_style)
                .into()
        } else {
            container(
                column![
                    text("No network selected").size(12).color(colors::TEXT_DIM),
                    text("Select a network from the list on the left to begin")
                        .size(10)
                        .color(colors::TEXT_DIM),
                ]
                .spacing(4),
            )
            .padding(12)
            .width(Length::Fill)
            .style(theme::card_style)
            .into()
        };

        // ========== STATUS BLOCK ==========
        let status_block: Element<'_, Message> = if handshake_done {
            // Success state
            container(
                column![
                    row![
                        text("✅").size(20),
                        text("Handshake Captured!").size(14).color(colors::SUCCESS),
                    ]
                    .spacing(8)
                    .align_y(iced::Alignment::Center),
                    text("The capture file contains a valid WPA handshake.")
                        .size(10)
                        .color(colors::TEXT_DIM),
                ]
                .spacing(6),
            )
            .padding(12)
            .width(Length::Fill)
            .style(|_: &Theme| container::Style {
                background: Some(iced::Background::Color(iced::Color::from_rgba(
                    0.18, 0.80, 0.44, 0.15,
                ))),
                border: iced::Border {
                    color: colors::SUCCESS,
                    width: 2.0,
                    radius: 8.0.into(),
                },
                ..Default::default()
            })
            .into()
        } else if self.is_capturing {
            // Capturing state
            let hp = &self.handshake_progress;
            container(
                column![
                    row![
                        text("🔍").size(14),
                        text("Listening for handshake...")
                            .size(12)
                            .color(colors::TEXT),
                    ]
                    .spacing(6),
                    row![
                        if hp.m1_received {
                            text("✅ M1").size(10).color(colors::SUCCESS)
                        } else {
                            text("⏳ M1").size(10).color(colors::TEXT_DIM)
                        },
                        if hp.m2_received {
                            text("✅ M2").size(10).color(colors::SUCCESS)
                        } else {
                            text("⏳ M2").size(10).color(colors::TEXT_DIM)
                        },
                    ]
                    .spacing(12),
                ]
                .spacing(6),
            )
            .padding(12)
            .width(Length::Fill)
            .style(theme::card_style)
            .into()
        } else {
            // Ready state
            container(
                column![
                    text("Ready to capture").size(12).color(colors::TEXT_DIM),
                    text("Click 'Start Capture' to begin listening for the handshake")
                        .size(10)
                        .color(colors::TEXT_DIM),
                ]
                .spacing(4),
            )
            .padding(12)
            .width(Length::Fill)
            .style(theme::card_style)
            .into()
        };

        // ========== LOGS BLOCK ==========
        let logs_block: Option<Element<'_, Message>> = if !self.log_messages.is_empty() {
            Some(
                container(
                    column![
                        text("Logs").size(13).color(colors::TEXT),
                        scrollable(
                            container(text(self.log_messages.join("\n")).size(11))
                                .padding(8)
                                .width(Length::Fill)
                        )
                        .height(Length::Fixed(150.0))
                    ]
                    .spacing(8)
                    .padding(15),
                )
                .style(theme::card_style)
                .into(),
            )
        } else {
            None
        };

        // ========== ERROR BLOCK ==========
        let error_block: Option<Element<'_, Message>> = self.error_message.as_ref().map(|msg| {
            container(text(msg).size(11).color(colors::DANGER))
                .padding(12)
                .width(Length::Fill)
                .style(|_: &Theme| container::Style {
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
                .into()
        });

        // ========== ACTION BUTTONS ==========
        let action_buttons: Element<'_, Message> = {
            let mut buttons_vec: Vec<Element<'_, Message>> = Vec::new();

            // Disconnect WiFi button (always visible)
            buttons_vec.push(
                button(text("Disconnect WiFi").size(12))
                    .padding([8, 16])
                    .style(theme::secondary_button_style)
                    .on_press(Message::DisconnectWifi)
                    .into(),
            );

            if handshake_done {
                // Show Continue and Download buttons
                buttons_vec.push(
                    button(text("Continue to Crack").size(12))
                        .padding([8, 16])
                        .style(theme::primary_button_style)
                        .on_press(Message::GoToCrack)
                        .into(),
                );
                buttons_vec.push(
                    button(text("Download pcap").size(12))
                        .padding([8, 16])
                        .style(theme::secondary_button_style)
                        .on_press(Message::DownloadCapturedPcap)
                        .into(),
                );
            } else if self.is_capturing {
                // Show Stop button
                buttons_vec.push(
                    button(text("Stop Capture").size(12))
                        .padding([8, 16])
                        .style(theme::danger_button_style)
                        .on_press(Message::StopCapture)
                        .into(),
                );
            } else {
                // Show Start button
                let network_selected = self.target_network.is_some();
                let channel_ok = if self.available_channels.len() > 1 {
                    self.selected_channel.is_some()
                } else {
                    true
                };
                let can_capture = network_selected && channel_ok;

                let start_btn = button(text("Start Capture").size(12))
                    .padding([8, 16])
                    .style(theme::primary_button_style);

                buttons_vec.push(if can_capture {
                    start_btn.on_press(Message::StartCapture).into()
                } else {
                    start_btn.into()
                });
            }

            container(row(buttons_vec).spacing(8))
                .padding(8)
                .width(Length::Fill)
                .into()
        };

        // ========== BUILD FINAL LAYOUT WITH SCROLLVIEW ==========
        let mut content = column![title, horizontal_rule(1)].spacing(10);

        // Add info message only if no network selected
        if self.target_network.is_none() {
            content = content.push(
                container(
                    column![
                        text("ℹ️ Getting Started").size(11).color(colors::TEXT),
                        text("1. Select a network from the list on the left")
                            .size(10)
                            .color(colors::TEXT_DIM),
                        text("2. If connected to WiFi, disconnect first")
                            .size(10)
                            .color(colors::TEXT_DIM),
                        text("3. Click 'Start Capture' to begin")
                            .size(10)
                            .color(colors::TEXT_DIM),
                    ]
                    .spacing(4),
                )
                .padding(10)
                .width(Length::Fill)
                .style(|_: &Theme| container::Style {
                    background: Some(iced::Background::Color(iced::Color::from_rgba(
                        0.2, 0.6, 0.86, 0.1,
                    ))),
                    border: iced::Border {
                        color: iced::Color::from_rgb(0.4, 0.7, 0.9),
                        width: 1.0,
                        radius: 4.0.into(),
                    },
                    ..Default::default()
                }),
            );
        }

        content = content.push(network_info_block);
        content = content.push(status_block);

        if let Some(logs) = logs_block {
            content = content.push(logs);
        }

        if let Some(error) = error_block {
            content = content.push(error);
        }

        content = content.push(action_buttons);

        // Wrap in scrollable
        let scrollable_content = scrollable(content).height(Length::Fill);

        container(scrollable_content)
            .width(Length::FillPortion(3))
            .height(Length::Fill)
            .into()
    }
}
