/*!
 * WiFi Bruteforce Desktop GUI Application
 *
 * Built with Iced framework for macOS/Linux/Windows support.
 * Provides a user-friendly interface for:
 * - Scanning WiFi networks
 * - Capturing WPA/WPA2 handshakes
 * - Cracking passwords (numeric or wordlist)
 */

mod app;
mod screens;
mod theme;
mod workers;
mod workers_optimized;

use app::BruteforceApp;
use iced::window;
use iced::Size;
use std::panic;

#[cfg(target_os = "macos")]
use std::env;
#[cfg(target_os = "macos")]
use std::process::Command;

/// Check if the application is running with root privileges
#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn shell_escape(arg: &str) -> String {
    let mut escaped = String::from("'");
    for ch in arg.chars() {
        if ch == '\'' {
            escaped.push_str("'\\''");
        } else {
            escaped.push(ch);
        }
    }
    escaped.push('\'');
    escaped
}

#[cfg(target_os = "macos")]
fn relaunch_as_root() -> bool {
    let exe = match env::current_exe() {
        Ok(path) => path,
        Err(_) => return false,
    };

    let mut command = shell_escape(exe.to_string_lossy().as_ref());
    for arg in env::args().skip(1) {
        command.push(' ');
        command.push_str(&shell_escape(&arg));
    }

    let script = format!(
        "do shell script \"{}\" with administrator privileges",
        command
    );

    Command::new("osascript")
        .arg("-e")
        .arg(script)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Setup panic handler to show errors instead of silent exit
fn setup_panic_handler() {
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        // Log to stderr
        eprintln!("\n");
        eprintln!("Application Error");
        eprintln!("=================");

        if let Some(location) = panic_info.location() {
            eprintln!(
                "Location: {}:{}:{}",
                location.file(),
                location.line(),
                location.column()
            );
        }

        if let Some(message) = panic_info.payload().downcast_ref::<&str>() {
            eprintln!("Message: {}", message);
        } else if let Some(message) = panic_info.payload().downcast_ref::<String>() {
            eprintln!("Message: {}", message);
        }

        eprintln!("\nPlease report this issue at:");
        eprintln!("https://github.com/maxgfr/bruteforce-wifi/issues\n");

        // Call default handler for stack trace
        default_hook(panic_info);
    }));
}

/// Load the application icon from the assets directory
fn load_icon() -> Option<window::icon::Icon> {
    window::icon::from_file_data(
        include_bytes!("../assets/icon.png"),
        Some(image::ImageFormat::Png),
    )
    .ok()
}

fn main() -> iced::Result {
    // Setup panic handler first
    setup_panic_handler();

    // Check for root privileges
    let is_root = is_root();

    // macOS: request admin privileges at launch if needed
    #[cfg(target_os = "macos")]
    {
        if !is_root {
            if relaunch_as_root() {
                return Ok(());
            }

            eprintln!("Failed to request administrator privileges. Continuing without root.");
        }
    }

    // Print startup info
    eprintln!("\nBrutyFi v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("================================\n");

    // macOS-specific guidance
    #[cfg(target_os = "macos")]
    {
        eprintln!("macOS Permission Guide:");
        eprintln!("------------------------");
        eprintln!("  Capture:  Requires root (sudo) for monitor mode");
        eprintln!("            Note: Apple Silicon Macs have limited capture support");
        eprintln!();
        eprintln!("  Crack:    Works without any special permissions");
        eprintln!("================================\n");

        if is_root {
            eprintln!("Running as root. Capture mode is available.\n");
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("Windows Permission Guide:");
        eprintln!("------------------------");
        eprintln!("  IMPORTANT: Run this application as Administrator for full functionality");
        eprintln!();
        eprintln!("  - Network scanning: Requires administrator privileges");
        eprintln!("  - Packet capture: Requires administrator privileges");
        eprintln!("  - Crack mode: Works without administrator privileges");
        eprintln!();
        eprintln!("To run as Administrator:");
        eprintln!("  Right-click on brutifi.exe -> Run as Administrator");
        eprintln!("================================\n");
    }

    // Run the GUI application
    iced::application("BrutiFi", BruteforceApp::update, BruteforceApp::view)
        .subscription(BruteforceApp::subscription)
        .theme(BruteforceApp::theme)
        .window_size(Size::new(900.0, 700.0))
        .window(window::Settings {
            icon: load_icon(),
            ..window::Settings::default()
        })
        .run_with(move || BruteforceApp::new(is_root))
}
