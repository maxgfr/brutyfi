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
use iced::Size;
use std::panic;

/// Check if the application is running with root privileges
#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

/// Request location services permission on macOS
/// Returns true if permission was granted or already available
#[cfg(target_os = "macos")]
fn check_and_request_location_permission() -> bool {
    use std::process::Command;

    // Simple check script - just checks status without blocking
    let check_script = r#"
import CoreLocation
import Foundation

let manager = CLLocationManager()
let status = manager.authorizationStatus

switch status {
case .authorizedAlways, .authorizedWhenInUse:
    print("granted")
case .denied, .restricted:
    print("denied")
case .notDetermined:
    print("undetermined")
@unknown default:
    print("unknown")
}
"#;

    let script_path = "/tmp/wifi_check_location.swift";
    if std::fs::write(script_path, check_script).is_err() {
        eprintln!("Warning: Could not write location check script");
        return false;
    }

    match Command::new("swift").arg(script_path).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let status = stdout.trim();

            match status {
                "granted" => {
                    eprintln!("Location Services: Authorized");
                    true
                }
                "denied" => {
                    eprintln!("\nLocation Services: DENIED");
                    eprintln!("Please enable Location Services for this app:");
                    eprintln!("  System Settings > Privacy & Security > Location Services");
                    eprintln!("  Then restart the application.\n");
                    false
                }
                "undetermined" => {
                    eprintln!("Location Services: Not yet determined");
                    eprintln!("The app will request permission when scanning networks.\n");
                    true // Will be requested during scan
                }
                _ => {
                    eprintln!("Location Services: Unknown status ({})", status);
                    true // Try anyway
                }
            }
        }
        Err(e) => {
            eprintln!("Warning: Could not check location permission: {}", e);
            true // Try anyway
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn check_and_request_location_permission() -> bool {
    true // Not needed on non-macOS platforms
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
            eprintln!("Location: {}:{}:{}",
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

fn main() -> iced::Result {
    // Setup panic handler first
    setup_panic_handler();

    // Check for root privileges
    let is_root = is_root();

    // Print startup info
    eprintln!("\nWiFi Bruteforce Tool v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("================================\n");

    // Check location services (macOS)
    let _has_location = check_and_request_location_permission();

    if !is_root {
        eprintln!("WARNING: Not running with administrator privileges!");
        eprintln!("Some features require admin/root privileges:");
        eprintln!("  - Network scanning (may have limited results)");
        eprintln!("  - Packet capture (will not work)");
        eprintln!();
        eprintln!("To run with admin privileges:");
        eprintln!("  sudo ./target/release/bruteforce-wifi");
        eprintln!();
        eprintln!("Note: Crack mode works without admin privileges.");
        eprintln!("================================\n");
    } else {
        eprintln!("Running with administrator privileges.\n");
    }

    // Run the GUI application
    iced::application(
        "WiFi Bruteforce Tool",
        BruteforceApp::update,
        BruteforceApp::view,
    )
    .subscription(BruteforceApp::subscription)
    .theme(BruteforceApp::theme)
    .window_size(Size::new(900.0, 700.0))
    .run_with(move || BruteforceApp::new(is_root))
}
