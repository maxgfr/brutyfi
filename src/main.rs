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
use std::ffi::CString;
#[cfg(target_os = "macos")]
use std::os::unix::process::CommandExt;
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
pub(crate) fn relaunch_as_root_with_env(envs: &[(&'static str, String)]) -> bool {
    let exe = match env::current_exe() {
        Ok(path) => path,
        Err(_) => return false,
    };

    let user = env::var("USER").unwrap_or_else(|_| "".to_string());
    let home = env::var("HOME").unwrap_or_else(|_| "".to_string());
    let logname = env::var("LOGNAME").unwrap_or_else(|_| user.clone());
    let path_env = env::var("PATH").unwrap_or_else(|_| "".to_string());

    let mut command = shell_escape(exe.to_string_lossy().as_ref());
    for arg in env::args().skip(1) {
        command.push(' ');
        command.push_str(&shell_escape(&arg));
    }

    // Preserve user context and PATH for file dialogs/tools when relaunching as root
    let mut env_prefix = String::new();
    if !home.is_empty() {
        env_prefix.push_str(&format!(
            "HOME={} USER={} LOGNAME={} ",
            shell_escape(&home),
            shell_escape(&user),
            shell_escape(&logname)
        ));
    }
    if !path_env.is_empty() {
        env_prefix.push_str(&format!("PATH={} ", shell_escape(&path_env)));
    }
    for (k, v) in envs {
        env_prefix.push_str(&format!("{}={} ", k, shell_escape(v)));
    }
    if !env_prefix.is_empty() {
        command = format!("{}{}", env_prefix, command);
    }

    let script = format!(
        "do shell script \"{}\" with administrator privileges",
        command
    );

    Command::new("osascript")
        .arg("-e")
        .arg(script)
        .spawn()
        .map(|_| true)
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
pub(crate) fn relaunch_as_root() -> bool {
    relaunch_as_root_with_env(&[])
}

#[cfg(target_os = "macos")]
fn user_ids(username: &str) -> Option<(u32, u32)> {
    let cstr = CString::new(username).ok()?;
    unsafe {
        let pwd = libc::getpwnam(cstr.as_ptr());
        if pwd.is_null() {
            return None;
        }
        let uid = (*pwd).pw_uid;
        let gid = (*pwd).pw_gid;
        Some((uid, gid))
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn relaunch_as_user(envs: &[(&'static str, String)]) -> bool {
    let exe = match env::current_exe() {
        Ok(path) => path,
        Err(_) => return false,
    };

    let user = env::var("USER").unwrap_or_else(|_| "".to_string());
    if user.is_empty() {
        return false;
    }

    let (uid, gid) = match user_ids(&user) {
        Some(ids) => ids,
        None => return false,
    };

    let mut cmd = Command::new(exe);
    for (k, v) in envs {
        cmd.env(*k, v);
    }

    cmd.uid(uid).gid(gid).spawn().map(|_| true).unwrap_or(false)
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

    // macOS: do NOT auto-relaunch as root (prevents duplicate instances and file dialog issues).
    // Users can opt-in by setting BRUTIFI_AUTO_ELEVATE=1.
    #[cfg(target_os = "macos")]
    {
        if !is_root {
            let auto_elevate = std::env::var("BRUTIFI_AUTO_ELEVATE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);

            if auto_elevate {
                if relaunch_as_root() {
                    std::process::exit(0);
                }

                eprintln!("Failed to request administrator privileges. Continuing without root.");
            } else {
                eprintln!("Running without admin privileges. Capture will be disabled unless you launch with sudo or set BRUTIFI_AUTO_ELEVATE=1.");
            }
        }
    }

    // Windows: Check for WinPcap/Npcap before starting
    #[cfg(target_os = "windows")]
    {
        use brutifi::core::network::check_pcap_available;
        if let Err(e) = check_pcap_available() {
            eprintln!("\n{}", "!".repeat(60));
            eprintln!("WARNING: Npcap/WinPcap Not Found");
            eprintln!("{}\n", "!".repeat(60));
            eprintln!("{}\n", e);
            eprintln!("Network scanning and packet capture will be DISABLED.");
            eprintln!("You can still use the crack functionality with existing capture files.\n");
            eprintln!("To enable full functionality, install Npcap and restart BrutiFi.\n");
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
        eprintln!("  Requirements:");
        eprintln!("    - Npcap: Required for network scanning and packet capture");
        eprintln!("    - Administrator privileges: Required for scanning and capture");
        eprintln!();
        eprintln!("  - Network scanning: Requires Npcap + Administrator privileges");
        eprintln!("  - Packet capture: Requires Npcap + Administrator privileges");
        eprintln!("  - Crack mode: Works without any special requirements");
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
