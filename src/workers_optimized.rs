/*!
 * Optimized background workers for async operations
 */

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use bruteforce_wifi::{parse_cap_file, OfflineBruteForcer};

use super::workers::{CrackProgress, CrackState, NumericCrackParams, WordlistCrackParams};

/// Run wordlist crack in background with optimized blocking
pub async fn crack_wordlist_optimized(
    params: WordlistCrackParams,
    state: Arc<CrackState>,
    progress_tx: tokio::sync::mpsc::UnboundedSender<CrackProgress>,
) -> CrackProgress {
    match tokio::task::spawn_blocking(move || crack_wordlist_blocking(params, state, progress_tx))
        .await
    {
        Ok(result) => result,
        Err(e) => CrackProgress::Error(format!("Task panicked: {}", e)),
    }
}

fn crack_wordlist_blocking(
    params: WordlistCrackParams,
    state: Arc<CrackState>,
    progress_tx: tokio::sync::mpsc::UnboundedSender<CrackProgress>,
) -> CrackProgress {
    use rayon::prelude::*;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    // Load handshake
    let _ = progress_tx.send(CrackProgress::Log("Loading handshake...".to_string()));
    let handshake = match std::panic::catch_unwind(|| {
        parse_cap_file(&params.handshake_path, params.ssid.as_deref())
    }) {
        Ok(Ok(h)) => {
            let _ = progress_tx.send(CrackProgress::Log(format!(
                "Handshake loaded: SSID={}",
                h.ssid
            )));
            h
        }
        Ok(Err(e)) => return CrackProgress::Error(format!("Failed to parse handshake: {}", e)),
        Err(_) => {
            return CrackProgress::Error(
                "Crash while parsing handshake file. The file may be corrupted.".to_string(),
            )
        }
    };

    // Load wordlist
    let _ = progress_tx.send(CrackProgress::Log(format!(
        "Loading wordlist from {}...",
        params.wordlist_path.display()
    )));
    let file = match File::open(&params.wordlist_path) {
        Ok(f) => f,
        Err(e) => return CrackProgress::Error(format!("Failed to open wordlist: {}", e)),
    };

    let reader = BufReader::new(file);
    let passwords: Vec<String> = reader
        .lines()
        .map_while(Result::ok)
        .filter(|line| !line.trim().is_empty())
        .filter(|line| line.len() >= 8 && line.len() <= 63)
        .map(|line| line.trim().to_string())
        .collect();

    if passwords.is_empty() {
        return CrackProgress::Error("No valid passwords in wordlist".to_string());
    }

    let total = passwords.len() as u64;
    let _ = progress_tx.send(CrackProgress::Log(format!("Loaded {} passwords", total)));
    let _ = progress_tx.send(CrackProgress::Started { total });

    // Create bruteforcer
    let forcer = match OfflineBruteForcer::new(handshake, params.threads) {
        Ok(f) => f,
        Err(e) => return CrackProgress::Error(e.to_string()),
    };

    let _ = progress_tx.send(CrackProgress::Log(format!(
        "Starting crack with {} threads...",
        params.threads
    )));

    // Run crack with time-based progress updates
    let start = Instant::now();
    let last_update = Arc::new(AtomicU64::new(0));
    let chunk_size = (passwords.len() / params.threads).clamp(1000, 50_000);

    let found_password: Arc<parking_lot::Mutex<Option<String>>> =
        Arc::new(parking_lot::Mutex::new(None));
    let found_flag = Arc::new(AtomicBool::new(false));

    let found_password_clone = Arc::clone(&found_password);
    let _result = passwords.par_chunks(chunk_size).find_any(|chunk| {
        if found_flag.load(Ordering::Acquire) || !state.running.load(Ordering::Relaxed) {
            return false;
        }

        for password in chunk.iter() {
            if found_flag.load(Ordering::Acquire) || !state.running.load(Ordering::Relaxed) {
                return false;
            }

            let current = state.attempts.fetch_add(1, Ordering::Relaxed);

            // Time-based progress: update every 1 second
            let elapsed_ms = start.elapsed().as_millis() as u64;
            let last = last_update.load(Ordering::Relaxed);
            if elapsed_ms >= last + 1000
                && last_update
                    .compare_exchange(last, elapsed_ms, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                let elapsed_secs = elapsed_ms as f64 / 1000.0;
                let rate = if elapsed_secs > 0.0 {
                    current as f64 / elapsed_secs
                } else {
                    0.0
                };
                let _ = progress_tx.send(CrackProgress::Progress {
                    current,
                    total,
                    rate,
                });
            }

            if bruteforce_wifi::verify_password(
                password,
                &forcer.handshake.ssid,
                &forcer.handshake.ap_mac,
                &forcer.handshake.client_mac,
                &forcer.handshake.anonce,
                &forcer.handshake.snonce,
                &forcer.handshake.eapol_frame,
                &forcer.handshake.mic,
                forcer.handshake.key_version,
            ) {
                *found_password_clone.lock() = Some(password.to_string());
                found_flag.store(true, Ordering::Release);
                return true;
            }
        }
        false
    });

    // Final progress update
    let elapsed_secs = start.elapsed().as_secs_f64();
    let current = state.attempts.load(Ordering::Relaxed);
    let rate = if elapsed_secs > 0.0 {
        current as f64 / elapsed_secs
    } else {
        0.0
    };
    let _ = progress_tx.send(CrackProgress::Progress {
        current,
        total,
        rate,
    });

    // Check result
    if found_flag.load(Ordering::Acquire) {
        if let Some(password) = found_password.lock().clone() {
            let _ = progress_tx.send(CrackProgress::Log(format!("Password found: {}", password)));
            return CrackProgress::Found(password);
        }
    }

    if !state.running.load(Ordering::Relaxed) {
        return CrackProgress::Error("Stopped by user".to_string());
    }

    let _ = progress_tx.send(CrackProgress::Log(
        "Password not found in wordlist".to_string(),
    ));
    CrackProgress::NotFound
}

/// Run numeric crack in background with optimized blocking
pub async fn crack_numeric_optimized(
    params: NumericCrackParams,
    state: Arc<CrackState>,
    progress_tx: tokio::sync::mpsc::UnboundedSender<CrackProgress>,
) -> CrackProgress {
    match tokio::task::spawn_blocking(move || crack_numeric_blocking(params, state, progress_tx))
        .await
    {
        Ok(result) => result,
        Err(e) => CrackProgress::Error(format!("Task panicked: {}", e)),
    }
}

fn crack_numeric_blocking(
    params: NumericCrackParams,
    state: Arc<CrackState>,
    progress_tx: tokio::sync::mpsc::UnboundedSender<CrackProgress>,
) -> CrackProgress {
    use bruteforce_wifi::password_gen::ParallelPasswordGenerator;
    use rayon::prelude::*;

    // Load handshake
    let _ = progress_tx.send(CrackProgress::Log("Loading handshake...".to_string()));
    let handshake = match std::panic::catch_unwind(|| {
        parse_cap_file(&params.handshake_path, params.ssid.as_deref())
    }) {
        Ok(Ok(h)) => {
            let _ = progress_tx.send(CrackProgress::Log(format!(
                "Handshake loaded: SSID={}",
                h.ssid
            )));
            h
        }
        Ok(Err(e)) => return CrackProgress::Error(format!("Failed to parse handshake: {}", e)),
        Err(_) => {
            return CrackProgress::Error(
                "Crash while parsing handshake file. The file may be corrupted.".to_string(),
            )
        }
    };

    // Calculate total
    let mut total: u64 = 0;
    for len in params.min_digits..=params.max_digits {
        total += 10u64.pow(len as u32);
    }

    let _ = progress_tx.send(CrackProgress::Log(format!(
        "Testing {} combinations ({}-{} digits)",
        total, params.min_digits, params.max_digits
    )));
    let _ = progress_tx.send(CrackProgress::Started { total });

    let _ = progress_tx.send(CrackProgress::Log(format!(
        "Starting crack with {} threads...",
        params.threads
    )));

    // Run crack with time-based progress updates
    let start = Instant::now();
    let last_update = Arc::new(AtomicU64::new(0));
    let found_password: Arc<parking_lot::Mutex<Option<String>>> =
        Arc::new(parking_lot::Mutex::new(None));
    let found_flag = Arc::new(AtomicBool::new(false));

    // Process each length
    for length in params.min_digits..=params.max_digits {
        if found_flag.load(Ordering::Acquire) || !state.running.load(Ordering::Relaxed) {
            break;
        }

        let generator = ParallelPasswordGenerator::new(length, params.threads);

        for batch in generator.batches() {
            if found_flag.load(Ordering::Acquire) || !state.running.load(Ordering::Relaxed) {
                break;
            }

            let found_ref = Arc::clone(&found_flag);
            let found_password_ref = Arc::clone(&found_password);
            let state_ref = Arc::clone(&state);
            let last_update_ref = Arc::clone(&last_update);

            let _result = batch.par_iter().find_any(|password| {
                if found_ref.load(Ordering::Acquire) || !state_ref.running.load(Ordering::Relaxed) {
                    return false;
                }

                let current = state_ref.attempts.fetch_add(1, Ordering::Relaxed);

                // Time-based progress: update every 1 second
                let elapsed_ms = start.elapsed().as_millis() as u64;
                let last = last_update_ref.load(Ordering::Relaxed);
                if elapsed_ms >= last + 1000
                    && last_update_ref
                        .compare_exchange(last, elapsed_ms, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                {
                    let elapsed_secs = elapsed_ms as f64 / 1000.0;
                    let rate = if elapsed_secs > 0.0 {
                        current as f64 / elapsed_secs
                    } else {
                        0.0
                    };
                    let _ = progress_tx.send(CrackProgress::Progress {
                        current,
                        total,
                        rate,
                    });
                }

                if bruteforce_wifi::verify_password(
                    password,
                    &handshake.ssid,
                    &handshake.ap_mac,
                    &handshake.client_mac,
                    &handshake.anonce,
                    &handshake.snonce,
                    &handshake.eapol_frame,
                    &handshake.mic,
                    handshake.key_version,
                ) {
                    *found_password_ref.lock() = Some(password.to_string());
                    found_ref.store(true, Ordering::Release);
                    return true;
                }

                false
            });

            if found_flag.load(Ordering::Acquire) {
                break;
            }
        }
    }

    // Final progress update
    let elapsed_secs = start.elapsed().as_secs_f64();
    let current = state.attempts.load(Ordering::Relaxed);
    let rate = if elapsed_secs > 0.0 {
        current as f64 / elapsed_secs
    } else {
        0.0
    };
    let _ = progress_tx.send(CrackProgress::Progress {
        current,
        total,
        rate,
    });

    // Check result
    if found_flag.load(Ordering::Acquire) {
        if let Some(password) = found_password.lock().clone() {
            let _ = progress_tx.send(CrackProgress::Log(format!("Password found: {}", password)));
            return CrackProgress::Found(password);
        }
    }

    if !state.running.load(Ordering::Relaxed) {
        return CrackProgress::Error("Stopped by user".to_string());
    }

    let _ = progress_tx.send(CrackProgress::Log(
        "Password not found in range".to_string(),
    ));
    CrackProgress::NotFound
}
