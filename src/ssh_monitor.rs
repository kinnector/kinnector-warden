//! ssh_monitor.rs — SSH brute-force detection via auth log tailing (P3-1).
//!
//! Tails `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS)
//! for sshd authentication lines, converts them into synthetic `SSHAuth`
//! `TelemetryEventRaw` structs, and feeds them directly into the
//! `HeuristicsEngine`.
//!
//! This is the userspace data source for `EventType::SSHAuth`.  The eBPF uprobe
//! layer (Phase 3 / P3-2) will eventually supersede this, but log tailing works
//! on every kernel without special capabilities.

use crate::types::{TelemetryEventRaw, TelemetryHeader, EventType, TelemetrySource, SSHAuthDetails};
use crate::heuristics::HeuristicsEngine;
use std::sync::Arc;
use std::io::{BufRead, Seek, SeekFrom};

/// Paths to check for SSH auth log, in priority order.
const AUTH_LOG_PATHS: &[&str] = &[
    "/var/log/auth.log",    // Debian / Ubuntu
    "/var/log/secure",       // RHEL / CentOS / Fedora
    "/var/log/syslog",       // Fallback
];

/// Synthetic TelemetrySource for log-tailed SSH events.
const SRC_AUTH_LOG: TelemetrySource = TelemetrySource::Log_FIM;

/// Spawn a background task that tails the SSH auth log and feeds SSHAuth events
/// into the heuristics engine.
///
/// Poll interval: 500 ms (low latency for brute-force detection).
pub fn start_ssh_monitor(engine: Arc<HeuristicsEngine>) {
    tokio::spawn(async move {
        // Locate the first readable auth log
        let log_path = AUTH_LOG_PATHS.iter().find(|p| std::fs::metadata(p).is_ok());
        let log_path = match log_path {
            Some(p) => p,
            None => {
                eprintln!(
                    "[Warden SSHMonitor] No auth log found at any of {:?}. SSH brute-force \
                     detection disabled. Try running as root or installing rsyslog.",
                    AUTH_LOG_PATHS
                );
                return;
            }
        };

        println!("[Warden SSHMonitor] Tailing {} for SSH events.", log_path);

        // Open and seek to end so we don't replay historical failures
        let file = match std::fs::File::open(log_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[Warden SSHMonitor] Failed to open {}: {}", log_path, e);
                return;
            }
        };

        let mut reader = std::io::BufReader::new(file);
        // Seek to end — only process new lines from this point forward
        if let Err(e) = reader.seek(SeekFrom::End(0)) {
            eprintln!("[Warden SSHMonitor] Seek failed: {}", e);
        }

        let mut seq: u64 = 0;

        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break, // No new data
                    Ok(_) => {
                        if let Some(event) = parse_auth_line(line.trim(), &mut seq) {
                            engine.handle_raw_event(event);
                        }
                    }
                    Err(_) => break,
                }
            }

            // Handle log rotation: if file is shorter than our position, reopen
            if let Ok(current_pos) = reader.stream_position() {
                if let Ok(meta) = std::fs::metadata(log_path) {
                    if meta.len() < current_pos {
                        eprintln!("[Warden SSHMonitor] Log rotated, reopening {}", log_path);
                        match std::fs::File::open(log_path) {
                            Ok(f) => reader = std::io::BufReader::new(f),
                            Err(e) => {
                                eprintln!("[Warden SSHMonitor] Reopen failed: {}", e);
                            }
                        }
                    }
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse a single line from an SSH auth log into a `TelemetryEventRaw`.
///
/// Recognized patterns (subset of sshd log formats):
/// - Failed password for <user> from <ip> port <port> ssh2
/// - Failed publickey for <user> from <ip> ...
/// - Invalid user <user> from <ip> ...
/// - Accepted password for <user> from <ip> ...
/// - Accepted publickey for <user> from <ip> ...
/// - Disconnected from authenticating user <user> <ip> ...
fn parse_auth_line(line: &str, seq: &mut u64) -> Option<TelemetryEventRaw> {
    // Must be an sshd line
    if !line.contains("sshd[") {
        return None;
    }

    let (status, username, source_ip) = if line.contains("Failed password for")
        || line.contains("Failed publickey for")
        || line.contains("Invalid user")
    {
        let status = "failure";
        // Extract username — appears after "for " or "user " before " from "
        let user = extract_between(line, " for ", " from ")
            .or_else(|| extract_between(line, "Invalid user ", " from "))?;
        let ip = extract_between(line, " from ", " port")?;
        (status, user.trim().to_string(), ip.trim().to_string())
    } else if line.contains("Accepted password for") || line.contains("Accepted publickey for") {
        let status = "success";
        let user = extract_between(line, " for ", " from ")?;
        let ip = extract_between(line, " from ", " port")?;
        (status, user.trim().to_string(), ip.trim().to_string())
    } else if line.contains("Disconnected from authenticating user") {
        let status = "failure";
        let user = extract_between(line, "authenticating user ", " ")?;
        // IP follows the username
        let after_user = line.split_once(&format!("authenticating user {} ", user))?.1;
        let ip = after_user.split_whitespace().next().unwrap_or("").to_string();
        (status, user.trim().to_string(), ip)
    } else {
        return None;
    };

    // Build a synthetic TelemetryEventRaw
    *seq += 1;
    let mut details = SSHAuthDetails {
        username:    [0u8; 64],
        source_ip:   [0u8; 46],
        port:        0u16,
        auth_method: [0u8; 32],
        status:      [0u8; 16],
    };

    copy_str_to_buf(&username, &mut details.username);
    copy_str_to_buf(&source_ip, &mut details.source_ip);
    copy_str_to_buf(status, &mut details.status);
    // auth_method: derive from line content
    let method = if line.contains("publickey") { "publickey" } else { "password" };
    copy_str_to_buf(method, &mut details.auth_method);

    // Serialise SSHAuthDetails into details_buffer
    let mut buf = [0u8; 1544];
    let detail_bytes = unsafe {
        std::slice::from_raw_parts(
            &details as *const SSHAuthDetails as *const u8,
            std::mem::size_of::<SSHAuthDetails>(),
        )
    };
    let copy_len = detail_bytes.len().min(buf.len());
    buf[..copy_len].copy_from_slice(&detail_bytes[..copy_len]);

    Some(TelemetryEventRaw {
        header: TelemetryHeader {
            sequence_number: *seq,
            timestamp_ns: 0,
            pid: 0,
            event_type: EventType::SSHAuth,
            source: SRC_AUTH_LOG,
        },
        details_buffer: buf,
    })
}

fn extract_between<'a>(s: &'a str, after: &str, before: &str) -> Option<&'a str> {
    let start = s.find(after)? + after.len();
    let rest = &s[start..];
    let end = rest.find(before).unwrap_or(rest.len());
    Some(&rest[..end])
}

fn copy_str_to_buf(s: &str, buf: &mut [u8]) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(buf.len().saturating_sub(1));
    buf[..len].copy_from_slice(&bytes[..len]);
    if len < buf.len() {
        buf[len] = 0;
    }
}
