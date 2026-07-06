//! audit.rs — Shared structured audit logging for wardend.
//!
//! All heuristics, FIM, and scanner modules write JSON-encoded `AlertPayload`
//! entries here. The log is append-only; rotation is handled externally
//! (logrotate / systemd-journald).

use std::io::Write;

/// Append a single JSON line to `/var/log/kinnector/audit.log`.
/// Creates the directory and file if they do not yet exist.
pub fn write_to_audit_log(line: &str) -> std::io::Result<()> {
    let _ = std::fs::create_dir_all("/var/log/kinnector");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/log/kinnector/audit.log")?;
    writeln!(file, "{}", line)
}
