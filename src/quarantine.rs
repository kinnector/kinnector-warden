use std::path::{Path, PathBuf};
use std::os::unix::fs::MetadataExt;
use std::sync::OnceLock;
use chrono::Utc;

static QUARANTINE_DIR: OnceLock<String> = OnceLock::new();

/// Initialise the quarantine directory path from config or command-line.
pub fn init_quarantine_dir(dir: String) {
    let _ = QUARANTINE_DIR.set(dir);
}

/// Retrieve the active quarantine directory (defaults to /var/quarantine/kinnector).
pub fn get_quarantine_dir() -> &'static str {
    QUARANTINE_DIR.get().map(|s| s.as_str()).unwrap_or("/var/quarantine/kinnector")
}

/// Quarantine a file at `source_path` that was flagged by FIM or heuristics.
///
/// Returns `Ok(quarantine_path)` on success, `Err(e)` if the move failed.
/// In either case, a `.quarantined` shadow placeholder is created at the
/// original path and an alert is dispatched.
pub fn quarantine_file(
    source_path: &str,
    alert_id: &str,
    reason: &str,
    threat_type: &str,
) -> std::io::Result<PathBuf> {
    let qdir = get_quarantine_dir();
    let _ = std::fs::create_dir_all(qdir);

    // Derive a unique destination name: <quarantine_dir>/<timestamp>_<alert_id>_<basename>
    let source = Path::new(source_path);
    let basename = source
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let ts = Utc::now().timestamp();
    let dest_name = format!("{}_{}_{}", ts, &alert_id[..8.min(alert_id.len())], basename);
    let dest_path = PathBuf::from(qdir).join(&dest_name);

    // Stat the file before moving so we capture its inode
    let inode = std::fs::metadata(source_path)
        .map(|m| m.ino())
        .unwrap_or(0);

    // Move to quarantine
    let move_result = std::fs::rename(source_path, &dest_path);

    // Always write a shadow placeholder at the original path
    let shadow_path = format!("{}.quarantined", source_path);
    let shadow_content = serde_json::json!({
        "quarantine_id": alert_id,
        "original_path": source_path,
        "quarantine_path": dest_path.to_string_lossy(),
        "inode": inode,
        "timestamp": Utc::now().to_rfc3339(),
        "reason": reason,
    });
    if let Ok(json) = serde_json::to_string_pretty(&shadow_content) {
        let _ = std::fs::write(&shadow_path, &json);
        // Also write sidecar JSON file next to the quarantined file (P4-1, P4-2)
        let sidecar_path = dest_path.with_extension("json");
        let _ = std::fs::write(&sidecar_path, &json);
    }

    // Emit alert
    emit_quarantine_alert(
        alert_id,
        source_path,
        &dest_path.to_string_lossy(),
        inode,
        reason,
        move_result.is_ok(),
        threat_type,
    );

    move_result.map(|_| dest_path)
}

/// Restore a quarantined file back to its original path.
/// Called from warden-cli via the IPC socket (Phase 6 wires this up).
pub fn restore_file(quarantine_path: &str, original_path: &str) -> std::io::Result<()> {
    // Ensure destination directory exists
    if let Some(parent) = Path::new(original_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(quarantine_path, original_path)?;

    // Remove the shadow placeholder if present
    let shadow = format!("{}.quarantined", original_path);
    let _ = std::fs::remove_file(&shadow);

    // Remove the sidecar JSON file if present
    let sidecar = PathBuf::from(quarantine_path).with_extension("json");
    let _ = std::fs::remove_file(sidecar);

    // Re-register the restored inode in the allowlist
    crate::allowlist::register_inode(original_path);

    println!(
        "[Warden Quarantine] Restored {} to {}",
        quarantine_path, original_path
    );
    Ok(())
}

/// List all files currently in the quarantine directory with their metadata.
pub fn list_quarantined() -> Vec<QuarantineEntry> {
    let qdir = get_quarantine_dir();
    let Ok(dir) = std::fs::read_dir(qdir) else {
        return Vec::new();
    };

    let mut entries = Vec::new();
    for item in dir.flatten() {
        let path = item.path();
        // Skip JSON files when iterating (they are sidecars)
        if path.extension().map(|e| e == "json").unwrap_or(false) {
            continue;
        }
        
        let mut original_path = String::new();
        let mut reason = String::new();
        
        // Try to read original path and reason from sidecar JSON
        let sidecar_path = path.with_extension("json");
        if let Ok(metadata_str) = std::fs::read_to_string(&sidecar_path) {
            if let Ok(json_meta) = serde_json::from_str::<serde_json::Value>(&metadata_str) {
                original_path = json_meta.get("original_path").and_then(|o| o.as_str()).unwrap_or("").to_string();
                reason = json_meta.get("reason").and_then(|r| r.as_str()).unwrap_or("").to_string();
            }
        }

        let name = item.file_name().to_string_lossy().to_string();
        let parts: Vec<&str> = name.splitn(3, '_').collect();
        let (timestamp, alert_id_prefix, basename) = match parts.as_slice() {
            [ts, aid, bn] => (*ts, *aid, *bn),
            _ => ("0", "", name.as_str()),
        };

        entries.push(QuarantineEntry {
            quarantine_path: path.to_string_lossy().to_string(),
            original_path,
            reason,
            basename: basename.to_string(),
            alert_id_prefix: alert_id_prefix.to_string(),
            quarantined_at_unix: timestamp.parse::<i64>().unwrap_or(0),
        });
    }

    entries.sort_by_key(|e| e.quarantined_at_unix);
    entries
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct QuarantineEntry {
    pub quarantine_path: String,
    pub original_path: String,
    pub reason: String,
    pub basename: String,
    pub alert_id_prefix: String,
    pub quarantined_at_unix: i64,
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

fn emit_quarantine_alert(
    alert_id: &str,
    original_path: &str,
    quarantine_path: &str,
    inode: u64,
    reason: &str,
    success: bool,
    threat_type: &str,
) {
    let status = if success {
        format!(
            "File quarantined successfully. Original: {} → Quarantine: {} (inode {}). Reason: {}",
            original_path, quarantine_path, inode, reason
        )
    } else {
        format!(
            "Quarantine FAILED (file may still be at {}). Inode: {}. Reason: {}",
            original_path, inode, reason
        )
    };

    let payload = crate::notifications::AlertPayload {
        alert_id: alert_id.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        threat_type: threat_type.to_string(),
        severity: "CRITICAL".to_string(),
        container: None,
        process: crate::notifications::ProcessInfo {
            pid: 0,
            exec_path: "fim-quarantine".to_string(),
            cmdline: format!("quarantine({})", original_path),
            parent_exec_path: "wardend".to_string(),
            parent_pid: std::process::id(),
        },
        remediation: crate::notifications::RemediationInfo {
            action: if success { "QUARANTINED" } else { "QUARANTINE_FAILED" }.to_string(),
            status,
        },
    };

    crate::notifications::dispatch_alert(payload);
}
