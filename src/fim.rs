//! fim.rs — File Integrity Monitoring
//!
//! Uses notify (inotify) to watch the web root and config dirs.
//! New file detection: checks if the created file's inode is in the allowlist.
//! If NOT — the file was not present at startup (not in git/startup snapshot) —
//! it is an unregistered file, and we emit a CRITICAL alert (no quarantine race).
//! Config modification detection: any change outside web root triggers HIGH alert.

use notify::{Watcher, RecursiveMode, EventKind};
use std::path::{Path, PathBuf};
use std::os::unix::fs::MetadataExt;

pub fn start_fim_watcher(web_root: String, config_dirs: Vec<PathBuf>) {
    tokio::spawn(async move {
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);

        let mut watcher = match notify::recommended_watcher(move |res| {
            if let Ok(event) = res {
                let _ = tx.blocking_send(event);
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("[Warden FIM] Failed to initialize watcher: {}", e);
                return;
            }
        };

        // Watch web root
        let web_root_path = Path::new(&web_root);
        if web_root_path.exists() {
            let _ = watcher.watch(web_root_path, RecursiveMode::Recursive);
            println!("[Warden FIM] Watching web root: {}", web_root);
        }

        // Watch config directories
        for dir in &config_dirs {
            if dir.exists() {
                let _ = watcher.watch(dir, RecursiveMode::Recursive);
                println!("[Warden FIM] Watching config directory: {}", dir.display());
            }
        }

        while let Some(event) = rx.recv().await {
            match event.kind {
                EventKind::Modify(_) | EventKind::Create(_) => {
                    for path in event.paths {
                        process_fim_event(path, &web_root);
                    }
                }
                _ => {}
            }
        }

        drop(watcher);
    });
}

fn process_fim_event(path: PathBuf, web_root: &str) {
    let path_str = path.to_string_lossy();

    if path_str.starts_with(web_root) {
        // Check if the new/modified file's inode is in the allowlist
        // If the allowlist is populated and this inode is absent, it's an
        // unregistered file — alert immediately (no extension/path guessing)
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.is_file() {
                let inode_allowed = crate::allowlist::is_inode_allowed(&path_str);
                if !inode_allowed {
                    let alert_id = format!("fim-{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
                    let payload = crate::notifications::AlertPayload {
                        alert_id,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        threat_type: "Threat.Server.UnregisteredFileCreated".to_string(),
                        severity: "CRITICAL".to_string(),
                        container: None,
                        process: crate::notifications::ProcessInfo {
                            pid: 0,
                            exec_path: "fim-watcher".to_string(),
                            cmdline: String::new(),
                            parent_exec_path: "wardend".to_string(),
                            parent_pid: std::process::id(),
                        },
                        remediation: crate::notifications::RemediationInfo {
                            action: "LOG_ALERT".to_string(),
                            status: format!(
                                "Unregistered file created in web root (inode {} not in allowlist): {}",
                                meta.ino(), path.display()
                            ),
                        },
                    };
                    if let Ok(s) = serde_json::to_string(&payload) {
                        let _ = write_to_audit_log(&s);
                    }
                    crate::notifications::dispatch_alert(payload);
                }
            }
        }
    } else {
        // Config directory change (S-C)
        let alert_id = format!("fim-{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
        let payload = crate::notifications::AlertPayload {
            alert_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
            threat_type: "Threat.Server.ConfigModified".to_string(),
            severity: "HIGH".to_string(),
            container: None,
            process: crate::notifications::ProcessInfo {
                pid: 0,
                exec_path: "fim-watcher".to_string(),
                cmdline: String::new(),
                parent_exec_path: "wardend".to_string(),
                parent_pid: std::process::id(),
            },
            remediation: crate::notifications::RemediationInfo {
                action: "LOG_ALERT".to_string(),
                status: format!("Server configuration file modified: {}", path.display()),
            },
        };
        if let Ok(s) = serde_json::to_string(&payload) {
            let _ = write_to_audit_log(&s);
        }
        crate::notifications::dispatch_alert(payload);
    }
}

fn write_to_audit_log(line: &str) -> std::io::Result<()> {
    let _ = std::fs::create_dir_all("/var/log/kinnector");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/log/kinnector/audit.log")?;
    use std::io::Write;
    writeln!(file, "{}", line)
}
