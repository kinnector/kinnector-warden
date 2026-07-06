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
use std::sync::OnceLock;

pub enum FimCommand {
    Watch(PathBuf),
    Unwatch(PathBuf),
}

static FIM_CMD_TX: OnceLock<tokio::sync::mpsc::Sender<FimCommand>> = OnceLock::new();

/// Request FIM to watch a new path dynamically.
pub fn add_fim_watch_path(path: PathBuf) -> bool {
    if let Some(tx) = FIM_CMD_TX.get() {
        tx.try_send(FimCommand::Watch(path)).is_ok()
    } else {
        false
    }
}

/// Request FIM to stop watching a path dynamically.
pub fn remove_fim_watch_path(path: PathBuf) -> bool {
    if let Some(tx) = FIM_CMD_TX.get() {
        tx.try_send(FimCommand::Unwatch(path)).is_ok()
    } else {
        false
    }
}

pub fn start_fim_watcher(web_root: String, config_dirs: Vec<PathBuf>) {
    tokio::spawn(async move {
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<FimCommand>(20);
        let _ = FIM_CMD_TX.set(cmd_tx);

        // Mutex/Cell wrapper not needed since notify RecommendedWatcher has internal mutability
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

        loop {
            tokio::select! {
                Some(event) = rx.recv() => {
                    let is_modify = matches!(event.kind, EventKind::Modify(_));
                    match event.kind {
                        EventKind::Modify(_) | EventKind::Create(_) => {
                            for path in event.paths {
                                process_fim_event(path, &web_root, false, is_modify);
                            }
                        }
                        EventKind::Remove(_) => {
                            for path in event.paths {
                                process_fim_event(path, &web_root, true, false);
                            }
                        }
                        _ => {}
                    }
                }
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        FimCommand::Watch(new_path) => {
                            if new_path.exists() {
                                let _ = watcher.watch(&new_path, RecursiveMode::Recursive);
                                println!("[Warden FIM] Watching dynamically added path: {}", new_path.display());
                            }
                        }
                        FimCommand::Unwatch(old_path) => {
                            let _ = watcher.unwatch(&old_path);
                            println!("[Warden FIM] Unwatching dynamically removed path: {}", old_path.display());
                        }
                    }
                }
                else => break,
            }
        }

        drop(watcher);
    });
}

fn process_fim_event(path: PathBuf, web_root: &str, is_deletion: bool, is_modify: bool) {
    let path_str = path.to_string_lossy();

    if path_str.starts_with(web_root) {
        if is_deletion {
            // File deleted inside web root (S-H: deletion case)
            let alert_id = uuid::Uuid::new_v4().to_string();
            let payload = crate::notifications::AlertPayload {
                alert_id,
                timestamp: chrono::Utc::now().to_rfc3339(),
                threat_type: "Threat.Server.WebRootFileDeletion".to_string(),
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
                    status: format!("File deleted from web root: {}", path.display()),
                },
            };
            crate::notifications::dispatch_alert(payload);
            return;
        }

        // Check if the new/modified file's inode is in the allowlist
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.is_file() {
                let inode_allowed = crate::allowlist::is_inode_allowed(&path_str);
                if inode_allowed {
                    if is_modify {
                        // P4-4: Modify events on allowlisted inodes are audit-only (no quarantine)
                        let alert_id = uuid::Uuid::new_v4().to_string();
                        let payload = crate::notifications::AlertPayload {
                            alert_id,
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            threat_type: "Event.WebRoot.FileModified".to_string(),
                            severity: "INFO".to_string(),
                            container: None,
                            process: crate::notifications::ProcessInfo {
                                pid: 0,
                                exec_path: "fim-watcher".to_string(),
                                cmdline: String::new(),
                                parent_exec_path: "wardend".to_string(),
                                parent_pid: std::process::id(),
                            },
                            remediation: crate::notifications::RemediationInfo {
                                action: "AUDIT_ONLY".to_string(),
                                status: format!("Allowlisted file modified in web root: {}", path.display()),
                            },
                        };
                        crate::notifications::dispatch_alert(payload);
                    }
                } else {
                    let alert_id = uuid::Uuid::new_v4().to_string();
                    let reason = format!(
                        "Unregistered file {} in web root (inode {} not in {} allowlist)",
                        if is_modify { "modified" } else { "created" },
                        meta.ino(),
                        if crate::allowlist::is_git_seeded() { "git-indexed" } else { "startup-walk" }
                    );
                    // P3-4: Quarantine the file immediately rather than just alerting
                    let _ = crate::quarantine::quarantine_file(
                        &path_str, &alert_id, &reason
                    );
                }
            }
        }
    } else {
        // Config directory change (S-C)
        let alert_id = uuid::Uuid::new_v4().to_string();
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
        crate::notifications::dispatch_alert(payload);
    }
}

// Audit log helper removed — use crate::audit::write_to_audit_log instead (Q-01 fix).
