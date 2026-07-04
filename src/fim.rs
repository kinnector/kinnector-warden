use notify::{Watcher, RecursiveMode, EventKind};
use std::path::{Path, PathBuf};
use std::sync::Arc;

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

        // 1. Watch web root
        let web_root_path = Path::new(&web_root);
        if web_root_path.exists() {
            let _ = watcher.watch(web_root_path, RecursiveMode::Recursive);
            println!("[Warden FIM] Watching web root directory: {}", web_root);
        }

        // 2. Watch config directories
        for dir in config_dirs {
            if dir.exists() {
                let _ = watcher.watch(&dir, RecursiveMode::Recursive);
                println!("[Warden FIM] Watching config directory: {}", dir.display());
            }
        }

        // 3. Process events
        while let Some(event) = rx.recv().await {
            match event.kind {
                EventKind::Modify(_) | EventKind::Create(_) => {
                    for path in event.paths {
                        process_fim_change(path, &web_root);
                    }
                }
                _ => {}
            }
        }

        // Keep watcher alive in scope
        drop(watcher);
    });
}

fn process_fim_change(path: PathBuf, web_root: &str) {
    let path_str = path.to_string_lossy();
    
    // Check if the change is in the web root
    if path_str.starts_with(web_root) {
        // Exclude temporary or log directories inside web root if necessary
        if path_str.contains("/uploads/") || path_str.contains("/cache/") || path_str.contains("/tmp/") {
            // Wait! uploads/ is an asset directory, creations of code there is highly suspicious (RFI)
            // If a script file is created in uploads/, quarantine it!
        }

        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let script_exts = ["php", "py", "js", "sh", "pl", "cgi", "asp", "aspx"];
            if script_exts.contains(&ext) {
                // Suspicious code file creation/modification detected in web root!
                quarantine_file(&path);
            }
        }
    } else {
        // Change must be in configuration directories (S-C)
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
                status: format!("Server configuration modified: {}", path.display()),
            },
        };

        // Log and notify
        if let Ok(json_str) = serde_json::to_string(&payload) {
            let _ = write_to_audit_log(&json_str);
        }
        crate::notifications::dispatch_alert(payload);
    }
}

fn quarantine_file(path: &Path) {
    let filename = match path.file_name().and_then(|f| f.to_str()) {
        Some(name) => name,
        None => return,
    };

    let quarantine_dir = Path::new("/var/lib/kinnector/quarantine");
    let _ = std::fs::create_dir_all(quarantine_dir);
    let target_path = quarantine_dir.join(format!("{}-{}", chrono::Utc::now().timestamp_millis(), filename));

    // Try to move the file to quarantine
    if std::fs::rename(path, &target_path).is_ok() || std::fs::copy(path, &target_path).and_then(|_| std::fs::remove_file(path)).is_ok() {
        let alert_id = format!("fim-{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
        let payload = crate::notifications::AlertPayload {
            alert_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
            threat_type: "Threat.Server.ProjectFileTampered".to_string(),
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
                action: "QUARANTINE".to_string(),
                status: format!("Suspicious script file {} isolated to quarantine at {}", path.display(), target_path.display()),
            },
        };

        // Log and notify
        if let Ok(json_str) = serde_json::to_string(&payload) {
            let _ = write_to_audit_log(&json_str);
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
