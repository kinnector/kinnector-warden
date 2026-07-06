//! api.rs — HTTP/1.1-over-UDS server on /var/run/kinnector/warden.sock (Phase 7).
//!
//! Provides the REST API for both the wordpress plugin and the warden-cli tool.

use tokio::net::UnixListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use std::path::{Path, PathBuf};
use serde_json::json;
use crate::heuristics::HeuristicsEngine;

pub fn start_api_server(
    heuristics: Arc<HeuristicsEngine>,
    web_roots: Vec<String>,
) {
    tokio::spawn(async move {
        let socket_path = "/var/run/kinnector/warden.sock";
        
        // Clean up pre-existing socket file
        let _ = std::fs::remove_file(socket_path);
        
        // Ensure parent directory exists
        if let Some(parent) = Path::new(socket_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = match UnixListener::bind(socket_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[Warden API] Failed to bind UDS socket {}: {}", socket_path, e);
                return;
            }
        };

        // Make socket accessible to root and members of the socket group (0660)
        let _ = std::process::Command::new("chmod")
            .args(["0660", socket_path])
            .output();

        println!("[Warden API] Listening on UDS socket: {}", socket_path);

        let startup_time = std::time::Instant::now();

        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    // S-1 Fix: Verify peer UID is 0 (root) to prevent unprivileged access
                    if let Ok(cred) = stream.peer_cred() {
                        if cred.uid() != 0 {
                            eprintln!("[Warden API] Rejecting connection from non-root process (UID: {})", cred.uid());
                            continue;
                        }
                    } else {
                        eprintln!("[Warden API] Rejecting connection: unable to determine peer credentials");
                        continue;
                    }

                    let heuristics_clone = Arc::clone(&heuristics);
                    let web_roots_clone = web_roots.clone();
                    tokio::spawn(async move {
                        let mut buf = Vec::with_capacity(8192);
                        let mut tmp = [0u8; 4096];
                        // Read until full HTTP request headers received (\r\n\r\n)
                        loop {
                            match stream.read(&mut tmp).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    buf.extend_from_slice(&tmp[..n]);
                                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                        break;
                                    }
                                    // Safety cap: 1 MB max request size
                                    if buf.len() > 1_048_576 {
                                        return;
                                    }
                                }
                                Err(_) => return,
                            }
                        }
                        let bytes_read = buf.len();

                        if bytes_read == 0 {
                            return;
                        }

                        let request_str = String::from_utf8_lossy(&buf);
                        let response = handle_http_request(
                            &request_str,
                            heuristics_clone,
                            &web_roots_clone,
                            startup_time,
                        ).await;

                        let _ = stream.write_all(response.as_bytes()).await;
                        let _ = stream.flush().await;
                    });
                }
                Err(_) => {}
            }
        }
    });
}

async fn handle_http_request(
    request: &str,
    heuristics: Arc<HeuristicsEngine>,
    web_roots: &[String],
    startup_time: std::time::Instant,
) -> String {
    let mut lines = request.lines();
    let request_line = match lines.next() {
        Some(l) => l,
        None => return build_error_response(400, "Bad Request"),
    };

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return build_error_response(400, "Bad Request");
    }

    let method = parts[0];
    let path = parts[1];

    // Locate body in request if any
    let body = request.split("\r\n\r\n").nth(1).unwrap_or("").trim();

    match (method, path) {
        ("GET", "/api/v1/status") => {
            let is_lsm = unsafe { crate::ffi::is_lsm_active() };
            let uptime = startup_time.elapsed().as_secs();
            let is_paid = crate::tls_buffer::is_paid_tier();
            let in_container = std::path::Path::new("/.dockerenv").exists();
            // Snapshot of currently listening services (non-blocking, reads from /proc)
            let listening_services = crate::discovery::get_listening_services();
            // Snapshot of installed packages from known web root lockfiles
            let packages: Vec<serde_json::Value> = web_roots.iter()
                .flat_map(|r| crate::scanner::get_installed_packages(r))
                .map(|pkg| serde_json::json!({
                    "name": pkg.name,
                    "version": pkg.version,
                    "ecosystem": pkg.ecosystem,
                    "lock_file": pkg.lock_file,
                    "is_dev": pkg.is_dev,
                }))
                .collect();
            let state_json = json!({
                "status": if is_paid { "licensed" } else { "active" },
                "tier": if is_paid { "paid" } else { "free" },
                "version": env!("CARGO_PKG_VERSION"),
                "lsm_active": is_lsm,
                "in_container": in_container,
                "uptime_secs": uptime,
                "web_roots": web_roots,
                "listening_services": listening_services,
                "packages": packages,
                "tls_forensics": crate::tls_buffer::get_tls_forensics_status(),
            });
            build_json_response(200, &state_json)
        }
        ("POST", "/api/v1/scan/trigger") => {
            // Trigger OSV dependency scan for each web root in background
            for root in web_roots {
                let r = root.clone();
                tokio::spawn(async move {
                    let _ = crate::scanner::run_scan(&r).await;
                });
            }
            build_json_response(200, &json!({ "status": "triggered" }))
        }
        ("POST", "/api/v1/rules/reload") => {
            match heuristics.config.reload() {
                Ok(_) => build_json_response(200, &json!({ "status": "reloaded" })),
                Err(e) => build_json_response(500, &json!({ "error": format!("Reload failed: {}", e) })),
            }
        }
        ("POST", "/api/v1/rules/fetch") => {
            if crate::tls_buffer::is_paid_tier() {
                let config_clone = Arc::clone(&heuristics.config);
                tokio::spawn(async move {
                    let _ = crate::cloud::sync_rules_now(&config_clone).await;
                });
                build_json_response(200, &json!({ "status": "fetching" }))
            } else {
                build_json_response(402, &json!({ "error": "Remote signed rule fetch requires paid tier license." }))
            }
        }
        ("POST", "/api/v1/fim/add") => {
            let Ok(json_body) = serde_json::from_str::<serde_json::Value>(body) else {
                return build_error_response(400, "Invalid JSON");
            };
            let path_val = json_body.get("path").and_then(|p| p.as_str());
            match path_val {
                Some(p) => {
                    let path = PathBuf::from(p);
                    if crate::fim::add_fim_watch_path(path) {
                        build_json_response(200, &json!({ "status": "added" }))
                    } else {
                        build_json_response(500, &json!({ "error": "Failed to send watch command" }))
                    }
                }
                None => build_error_response(400, "Missing path parameter"),
            }
        }
        ("POST", "/api/v1/fim/remove") => {
            let Ok(json_body) = serde_json::from_str::<serde_json::Value>(body) else {
                return build_error_response(400, "Invalid JSON");
            };
            let path_val = json_body.get("path").and_then(|p| p.as_str());
            match path_val {
                Some(p) => {
                    let path = PathBuf::from(p);
                    if crate::fim::remove_fim_watch_path(path) {
                        build_json_response(200, &json!({ "status": "removed" }))
                    } else {
                        build_json_response(500, &json!({ "error": "Failed to send unwatch command" }))
                    }
                }
                None => build_error_response(400, "Missing path parameter"),
            }
        }
        ("POST", "/api/v1/allowlist/add") => {
            let Ok(json_body) = serde_json::from_str::<serde_json::Value>(body) else {
                return build_error_response(400, "Invalid JSON");
            };
            let path_val = json_body.get("path").and_then(|p| p.as_str());
            match path_val {
                Some(p) => {
                    crate::allowlist::register_path_recursive(p);
                    build_json_response(200, &json!({ "status": "registered", "path": p }))
                }
                None => build_error_response(400, "Missing path parameter"),
            }
        }
        ("POST", "/api/v1/allowlist/remove") => {
            let Ok(json_body) = serde_json::from_str::<serde_json::Value>(body) else {
                return build_error_response(400, "Invalid JSON");
            };
            let path_val = json_body.get("path").and_then(|p| p.as_str());
            match path_val {
                Some(p) => {
                    crate::allowlist::deregister_path_recursive(p);
                    build_json_response(200, &json!({ "status": "deregistered", "path": p }))
                }
                None => build_error_response(400, "Missing path parameter"),
            }
        }
        ("POST", "/api/v1/fim/register") => {
            let Ok(json_body) = serde_json::from_str::<serde_json::Value>(body) else {
                return build_error_response(400, "Invalid JSON");
            };
            
            if let Some(path) = json_body.get("path").and_then(|p| p.as_str()) {
                if crate::allowlist::register_inode(path) {
                    build_json_response(200, &json!({ "status": "registered", "path": path }))
                } else {
                    build_json_response(500, &json!({ "error": "Failed to register inode" }))
                }
            } else if let Some(git) = json_body.get("git").and_then(|g| g.as_bool()) {
                if git {
                    let mut added = 0;
                    for root in web_roots {
                        added += crate::allowlist::reseed_from_git(root);
                    }
                    build_json_response(200, &json!({ "status": "re-seeded", "new_inodes": added }))
                } else {
                    build_error_response(400, "git must be true")
                }
            } else {
                build_error_response(400, "Missing parameters (path or git)")
            }
        }
        ("GET", "/api/v1/containers") => {
            let list = crate::discovery::discover_docker_containers().await;
            build_json_response(200, &serde_json::to_value(&list).unwrap_or_else(|_| json!([])))
        }
        ("GET", "/api/v1/allowlist") => {
            if let Some(set) = crate::allowlist::get_allowlist() {
                let inodes: Vec<u64> = set.iter().map(|v| *v).collect();
                build_json_response(200, &json!({ "allowed_inodes": inodes }))
            } else {
                build_json_response(200, &json!({ "allowed_inodes": [] }))
            }
        }
        ("GET", "/api/v1/quarantine") => {
            let entries = crate::quarantine::list_quarantined();
            build_json_response(200, &json!({ "quarantined_files": entries }))
        }
        ("POST", "/api/v1/quarantine/restore") => {
            let Ok(json_body) = serde_json::from_str::<serde_json::Value>(body) else {
                return build_error_response(400, "Invalid JSON");
            };
            let q_path = json_body.get("quarantine_path").and_then(|p| p.as_str());
            let o_path = json_body.get("original_path").and_then(|p| p.as_str());
            match (q_path, o_path) {
                (Some(qp), Some(op)) => {
                    match crate::quarantine::restore_file(qp, op) {
                        Ok(_) => build_json_response(200, &json!({ "status": "restored" })),
                        Err(e) => build_json_response(500, &json!({ "error": format!("Restore failed: {}", e) })),
                    }
                }
                _ => build_error_response(400, "Missing quarantine_path or original_path"),
            }
        }
        ("POST", "/api/v1/test-alert") => {
            let alert_id = format!("test-{}", chrono::Utc::now().timestamp());
            let payload = crate::notifications::AlertPayload {
                alert_id: alert_id.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                threat_type: "Test.Alert".to_string(),
                severity: "LOW".to_string(),
                container: None,
                process: crate::notifications::ProcessInfo {
                    pid: 0,
                    exec_path: "warden-cli".to_string(),
                    cmdline: "test-alert".to_string(),
                    parent_exec_path: "operator".to_string(),
                    parent_pid: 0,
                },
                remediation: crate::notifications::RemediationInfo {
                    action: "TEST".to_string(),
                    status: "This is a test alert from warden-cli. All systems operational.".to_string(),
                },
            };
            crate::notifications::dispatch_alert(payload);
            build_json_response(200, &json!({ "status": "dispatched", "alert_id": alert_id }))
        }
        ("GET", "/api/v1/storage") => {
            let registry = crate::storage_discovery::get_registry();
            let mut list = Vec::new();
            for entry in registry.iter() {
                list.push(json!({
                    "path": entry.key().to_string_lossy().to_string(),
                    "roles": entry.value().roles.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
                    "confidence": entry.value().confidence.as_str(),
                    "discovered_via": entry.value().discovered_via,
                    "web_uid": entry.value().web_uid,
                    "allow_script_extensions": entry.value().allow_script_extensions,
                }));
            }
            build_json_response(200, &json!({ "storage_paths": list }))
        }
        ("POST", "/api/v1/storage/add") => {
            let Ok(json_body) = serde_json::from_str::<serde_json::Value>(body) else {
                return build_error_response(400, "Invalid JSON");
            };
            let path_val = json_body.get("path").and_then(|p| p.as_str());
            let role_val = json_body.get("role").and_then(|r| r.as_str()).unwrap_or("UploadDirectory");
            let web_root_val = json_body.get("web_root").and_then(|w| w.as_str()).unwrap_or("");
            
            match path_val {
                Some(p) => {
                    use crate::storage_discovery::{StoragePath, StorageRole, DiscoveryConfidence};
                    let role = match role_val {
                        "UploadDirectory" | "upload" => StorageRole::UploadDirectory,
                        "SessionStorage" | "session" => StorageRole::SessionStorage,
                        "TempDirectory" | "temp" => StorageRole::TempDirectory,
                        "AppStorage" | "app" => StorageRole::AppStorage,
                        "CompiledCache" | "cache" => StorageRole::CompiledCache,
                        "ObjectPassthrough" | "passthrough" => StorageRole::ObjectPassthrough,
                        _ => StorageRole::UploadDirectory,
                    };
                    let allow_script = matches!(role, StorageRole::CompiledCache);
                    crate::storage_discovery::register(StoragePath {
                        path: PathBuf::from(p),
                        roles: vec![role],
                        confidence: DiscoveryConfidence::High,
                        discovered_via: vec!["manual_add".to_string()],
                        web_uid: crate::storage_discovery::resolve_web_uid(web_root_val),
                        allow_script_extensions: allow_script,
                        max_file_size_hint: None,
                    });
                    build_json_response(200, &json!({ "status": "added", "path": p }))
                }
                None => build_error_response(400, "Missing path parameter"),
            }
        }
        ("POST", "/api/v1/storage/remove") => {
            let Ok(json_body) = serde_json::from_str::<serde_json::Value>(body) else {
                return build_error_response(400, "Invalid JSON");
            };
            let path_val = json_body.get("path").and_then(|p| p.as_str());
            match path_val {
                Some(p) => {
                    let path = Path::new(p);
                    if crate::storage_discovery::remove(path) {
                        build_json_response(200, &json!({ "status": "removed", "path": p }))
                    } else {
                        build_json_response(404, &json!({ "error": "Path not found in registry" }))
                    }
                }
                None => build_error_response(400, "Missing path parameter"),
            }
        }
        ("POST", "/api/v1/storage/scan") => {
            let Ok(json_body) = serde_json::from_str::<serde_json::Value>(body) else {
                return build_error_response(400, "Invalid JSON");
            };
            let path_val = json_body.get("path").and_then(|p| p.as_str());
            match path_val {
                Some(p) => {
                    let res = crate::upload_scan::scan_uploaded_file(p).await;
                    let status_str = match res {
                        crate::upload_scan::ScanResult::Clean => "clean",
                        crate::upload_scan::ScanResult::Elf => "elf",
                        crate::upload_scan::ScanResult::Suspicious(ref r) => r,
                    };
                    build_json_response(200, &json!({ "status": "scanned", "result": status_str }))
                }
                None => build_error_response(400, "Missing path parameter"),
            }
        }
        ("POST", "/api/v1/storage/acknowledge-none") => {
            let Ok(json_body) = serde_json::from_str::<serde_json::Value>(body) else {
                return build_error_response(400, "Invalid JSON");
            };
            let root_val = json_body.get("web_root").and_then(|r| r.as_str());
            match root_val {
                Some(r) => {
                    let ack_file = "/etc/kinnector/storage_ack.json";
                    let ack_data = json!({
                        "web_root": r,
                        "acknowledged_at": chrono::Utc::now().to_rfc3339(),
                        "reason": "object-storage-only"
                    });
                    if let Ok(json_str) = serde_json::to_string_pretty(&ack_data) {
                        if std::fs::write(ack_file, json_str).is_ok() {
                            return build_json_response(200, &json!({ "status": "acknowledged", "web_root": r }));
                        }
                    }
                    build_json_response(500, &json!({ "error": "Failed to write acknowledgement file" }))
                }
                None => build_error_response(400, "Missing web_root parameter"),
            }
        }
        ("POST", "/api/v1/storage/reset-ack") => {
            let _ = std::fs::remove_file("/etc/kinnector/storage_ack.json");
            build_json_response(200, &json!({ "status": "reset" }))
        }
        ("POST", "/api/v1/storage/rescan") => {
            let listening_pids = crate::discovery::discover_listening_pids();
            for root in web_roots {
                for pid in &listening_pids {
                    let paths = crate::storage_discovery::scan_process_env_for_storage(*pid);
                    for p in paths { crate::storage_discovery::register(p); }
                }
                let paths = crate::storage_discovery::run_framework_rules(root);
                for p in paths { crate::storage_discovery::register(p); }
                let web_uid = crate::storage_discovery::resolve_web_uid(root);
                let paths = crate::storage_discovery::scan_uid_writable_untracked(root, web_uid);
                for p in paths { crate::storage_discovery::register(p); }
                crate::storage_discovery::cross_reference_gitignore(root);
            }
            build_json_response(200, &json!({ "status": "rescanned", "count": crate::storage_discovery::get_registry().len() }))
        }
        ("POST", "/api/v1/storage/disable") => {
            let Ok(json_body) = serde_json::from_str::<serde_json::Value>(body) else {
                return build_error_response(400, "Invalid JSON");
            };
            let root_val = json_body.get("web_root").and_then(|r| r.as_str());
            let exe_val = json_body.get("exe").and_then(|e| e.as_str());
            match (root_val, exe_val) {
                (Some(r), _) => {
                    crate::storage_discovery::disable_storage_for_web_root(r);
                    build_json_response(200, &json!({ "status": "disabled", "web_root": r }))
                }
                (_, Some(e)) => {
                    crate::storage_discovery::disable_storage_for_exe(e);
                    build_json_response(200, &json!({ "status": "disabled", "exe": e }))
                }
                _ => build_error_response(400, "Missing web_root or exe parameter"),
            }
        }
        ("POST", "/api/v1/storage/enable") => {
            let Ok(json_body) = serde_json::from_str::<serde_json::Value>(body) else {
                return build_error_response(400, "Invalid JSON");
            };
            let root_val = json_body.get("web_root").and_then(|r| r.as_str());
            let exe_val = json_body.get("exe").and_then(|e| e.as_str());
            match (root_val, exe_val) {
                (Some(r), _) => {
                    crate::storage_discovery::enable_storage_for_web_root(r);
                    build_json_response(200, &json!({ "status": "enabled", "web_root": r }))
                }
                (_, Some(e)) => {
                    crate::storage_discovery::enable_storage_for_exe(e);
                    build_json_response(200, &json!({ "status": "enabled", "exe": e }))
                }
                _ => build_error_response(400, "Missing web_root or exe parameter"),
            }
        }
        _ => build_error_response(404, "Not Found"),
    }
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        402 => "Payment Required",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown Status",
    }
}

fn build_json_response(status_code: u16, value: &serde_json::Value) -> String {
    let body = serde_json::to_string(value).unwrap_or_default();
    format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {}",
        status_code,
        status_text(status_code),
        body.len(),
        body
    )
}

fn build_error_response(status_code: u16, message: &str) -> String {
    let body = format!("{{\"error\":\"{}\"}}", message);
    format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {}",
        status_code,
        status_text(status_code),
        body.len(),
        body
    )
}
