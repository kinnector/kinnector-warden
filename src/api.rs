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

        // Make socket accessible to wordpress (www-data) and warden-cli (users)
        let _ = std::process::Command::new("chmod")
            .args(["0666", socket_path])
            .output();

        println!("[Warden API] Listening on UDS socket: {}", socket_path);

        let startup_time = std::time::Instant::now();

        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    let heuristics_clone = Arc::clone(&heuristics);
                    let web_roots_clone = web_roots.clone();
                    tokio::spawn(async move {
                        let mut buffer = [0u8; 4096];
                        let mut bytes_read = 0;
                        
                        // Read request
                        loop {
                            match stream.read(&mut buffer[bytes_read..]).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    bytes_read += n;
                                    // Check if we reached end of headers
                                    if String::from_utf8_lossy(&buffer[..bytes_read]).contains("\r\n\r\n") {
                                        break;
                                    }
                                }
                                Err(_) => return,
                            }
                        }

                        if bytes_read == 0 {
                            return;
                        }

                        let request_str = String::from_utf8_lossy(&buffer[..bytes_read]);
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
            let state_json = json!({
                "status": "active",
                "version": "0.1.0",
                "lsm_active": is_lsm,
                "uptime_secs": uptime,
                "web_roots": web_roots,
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
        _ => build_error_response(444, "Not Found"),
    }
}

fn build_json_response(status_code: u16, value: &serde_json::Value) -> String {
    let body = serde_json::to_string(value).unwrap_or_default();
    format!(
        "HTTP/1.1 {} OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {}",
        status_code,
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
        message,
        body.len(),
        body
    )
}
