use std::path::{Path, PathBuf};
use std::collections::HashMap;
use tokio::io::AsyncBufReadExt;

#[derive(Debug, Clone)]
pub struct DiscoveredProxy {
    pub name: String,
    pub config_dirs: Vec<PathBuf>,
    pub access_logs: Vec<PathBuf>,
}

pub fn auto_discover_proxies() -> Vec<DiscoveredProxy> {
    let mut proxies = Vec::new();

    // 1. Nginx Check
    let mut nginx_configs = Vec::new();
    if Path::new("/etc/nginx").exists() {
        nginx_configs.push(PathBuf::from("/etc/nginx"));
    }
    let mut nginx_logs = Vec::new();
    let common_nginx_logs = [
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
    ];
    for log in &common_nginx_logs {
        if Path::new(log).exists() {
            nginx_logs.push(PathBuf::from(log));
        }
    }
    if !nginx_configs.is_empty() || !nginx_logs.is_empty() {
        proxies.push(DiscoveredProxy {
            name: "nginx".to_string(),
            config_dirs: nginx_configs,
            access_logs: nginx_logs,
        });
    }

    // 2. Apache Check
    let mut apache_configs = Vec::new();
    if Path::new("/etc/apache2").exists() {
        apache_configs.push(PathBuf::from("/etc/apache2"));
    } else if Path::new("/etc/httpd").exists() {
        apache_configs.push(PathBuf::from("/etc/httpd"));
    }
    let mut apache_logs = Vec::new();
    let common_apache_logs = [
        "/var/log/apache2/access.log",
        "/var/log/httpd/access_log",
    ];
    for log in &common_apache_logs {
        if Path::new(log).exists() {
            apache_logs.push(PathBuf::from(log));
        }
    }
    if !apache_configs.is_empty() || !apache_logs.is_empty() {
        proxies.push(DiscoveredProxy {
            name: "apache".to_string(),
            config_dirs: apache_configs,
            access_logs: apache_logs,
        });
    }

    // 3. Caddy Check
    let mut caddy_configs = Vec::new();
    if Path::new("/etc/caddy").exists() {
        caddy_configs.push(PathBuf::from("/etc/caddy"));
    }
    let mut caddy_logs = Vec::new();
    let common_caddy_logs = [
        "/var/log/caddy/access.log",
    ];
    for log in &common_caddy_logs {
        if Path::new(log).exists() {
            caddy_logs.push(PathBuf::from(log));
        }
    }
    if !caddy_configs.is_empty() || !caddy_logs.is_empty() {
        proxies.push(DiscoveredProxy {
            name: "caddy".to_string(),
            config_dirs: caddy_configs,
            access_logs: caddy_logs,
        });
    }

    proxies
}

pub fn start_log_pipeline_auditing(access_log_path: PathBuf, proxy_name: String) {
    tokio::spawn(async move {
        println!("[Warden Log Auditor] Attaching tail reader to {} access log: {}", proxy_name, access_log_path.display());
        
        let mut file = match tokio::fs::File::open(&access_log_path).await {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[Warden Log Auditor] Failed to open log file {}: {}", access_log_path.display(), e);
                return;
            }
        };

        // Seek to the end of the file to only process new entries
        use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
        if let Err(e) = file.seek(SeekFrom::End(0)).await {
            eprintln!("[Warden Log Auditor] Failed to seek to end of file {}: {}", access_log_path.display(), e);
            return;
        }

        let mut reader = tokio::io::BufReader::new(file);
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    // EOF reached, wait for more data
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                }
                Ok(_) => {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        audit_log_line(trimmed, &proxy_name, &access_log_path);
                    }
                }
                Err(e) => {
                    eprintln!("[Warden Log Auditor] Error reading {}: {}", access_log_path.display(), e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }
        }
    });
}

fn audit_log_line(line: &str, proxy_name: &str, log_path: &Path) {
    // Parse query/URI from Combined log line
    // Pattern: "... "GET /path?query HTTP/1.1" 200 ..."
    let parts: Vec<&str> = line.split('"').collect();
    if parts.len() >= 2 {
        let request_field = parts[1]; // e.g. "GET /index.php?id=1 HTTP/1.1"
        let request_parts: Vec<&str> = request_field.split_whitespace().collect();
        if request_parts.len() >= 2 {
            let uri = request_parts[1]; // e.g. "/index.php?id=1"
            let decoded_uri = url_decode(uri);
            
            let mut detected_threat = None;
            if crate::vet::check_sqli(&decoded_uri) {
                detected_threat = Some("Threat.Server.RequestPayloadInjection (SQLi)");
            } else if crate::vet::check_cmdi(&decoded_uri) {
                detected_threat = Some("Threat.Server.RequestPayloadInjection (CMD-i)");
            }

            if let Some(threat) = detected_threat {
                let alert_id = format!("logalert-{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
                let payload = crate::notifications::AlertPayload {
                    alert_id,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    threat_type: threat.to_string(),
                    severity: "HIGH".to_string(),
                    container: None,
                    process: crate::notifications::ProcessInfo {
                        pid: 0,
                        exec_path: proxy_name.to_string(),
                        cmdline: format!("Log Tail Auditing ({})", log_path.display()),
                        parent_exec_path: "systemd".to_string(),
                        parent_pid: 1,
                    },
                    remediation: crate::notifications::RemediationInfo {
                        action: "LOG_ALERT".to_string(),
                        status: format!("Malicious URI payload detected in reverse proxy log: {}", decoded_uri),
                    },
                };

                // Write to audit log
                if let Ok(json_str) = serde_json::to_string(&payload) {
                    let _ = write_to_audit_log(&json_str);
                }

                // Dispatch notification
                crate::notifications::dispatch_alert(payload);
            }
        }
    }
}

fn url_decode(input: &str) -> String {
    let mut chars = input.chars().peekable();
    let mut output = String::new();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            let mut hex = String::new();
            if let Some(&h1) = chars.peek() {
                hex.push(h1);
            }
            let _ = chars.next();
            if let Some(&h2) = chars.peek() {
                hex.push(h2);
            }
            let _ = chars.next();

            if hex.len() == 2 {
                if let Ok(val) = u8::from_str_radix(&hex, 16) {
                    output.push(val as char);
                    continue;
                }
            }
            output.push('%');
            output.push_str(&hex);
        } else if ch == '+' {
            output.push(' ');
        } else {
            output.push(ch);
        }
    }
    output
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
