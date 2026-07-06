use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use std::str::FromStr;
use std::path::Path;
use tokio::time::sleep;
use crate::heuristics::HeuristicsEngine;

static CLOUD_CLIENT: OnceLock<CloudClient> = OnceLock::new();
static LOGS_BUFFER: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

pub fn get_http_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

struct CloudClient {
    pub cloud_endpoint: Option<String>,
    pub updates_server: String,
    pub license_key: Option<String>,
    pub auto_analyze: bool,
}

fn get_client() -> &'static CloudClient {
    CLOUD_CLIENT.get_or_init(|| {
        let conf = std::fs::read_to_string("/etc/kinnector/core.conf").unwrap_or_default();
        let mut cloud_endpoint = None;
        let mut updates_server = "https://updates.kinnector.com/rules.db".to_string();
        let mut license_key = None;
        let mut auto_analyze = false;

        for line in conf.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() { continue; }
            if let Some(pos) = line.find('=') {
                let key = line[..pos].trim();
                let val = line[pos+1..].trim();
                match key {
                    "cloud_endpoint" => {
                        if !val.is_empty() {
                            cloud_endpoint = Some(val.to_string());
                        }
                    }
                    "updates_server" => {
                        if !val.is_empty() {
                            updates_server = val.to_string();
                        }
                    }
                    "license_key" => {
                        if !val.is_empty() && val != "free" {
                            license_key = Some(val.to_string());
                        }
                    }
                    "auto_analyze" | "auto_analyze_incidents" => {
                        auto_analyze = val.to_lowercase() == "true" || val == "1";
                    }
                    _ => {}
                }
            }
        }

        CloudClient {
            cloud_endpoint,
            updates_server,
            license_key,
            auto_analyze,
        }
    })
}

fn get_logs_buffer() -> &'static Mutex<Vec<String>> {
    LOGS_BUFFER.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn queue_log_entry(entry: &str) {
    if let Ok(mut buf) = get_logs_buffer().lock() {
        buf.push(entry.to_string());
    }
}

pub fn start_cloud_services(heuristics: Arc<HeuristicsEngine>) {
    let client = get_client();
    let config = Arc::clone(&heuristics.config);

    // 1. Start remote rule updates sync loop (every 6 hours)
    tokio::spawn(async move {
        // Initial sync on boot
        sleep(Duration::from_secs(10)).await;
        loop {
            let _ = sync_rules_now(&config).await;
            sleep(Duration::from_secs(6 * 3600)).await;
        }
    });

    // 2. Start log streaming loop (every 60 seconds)
    start_log_streamer(client);

    // 3. Start cloud-initiated command listener
    start_command_listener(Arc::clone(&heuristics), client);

    // 4. Start forensic offline recovery uploader (every 5 minutes)
    start_forensic_uploader(client);

    // 5. Start initial inventory sync on boot (after 15 seconds)
    let heuristics_clone = Arc::clone(&heuristics);
    tokio::spawn(async move {
        sleep(Duration::from_secs(15)).await;
        send_inventory_sync(&heuristics_clone).await;
    });
}

pub async fn sync_rules_now(config: &Arc<kinnector_config::ConfigManager>) -> bool {
    let client_info = get_client();
    let Some(license) = &client_info.license_key else {
        println!("[Warden Cloud] License check: Free tier, remote rule updates disabled.");
        return false;
    };

    println!("[Warden Cloud] License validated. Initiating remote rule updates sync from {}", client_info.updates_server);
    let http_client = get_http_client().clone();
    let req = http_client.get(&client_info.updates_server)
        .header("X-License-Key", license)
        .header("X-Agent-Version", env!("CARGO_PKG_VERSION"));

    match req.send().await {
        Ok(res) => {
            if res.status().is_success() {
                match res.bytes().await {
                    Ok(bytes) => {
                        // Reload in-memory dynamically (Ed25519 signature is verified inside)
                        match config.reload_from_bytes(&bytes) {
                            Ok(_) => {
                                println!("[Warden Cloud] Remote rule sync successful. Rules verified & reloaded in-memory.");
                                true
                            }
                            Err(e) => {
                                eprintln!("[Warden Cloud] Cryptographic verification failed for updates: {}. Fallback to existing rules.", e);
                                false
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[Warden Cloud] Failed to read rules bytes from update payload: {}", e);
                        false
                    }
                }
            } else {
                eprintln!("[Warden Cloud] Rule update server returned status: {}", res.status());
                false
            }
        }
        Err(e) => {
            eprintln!("[Warden Cloud] Failed to connect to updates server: {}. Fallback to local rules.", e);
            false
        }
    }
}

pub async fn send_forensic_payload(alert_id: &str, payload: Vec<u8>) -> bool {
    let client = get_client();
    let Some(endpoint) = &client.cloud_endpoint else { return false; };

    let url = format!("{}/api/v1/forensics/{}", endpoint, alert_id);
    let http_client = get_http_client().clone();
    let mut req = http_client.post(&url)
        .body(payload)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Encoding", "zstd");

    if let Some(key) = &client.license_key {
        req = req.header("X-License-Key", key);
    }

    match req.send().await {
        Ok(res) => {
            if res.status().is_success() {
                println!("[Warden Cloud] Forensic payload for alert {} successfully uploaded to cloud.", alert_id);
                // Mark local file as uploaded if it exists
                let local_path = format!("/var/log/kinnector/forensic_{}.json.zst", alert_id);
                let uploaded_path = format!("/var/log/kinnector/uploaded_forensic_{}.json.zst", alert_id);
                let _ = std::fs::rename(local_path, uploaded_path);
                true
            } else {
                eprintln!("[Warden Cloud] Forensic upload returned status: {}", res.status());
                false
            }
        }
        Err(e) => {
            eprintln!("[Warden Cloud] Forensic upload failed to connect: {}", e);
            false
        }
    }
}

static STARTUP_TIME: OnceLock<std::time::Instant> = OnceLock::new();

fn get_uptime() -> u64 {
    let start = STARTUP_TIME.get_or_init(std::time::Instant::now);
    start.elapsed().as_secs()
}

fn start_log_streamer(client: &'static CloudClient) {
    let endpoint = match &client.cloud_endpoint {
        Some(ep) => ep.clone(),
        None => return,
    };

    // Initialize startup time
    let _ = STARTUP_TIME.get_or_init(std::time::Instant::now);

    tokio::spawn(async move {
        let http_client = get_http_client().clone();
        loop {
            sleep(Duration::from_secs(60)).await;

            let mut logs = Vec::new();
            if let Ok(buf) = get_logs_buffer().lock() {
                logs = buf.clone();
            }

            if logs.is_empty() {
                continue;
            }

            let is_lsm = unsafe { crate::ffi::is_lsm_active() };
            let in_container = std::path::Path::new("/.dockerenv").exists();
            let is_paid = crate::tls_buffer::is_paid_tier();
            let uptime = get_uptime();

            let payload = serde_json::json!({
                "logs": logs,
                "agent_status": {
                    "version": env!("CARGO_PKG_VERSION"),
                    "status": if is_paid { "licensed" } else { "active" },
                    "tier": if is_paid { "paid" } else { "free" },
                    "lsm_active": is_lsm,
                    "in_container": in_container,
                    "uptime_secs": uptime,
                }
            });
            let json_str = serde_json::to_string(&payload).unwrap_or_default();

            // Compress with zstd
            match zstd::stream::encode_all(json_str.as_bytes(), 0) {
                Ok(compressed) => {
                    let url = format!("{}/api/v1/logs/stream", endpoint);
                    let mut req = http_client.post(&url)
                        .body(compressed)
                        .header("Content-Type", "application/octet-stream")
                        .header("Content-Encoding", "zstd");
                    if let Some(key) = &client.license_key {
                        req = req.header("X-License-Key", key);
                    }
                    
                    match req.send().await {
                        Ok(res) if res.status().is_success() => {
                            if let Ok(mut buf) = get_logs_buffer().lock() {
                                let sent_len = logs.len();
                                if buf.len() >= sent_len {
                                    buf.drain(0..sent_len);
                                } else {
                                    buf.clear();
                                }
                            }
                        }
                        _ => {
                            eprintln!("[Warden Cloud] Log streaming endpoint offline or failed. Retaining log buffer for retry.");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[Warden Cloud] Failed to compress logs for streaming: {}", e);
                }
            }
        }
    });
}

fn start_forensic_uploader(client: &'static CloudClient) {
    if client.cloud_endpoint.is_none() { return; }

    tokio::spawn(async move {
        loop {
            // Check for unsent forensic payloads every 5 minutes
            sleep(Duration::from_secs(300)).await;

            let log_dir = Path::new("/var/log/kinnector");
            let Ok(entries) = std::fs::read_dir(log_dir) else { continue; };

            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                        if filename.starts_with("forensic_") && filename.ends_with(".json.zst") {
                            let alert_id = filename
                                .trim_start_matches("forensic_")
                                .trim_end_matches(".json.zst");

                            if let Ok(bytes) = std::fs::read(&path) {
                                println!("[Warden Cloud] Offline recovery: Retrying forensic upload for alert {}", alert_id);
                                let _ = send_forensic_payload(alert_id, bytes).await;
                            }
                        }
                    }
                }
            }
        }
    });
}

pub mod proto {
    tonic::include_proto!("warden");
}

use proto::warden_service_client::WardenServiceClient;
use proto::AgentMessage;

struct MyStream(tokio::sync::mpsc::Receiver<AgentMessage>);

impl futures_core::Stream for MyStream {
    type Item = AgentMessage;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

fn start_command_listener(heuristics: Arc<HeuristicsEngine>, client: &'static CloudClient) {
    let endpoint = match &client.cloud_endpoint {
        Some(ep) => ep.clone(),
        None => return,
    };

    tokio::spawn(async move {
        loop {
            let url = if endpoint.contains("/api/v1") {
                if let Some(pos) = endpoint.find("/api/v1") {
                    endpoint[..pos].to_string()
                } else {
                    endpoint.clone()
                }
            } else {
                endpoint.clone()
            };

            tracing::info!("[Warden Cloud] Attempting gRPC connection to console: {}", url);
            match tonic::transport::Endpoint::from_shared(url) {
                Ok(endpoint_conf) => {
                    let endpoint_conf = endpoint_conf
                        .keep_alive_while_idle(true)
                        .connect_timeout(Duration::from_secs(10));
                    
                    match endpoint_conf.connect().await {
                        Ok(channel) => {
                            tracing::info!("[Warden Cloud] gRPC connected to console.");
                            let mut grpc_client = WardenServiceClient::new(channel);

                            let (tx, rx) = tokio::sync::mpsc::channel(100);
                            
                            let agent_id = uuid::Uuid::new_v4().to_string();
                            let license_key = client.license_key.clone().unwrap_or_default();
                            let reg_payload = serde_json::json!({
                                "event": "register",
                                "agent_version": env!("CARGO_PKG_VERSION"),
                            }).to_string();

                            let _ = tx.send(AgentMessage {
                                agent_id: agent_id.clone(),
                                license_key: license_key.clone(),
                                payload_json: reg_payload,
                            }).await;

                            let outbound_stream = MyStream(rx);
                            
                            match grpc_client.command_stream(outbound_stream).await {
                                Ok(response) => {
                                    let mut inbound_stream = response.into_inner();
                                    
                                    while let Ok(Some(msg)) = inbound_stream.message().await {
                                        if let Ok(cmd_json) = serde_json::from_str::<serde_json::Value>(&msg.command_json) {
                                            process_cloud_command(cmd_json, Arc::clone(&heuristics)).await;
                                        }
                                    }
                                    tracing::warn!("[Warden Cloud] gRPC stream closed by remote console.");
                                }
                                Err(e) => {
                                    tracing::error!("[Warden Cloud] Failed to establish gRPC stream: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("[Warden Cloud] gRPC connection failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("[Warden Cloud] Invalid gRPC URL: {}", e);
                }
            }

            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });
}

async fn process_cloud_command(cmd: serde_json::Value, heuristics: Arc<HeuristicsEngine>) {
    let Some(action) = cmd.get("action").and_then(|a| a.as_str()) else { return; };
    println!("[Warden Cloud] Received remote control command: {}", action);
    match action {
        "disable_monitoring" => {
            if let Some(pid) = cmd.get("pid").and_then(|p| p.as_u64()) {
                println!("[Warden Cloud] Remote command: Disabling monitoring for PID {}", pid);
                crate::allowlist::get_disabled_monitoring_pids().insert(pid as u32);
            } else if let Some(path) = cmd.get("web_root").and_then(|p| p.as_str()) {
                println!("[Warden Cloud] Remote command: Disabling FIM/monitoring for web root {}", path);
                crate::allowlist::get_disabled_web_roots().insert(path.to_string());
            }
        }
        "enable_monitoring" => {
            if let Some(pid) = cmd.get("pid").and_then(|p| p.as_u64()) {
                println!("[Warden Cloud] Remote command: Re-enabling monitoring for PID {}", pid);
                crate::allowlist::get_disabled_monitoring_pids().remove(&(pid as u32));
            } else if let Some(path) = cmd.get("web_root").and_then(|p| p.as_str()) {
                println!("[Warden Cloud] Remote command: Re-enabling FIM/monitoring for web root {}", path);
                crate::allowlist::get_disabled_web_roots().remove(path);
            }
        }
        "disable_tls" => {
            if let Some(pid) = cmd.get("pid").and_then(|p| p.as_u64()) {
                println!("[Warden Cloud] Remote command: Disabling TLS telemetry decryption/storage for PID {}", pid);
                crate::allowlist::get_disabled_tls_pids().insert(pid as u32);
            }
        }
        "enable_tls" => {
            if let Some(pid) = cmd.get("pid").and_then(|p| p.as_u64()) {
                println!("[Warden Cloud] Remote command: Re-enabling TLS telemetry decryption/storage for PID {}", pid);
                crate::allowlist::get_disabled_tls_pids().remove(&(pid as u32));
            }
        }
        "kill_process" => {
            if let Some(pid) = cmd.get("pid").and_then(|p| p.as_u64()) {
                println!("[Warden Cloud] Remote command: Killing process ID {}", pid);
                unsafe { libc::kill(pid as i32, libc::SIGKILL); }
            }
        }
        "restore_file" => {
            if let (Some(qp), Some(op)) = (
                cmd.get("quarantine_path").and_then(|p| p.as_str()),
                cmd.get("original_path").and_then(|p| p.as_str()),
            ) {
                println!("[Warden Cloud] Remote command: Restoring quarantined file {} to {}", qp, op);
                let _ = crate::quarantine::restore_file(qp, op);
            }
        }
        "quarantine_file" => {
            if let Some(path) = cmd.get("path").and_then(|p| p.as_str()) {
                println!("[Warden Cloud] Remote command: Quarantining file path {}", path);
                let alert_id = uuid::Uuid::new_v4().to_string();
                let _ = crate::quarantine::quarantine_file(
                    path,
                    &alert_id,
                    "Remote-initiated quarantine command from fleet manager",
                    "Threat.Server.FileQuarantined"
                );
            }
        }
        "block_ip" => {
            if let Some(ip) = cmd.get("ip").and_then(|i| i.as_str()) {
                println!("[Warden Cloud] Remote command: Blocking IP {}", ip);
                if let Ok(ip_addr) = std::net::IpAddr::from_str(ip) {
                    let ip_owned = ip.to_string();
                    let binary = if ip_addr.is_ipv6() { "ip6tables" } else { "iptables" };
                    tokio::spawn(async move {
                        let _ = tokio::process::Command::new(binary)
                            .args(["-A", "INPUT", "-s", &ip_owned, "-j", "DROP"])
                            .output().await;
                    });
                }
            }
        }
        "unblock_ip" => {
            if let Some(ip) = cmd.get("ip").and_then(|i| i.as_str()) {
                println!("[Warden Cloud] Remote command: Unblocking IP {}", ip);
                if let Ok(ip_addr) = std::net::IpAddr::from_str(ip) {
                    let ip_owned = ip.to_string();
                    let binary = if ip_addr.is_ipv6() { "ip6tables" } else { "iptables" };
                    tokio::spawn(async move {
                        let _ = tokio::process::Command::new(binary)
                            .args(["-D", "INPUT", "-s", &ip_owned, "-j", "DROP"])
                            .output().await;
                    });
                }
            }
        }
        "trigger_scan" => {
            println!("[Warden Cloud] Remote command: Triggering OSV vulnerability scan");
            let roots = heuristics.web_roots.clone();
            tokio::spawn(async move {
                for root in roots {
                    let _ = crate::scanner::run_scan(&root).await;
                }
            });
        }
        "reload_rules" => {
            println!("[Warden Cloud] Remote command: Reloading local rule database");
            let _ = heuristics.config.reload();
        }
        "sync_rules" | "rules_sync" => {
            println!("[Warden Cloud] Remote command: Triggering immediate remote rules sync");
            let config_clone = Arc::clone(&heuristics.config);
            tokio::spawn(async move {
                let _ = sync_rules_now(&config_clone).await;
            });
        }
        "push_rules" => {
            if let Some(rules_hex) = cmd.get("rules_hex").and_then(|r| r.as_str()) {
                println!("[Warden Cloud] Remote command: Received rules push payload over stream.");
                if let Some(bytes) = hex_to_bytes(rules_hex) {
                    match heuristics.config.reload_from_bytes(&bytes) {
                        Ok(_) => {
                            println!("[Warden Cloud] Rules updated and activated successfully from stream payload.");
                        }
                        Err(e) => {
                            eprintln!("[Warden Cloud] Failed to load rules pushed over stream: {}", e);
                        }
                    }
                }
            }
        }
        "fim_add" => {
            if let Some(path) = cmd.get("path").and_then(|p| p.as_str()) {
                println!("[Warden Cloud] Remote command: Adding FIM watch path {}", path);
                let _ = crate::fim::add_fim_watch_path(std::path::PathBuf::from(path));
            }
        }
        "fim_remove" => {
            if let Some(path) = cmd.get("path").and_then(|p| p.as_str()) {
                println!("[Warden Cloud] Remote command: Removing FIM watch path {}", path);
                let _ = crate::fim::remove_fim_watch_path(std::path::PathBuf::from(path));
            }
        }
        "allowlist_add" => {
            if let Some(path) = cmd.get("path").and_then(|p| p.as_str()) {
                println!("[Warden Cloud] Remote command: Registering path in allowlist: {}", path);
                crate::allowlist::register_path_recursive(path);
            }
        }
        "allowlist_remove" => {
            if let Some(path) = cmd.get("path").and_then(|p| p.as_str()) {
                println!("[Warden Cloud] Remote command: Deregistering path from allowlist: {}", path);
                crate::allowlist::deregister_path_recursive(path);
            }
        }
        "sync_inventory" | "inventory_sync" => {
            println!("[Warden Cloud] Remote command: Triggering immediate inventory sync");
            let heuristics_clone = Arc::clone(&heuristics);
            tokio::spawn(async move {
                send_inventory_sync(&heuristics_clone).await;
            });
        }
        _ => {
            eprintln!("[Warden Cloud] Unknown remote command action: {}", action);
        }
    }
}

pub async fn send_inventory_sync(heuristics: &HeuristicsEngine) {
    let client = get_client();
    let Some(endpoint) = &client.cloud_endpoint else { return; };

    let mut containers = Vec::new();
    let mounts = crate::discovery::get_active_container_mounts();
    for entry in mounts.iter() {
        containers.push(serde_json::json!({
            "container_id": entry.key(),
            "mounts": entry.value().iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>()
        }));
    }

    let mut proxies = Vec::new();
    for p in crate::discovery::auto_discover_proxies() {
        proxies.push(serde_json::json!({
            "name": p.name,
            "config_dirs": p.config_dirs.iter().map(|f| f.to_string_lossy()).collect::<Vec<_>>(),
            "access_logs": p.access_logs.iter().map(|f| f.to_string_lossy()).collect::<Vec<_>>(),
        }));
    }

    let listening_services = crate::discovery::get_listening_services();

    let mut packages = Vec::new();
    for root in &heuristics.web_roots {
        packages.extend(crate::scanner::get_installed_packages(root));
    }

    let payload = serde_json::json!({
        "web_roots": heuristics.web_roots,
        "proxies": proxies,
        "listening_services": listening_services,
        "containers": containers,
        "packages": packages,
        "tls_forensics": crate::tls_buffer::get_tls_forensics_status(),
    });

    let url = format!("{}/api/v1/agent/inventory", endpoint);
    let http_client = get_http_client().clone();
    let mut req = http_client.post(&url)
        .json(&payload);
    if let Some(key) = &client.license_key {
        req = req.header("X-License-Key", key);
    }

    match req.send().await {
        Ok(res) if res.status().is_success() => {
            println!("[Warden Cloud] Host inventory successfully synced to fleet manager.");
        }
        _ => {
            eprintln!("[Warden Cloud] Failed to sync host inventory to fleet manager.");
        }
    }
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 { return None; }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i+2];
        let byte = u8::from_str_radix(byte_str, 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

fn resolve_incident_file(payload: &crate::notifications::AlertPayload) -> Option<std::path::PathBuf> {
    // 1. If it's a binary execution threat, the executed binary itself is the target
    let exec_path = std::path::PathBuf::from(&payload.process.exec_path);
    
    // Check if the exec_path itself exists and is a file
    if exec_path.exists() && exec_path.is_file() {
        let name_lower = exec_path.to_string_lossy().to_lowercase();
        // If it's not a standard system interpreter/shell, it could be a compiled payload (ELF) or binary itself
        let is_system_interpreter = name_lower.contains("/php") || name_lower.contains("/python") ||
            name_lower.contains("/node") || name_lower.contains("/ruby") ||
            name_lower.contains("/java") || name_lower.contains("/bash") ||
            name_lower.contains("/sh") || name_lower.contains("/dash");
        
        if !is_system_interpreter {
            return Some(exec_path);
        }
    }

    // 2. If the exec_path is a system interpreter, we parse the command line to find the script/jar file
    let cmdline = &payload.process.cmdline;
    let parts: Vec<&str> = cmdline.split_whitespace().collect();
    for part in parts.iter().skip(1) {
        if part.starts_with('-') {
            continue;
        }
        let p = std::path::PathBuf::from(part);
        if p.exists() && p.is_file() {
            let ext = p.extension().and_then(|s| s.to_str()).unwrap_or_default().to_lowercase();
            if ext == "php" || ext == "js" || ext == "py" || ext == "rb" || ext == "jar" || ext == "class" {
                return Some(p);
            }
        }
    }

    // 3. Fallback: Parse the alert's remediation status/description for any absolute paths
    let status = &payload.remediation.status;
    let words: Vec<&str> = status.split_whitespace().collect();
    for word in words {
        let cleaned = word.trim_matches(|c| c == ',' || c == '.' || c == '\'' || c == '"' || c == '(' || c == ')');
        if cleaned.starts_with('/') {
            let p = std::path::PathBuf::from(cleaned);
            if p.exists() && p.is_file() {
                let ext = p.extension().and_then(|s| s.to_str()).unwrap_or_default().to_lowercase();
                if ext == "php" || ext == "js" || ext == "py" || ext == "rb" || ext == "jar" || ext == "class" || ext == "elf" {
                    return Some(p);
                }
                if cleaned.contains("quarantine") || cleaned.contains("uploads") || cleaned.contains("/tmp") {
                    return Some(p);
                }
            }
        }
    }

    None
}

pub fn send_alert_immediate(payload: &crate::notifications::AlertPayload) {
    let client = get_client();
    let Some(endpoint) = &client.cloud_endpoint else { return; };
    if client.license_key.is_none() { return; }

    let url = format!("{}/api/v1/alerts/stream", endpoint);
    let payload = payload.clone();
    let auto_analyze = client.auto_analyze;

    tokio::spawn(async move {
        let http_client = get_http_client().clone();
        let mut req = http_client.post(&url);
        if let Some(key) = &get_client().license_key {
            req = req.header("X-License-Key", key);
        }

        let mut file_payload = None;
        if auto_analyze {
            file_payload = resolve_incident_file(&payload);
        }

        if let Some(file_path) = file_payload {
            if let Ok(mut file) = std::fs::File::open(&file_path) {
                let mut buffer = Vec::new();
                use std::io::Read;
                if file.read_to_end(&mut buffer).is_ok() {
                    let filename = file_path.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "file".to_string());
                    
                    let part = reqwest::multipart::Part::bytes(buffer)
                        .file_name(filename);
                    
                    let json_payload = serde_json::to_string(&payload).unwrap_or_default();
                    let form = reqwest::multipart::Form::new()
                        .text("alert", json_payload)
                        .part("file", part);
                    
                    let _ = req.multipart(form).send().await;
                    return;
                }
            }
        }

        let _ = req.json(&payload).send().await;
    });
}
