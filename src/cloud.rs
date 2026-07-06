use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use std::str::FromStr;
use tokio::time::sleep;
use crate::heuristics::HeuristicsEngine;

static CLOUD_CLIENT: OnceLock<CloudClient> = OnceLock::new();
static LOGS_BUFFER: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

struct CloudClient {
    pub cloud_endpoint: Option<String>,
    pub updates_server: String,
    pub license_key: Option<String>,
}

fn get_client() -> &'static CloudClient {
    CLOUD_CLIENT.get_or_init(|| {
        let conf = std::fs::read_to_string("/etc/kinnector/core.conf").unwrap_or_default();
        let mut cloud_endpoint = None;
        let mut updates_server = "https://updates.kinnector.com/rules.db".to_string();
        let mut license_key = None;

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
                    _ => {}
                }
            }
        }

        CloudClient {
            cloud_endpoint,
            updates_server,
            license_key,
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
    start_command_listener(heuristics, client);
}

pub async fn sync_rules_now(config: &Arc<kinnector_config::ConfigManager>) -> bool {
    let client_info = get_client();
    let Some(license) = &client_info.license_key else {
        println!("[Warden Cloud] License check: Free tier, remote rule updates disabled.");
        return false;
    };

    println!("[Warden Cloud] License validated. Initiating remote rule updates sync from {}", client_info.updates_server);
    let http_client = reqwest::Client::new();
    let req = http_client.get(&client_info.updates_server)
        .header("X-License-Key", license)
        .header("X-Agent-Version", "0.1.0");

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

pub async fn send_forensic_payload(alert_id: &str, payload: Vec<u8>) {
    let client = get_client();
    let Some(endpoint) = &client.cloud_endpoint else { return; };

    let url = format!("{}/api/v1/forensics/{}", endpoint, alert_id);
    let http_client = reqwest::Client::new();
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
            } else {
                eprintln!("[Warden Cloud] Forensic upload returned status: {}", res.status());
            }
        }
        Err(e) => {
            eprintln!("[Warden Cloud] Forensic upload failed to connect: {}", e);
        }
    }
}

fn start_log_streamer(client: &'static CloudClient) {
    let endpoint = match &client.cloud_endpoint {
        Some(ep) => ep.clone(),
        None => return,
    };

    tokio::spawn(async move {
        let http_client = reqwest::Client::new();
        loop {
            sleep(Duration::from_secs(60)).await;

            let mut logs = Vec::new();
            if let Ok(mut buf) = get_logs_buffer().lock() {
                std::mem::swap(&mut logs, &mut buf);
            }

            if logs.is_empty() {
                continue;
            }

            let payload = serde_json::json!({
                "logs": logs
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
                    let _ = req.send().await;
                }
                Err(e) => {
                    eprintln!("[Warden Cloud] Failed to compress logs for streaming: {}", e);
                }
            }
        }
    });
}

fn start_command_listener(heuristics: Arc<HeuristicsEngine>, client: &'static CloudClient) {
    let endpoint = match &client.cloud_endpoint {
        Some(ep) => ep.clone(),
        None => return,
    };

    tokio::spawn(async move {
        let http_client = reqwest::Client::new();
        loop {
            let url = format!("{}/api/v1/agent/commands", endpoint);
            let mut req = http_client.get(&url)
                .header("Connection", "keep-alive");
            if let Some(key) = &client.license_key {
                req = req.header("X-License-Key", key);
            }

            match req.send().await {
                Ok(res) => {
                    if res.status().is_success() {
                        if let Ok(cmd_json) = res.json::<serde_json::Value>().await {
                            process_cloud_command(cmd_json, &heuristics).await;
                        }
                    }
                }
                Err(_) => {
                    sleep(Duration::from_secs(10)).await;
                }
            }
            sleep(Duration::from_secs(5)).await;
        }
    });
}

async fn process_cloud_command(cmd: serde_json::Value, _heuristics: &HeuristicsEngine) {
    let Some(action) = cmd.get("action").and_then(|a| a.as_str()) else { return; };
    println!("[Warden Cloud] Received remote control command: {}", action);
    match action {
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
        "block_ip" => {
            if let Some(ip) = cmd.get("ip").and_then(|i| i.as_str()) {
                println!("[Warden Cloud] Remote command: Blocking IP {}", ip);
                if std::net::IpAddr::from_str(ip).is_ok() {
                    let ip_owned = ip.to_string();
                    tokio::spawn(async move {
                        let _ = tokio::process::Command::new("iptables")
                            .args(["-A", "INPUT", "-s", &ip_owned, "-j", "DROP"])
                            .output().await;
                    });
                }
            }
        }
        _ => {
            eprintln!("[Warden Cloud] Unknown remote command action: {}", action);
        }
    }
}

pub fn send_alert_immediate(payload: &crate::notifications::AlertPayload) {
    let client = get_client();
    let Some(endpoint) = &client.cloud_endpoint else { return; };
    if client.license_key.is_none() { return; }

    let url = format!("{}/api/v1/alerts/stream", endpoint);
    let payload = payload.clone();
    tokio::spawn(async move {
        let http_client = reqwest::Client::new();
        let mut req = http_client.post(&url)
            .json(&payload);
        if let Some(key) = &get_client().license_key {
            req = req.header("X-License-Key", key);
        }
        let _ = req.send().await;
    });
}
