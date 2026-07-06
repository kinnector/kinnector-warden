use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, Duration};
use dashmap::DashMap;
use tokio::net::UnixListener;
use tokio::io::AsyncReadExt;
use chrono::Utc;
use regex::Regex;

#[derive(Clone, Debug)]
pub struct TlsRecord {
    pub arrival_time: Instant,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub container_id: String,
    pub direction: u8,
    pub tls_layer: u8,
    pub payload: Vec<u8>,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
struct WardenTlsHeader {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub container_id: [u8; 12],
    pub direction: u8,
    pub tls_layer: u8,
    pub payload_len: u16,
}

struct ProcessBuffer {
    records: VecDeque<TlsRecord>,
    total_bytes: usize,
}

struct TlsBufferConfig {
    pub capacity_bytes: usize,
    pub global_capacity_bytes: usize,
    pub redact_headers: Vec<String>,
    pub exclude_paths: Vec<Regex>,
}

static CONFIG: OnceLock<TlsBufferConfig> = OnceLock::new();
static TLS_BUFFERS: OnceLock<DashMap<u32, Mutex<ProcessBuffer>>> = OnceLock::new();

fn get_buffers() -> &'static DashMap<u32, Mutex<ProcessBuffer>> {
    TLS_BUFFERS.get_or_init(DashMap::new)
}

fn get_config() -> &'static TlsBufferConfig {
    CONFIG.get_or_init(|| {
        let conf = std::fs::read_to_string("/etc/kinnector/core.conf").unwrap_or_default();
        let mut capacity_bytes = 32 * 1024 * 1024;
        let mut global_capacity_bytes = 256 * 1024 * 1024;
        let mut redact_headers = vec![
            "Authorization".to_string(),
            "Cookie".to_string(),
            "Set-Cookie".to_string(),
        ];
        let mut exclude_paths = Vec::new();

        for line in conf.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() { continue; }
            if let Some(pos) = line.find('=') {
                let key = line[..pos].trim();
                let val = line[pos+1..].trim();
                match key {
                    "tls_buffer.capacity_mb" => {
                        if let Ok(mb) = val.parse::<usize>() {
                            capacity_bytes = mb * 1024 * 1024;
                        }
                    }
                    "tls_buffer.global_capacity_mb" => {
                        if let Ok(mb) = val.parse::<usize>() {
                            global_capacity_bytes = mb * 1024 * 1024;
                        }
                    }
                    "tls_buffer.redact_headers" => {
                        redact_headers = val.split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                    }
                    "tls_buffer.exclude_paths" => {
                        exclude_paths = val.split(',')
                            .map(|s| s.trim())
                            .filter(|s| !s.is_empty())
                            .filter_map(|s| Regex::new(s).ok())
                            .collect();
                    }
                    _ => {}
                }
            }
        }

        TlsBufferConfig {
            capacity_bytes,
            global_capacity_bytes,
            redact_headers,
            exclude_paths,
        }
    })
}

static IS_PAID_TIER: OnceLock<bool> = OnceLock::new();

pub fn is_paid_tier() -> bool {
    *IS_PAID_TIER.get_or_init(|| {
        let conf = std::fs::read_to_string("/etc/kinnector/core.conf").unwrap_or_default();
        conf.lines()
            .find(|l| l.starts_with("license_key="))
            .map(|l| l.trim_start_matches("license_key=").trim())
            .map(|val| !val.is_empty() && val != "free")
            .unwrap_or(false)
    })
}

pub fn get_tls_forensics_status() -> serde_json::Value {
    let is_paid = is_paid_tier();
    serde_json::json!({
        "supported_layers": [1, 2, 3, 4],
        "active_layers": if is_paid { vec![1, 2, 3] } else { vec![] },
        "layer_status": {
            "layer_1_uprobe": if is_paid { "active" } else { "disabled_free_tier" },
            "layer_2_jvmti": if is_paid { "active" } else { "disabled_free_tier" },
            "layer_3_ktls": if is_paid { "active" } else { "disabled_free_tier" },
            "layer_4_proxy": "disabled"
        },
        "overhead_warnings": {
            "layer_4_proxy": "High CPU and connection latency overhead if enabled"
        }
    })
}

fn should_exclude_payload(payload: &[u8]) -> bool {
    let config = get_config();
    if config.exclude_paths.is_empty() {
        return false;
    }
    let text = String::from_utf8_lossy(payload);
    for re in &config.exclude_paths {
        if re.is_match(&text) {
            return true;
        }
    }
    false
}

pub fn add_record(record: TlsRecord) {
    if crate::allowlist::get_disabled_tls_pids().contains(&record.pid) {
        return;
    }
    if should_exclude_payload(&record.payload) {
        return;
    }

    let pid = record.pid;
    let record_len = record.payload.len();
    let buffers = get_buffers();
    let config = get_config();
    let max_proc = config.capacity_bytes;
    let max_global = config.global_capacity_bytes;
    
    // Check global size first to prevent memory exhaustion
    let mut global_bytes = 0;
    for entry in buffers.iter() {
        if let Ok(buf) = entry.value().lock() {
            global_bytes += buf.total_bytes;
        }
    }
    
    // If global limit reached, evict oldest records across all buffers
    if global_bytes + record_len > max_global {
        let mut largest_pid = None;
        let mut largest_bytes = 0;
        for entry in buffers.iter() {
            if let Ok(buf) = entry.value().lock() {
                if buf.total_bytes > largest_bytes {
                    largest_bytes = buf.total_bytes;
                    largest_pid = Some(*entry.key());
                }
            }
        }
        if let Some(l_pid) = largest_pid {
            if let Some(entry) = buffers.get(&l_pid) {
                if let Ok(mut buf) = entry.value().lock() {
                    if let Some(old) = buf.records.pop_front() {
                        buf.total_bytes -= old.payload.len();
                    }
                }
            }
        }
    }

    let entry = buffers.entry(pid).or_insert_with(|| {
        Mutex::new(ProcessBuffer {
            records: VecDeque::new(),
            total_bytes: 0,
        })
    });

    if let Ok(mut buf) = entry.value().lock() {
        // Evict oldest from this PID until space is available
        while buf.total_bytes + record_len > max_proc && !buf.records.is_empty() {
            if let Some(old) = buf.records.pop_front() {
                buf.total_bytes -= old.payload.len();
            }
        }
        
        buf.total_bytes += record_len;
        buf.records.push_back(record);
    }
    drop(entry);
}

pub fn start_tls_telemetry_server() {
    tokio::spawn(async move {
        let socket_path = "/var/run/kinnector/tls_telemetry.sock";
        let _ = std::fs::remove_file(socket_path);
        
        if let Some(parent) = std::path::Path::new(socket_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = match UnixListener::bind(socket_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[Warden TLS] Failed to bind UDS socket {}: {}", socket_path, e);
                return;
            }
        };

        let _ = std::process::Command::new("chmod")
            .args(["0666", socket_path])
            .output();

        println!("[Warden TLS] Listening for TLS plaintext telemetry on: {}", socket_path);

        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        let header_size = std::mem::size_of::<WardenTlsHeader>();
                        let mut header_buf = vec![0u8; header_size];

                        loop {
                            if stream.read_exact(&mut header_buf).await.is_err() {
                                break;
                            }

                            let header: WardenTlsHeader = unsafe {
                                std::ptr::read(header_buf.as_ptr() as *const WardenTlsHeader)
                            };

                            let payload_len = header.payload_len as usize;
                            if payload_len > 16384 { // cap at 16 KB as per spec
                                break;
                            }

                            let mut payload = vec![0u8; payload_len];
                            if stream.read_exact(&mut payload).await.is_err() {
                                break;
                            }

                            let container_id = String::from_utf8_lossy(&header.container_id)
                                .trim_end_matches('\0')
                                .to_string();

                            let record = TlsRecord {
                                arrival_time: Instant::now(),
                                timestamp_ns: header.timestamp_ns,
                                pid: header.pid,
                                tid: header.tid,
                                container_id,
                                direction: header.direction,
                                tls_layer: header.tls_layer,
                                payload,
                            };

                            add_record(record);
                        }
                    });
                }
                Err(_) => {}
            }
        }
    });
}

pub fn flush_on_alert(pid: u32, alert_id: &str) {
    if !is_paid_tier() {
        println!("[Warden TLS] Free tier active: forensic ring buffer captured locally in memory but not flushed (requires paid tier license).");
        return;
    }

    let alert_id_owned = alert_id.to_string();
    let buffers = get_buffers();
    tokio::spawn(async move {
        let alert_time = Instant::now();
        println!("[Warden TLS] Alert triggered for PID {}. Preparing forensic flush (alert: {})...", pid, alert_id_owned);

        // Wait 30 seconds for the post-event window to accumulate (as per Section 7.D)
        tokio::time::sleep(Duration::from_secs(30)).await;

        let mut collected = Vec::new();

        if let Some(entry) = buffers.get(&pid) {
            if let Ok(buf) = entry.value().lock() {
                for rec in &buf.records {
                    let time_diff = if rec.arrival_time < alert_time {
                        alert_time.duration_since(rec.arrival_time)
                    } else {
                        rec.arrival_time.duration_since(alert_time)
                    };

                    if rec.arrival_time < alert_time && time_diff <= Duration::from_secs(60) {
                        collected.push(rec.clone());
                    } else if rec.arrival_time >= alert_time && time_diff <= Duration::from_secs(30) {
                        collected.push(rec.clone());
                    }
                }
            }
        }

        if collected.is_empty() {
            println!("[Warden TLS] Forensic flush completed: no TLS records found in time window for PID {}.", pid);
            return;
        }

        let mut json_records = Vec::new();
        let config = get_config();
        
        for rec in &collected {
            let mut payload_str = String::from_utf8_lossy(&rec.payload).to_string();
            
            for header in &config.redact_headers {
                let header_colon = if header.ends_with(':') {
                    header.clone()
                } else {
                    format!("{}:", header)
                };
                if let Some(idx) = payload_str.to_lowercase().find(&header_colon.to_lowercase()) {
                    if let Some(end_line) = payload_str[idx..].find('\n') {
                        let line_start = idx;
                        let line_end = idx + end_line;
                        payload_str.replace_range(line_start..line_end, &format!("{} [REDACTED]", header_colon));
                    }
                }
            }

            json_records.push(serde_json::json!({
                "timestamp_ns": rec.timestamp_ns,
                "pid": rec.pid,
                "tid": rec.tid,
                "container_id": rec.container_id,
                "direction": if rec.direction == 0 { "INBOUND" } else { "OUTBOUND" },
                "tls_layer": match rec.tls_layer {
                    1 => "uprobe",
                    2 => "jvmti",
                    3 => "ktls",
                    4 => "proxy",
                    _ => "unknown"
                },
                "payload": payload_str,
            }));
        }

        let output_data = serde_json::json!({
            "alert_id": alert_id_owned,
            "flushed_at": Utc::now().to_rfc3339(),
            "pid": pid,
            "record_count": json_records.len(),
            "records": json_records
        });

        let json_str = serde_json::to_string(&output_data).unwrap_or_default();
        
        // Compress using zstd
        let compressed = match zstd::stream::encode_all(json_str.as_bytes(), 0) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[Warden TLS] Failed to compress forensic payload: {}", e);
                return;
            }
        };

        let output_path = format!("/var/log/kinnector/forensic_{}.json.zst", alert_id_owned);
        let _ = std::fs::create_dir_all("/var/log/kinnector");
        if let Ok(mut file) = std::fs::File::create(&output_path) {
            use std::io::Write;
            let _ = file.write_all(&compressed);
            println!("[Warden TLS] Forensic flush completed successfully. Saved {} compressed records to {}", collected.len(), output_path);
        }

        // Upload forensic payload to backend over cloud TLS/gRPC channel
        crate::cloud::send_forensic_payload(&alert_id_owned, compressed).await;
    });
}
