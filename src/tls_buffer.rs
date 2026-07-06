use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, Duration};
use dashmap::DashMap;
use tokio::net::UnixListener;
use tokio::io::AsyncReadExt;
use chrono::Utc;

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

static TLS_BUFFERS: OnceLock<DashMap<u32, Mutex<ProcessBuffer>>> = OnceLock::new();

fn get_buffers() -> &'static DashMap<u32, Mutex<ProcessBuffer>> {
    TLS_BUFFERS.get_or_init(DashMap::new)
}

// Max buffer size per process: 32 MB
const MAX_PROC_BUFFER_BYTES: usize = 32 * 1024 * 1024;
// Max buffer size globally across all processes: 256 MB
const MAX_GLOBAL_BUFFER_BYTES: usize = 256 * 1024 * 1024;

pub fn add_record(record: TlsRecord) {
    let pid = record.pid;
    let record_len = record.payload.len();
    let buffers = get_buffers();
    
    // Check global size first to prevent memory exhaustion
    let mut global_bytes = 0;
    for entry in buffers.iter() {
        if let Ok(buf) = entry.value().lock() {
            global_bytes += buf.total_bytes;
        }
    }
    
    // If global limit reached, evict oldest records across all buffers
    if global_bytes + record_len > MAX_GLOBAL_BUFFER_BYTES {
        // Find process buffer with largest size and evict oldest record
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
        while buf.total_bytes + record_len > MAX_PROC_BUFFER_BYTES && !buf.records.is_empty() {
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
                            // 1. Read header
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

                            // 2. Read payload
                            let mut payload = vec![0u8; payload_len];
                            if stream.read_exact(&mut payload).await.is_err() {
                                break;
                            }

                            // 3. Convert container ID to string
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
    let alert_id_owned = alert_id.to_string();
    let buffers = get_buffers();
    tokio::spawn(async move {
        // Capture pre-event window (now)
        let alert_time = Instant::now();
        println!("[Warden TLS] Alert triggered for PID {}. Preparing forensic flush (alert: {})...", pid, alert_id_owned);

        // Wait 30 seconds for the post-event window to accumulate (as per Section 7.D)
        tokio::time::sleep(Duration::from_secs(30)).await;

        let mut collected = Vec::new();

        if let Some(entry) = buffers.get(&pid) {
            if let Ok(buf) = entry.value().lock() {
                for rec in &buf.records {
                    // Check if it falls within 60s before and 30s after the alert
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

        // Format and save forensic packet to disk
        let output_path = format!("/var/log/kinnector/forensic_{}.json", alert_id_owned);
        let mut json_records = Vec::new();
        for rec in &collected {
            // Redact headers if configured (Privacy controls: Section 7.D)
            let mut payload_str = String::from_utf8_lossy(&rec.payload).to_string();
            // Basic header redaction (Authorization, Cookie)
            for header in &["Authorization:", "Cookie:", "Set-Cookie:"] {
                if let Some(idx) = payload_str.to_lowercase().find(&header.to_lowercase()) {
                    // Redact the rest of the line
                    if let Some(end_line) = payload_str[idx..].find('\n') {
                        let line_start = idx;
                        let line_end = idx + end_line;
                        payload_str.replace_range(line_start..line_end, &format!("{} [REDACTED]", header));
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

        let _ = std::fs::create_dir_all("/var/log/kinnector");
        if let Ok(mut file) = std::fs::File::create(&output_path) {
            use std::io::Write;
            if let Ok(json_str) = serde_json::to_string_pretty(&output_data) {
                let _ = file.write_all(json_str.as_bytes());
                println!("[Warden TLS] Forensic flush completed successfully. Saved {} records to {}", collected.len(), output_path);
            }
        }
    });
}
