use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use chrono::Utc;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TtyEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub len: u32,
    pub is_write: u8,
    pub comm: [u8; 16],
    pub data: [u8; 1024],
}

pub fn start_tty_logger() {
    let tty_socket_path = "/var/run/kinnector/tty_telemetry.sock";
    let log_path = "/var/log/kinnector/tty.log";

    tokio::spawn(async move {
        println!("[Warden TTY] Starting event-driven PTY/TTY logger on socket: {}", tty_socket_path);
        
        loop {
            // Wait for socket to exist (it is created by the core shared library on start)
            if !std::path::Path::new(tty_socket_path).exists() {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                continue;
            }

            match UnixStream::connect(tty_socket_path).await {
                Ok(mut stream) => {
                    println!("[Warden TTY] Connected to PTY/TTY telemetry stream.");
                    let event_size = std::mem::size_of::<TtyEvent>();
                    let mut buffer = vec![0u8; event_size * 4];
                    let mut bytes_in_buf = 0;

                    loop {
                        match stream.read(&mut buffer[bytes_in_buf..]).await {
                            Ok(0) => {
                                println!("[Warden TTY] Stream EOF. Reconnecting...");
                                break;
                            }
                            Ok(n) => {
                                bytes_in_buf += n;
                                while bytes_in_buf >= event_size {
                                    let mut frame = vec![0u8; event_size];
                                    frame.copy_from_slice(&buffer[..event_size]);

                                    let event: TtyEvent = unsafe {
                                        std::ptr::read(frame.as_ptr() as *const TtyEvent)
                                    };

                                    // Log event
                                    log_tty_event(&event, log_path);

                                    // Shift remaining bytes
                                    buffer.copy_within(event_size..bytes_in_buf, 0);
                                    bytes_in_buf -= event_size;
                                }
                            }
                            Err(e) => {
                                eprintln!("[Warden TTY] Socket read error: {}. Reconnecting...", e);
                                break;
                            }
                        }
                    }
                }
                Err(_) => {
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                }
            }
        }
    });
}

fn log_tty_event(ev: &TtyEvent, log_path: &str) {
    let comm_len = ev.comm.iter().position(|&b| b == 0).unwrap_or(ev.comm.len());
    let comm = String::from_utf8_lossy(&ev.comm[..comm_len]).to_string();

    let pid = ev.pid;
    let len = ev.len;
    let data_len = (len as usize).min(ev.data.len());
    // Convert control characters or binary data to safe printable strings or hex representation
    let mut data_str = String::new();
    for &b in &ev.data[..data_len] {
        if b >= 32 && b <= 126 {
            data_str.push(b as char);
        } else if b == b'\n' {
            data_str.push_str("\\n");
        } else if b == b'\r' {
            data_str.push_str("\\r");
        } else if b == b'\t' {
            data_str.push_str("\\t");
        } else {
            data_str.push_str(&format!("\\x{:02x}", b));
        }
    }

    let direction = if ev.is_write == 1 { "WRITE" } else { "READ" };
    let timestamp = Utc::now().to_rfc3339();

    let log_line = format!(
        "[{}] PID={} ({}) [{}] (len={}) {}\n",
        timestamp, pid, comm, direction, len, data_str
    );

    let _ = std::fs::create_dir_all("/var/log/kinnector");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        use std::io::Write;
        let _ = file.write_all(log_line.as_bytes());
    }
}
