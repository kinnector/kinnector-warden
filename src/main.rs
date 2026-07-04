use clap::Parser;
use std::path::PathBuf;
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use std::sync::Arc;
use crate::types::{TelemetryEventRaw, RAW_EVENT_SIZE};
use crate::heuristics::HeuristicsEngine;

mod types;
mod heuristics;
mod vet;
mod api;
mod notifications;
mod scanner;
mod discovery;
mod fim;

#[derive(Parser, Debug)]
#[command(name = "wardend")]
#[command(about = "Kinnector Warden: Server EDR Daemon", long_about = None)]
struct Args {
    #[arg(short, long, default_value = "/var/run/kinnector/telemetry.sock", help = "Path to core telemetry UDS socket")]
    telemetry_socket: String,

    #[arg(short, long, default_value = "/var/www/html", help = "Web application root directory for FIM and OSV scans")]
    web_root: String,

    #[arg(long, default_value = "/etc/kinnector/rules.json", help = "Path to rules database configuration")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Kinnector Warden Server EDR Daemon (wardend) starting... ===");

    // Check for root privileges (necessary for process containment/killing and socket bindings)
    if unsafe { libc::getuid() } != 0 {
        eprintln!("Error: wardend must be run with root privileges (sudo).");
        std::process::exit(1);
    }

    let args = Args::parse();

    // 1. Initialize EDR Heuristics Engine
    let heuristics = Arc::new(HeuristicsEngine::new());

    // 2. Start Web Vetting HTTP / UNIX API Servers
    crate::api::start_api_servers();

    // 3. Auto-discover Reverse Proxies & Start Log tail auditors
    let proxies = crate::discovery::auto_discover_proxies();
    let mut config_dirs = Vec::new();
    for proxy in proxies {
        println!("[Warden Discovery] Discovered active reverse proxy: {}", proxy.name);
        for log_path in proxy.access_logs {
            crate::discovery::start_log_pipeline_auditing(log_path, proxy.name.clone());
        }
        for conf_dir in proxy.config_dirs {
            config_dirs.push(conf_dir);
        }
    }

    // 4. Start File Integrity Monitoring (FIM)
    crate::fim::start_fim_watcher(args.web_root.clone(), config_dirs);

    // 5. Start Dependency Vulnerabilities OSV Scanner
    crate::scanner::start_scanner(args.web_root.clone());

    // 6. Connect to core eBPF telemetry loop
    let telemetry_path = args.telemetry_socket.clone();
    let engine_clone = Arc::clone(&heuristics);
    
    tokio::spawn(async move {
        println!("[Warden Telemetry] Attempting connection to telemetry stream: {}", telemetry_path);
        loop {
            match UnixStream::connect(&telemetry_path).await {
                Ok(mut stream) => {
                    println!("[Warden Telemetry] Connected to eBPF telemetry socket successfully.");
                    let mut buffer = vec![0u8; RAW_EVENT_SIZE * 4];
                    let mut bytes_in_buf = 0;

                    loop {
                        match stream.read(&mut buffer[bytes_in_buf..]).await {
                            Ok(0) => {
                                println!("[Warden Telemetry] Stream EOF. Reconnecting...");
                                break;
                            }
                            Ok(n) => {
                                bytes_in_buf += n;
                                while bytes_in_buf >= RAW_EVENT_SIZE {
                                    // Parse event frame
                                    let mut frame = [0u8; RAW_EVENT_SIZE];
                                    frame.copy_from_slice(&buffer[..RAW_EVENT_SIZE]);
                                    
                                    let raw_event: TelemetryEventRaw = unsafe {
                                        std::ptr::read(frame.as_ptr() as *const TelemetryEventRaw)
                                    };

                                    engine_clone.handle_raw_event(raw_event);

                                    // Shift remaining bytes
                                    buffer.copy_within(RAW_EVENT_SIZE..bytes_in_buf, 0);
                                    bytes_in_buf -= RAW_EVENT_SIZE;
                                }
                            }
                            Err(e) => {
                                eprintln!("[Warden Telemetry] Socket read error: {}. Reconnecting...", e);
                                break;
                            }
                        }
                    }
                }
                Err(_) => {
                    // Core is not running or socket is offline, sleep and retry
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                }
            }
        }
    });

    // Keep daemon main thread running
    let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("Warden shutdown requested via Ctrl-C");
        }
        _ = signal.recv() => {
            println!("Warden shutdown requested via SIGTERM");
        }
    }

    println!("Warden daemon stopped.");
    Ok(())
}
