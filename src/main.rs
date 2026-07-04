use clap::Parser;
use std::sync::Arc;
use crate::types::{TelemetryEventRaw, RAW_EVENT_SIZE};
use crate::heuristics::HeuristicsEngine;

mod types;
mod heuristics;
mod notifications;
mod scanner;
mod discovery;
mod fim;
mod ffi;

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

    // 1. Resolve BPF object path
    let bpf_packaged_path = "/usr/lib/kinnector/kinnector.bpf.o";
    let bpf_path = if std::path::Path::new(bpf_packaged_path).exists() {
        bpf_packaged_path
    } else {
        "/home/user/Documents/kinnector/kinnector-core/build/kinnector.bpf.o"
    };

    let telemetry_socket = "/var/run/kinnector/telemetry.sock";
    let auth_token = "super-secret-agent-token-12345";

    // 2. Initialize FFI low-level C++ telemetry engine
    let bpf_path_c = std::ffi::CString::new(bpf_path)?;
    let socket_path_c = std::ffi::CString::new(telemetry_socket)?;
    let auth_token_c = std::ffi::CString::new(auth_token)?;

    println!("[Warden] Initializing low-level C++ telemetry engine...");
    let init_success = unsafe {
        ffi::initialize_telemetry_engine(
            bpf_path_c.as_ptr(),
            socket_path_c.as_ptr(),
            auth_token_c.as_ptr(),
        )
    };

    if !init_success {
        eprintln!("[Warden] Failed to initialize C++ telemetry engine via FFI!");
        std::process::exit(1);
    }

    println!("[Warden] Starting low-level C++ telemetry engine...");
    let start_success = unsafe { ffi::start_telemetry_engine() };
    if !start_success {
        eprintln!("[Warden] Failed to start C++ telemetry engine!");
        std::process::exit(1);
    }

    // 3. Load and register sensitive inodes in the kernel BPF maps
    let rules_path = "/etc/kinnector/rules.db";
    let public_key = [25, 127, 107, 35, 225, 108, 133, 50, 198, 171, 200, 56, 250, 205, 94, 167, 137, 190, 12, 118, 178, 146, 3, 52, 3, 155, 250, 139, 61, 54, 141, 97];
    if let Ok(mgr) = kinnector_config::ConfigManager::load(rules_path, &public_key) {
        println!("[Warden] Rules database loaded successfully from {}", rules_path);
        let sensitive_files = mgr.sensitive_files();
        use std::os::unix::fs::MetadataExt;
        for (path_str, category_flags) in sensitive_files {
            if let Ok(metadata) = std::fs::metadata(&path_str) {
                let inode = metadata.ino();
                println!("[Warden] Registering sensitive file: {} (Inode: {}, Category: {:#x})", path_str, inode, category_flags);
                unsafe {
                    ffi::add_sensitive_inode(inode, category_flags);
                }
            }
        }
    }

    // 4. Initialize EDR Heuristics Engine
    let heuristics = Arc::new(HeuristicsEngine::new());

    // 5. Auto-discover Reverse Proxies
    let proxies = crate::discovery::auto_discover_proxies();
    let mut config_dirs = Vec::new();
    for proxy in proxies {
        println!("[Warden Discovery] Discovered active reverse proxy: {}", proxy.name);
        for conf_dir in proxy.config_dirs {
            config_dirs.push(conf_dir);
        }
    }

    // 7. Start File Integrity Monitoring (FIM)
    crate::fim::start_fim_watcher(args.web_root.clone(), config_dirs);

    // 8. Start Dependency Vulnerabilities OSV Scanner
    crate::scanner::start_scanner(args.web_root.clone());

    // 9. Connect to core eBPF telemetry loop
    let telemetry_path = args.telemetry_socket.clone();
    let engine_clone = Arc::clone(&heuristics);
    
    tokio::spawn(async move {
        println!("[Warden Telemetry] Attempting connection to telemetry stream: {}", telemetry_path);
        loop {
            match tokio::net::UnixStream::connect(&telemetry_path).await {
                Ok(mut stream) => {
                    println!("[Warden Telemetry] Connected to eBPF telemetry socket successfully.");
                    let mut buffer = vec![0u8; RAW_EVENT_SIZE * 4];
                    let mut bytes_in_buf = 0;

                    loop {
                        use tokio::io::AsyncReadExt;
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
    // Cleanup low-level telemetry resources
    unsafe { ffi::stop_telemetry_engine(); }
    Ok(())
}
