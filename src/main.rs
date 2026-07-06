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
mod allowlist;
mod audit;
mod ssh_monitor;
mod quarantine;
mod api;
mod tty_logger;

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

    // B-08 & Section 1: Load config values from /etc/kinnector/core.conf dynamically
    let telemetry_socket = args.telemetry_socket.clone();
    let core_conf = std::fs::read_to_string("/etc/kinnector/core.conf").unwrap_or_default();
    
    let auth_token = core_conf.lines()
        .find(|l| l.starts_with("auth_token="))
        .map(|l| l.trim_start_matches("auth_token=").trim().to_string())
        .unwrap_or_default();

    let quarantine_dir = core_conf.lines()
        .find(|l| l.starts_with("quarantine_dir="))
        .map(|l| l.trim_start_matches("quarantine_dir=").trim().to_string())
        .unwrap_or_else(|| "/var/quarantine/kinnector".to_string());
    crate::quarantine::init_quarantine_dir(quarantine_dir);

    let pid_file_path = core_conf.lines()
        .find(|l| l.starts_with("pid_file="))
        .map(|l| l.trim_start_matches("pid_file=").trim().to_string())
        .unwrap_or_else(|| "/var/run/kinnector/wardend.pid".to_string());

    // Write PID file
    if let Some(parent) = std::path::Path::new(&pid_file_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let pid = std::process::id();
    if let Err(e) = std::fs::write(&pid_file_path, pid.to_string()) {
        eprintln!("[Warden] Warning: could not write PID file {}: {}", pid_file_path, e);
    } else {
        println!("[Warden] PID {} written to {}", pid, pid_file_path);
    }

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

    // 3b. Load config Arc for heuristics engine
    let config_arc = Arc::new(
        kinnector_config::ConfigManager::load(rules_path, &public_key)
            .unwrap_or_else(|_| kinnector_config::ConfigManager::load_defaults())
    );

    // 4. Agnostic dynamic web-roots auto-detection & shell loading
    let mut web_roots = crate::discovery::discover_web_roots(&config_arc);
    // Merge user-supplied parameter if not already discovered
    if !args.web_root.is_empty() && !web_roots.contains(&args.web_root) {
        web_roots.push(args.web_root.clone());
    }

    // 6. Auto-discover Reverse Proxies
    let proxies = crate::discovery::auto_discover_proxies();
    let mut config_dirs = Vec::new();
    for proxy in proxies {
        println!("[Warden Discovery] Discovered active reverse proxy: {}", proxy.name);
        for conf_dir in proxy.config_dirs {
            config_dirs.push(conf_dir);
        }
    }

    // P6-1/P6-3: Auto-discover Docker container mounts at startup
    let docker_containers = crate::discovery::discover_docker_containers().await;
    for container in docker_containers {
        println!("[Warden Docker] Monitoring Docker container: {} (Image: {})", container.name, container.image);
        for wr in container.web_roots {
            let wr_str = wr.to_string_lossy().to_string();
            if !web_roots.contains(&wr_str) {
                web_roots.push(wr_str);
            }
        }
        for cd in container.config_dirs {
            if !config_dirs.contains(&cd) {
                config_dirs.push(cd);
            }
        }
    }

    // P6-4: Start event-driven Docker listener to dynamically watch new containers in real-time
    crate::discovery::start_docker_event_listener();

    println!("[Warden WebRoots] Actively monitoring web roots: {:?}", web_roots);

    let system_shells = crate::allowlist::load_system_shells();
    println!("[Warden Shells] Dynamically loaded {} login shells from /etc/shells", system_shells.len());

    // 4b. Seed inode allowlist from git (git-authoritative enforcement)
    let _allowlist = crate::allowlist::seed_inode_allowlist(&web_roots);

    // 4c. Start git commit watchers for all discovered web roots
    for root in &web_roots {
        crate::allowlist::start_git_commit_watcher(root.clone());
    }

    // 5. Initialize EDR Heuristics Engine
    let heuristics = Arc::new(HeuristicsEngine::new(
        Arc::clone(&config_arc),
        web_roots.clone(),
        system_shells,
    ));

    // P4-5 & P4-6: Add system persistence and SSL/TLS directories to FIM watch list
    let extra_fim_paths = [
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.monthly",
        "/etc/cron.weekly",
        "/etc/crontab",
        "/var/spool/cron",
        "/etc/profile",
        "/etc/profile.d",
        "/etc/bash.bashrc",
        "/etc/ssl",
        "/etc/letsencrypt",
    ];
    for path_str in &extra_fim_paths {
        let path = std::path::Path::new(path_str);
        if path.exists() {
            config_dirs.push(std::path::PathBuf::from(path_str));
        }
    }

    // 7. Start File Integrity Monitoring (FIM) on the main web roots
    for root in &web_roots {
        crate::fim::start_fim_watcher(root.clone(), config_dirs.clone());
    }

    // 8. Start Dependency Vulnerabilities OSV Scanner
    for root in &web_roots {
        crate::scanner::start_scanner(root.clone());
    }

    // 8b. Start SSH brute-force monitor (auth log tailer — Phase 3)
    crate::ssh_monitor::start_ssh_monitor(Arc::clone(&heuristics));

    // 8c. Start HTTP-over-UDS REST API server (Phase 7)
    crate::api::start_api_server(Arc::clone(&heuristics), web_roots.clone());

    // 8d. Start PTY/TTY logging monitor
    crate::tty_logger::start_tty_logger();



    // 9. Periodic process-map TTL eviction (P1-13 / B-10 fix)
    {
        let engine_evict = Arc::clone(&heuristics);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(300)).await; // every 5 min
                engine_evict.evict_stale_processes();
            }
        });
    }

    // 10. Connect to core eBPF telemetry loop
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
    // Remove PID file on clean exit (P1-9)
    let _ = std::fs::remove_file(pid_file_path);
    // Cleanup low-level telemetry resources
    unsafe { ffi::stop_telemetry_engine(); }
    Ok(())
}
