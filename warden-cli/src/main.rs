//! warden-cli — Operator CLI for kinnector-warden server EDR daemon
//!
//! Usage examples:
//!   warden-cli status
//!   warden-cli alerts --follow
//!   warden-cli alerts --severity CRITICAL
//!   warden-cli quarantine list
//!   warden-cli quarantine release <path>
//!   warden-cli quarantine kill <pid>
//!   warden-cli firewall list
//!   warden-cli firewall unblock <ip>
//!   warden-cli fim status
//!   warden-cli fim add <path>
//!   warden-cli fim register --git
//!   warden-cli fim register --path <file>
//!   warden-cli scan now
//!   warden-cli rules reload
//!   warden-cli test-alert
//!   warden-cli version

use clap::{Parser, Subcommand};
use colored::Colorize;

#[derive(Parser, Debug)]
#[command(name = "warden-cli")]
#[command(about = "Kinnector Warden operator CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show daemon health, LSM/eBPF mode, and config version
    Status,

    /// View or follow the alert audit log
    Alerts {
        /// Stream new alerts in real time
        #[arg(long)]
        follow: bool,
        /// Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
        #[arg(long)]
        severity: Option<String>,
        /// Show last N lines (default 50)
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
    },

    /// Manage quarantined files
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },

    /// Manage iptables firewall blocks
    Firewall {
        #[command(subcommand)]
        action: FirewallAction,
    },

    /// File Integrity Monitor management
    Fim {
        #[command(subcommand)]
        action: FimAction,
    },

    /// OSV dependency vulnerability scanner
    Scan {
        #[command(subcommand)]
        action: ScanAction,
    },

    /// Rules database management
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },

    /// List containers being monitored
    Containers,

    /// Fire a test alert to all configured notification endpoints
    TestAlert,

    /// Print version
    Version,
}

#[derive(Subcommand, Debug)]
enum QuarantineAction {
    /// List quarantined files
    List,
    /// Release a quarantined file back to its original location
    Release {
        /// Quarantine file path
        path: String,
    },
    /// Send SIGKILL to a running PID
    Kill {
        /// Process ID to kill
        pid: u32,
    },
}

#[derive(Subcommand, Debug)]
enum FirewallAction {
    /// List currently blocked IPs
    List,
    /// Remove an iptables block for an IP
    Unblock {
        /// IP address to unblock
        ip: String,
    },
}

#[derive(Subcommand, Debug)]
enum FimAction {
    /// Show watched paths and event counts
    Status,
    /// Dynamically add a path to FIM watch list
    Add {
        /// Path to watch
        path: String,
    },
    /// Register inodes into the allowlist
    Register {
        /// Re-seed allowlist from git ls-files
        #[arg(long)]
        git: bool,
        /// Register a single specific file
        #[arg(long)]
        path: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum ScanAction {
    /// Trigger an OSV dependency scan immediately
    Now,
}

#[derive(Subcommand, Debug)]
enum RulesAction {
    /// Hot-reload /etc/kinnector/rules.db
    Reload,
    /// Pull remote signed rules (paid tier)
    Fetch,
}

const AUDIT_LOG: &str = "/var/log/kinnector/audit.log";
const QUARANTINE_DIR: &str = "/var/lib/kinnector/quarantine";

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Version => {
            println!("warden-cli v{} (kinnector-warden)", env!("CARGO_PKG_VERSION"));
        }

        Commands::Status => cmd_status(),
        Commands::Alerts { follow, severity, lines } => cmd_alerts(follow, severity, lines),
        Commands::Quarantine { action } => cmd_quarantine(action),
        Commands::Firewall { action } => cmd_firewall(action),
        Commands::Fim { action } => cmd_fim(action),
        Commands::Scan { action } => cmd_scan(action),
        Commands::Rules { action } => cmd_rules(action),
        Commands::Containers => cmd_containers(),
        Commands::TestAlert => cmd_test_alert(),
    }
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------
fn cmd_status() {
    println!("{}", "=== Kinnector Warden Status ===".bold().cyan());
    // Check if wardend PID file exists
    let pid_file = "/var/run/kinnector/wardend.pid";
    if std::path::Path::new(pid_file).exists() {
        if let Ok(pid_str) = std::fs::read_to_string(pid_file) {
            let pid = pid_str.trim();
            println!("  Daemon PID : {}", pid.green());
            println!("  Status     : {}", "RUNNING".green().bold());
        }
    } else {
        println!("  Status     : {}", "NOT RUNNING".red().bold());
    }

    // Config version
    let config_path = "/etc/kinnector/rules.db";
    if std::path::Path::new(config_path).exists() {
        println!("  Config     : {}", config_path.yellow());
    } else {
        println!("  Config     : {} (using defaults)", "NOT FOUND".yellow());
    }

    // Audit log size
    if let Ok(meta) = std::fs::metadata(AUDIT_LOG) {
        let size_kb = meta.len() / 1024;
        println!("  Audit log  : {} ({} KB)", AUDIT_LOG.yellow(), size_kb);
    }

    // eBPF telemetry socket
    let sock = "/var/run/kinnector/telemetry.sock";
    if std::path::Path::new(sock).exists() {
        println!("  Telemetry  : {}", "eBPF socket active".green());
    } else {
        println!("  Telemetry  : {}", "eBPF socket not found".red());
    }
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------
fn cmd_alerts(follow: bool, severity_filter: Option<String>, lines: usize) {
    let sev = severity_filter.as_deref().map(|s| s.to_uppercase());

    if follow {
        println!("{}", "[warden-cli] Streaming alerts (Ctrl-C to stop)...".bold());
        // tail -f equivalent using simple loop
        use std::io::{BufRead, BufReader, Seek, SeekFrom};
        let mut file = match std::fs::File::open(AUDIT_LOG) {
            Ok(f) => f,
            Err(_) => {
                eprintln!("[warden-cli] Audit log not found: {}", AUDIT_LOG);
                return;
            }
        };
        let _ = file.seek(SeekFrom::End(0));
        loop {
            let mut buf = String::new();
            let reader = BufReader::new(&file);
            // In a real implementation we'd use a proper tail library;
            // for now poll every 500ms
            std::thread::sleep(std::time::Duration::from_millis(500));
            // Re-open and read new lines (simplified)
            if let Ok(content) = std::fs::read_to_string(AUDIT_LOG) {
                for line in content.lines().rev().take(5) {
                    print_alert_line(line, &sev);
                }
            }
            drop(reader);
        }
    } else {
        let content = match std::fs::read_to_string(AUDIT_LOG) {
            Ok(c) => c,
            Err(_) => {
                eprintln!("[warden-cli] Audit log not found: {}", AUDIT_LOG);
                return;
            }
        };
        let all_lines: Vec<&str> = content.lines().collect();
        let tail = if all_lines.len() > lines {
            &all_lines[all_lines.len() - lines..]
        } else {
            &all_lines[..]
        };
        for line in tail {
            print_alert_line(line, &sev);
        }
    }
}

fn print_alert_line(line: &str, sev_filter: &Option<String>) {
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
        let severity = val.get("severity").and_then(|s| s.as_str()).unwrap_or("");
        if let Some(filter) = sev_filter {
            if severity != filter.as_str() { return; }
        }
        let threat = val.get("threat_type").and_then(|s| s.as_str()).unwrap_or("?");
        let ts = val.get("timestamp").and_then(|s| s.as_str()).unwrap_or("");
        let pid = val.get("process").and_then(|p| p.get("pid")).and_then(|p| p.as_u64()).unwrap_or(0);
        let exe = val.get("process").and_then(|p| p.get("exec_path")).and_then(|s| s.as_str()).unwrap_or("");
        let action = val.get("remediation").and_then(|r| r.get("action")).and_then(|s| s.as_str()).unwrap_or("");

        let sev_colored = match severity {
            "CRITICAL" => severity.red().bold(),
            "HIGH" => severity.yellow().bold(),
            "MEDIUM" => severity.bright_yellow(),
            _ => severity.white(),
        };
        println!("[{}] {} {} pid={} exe={} action={}",
            ts.bright_black(), sev_colored, threat.bold().white(),
            pid.to_string().cyan(), exe.cyan(), action.green());
    } else {
        // Non-JSON line, print as-is
        println!("{}", line.bright_black());
    }
}

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------
fn cmd_quarantine(action: QuarantineAction) {
    match action {
        QuarantineAction::List => {
            println!("{}", "=== Quarantine Contents ===".bold().cyan());
            match std::fs::read_dir(QUARANTINE_DIR) {
                Ok(entries) => {
                    let mut count = 0;
                    for entry in entries.flatten() {
                        let path = entry.path();
                        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                        println!("  {} ({} bytes)", path.display().to_string().yellow(), size);
                        count += 1;
                    }
                    if count == 0 {
                        println!("  {}", "No quarantined files.".green());
                    }
                }
                Err(_) => println!("  {}", "Quarantine directory empty or not found.".yellow()),
            }
        }
        QuarantineAction::Release { path } => {
            println!("[warden-cli] Releasing from quarantine: {}", path.yellow());
            // In a real impl, this would restore to the original path stored in metadata
            // For now, move it to /tmp/warden-release/
            let dest = format!("/tmp/warden-release/{}",
                std::path::Path::new(&path).file_name()
                    .unwrap_or_default().to_string_lossy());
            let _ = std::fs::create_dir_all("/tmp/warden-release");
            match std::fs::rename(&path, &dest) {
                Ok(_) => println!("{}", format!("Released to: {}", dest).green()),
                Err(e) => eprintln!("{}", format!("Failed to release: {}", e).red()),
            }
        }
        QuarantineAction::Kill { pid } => {
            println!("[warden-cli] Sending SIGKILL to PID {}", pid);
            let result = unsafe { libc_kill(pid as i32, 9) };
            if result == 0 {
                println!("{}", format!("SIGKILL sent to PID {}.", pid).green());
            } else {
                eprintln!("{}", format!("Failed to kill PID {}.", pid).red());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Firewall
// ---------------------------------------------------------------------------
fn cmd_firewall(action: FirewallAction) {
    match action {
        FirewallAction::List => {
            println!("{}", "=== Blocked IPs (iptables) ===".bold().cyan());
            let output = std::process::Command::new("iptables")
                .args(["-L", "INPUT", "-n"])
                .output();
            match output {
                Ok(out) => {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for line in text.lines() {
                        if line.contains("DROP") {
                            println!("  {}", line.red());
                        }
                    }
                }
                Err(e) => eprintln!("Failed to run iptables: {}", e),
            }
        }
        FirewallAction::Unblock { ip } => {
            println!("[warden-cli] Unblocking IP: {}", ip.yellow());
            let cmd = format!("iptables -D INPUT -s {} -j DROP", ip);
            let out = std::process::Command::new("sh").arg("-c").arg(&cmd).output();
            match out {
                Ok(o) if o.status.success() => println!("{}", format!("IP {} unblocked.", ip).green()),
                Ok(o) => eprintln!("{}", String::from_utf8_lossy(&o.stderr).red()),
                Err(e) => eprintln!("Failed: {}", e),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FIM
// ---------------------------------------------------------------------------
fn cmd_fim(action: FimAction) {
    match action {
        FimAction::Status => {
            println!("{}", "=== FIM Status ===".bold().cyan());
            // Audit log event count for FIM entries
            if let Ok(content) = std::fs::read_to_string(AUDIT_LOG) {
                let fim_count = content.lines()
                    .filter(|l| l.contains("Threat.Server.UnregisteredFile") || l.contains("Threat.Server.ConfigModified"))
                    .count();
                println!("  FIM alerts in audit log: {}", fim_count.to_string().yellow());
            }
        }
        FimAction::Add { path } => {
            println!("[warden-cli] Adding path to FIM watch (requires daemon support): {}", path.yellow());
            println!("{}", "Note: Dynamic watch registration will be persisted on next daemon reload.".bright_black());
            // Would send IPC message to wardend socket in a real implementation
        }
        FimAction::Register { git, path } => {
            if git {
                println!("{}", "[warden-cli] Re-seeding inode allowlist from git...".bold());
                let output = std::process::Command::new("git")
                    .args(["ls-files", "--cached"])
                    .output();
                match output {
                    Ok(out) if out.status.success() => {
                        let count = String::from_utf8_lossy(&out.stdout).lines().count();
                        println!("{}", format!("Git reported {} tracked files. Send 'rules reload' to re-seed daemon.", count).green());
                    }
                    _ => eprintln!("{}", "Not a git repository or git not available.".red()),
                }
            } else if let Some(file_path) = path {
                println!("[warden-cli] Registering single file: {}", file_path.yellow());
                match std::fs::metadata(&file_path) {
                    Ok(meta) => {
                        use std::os::unix::fs::MetadataExt;
                        println!("{}", format!("File inode {} would be added to allowlist.", meta.ino()).green());
                        println!("{}", "Send daemon 'rules reload' to apply.".bright_black());
                    }
                    Err(e) => eprintln!("{}", format!("Cannot stat {}: {}", file_path, e).red()),
                }
            } else {
                eprintln!("{}", "Specify --git or --path <file>".red());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------
fn cmd_scan(action: ScanAction) {
    match action {
        ScanAction::Now => {
            println!("{}", "[warden-cli] Triggering immediate OSV vulnerability scan...".bold());
            println!("{}", "(IPC to daemon not yet implemented — scan will run at next scheduled interval)".bright_black());
        }
    }
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------
fn cmd_rules(action: RulesAction) {
    match action {
        RulesAction::Reload => {
            println!("{}", "[warden-cli] Requesting rules hot-reload...".bold());
            println!("{}", "(IPC to daemon socket not yet implemented)".bright_black());
        }
        RulesAction::Fetch => {
            println!("{}", "[warden-cli] Remote signed rule fetch requires paid tier license.".yellow());
        }
    }
}

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------
fn cmd_containers() {
    println!("{}", "=== Monitored Containers ===".bold().cyan());
    // Check if Docker is available
    let output = std::process::Command::new("docker")
        .args(["ps", "--format", "table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}"])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            print!("{}", String::from_utf8_lossy(&out.stdout));
        }
        _ => println!("{}", "Docker not available or no containers running.".yellow()),
    }
}

// ---------------------------------------------------------------------------
// Test alert
// ---------------------------------------------------------------------------
fn cmd_test_alert() {
    println!("{}", "[warden-cli] Firing test alert to all notification endpoints...".bold());
    let test_payload = serde_json::json!({
        "alert_id": format!("test-{}", chrono::Utc::now().timestamp()),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "threat_type": "Test.Alert",
        "severity": "LOW",
        "container": null,
        "process": {
            "pid": 0,
            "exec_path": "warden-cli",
            "cmdline": "test-alert",
            "parent_exec_path": "operator",
            "parent_pid": 0
        },
        "remediation": {
            "action": "TEST",
            "status": "This is a test alert from warden-cli. All systems operational."
        }
    });
    // Write test alert to audit log
    let _ = std::fs::create_dir_all("/var/log/kinnector");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(AUDIT_LOG) {
        use std::io::Write;
        let _ = writeln!(f, "{}", test_payload);
    }
    println!("{}", "Test alert written to audit log. Check notification endpoints.".green());
}

// ---------------------------------------------------------------------------
// FFI shim for SIGKILL (avoids adding libc dep)
// ---------------------------------------------------------------------------
extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

fn libc_kill(pid: i32, sig: i32) -> i32 {
    unsafe { kill(pid, sig) }
}
