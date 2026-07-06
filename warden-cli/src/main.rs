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
//!   warden-cli fim remove <path>
//!   warden-cli fim register --git
//!   warden-cli fim register --path <file>
//!   warden-cli allowlist add <path>
//!   warden-cli allowlist remove <path>
//!   warden-cli scan now
//!   warden-cli rules reload
//!   warden-cli rules fetch
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

    /// Inode allowlist management
    Allowlist {
        #[command(subcommand)]
        action: AllowlistAction,
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
    /// Dynamically remove a path from FIM watch list
    Remove {
        /// Path to stop watching
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
enum AllowlistAction {
    /// Recursively register a path and its inodes into the allowlist
    Add {
        /// Path to register
        path: String,
    },
    /// Recursively remove a path and its inodes from the allowlist
    Remove {
        /// Path to deregister
        path: String,
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
        Commands::Allowlist { action } => cmd_allowlist(action),
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
    
    // Query UDS status
    match query_daemon("GET", "/api/v1/status", None) {
        Ok(status) => {
            let pid_file = "/var/run/kinnector/wardend.pid";
            let pid = std::fs::read_to_string(pid_file).unwrap_or_else(|_| "?".to_string());
            println!("  Daemon PID   : {}", pid.trim().green());
            println!("  Status       : {}", "RUNNING".green().bold());
            println!("  Version      : {}", status.get("version").and_then(|v| v.as_str()).unwrap_or("0.1.0").green());
            println!("  LSM Mode     : {}", if status.get("lsm_active").and_then(|l| l.as_bool()).unwrap_or(false) { "LSM-active".green() } else { "Tracepoint-fallback".yellow() });
            println!("  Uptime (s)   : {}", status.get("uptime_secs").and_then(|u| u.as_u64()).unwrap_or(0).to_string().cyan());
            if let Some(roots) = status.get("web_roots").and_then(|r| r.as_array()) {
                let root_paths: Vec<&str> = roots.iter().flat_map(|r| r.as_str()).collect();
                println!("  Web Roots    : {:?}", root_paths);
            }
        }
        Err(e) => {
            println!("  Status       : {}", "NOT RUNNING".red().bold());
            println!("  Error        : {}", e.red());
        }
    }

    // Config version
    let config_path = "/etc/kinnector/rules.db";
    if std::path::Path::new(config_path).exists() {
        println!("  Config       : {}", config_path.yellow());
    } else {
        println!("  Config       : {} (using defaults)", "NOT FOUND".yellow());
    }

    // Audit log size
    if let Ok(meta) = std::fs::metadata(AUDIT_LOG) {
        let size_kb = meta.len() / 1024;
        println!("  Audit log    : {} ({} KB)", AUDIT_LOG.yellow(), size_kb);
    }
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------
fn cmd_alerts(follow: bool, severity_filter: Option<String>, lines: usize) {
    let sev = severity_filter.as_deref().map(|s| s.to_uppercase());

    if follow {
        println!("{}", "[warden-cli] Streaming alerts (Ctrl-C to stop)...".bold());
        use std::io::{BufRead, BufReader, Seek, SeekFrom};
        let file = match std::fs::File::open(AUDIT_LOG) {
            Ok(f) => f,
            Err(_) => {
                eprintln!("[warden-cli] Audit log not found: {}", AUDIT_LOG);
                return;
            }
        };
        let mut reader = BufReader::new(file);
        let _ = reader.seek(SeekFrom::End(0));
        loop {
            std::thread::sleep(std::time::Duration::from_millis(250));
            let mut line = String::new();
            while let Ok(n) = reader.read_line(&mut line) {
                if n == 0 { break; }
                print_alert_line(line.trim(), &sev);
                line.clear();
            }
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
            match query_daemon("GET", "/api/v1/quarantine", None) {
                Ok(res) => {
                    if let Some(files) = res.get("quarantined_files").and_then(|f| f.as_array()) {
                        if files.is_empty() {
                            println!("  {}", "No quarantined files.".green());
                        } else {
                            for f in files {
                                let q_path = f.get("quarantine_path").and_then(|p| p.as_str()).unwrap_or("");
                                let o_path = f.get("original_path").and_then(|p| p.as_str()).unwrap_or("unknown");
                                let reason = f.get("reason").and_then(|r| r.as_str()).unwrap_or("unknown");
                                println!("  {} -> {}\n    Reason: {}", q_path.yellow(), o_path.green(), reason.bright_black());
                            }
                        }
                    }
                }
                Err(e) => eprintln!("Failed to query quarantine list: {}", e.red()),
            }
        }
        QuarantineAction::Release { path } => {
            println!("[warden-cli] Releasing from quarantine: {}", path.yellow());
            
            // Look up original path from the quarantine list
            let mut original_path = String::new();
            if let Ok(res) = query_daemon("GET", "/api/v1/quarantine", None) {
                if let Some(files) = res.get("quarantined_files").and_then(|f| f.as_array()) {
                    for f in files {
                        let qp = f.get("quarantine_path").and_then(|p| p.as_str()).unwrap_or("");
                        if qp == path {
                            original_path = f.get("original_path").and_then(|o| o.as_str()).unwrap_or("").to_string();
                            break;
                        }
                    }
                }
            }

            if original_path.is_empty() {
                eprintln!("{}", "Error: original path metadata not found for this quarantined file.".red());
                return;
            }

            let body = serde_json::json!({
                "quarantine_path": path,
                "original_path": original_path
            });

            match query_daemon("POST", "/api/v1/quarantine/restore", Some(&body)) {
                Ok(_) => println!("{}", format!("Successfully restored quarantined file back to: {}", original_path).green()),
                Err(e) => eprintln!("{}", format!("Failed to restore file: {}", e).red()),
            }
        }
        QuarantineAction::Kill { pid } => {
            println!("[warden-cli] Sending SIGKILL to PID {}", pid);
            let result = unsafe { kill(pid as i32, 9) };
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
            println!("{}", "=== Blocked IPv4 IPs (iptables) ===".bold().cyan());
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

            println!("{}", "=== Blocked IPv6 IPs (ip6tables) ===".bold().cyan());
            let output6 = std::process::Command::new("ip6tables")
                .args(["-L", "INPUT", "-n"])
                .output();
            match output6 {
                Ok(out) => {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for line in text.lines() {
                        if line.contains("DROP") {
                            println!("  {}", line.red());
                        }
                    }
                }
                Err(e) => eprintln!("Failed to run ip6tables: {}", e),
            }
        }
        FirewallAction::Unblock { ip } => {
            println!("[warden-cli] Unblocking IP: {}", ip.yellow());
            use std::str::FromStr;
            let binary = if let Ok(ip_addr) = std::net::IpAddr::from_str(&ip) {
                if ip_addr.is_ipv6() { "ip6tables" } else { "iptables" }
            } else {
                "iptables"
            };
            let out = std::process::Command::new(binary)
                .args(["-D", "INPUT", "-s", &ip, "-j", "DROP"])
                .output();
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
            if let Ok(content) = std::fs::read_to_string(AUDIT_LOG) {
                let fim_count = content.lines()
                    .filter(|l| l.contains("Threat.Server.UnregisteredFile") || l.contains("Threat.Server.ConfigModified"))
                    .count();
                println!("  FIM alerts in audit log: {}", fim_count.to_string().yellow());
            }
        }
        FimAction::Add { path } => {
            println!("[warden-cli] Adding path to FIM watch dynamically: {}", path.yellow());
            let body = serde_json::json!({ "path": path });
            match query_daemon("POST", "/api/v1/fim/add", Some(&body)) {
                Ok(_) => println!("{}", "Dynamic FIM watch registered successfully in daemon.".green()),
                Err(e) => eprintln!("Failed to add FIM path: {}", e.red()),
            }
        }
        FimAction::Remove { path } => {
            println!("[warden-cli] Removing path from FIM watch: {}", path.yellow());
            let body = serde_json::json!({ "path": path });
            match query_daemon("POST", "/api/v1/fim/remove", Some(&body)) {
                Ok(_) => println!("{}", "FIM watch path removed successfully.".green()),
                Err(e) => eprintln!("Failed to remove FIM path: {}", e.red()),
            }
        }
        FimAction::Register { git, path } => {
            let body = if git {
                serde_json::json!({ "git": true })
            } else if let Some(file_path) = path {
                serde_json::json!({ "path": file_path })
            } else {
                eprintln!("{}", "Specify --git or --path <file>".red());
                return;
            };

            println!("{}", "[warden-cli] Requesting inode allowlist registration...".bold());
            match query_daemon("POST", "/api/v1/fim/register", Some(&body)) {
                Ok(res) => {
                    let status = res.get("status").and_then(|s| s.as_str()).unwrap_or("done");
                    println!("{}", format!("Allowlist updated successfully: {}", status).green());
                }
                Err(e) => eprintln!("Failed to register allowlist: {}", e.red()),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------
fn cmd_allowlist(action: AllowlistAction) {
    match action {
        AllowlistAction::Add { path } => {
            println!("[warden-cli] Registering path in allowlist: {}", path.yellow());
            let body = serde_json::json!({ "path": path });
            match query_daemon("POST", "/api/v1/allowlist/add", Some(&body)) {
                Ok(res) => {
                    let status = res.get("status").and_then(|s| s.as_str()).unwrap_or("registered");
                    println!("{}", format!("Allowlist updated: {} ({})", path, status).green());
                }
                Err(e) => eprintln!("Failed to add to allowlist: {}", e.red()),
            }
        }
        AllowlistAction::Remove { path } => {
            println!("[warden-cli] Removing path from allowlist: {}", path.yellow());
            let body = serde_json::json!({ "path": path });
            match query_daemon("POST", "/api/v1/allowlist/remove", Some(&body)) {
                Ok(res) => {
                    let status = res.get("status").and_then(|s| s.as_str()).unwrap_or("deregistered");
                    println!("{}", format!("Allowlist updated: {} ({})", path, status).green());
                }
                Err(e) => eprintln!("Failed to remove from allowlist: {}", e.red()),
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
            match query_daemon("POST", "/api/v1/scan/trigger", None) {
                Ok(_) => println!("{}", "Daemon vulnerability scan triggered.".green()),
                Err(e) => eprintln!("Failed to trigger scan: {}", e.red()),
            }
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
            match query_daemon("POST", "/api/v1/rules/reload", None) {
                Ok(_) => println!("{}", "Rules hot-reloaded successfully.".green()),
                Err(e) => eprintln!("Failed to reload rules: {}", e.red()),
            }
        }
        RulesAction::Fetch => {
            println!("{}", "[warden-cli] Requesting remote rule sync...".bold());
            match query_daemon("POST", "/api/v1/rules/fetch", None) {
                Ok(_) => println!("{}", "Remote rules fetch triggered successfully.".green()),
                Err(e) => {
                    if e.contains("402") {
                        eprintln!("{}", "Error: Remote signed rule fetch requires paid tier license.".red());
                    } else {
                        eprintln!("Failed to fetch rules: {}", e.red());
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------
fn cmd_containers() {
    println!("{}", "=== Monitored Containers ===".bold().cyan());
    match query_daemon("GET", "/api/v1/containers", None) {
        Ok(serde_json::Value::Array(list)) => {
            if list.is_empty() {
                println!("{}", "  No containers currently monitored.".yellow());
                return;
            }
            println!("{:<12} {:<20} {:<25} {:<30}", "CONTAINER ID", "NAME", "IMAGE", "MONITORED MOUNTS");
            for item in list {
                let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let short_id = if id.len() > 12 { &id[..12] } else { id };
                let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let image = item.get("image").and_then(|v| v.as_str()).unwrap_or("");

                let mut mounts = Vec::new();
                if let Some(roots) = item.get("web_roots").and_then(|v| v.as_array()) {
                    for r in roots {
                        if let Some(s) = r.as_str() {
                            mounts.push(format!("web:{}", s));
                        }
                    }
                }
                if let Some(configs) = item.get("config_dirs").and_then(|v| v.as_array()) {
                    for c in configs {
                        if let Some(s) = c.as_str() {
                            mounts.push(format!("cfg:{}", s));
                        }
                    }
                }
                let mounts_str = mounts.join(", ");
                println!("{:<12} {:<20} {:<25} {:<30}", short_id, name, image, mounts_str);
            }
        }
        _ => eprintln!("{}", "Failed to query containers endpoint on daemon.".red()),
    }
}

// ---------------------------------------------------------------------------
// Test alert
// ---------------------------------------------------------------------------
fn cmd_test_alert() {
    println!("{}", "[warden-cli] Firing test alert to all notification endpoints...".bold());
    match query_daemon("POST", "/api/v1/test-alert", None) {
        Ok(res) => {
            let alert_id = res.get("alert_id").and_then(|id| id.as_str()).unwrap_or("unknown");
            println!("{}", format!("Test alert successfully triggered via API (ID: {}).", alert_id).green());
            println!("Check Slack, Discord, Telegram, custom webhooks, and local audit logs.");
        }
        Err(e) => {
            eprintln!("Failed to fire test alert: {}", e.red());
        }
    }
}

// ---------------------------------------------------------------------------
// IPC client helper using UDS HTTP-over-Unix socket (Phase 7)
// ---------------------------------------------------------------------------
fn query_daemon(
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Result<serde_json::Value, String> {
    use std::os::unix::net::UnixStream;
    use std::io::{Write, Read};

    let mut stream = UnixStream::connect("/var/run/kinnector/warden.sock")
        .map_err(|e| format!("Failed to connect to daemon socket: {}. Is wardend running?", e))?;

    let body_str = body.map(|b| b.to_string()).unwrap_or_default();
    let req = if body_str.is_empty() {
        format!("{} {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", method, path)
    } else {
        format!(
            "{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            method, path, body_str.len(), body_str
        )
    };

    stream.write_all(req.as_bytes())
        .map_err(|e| format!("Failed to write to daemon socket: {}", e))?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)
        .map_err(|e| format!("Failed to read from daemon socket: {}", e))?;

    let res_str = String::from_utf8_lossy(&response);
    let body_part = res_str.split("\r\n\r\n").nth(1)
        .ok_or_else(|| "Malformed HTTP response from daemon".to_string())?;

    serde_json::from_str(body_part)
        .map_err(|e| format!("Failed to parse JSON response: {}. Body: {}", e, body_part))
}

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}
