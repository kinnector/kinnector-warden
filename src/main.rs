use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use nix::unistd::{getuid, getgid, getgroups, Group};

#[derive(Parser, Debug)]
#[command(name = "kinnector-warden")]
#[command(about = "Setuid-root privilege separator helper for Kinnector EDR client commands", long_about = None)]
struct Args {
    #[arg(short, long, default_value = "/var/run/kinnector/control.sock", help = "Path to agent control socket")]
    socket: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "Check daemon status")]
    Status,
    #[command(about = "List active tracked processes and their containment status")]
    Ps,
    #[command(about = "Release containment on a suspended process tree")]
    Release {
        #[arg(help = "Root PID of the suspended process tree to release")]
        pid: u32,
    },
    #[command(about = "Grant a temporary trust bypass to a process")]
    TrustOnce {
        #[arg(help = "PID to trust")]
        pid: u32,
    },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", content = "payload")]
enum CliRequest {
    Status,
    ReloadRules,
    ReleaseContainment { pid: u32 },
    ListProcesses,
    ListRules,
    TrustOnce { pid: u32 },
    Subscribe,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "status", content = "payload")]
enum CliResponse {
    Success(serde_json::Value),
    Error(String),
}

fn check_permission() -> Result<(), String> {
    let ruid = getuid();
    let rgid = getgid();

    // If caller is root, allow it automatically
    if ruid.is_root() {
        return Ok(());
    }

    // Resolve the GID of "kinnector" group
    let target_group = Group::from_name("kinnector")
        .map_err(|e| format!("Failed to look up group 'kinnector': {}", e))?
        .ok_or_else(|| "Group 'kinnector' does not exist on this system. Run installation configuration.".to_string())?;

    let kinnector_gid = target_group.gid;

    // Check if process real GID matches kinnector group GID
    if rgid == kinnector_gid {
        return Ok(());
    }

    // Check supplementary groups of the real user
    let groups = getgroups()
        .map_err(|e| format!("Failed to read user supplementary groups: {}", e))?;

    if groups.contains(&kinnector_gid) {
        return Ok(());
    }

    Err("Permission denied: Executing user must be root or a member of the 'kinnector' group.".to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Enforce GID authorization checks
    if let Err(err) = check_permission() {
        eprintln!("{}", err);
        std::process::exit(1);
    }

    let args = Args::parse();

    // 2. Map command to request
    let req = match args.command {
        Commands::Status => CliRequest::Status,
        Commands::Ps => CliRequest::ListProcesses,
        Commands::Release { pid } => CliRequest::ReleaseContainment { pid },
        Commands::TrustOnce { pid } => CliRequest::TrustOnce { pid },
    };

    // 3. Connect to agent control socket (requires root effective UID, which setuid provides)
    let socket_path = Path::new(&args.socket);
    if !socket_path.exists() {
        eprintln!("Error: Control socket not found at {}. Is the EDR daemon running?", args.socket);
        std::process::exit(1);
    }

    let mut stream = UnixStream::connect(socket_path).await?;
    let req_bytes = serde_json::to_vec(&req)?;
    stream.write_all(&req_bytes).await?;
    stream.shutdown().await?;

    let mut resp_bytes = Vec::new();
    stream.read_to_end(&mut resp_bytes).await?;

    let resp: CliResponse = serde_json::from_slice(&resp_bytes)?;
    match resp {
        CliResponse::Success(val) => {
            match req {
                CliRequest::Status => {
                    println!("EDR Agent: Active");
                    if let Some(rules_ver) = val.get("rules_version") {
                        println!("Rules Database Version: {}", rules_ver);
                    }
                    if let Some(lsm_active) = val.get("lsm_active") {
                        println!("BPF LSM Active: {}", lsm_active);
                    }
                    if let Some(proc_count) = val.get("active_processes") {
                        println!("Tracked Processes: {}", proc_count);
                    }
                }
                CliRequest::ListProcesses => {
                    if let Some(processes) = val.get("processes").and_then(|v| v.as_array()) {
                        println!("{:<8} | {:<8} | {:<12} | {:<20} | {}", "PID", "PPID", "Status", "Process Name", "Command Line");
                        println!("{}", "-".repeat(100));
                        for p in processes {
                            let pid = p.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
                            let ppid = p.get("ppid").and_then(|v| v.as_u64()).unwrap_or(0);
                            let exe = p.get("exe").and_then(|v| v.as_str()).unwrap_or("");
                            let cmdline = p.get("cmdline").and_then(|v| v.as_str()).unwrap_or("");
                            let contained = p.get("contained").and_then(|v| v.as_bool()).unwrap_or(false);
                            
                            let status = if contained {
                                "\x1b[1;31mCONTAINED\x1b[0m"
                            } else {
                                "\x1b[1;32mTRACKING\x1b[0m"
                            };

                            let file_name = Path::new(exe).file_name().and_then(|f| f.to_str()).unwrap_or(exe);
                            println!("{:<8} | {:<8} | {:<12} | {:<20} | {}", pid, ppid, status, file_name, cmdline);
                        }
                    }
                }
                CliRequest::ReleaseContainment { pid } => {
                    if let Some(msg) = val.get("message") {
                        println!("Success: {}", msg.as_str().unwrap_or(""));
                    } else {
                        println!("Success: Containment released for PID {}", pid);
                    }
                }
                CliRequest::TrustOnce { pid } => {
                    if let Some(msg) = val.get("message") {
                        println!("Success: {}", msg.as_str().unwrap_or(""));
                    } else {
                        println!("Success: Process PID {} trusted successfully", pid);
                    }
                }
                _ => {}
            }
        }
        CliResponse::Error(err) => {
            eprintln!("Error: {}", err);
            std::process::exit(1);
        }
    }

    Ok(())
}
