use std::sync::Arc;
use dashmap::DashMap;
use std::collections::{HashSet, HashMap};
use chrono::Utc;
use std::path::Path;
use tokio::net::UnixStream;
use tokio::io::AsyncReadExt;
use crate::types::{TelemetryEventRaw, EventType, ProcessCreateDetails, NetworkConnectDetails, SSHAuthDetails, TerminalCommandDetails};

#[derive(Clone, Debug)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub exe: String,
    pub cmdline: String,
    pub is_web_server: bool,
    pub is_install_context: bool,
    pub depth: u32,
}

pub struct HeuristicsEngine {
    pub process_map: Arc<DashMap<u32, ProcessNode>>,
    pub ssh_attempts: Arc<DashMap<String, Vec<i64>>>, // IP -> timestamps
}

impl HeuristicsEngine {
    pub fn new() -> Self {
        Self {
            process_map: Arc::new(DashMap::new()),
            ssh_attempts: Arc::new(DashMap::new()),
        }
    }

    pub fn handle_raw_event(&self, raw: TelemetryEventRaw) {
        let header = raw.header;
        let event_pid = header.pid;
        match header.event_type {
            EventType::ProcessCreate => {
                let details: ProcessCreateDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const ProcessCreateDetails)
                };

                let child_pid = details.child_pid;
                let parent_pid = details.real_parent_pid;
                
                let child_exe = crate::heuristics::null_terminated_str(&details.child_image_path);
                let child_cmdline = crate::heuristics::null_terminated_str(&details.child_command_line);

                let mut is_parent_web = false;
                let mut is_parent_install = false;
                let mut parent_exe = String::new();
                let mut depth = 0;

                if let Some(parent) = self.process_map.get(&parent_pid) {
                    is_parent_web = parent.is_web_server;
                    is_parent_install = parent.is_install_context;
                    parent_exe = parent.exe.clone();
                    depth = parent.depth + 1;
                } else {
                    // Try to guess from exe name if parent not tracked
                    let parent_lower = parent_exe.to_lowercase();
                    if parent_lower.contains("nginx") || parent_lower.contains("apache") || parent_lower.contains("httpd") || parent_lower.contains("caddy") || parent_lower.contains("php-fpm") || parent_lower.contains("node") || parent_lower.contains("python") {
                        is_parent_web = true;
                    }
                }

                let child_lower = child_exe.to_lowercase();
                let is_child_web = child_lower.contains("nginx") || child_lower.contains("apache2") || child_lower.contains("httpd") || child_lower.contains("caddy") || child_lower.contains("php-fpm");
                let is_child_install = child_lower.contains("npm") || child_lower.contains("pip") || child_lower.contains("cargo") || child_lower.contains("gem") || child_lower.contains("composer");

                let node = ProcessNode {
                    pid: child_pid,
                    ppid: parent_pid,
                    exe: child_exe.clone(),
                    cmdline: child_cmdline.clone(),
                    is_web_server: is_child_web || is_parent_web,
                    is_install_context: is_child_install || is_parent_install,
                    depth,
                };

                self.process_map.insert(child_pid, node);

                // --- Heuristic S-A: Web-Server Shell Spawn Restriction ---
                if is_parent_web {
                    let shell_interpreters = ["/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/ash", "sh", "bash", "dash"];
                    let mut is_shell = false;
                    for sh in &shell_interpreters {
                        if child_exe.ends_with(sh) || child_lower == **sh {
                            is_shell = true;
                            break;
                        }
                    }

                    if is_shell {
                        self.execute_containment(child_pid, &child_exe, &child_cmdline, &parent_exe, parent_pid, "Threat.Server.ShellSpawnAttempt", "SIGKILL", "Blocked web server spawning interactive command interpreter shell.");
                    }
                }

                // --- Heuristic S-J: Binary Hijacking / Package Manager Source Poisoning ---
                if is_parent_install && depth >= 2 {
                    // Suspicious deep execution under installation context
                    // Often indicates a preinstall/postinstall execution of hidden malware
                    // We generate an alert
                    let alert_id = format!("wpn-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));
                    let payload = crate::notifications::AlertPayload {
                        alert_id,
                        timestamp: Utc::now().to_rfc3339(),
                        threat_type: "Threat.Server.BinaryOrSourcePoisoned".to_string(),
                        severity: "HIGH".to_string(),
                        container: None,
                        process: crate::notifications::ProcessInfo {
                            pid: child_pid,
                            exec_path: child_exe,
                            cmdline: child_cmdline,
                            parent_exec_path: parent_exe,
                            parent_pid,
                        },
                        remediation: crate::notifications::RemediationInfo {
                            action: "AUDIT_WARNING".to_string(),
                            status: format!("Deep child subprocess (depth {}) running under install context: potential supply chain poisoning.", depth),
                        },
                    };
                    if let Ok(json_str) = serde_json::to_string(&payload) {
                        let _ = write_to_audit_log(&json_str);
                    }
                    crate::notifications::dispatch_alert(payload);
                }
            }
            EventType::ProcessStop => {
                // Clear from map
                self.process_map.remove(&event_pid);
            }
            EventType::NetworkConnect => {
                let details: NetworkConnectDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const NetworkConnectDetails)
                };

                let dest_ip = crate::heuristics::null_terminated_str(&details.destination_ip);
                let dest_port = details.destination_port;

                let mut proc_exe = String::new();
                let mut proc_cmd = String::new();
                let mut p_exe = String::new();
                let mut p_pid = 0;
                let mut is_web = false;
                let mut is_install = false;
                let mut depth = 0;

                if let Some(p) = self.process_map.get(&event_pid) {
                    proc_exe = p.exe.clone();
                    proc_cmd = p.cmdline.clone();
                    p_pid = p.ppid;
                    is_web = p.is_web_server;
                    is_install = p.is_install_context;
                    depth = p.depth;
                    if let Some(parent) = self.process_map.get(&p_pid) {
                        p_exe = parent.exe.clone();
                    }
                }

                // --- Heuristic S-J: Out-of-Registry Network Access (InstallContext) ---
                if is_install && depth >= 2 {
                    // Check if dest_ip is outside registry ranges
                    // In a simplified EDR we alert on outbound socket connections in pre/postinstall scripts
                    let alert_id = format!("wpn-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));
                    let payload = crate::notifications::AlertPayload {
                        alert_id,
                        timestamp: Utc::now().to_rfc3339(),
                        threat_type: "Threat.Server.BinaryOrSourcePoisoned".to_string(),
                        severity: "HIGH".to_string(),
                        container: None,
                        process: crate::notifications::ProcessInfo {
                            pid: header.pid,
                            exec_path: proc_exe.clone(),
                            cmdline: proc_cmd.clone(),
                            parent_exec_path: p_exe.clone(),
                            parent_pid: p_pid,
                        },
                        remediation: crate::notifications::RemediationInfo {
                            action: "AUDIT_WARNING".to_string(),
                            status: format!("InstallContext process initiated outbound connection to {}:{}", dest_ip, dest_port),
                        },
                    };
                    if let Ok(json_str) = serde_json::to_string(&payload) {
                        let _ = write_to_audit_log(&json_str);
                    }
                    crate::notifications::dispatch_alert(payload);
                }
            }
            EventType::SSHAuth => {
                let details: SSHAuthDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const SSHAuthDetails)
                };

                let username = crate::heuristics::null_terminated_str(&details.username);
                let ip = crate::heuristics::null_terminated_str(&details.source_ip);
                let status = crate::heuristics::null_terminated_str(&details.status);

                if status.to_lowercase() == "failure" {
                    let now = Utc::now().timestamp();
                    let mut attempts = self.ssh_attempts.entry(ip.clone()).or_insert_with(Vec::new);
                    attempts.push(now);
                    // Retain only last 60 seconds
                    attempts.retain(|&t| now - t < 60);

                    if attempts.len() > 5 {
                        // SSH brute force detected!
                        let alert_id = format!("ssh-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));
                        let payload = crate::notifications::AlertPayload {
                            alert_id,
                            timestamp: Utc::now().to_rfc3339(),
                            threat_type: "Event.Server.SSHAuth (BruteForce)".to_string(),
                            severity: "HIGH".to_string(),
                            container: None,
                            process: crate::notifications::ProcessInfo {
                                pid: 0,
                                exec_path: "/usr/sbin/sshd".to_string(),
                                cmdline: format!("Target user: {}", username),
                                parent_exec_path: "systemd".to_string(),
                                parent_pid: 1,
                            },
                            remediation: crate::notifications::RemediationInfo {
                                action: "FIREWALL_BLOCK".to_string(),
                                status: format!("IP {} blocked temporarily due to excessive SSH auth failures ({} failures in 60s)", ip, attempts.len()),
                            },
                        };

                        if let Ok(json_str) = serde_json::to_string(&payload) {
                            let _ = write_to_audit_log(&json_str);
                        }
                        crate::notifications::dispatch_alert(payload);

                        // Trigger firewall mitigation
                        trigger_firewall_block(&ip);
                    }
                }
            }
            EventType::TerminalCommand => {
                let details: TerminalCommandDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const TerminalCommandDetails)
                };

                let tty = crate::heuristics::null_terminated_str(&details.tty_device);
                let cmd = crate::heuristics::null_terminated_str(&details.command);

                // Log shell keystrokes directly to audit trail
                let log_entry = serde_json::json!({
                    "ts": Utc::now().to_rfc3339(),
                    "event": "TerminalCommand",
                    "pid": event_pid,
                    "tty": tty,
                    "command": cmd
                });
                if let Ok(json_str) = serde_json::to_string(&log_entry) {
                    let _ = write_to_audit_log(&json_str);
                }
            }
            _ => {}
        }
    }

    fn execute_containment(&self, child_pid: u32, child_exe: &str, child_cmdline: &str, parent_exe: &str, parent_pid: u32, threat_type: &str, action: &str, desc: &str) {
        // Run SIGKILL or SIGSTOP containment
        if action == "SIGKILL" {
            unsafe {
                libc::kill(child_pid as i32, libc::SIGKILL);
            }
        } else if action == "SIGSTOP" {
            unsafe {
                libc::kill(child_pid as i32, libc::SIGSTOP);
            }
        }

        let alert_id = format!("cnt-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));
        let payload = crate::notifications::AlertPayload {
            alert_id,
            timestamp: Utc::now().to_rfc3339(),
            threat_type: threat_type.to_string(),
            severity: "CRITICAL".to_string(),
            container: None,
            process: crate::notifications::ProcessInfo {
                pid: child_pid,
                exec_path: child_exe.to_string(),
                cmdline: child_cmdline.to_string(),
                parent_exec_path: parent_exe.to_string(),
                parent_pid,
            },
            remediation: crate::notifications::RemediationInfo {
                action: action.to_string(),
                status: format!("Remediation status: SUCCESSFUL. {}", desc),
            },
        };

        if let Ok(json_str) = serde_json::to_string(&payload) {
            let _ = write_to_audit_log(&json_str);
        }
        crate::notifications::dispatch_alert(payload);
    }
}

pub fn null_terminated_str(buf: &[u8]) -> String {
    let mut len = 0;
    while len < buf.len() && buf[len] != 0 {
        len += 1;
    }
    String::from_utf8_lossy(&buf[..len]).to_string()
}

fn trigger_firewall_block(ip: &str) {
    let ip_owned = ip.to_string();
    tokio::spawn(async move {
        // Run iptables rules command to block the IP for 2 hours
        let cmd = format!("iptables -A INPUT -s {} -j DROP", ip_owned);
        let _ = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .await;
            
        // Sleep for 2 hours
        tokio::time::sleep(tokio::time::Duration::from_secs(2 * 3600)).await;
        
        let remove_cmd = format!("iptables -D INPUT -s {} -j DROP", ip_owned);
        let _ = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&remove_cmd)
            .output()
            .await;
    });
}

fn write_to_audit_log(line: &str) -> std::io::Result<()> {
    let _ = std::fs::create_dir_all("/var/log/kinnector");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/log/kinnector/audit.log")?;
    use std::io::Write;
    writeln!(file, "{}", line)
}
