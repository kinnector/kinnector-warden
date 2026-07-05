use std::sync::Arc;
use dashmap::DashMap;
use chrono::Utc;
use crate::types::{
    TelemetryEventRaw, EventType, ProcessCreateDetails, NetworkConnectDetails,
    SSHAuthDetails, TerminalCommandDetails, FileOpenDetails, MemoryMapDetails, Dup2Details,
    FileWriteDetails, FileRenameDetails,
};

// PROT_EXEC flag for mmap/mprotect detection
const PROT_EXEC: u32 = 4;
// MAP_ANONYMOUS flag
const MAP_ANONYMOUS: u32 = 32;

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
    pub process_map:   Arc<DashMap<u32, ProcessNode>>,
    pub ssh_attempts:  Arc<DashMap<String, Vec<i64>>>,
    pub config:        Arc<kinnector_config::ConfigManager>,
}

impl HeuristicsEngine {
    pub fn new(config: Arc<kinnector_config::ConfigManager>) -> Self {
        Self {
            process_map:   Arc::new(DashMap::new()),
            ssh_attempts:  Arc::new(DashMap::new()),
            config,
        }
    }

    pub fn handle_raw_event(&self, raw: TelemetryEventRaw) {
        let header = raw.header;
        let event_pid = header.pid;

        match header.event_type {
            // ---------------------------------------------------------------
            // ProcessCreate — S-A shell spawn, S-H unregistered inode exec,
            //                  S-J supply-chain deep subprocess
            // ---------------------------------------------------------------
            EventType::ProcessCreate => {
                let details: ProcessCreateDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const ProcessCreateDetails)
                };

                let child_pid = details.child_pid;
                let parent_pid = details.real_parent_pid;
                let child_exe = null_terminated_str(&details.child_image_path);
                let child_cmdline = null_terminated_str(&details.child_command_line);

                let mut is_parent_web = false;
                let mut is_parent_install = false;
                let mut parent_exe = String::new();
                let mut depth = 0u32;

                if let Some(parent) = self.process_map.get(&parent_pid) {
                    is_parent_web     = parent.is_web_server;
                    is_parent_install = parent.is_install_context;
                    parent_exe        = parent.exe.clone();
                    depth             = parent.depth + 1;
                } else {
                    // Parent not yet tracked — guess from exe
                    if self.config.is_web_process(&parent_exe) {
                        is_parent_web = true;
                    }
                }

                // Classify child
                let is_child_web     = self.config.is_web_process(&child_exe);
                let child_lower = child_exe.to_lowercase();
                let is_child_install = child_lower.contains("npm")
                    || child_lower.contains("pip")
                    || child_lower.contains("cargo")
                    || child_lower.contains("gem")
                    || child_lower.contains("composer");

                self.process_map.insert(child_pid, ProcessNode {
                    pid: child_pid,
                    ppid: parent_pid,
                    exe: child_exe.clone(),
                    cmdline: child_cmdline.clone(),
                    is_web_server: is_child_web || is_parent_web,
                    is_install_context: is_child_install || is_parent_install,
                    depth,
                });

                // --- S-A: Web process spawns shell interpreter (SIGKILL) ---
                if is_parent_web {
                    let shell_names = ["/bin/sh", "/bin/bash", "/bin/dash",
                                      "/bin/zsh", "/bin/ash", "sh", "bash", "dash", "zsh"];
                    let is_shell = shell_names.iter().any(|s| {
                        child_exe.ends_with(s) || child_lower == *s
                    });

                    if is_shell {
                        self.execute_containment(
                            child_pid, &child_exe, &child_cmdline,
                            &parent_exe, parent_pid,
                            "Threat.Server.ShellSpawnAttempt", "SIGKILL",
                            "Web process spawned interactive shell interpreter."
                        );
                    }

                    // --- S-H: Unregistered inode exec (RFI / webshell) ---
                    if !child_exe.is_empty() {
                        if !crate::allowlist::is_inode_allowed(&child_exe) {
                            self.execute_containment(
                                child_pid, &child_exe, &child_cmdline,
                                &parent_exe, parent_pid,
                                "Threat.Server.ExploitInjection", "SIGKILL",
                                "Unregistered binary executed by web process — not in git/startup inode allowlist."
                            );
                        }
                    }

                    // --- S-J Trigger 2: Protected binary replacement trigger ---
                    if self.config.is_protected_binary(&child_exe) {
                        // Web process re-execing a protected binary — suspicious
                        self.emit_alert(
                            "Threat.Server.BinaryOrSourcePoisoned", "CRITICAL",
                            child_pid, &child_exe, &child_cmdline,
                            &parent_exe, parent_pid,
                            "SIGKILL",
                            "Web process re-executed a protected server binary.",
                        );
                        unsafe { libc::kill(child_pid as i32, libc::SIGKILL); }
                    }
                }

                // --- S-J: Deep install-context subprocess ---
                if is_parent_install && depth >= 2 {
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
                            status: format!("Deep subprocess (depth {}) in install context: potential supply chain poisoning.", depth),
                        },
                    };
                    log_and_dispatch(payload);
                }
            }

            // ---------------------------------------------------------------
            // ProcessStop — evict from map
            // ---------------------------------------------------------------
            EventType::ProcessStop => {
                self.process_map.remove(&event_pid);
            }

            // ---------------------------------------------------------------
            // FileOpen — S-B LFI: web process opens sensitive file (alert)
            // ---------------------------------------------------------------
            EventType::FileOpen => {
                let details: FileOpenDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const FileOpenDetails)
                };
                let path = null_terminated_str(&details.file_path);

                if let Some(proc) = self.process_map.get(&event_pid) {
                    if proc.is_web_server {
                        // Check against sensitive files from config
                        let sensitive = self.config.sensitive_files();
                        let is_sensitive = sensitive.contains_key(&path)
                            || path.starts_with("/etc/shadow")
                            || path.starts_with("/root/.ssh");

                        if is_sensitive {
                            let alert_id = format!("lfi-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));
                            let payload = crate::notifications::AlertPayload {
                                alert_id,
                                timestamp: Utc::now().to_rfc3339(),
                                threat_type: "Threat.Server.LFI".to_string(),
                                severity: "CRITICAL".to_string(),
                                container: None,
                                process: crate::notifications::ProcessInfo {
                                    pid: event_pid,
                                    exec_path: proc.exe.clone(),
                                    cmdline: proc.cmdline.clone(),
                                    parent_exec_path: String::new(),
                                    parent_pid: proc.ppid,
                                },
                                remediation: crate::notifications::RemediationInfo {
                                    action: "LOG_ALERT".to_string(),
                                    status: format!("Web process opened sensitive file: {}", path),
                                },
                            };
                            log_and_dispatch(payload);
                        }
                    }
                }
            }

            // ---------------------------------------------------------------
            // MemoryMap — S-A anonymous mmap(PROT_EXEC) shellcode (SIGKILL)
            // ---------------------------------------------------------------
            EventType::MemoryMap => {
                let details: MemoryMapDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const MemoryMapDetails)
                };

                let is_anon_exec = (details.prot_flags & PROT_EXEC) != 0
                    && (details.map_flags & MAP_ANONYMOUS) != 0
                    && details.fd == -1;

                if is_anon_exec {
                    if let Some(proc) = self.process_map.get(&event_pid) {
                        if proc.is_web_server {
                            let exe = proc.exe.clone();
                            let cmd = proc.cmdline.clone();
                            let ppid = proc.ppid;
                            drop(proc);
                            self.execute_containment(
                                event_pid, &exe, &cmd,
                                "", ppid,
                                "Threat.Server.MemoryShellcode", "SIGKILL",
                                "Web process created anonymous executable memory mapping — likely in-memory shellcode."
                            );
                        }
                    }
                }
            }

            // ---------------------------------------------------------------
            // Dup2 — S-G reverse shell: socket fd dup'd to stdin/stdout (SIGKILL)
            // ---------------------------------------------------------------
            EventType::Dup2 => {
                let details: Dup2Details = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const Dup2Details)
                };

                // old_fd_type == 2 means socket; new_fd == 0/1/2 = stdin/stdout/stderr
                let is_reverse_shell = details.old_fd_type == 2
                    && (details.new_fd == 0 || details.new_fd == 1 || details.new_fd == 2);

                if is_reverse_shell {
                    if let Some(proc) = self.process_map.get(&event_pid) {
                        if proc.is_web_server {
                            let exe = proc.exe.clone();
                            let cmd = proc.cmdline.clone();
                            let ppid = proc.ppid;
                            drop(proc);
                            self.execute_containment(
                                event_pid, &exe, &cmd,
                                "", ppid,
                                "Threat.Server.ReverseShell", "SIGKILL",
                                "Web process duplicated socket fd to stdin/stdout — classic reverse shell pattern."
                            );
                        }
                    }
                }
            }

            // ---------------------------------------------------------------
            // FileWrite / FileCreate — S-I persistence, S-J binary replacement
            // ---------------------------------------------------------------
            EventType::FileWrite | EventType::FileCreate => {
                let path = if header.event_type == EventType::FileWrite {
                    let d: FileWriteDetails = unsafe {
                        std::ptr::read(raw.details_buffer.as_ptr() as *const FileWriteDetails)
                    };
                    null_terminated_str(&d.file_path)
                } else {
                    let d: crate::types::FileCreateDetails = unsafe {
                        std::ptr::read(raw.details_buffer.as_ptr() as *const crate::types::FileCreateDetails)
                    };
                    null_terminated_str(&d.file_path)
                };

                if let Some(proc) = self.process_map.get(&event_pid) {
                    let exe = proc.exe.clone();
                    let cmd = proc.cmdline.clone();
                    let ppid = proc.ppid;
                    let is_web = proc.is_web_server;
                    let is_install = proc.is_install_context;
                    drop(proc);

                    // S-I: Persistence path monitoring — SIGSTOP + alert
                    if (is_web || is_install) && self.config.is_persistence_path(&path) {
                        self.execute_containment(
                            event_pid, &exe, &cmd,
                            "", ppid,
                            "Threat.Server.PersistenceTampered", "SIGSTOP",
                            &format!("Web/install process wrote to persistence path: {}", path),
                        );
                    }

                    // S-J Trigger 1: Protected binary written by non-package-manager
                    if self.config.is_protected_binary(&path) {
                        let trusted = self.config.is_trusted_cli(&exe, kinnector_config::Category::SystemUpdate);
                        if !trusted {
                            self.emit_alert(
                                "Threat.Server.BinaryOrSourcePoisoned", "CRITICAL",
                                event_pid, &exe, &cmd,
                                "", ppid,
                                "LOG_ALERT",
                                &format!("Protected binary modified outside package manager: {}", path),
                            );
                        }
                    }
                }
            }

            // ---------------------------------------------------------------
            // FileRename — S-J protected binary swap via rename
            // ---------------------------------------------------------------
            EventType::FileRename => {
                let details: FileRenameDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const FileRenameDetails)
                };
                let dest = null_terminated_str(&details.destination_path);

                if self.config.is_protected_binary(&dest) {
                    if let Some(proc) = self.process_map.get(&event_pid) {
                        let exe = proc.exe.clone();
                        let cmd = proc.cmdline.clone();
                        let ppid = proc.ppid;
                        let trusted = self.config.is_trusted_cli(&exe, kinnector_config::Category::SystemUpdate);
                        drop(proc);
                        if !trusted {
                            self.emit_alert(
                                "Threat.Server.BinaryOrSourcePoisoned", "CRITICAL",
                                event_pid, &exe, &cmd,
                                "", ppid,
                                "LOG_ALERT",
                                &format!("Protected binary replaced via rename to: {}", dest),
                            );
                        }
                    }
                }
            }

            // ---------------------------------------------------------------
            // NetworkConnect — S-J install-context outbound
            // ---------------------------------------------------------------
            EventType::NetworkConnect => {
                let details: NetworkConnectDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const NetworkConnectDetails)
                };
                let dest_ip = null_terminated_str(&details.destination_ip);
                let dest_port = details.destination_port;

                if let Some(proc) = self.process_map.get(&event_pid) {
                    if proc.is_install_context && proc.depth >= 2 {
                        let exe = proc.exe.clone();
                        let cmd = proc.cmdline.clone();
                        let ppid = proc.ppid;
                        drop(proc);

                        let alert_id = format!("wpn-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));
                        let payload = crate::notifications::AlertPayload {
                            alert_id,
                            timestamp: Utc::now().to_rfc3339(),
                            threat_type: "Threat.Server.BinaryOrSourcePoisoned".to_string(),
                            severity: "HIGH".to_string(),
                            container: None,
                            process: crate::notifications::ProcessInfo {
                                pid: event_pid,
                                exec_path: exe,
                                cmdline: cmd,
                                parent_exec_path: String::new(),
                                parent_pid: ppid,
                            },
                            remediation: crate::notifications::RemediationInfo {
                                action: "AUDIT_WARNING".to_string(),
                                status: format!("InstallContext process initiated outbound connection to {}:{}", dest_ip, dest_port),
                            },
                        };
                        log_and_dispatch(payload);
                    }
                }
            }

            // ---------------------------------------------------------------
            // SSHAuth — brute force detection + iptables block
            // ---------------------------------------------------------------
            EventType::SSHAuth => {
                let details: SSHAuthDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const SSHAuthDetails)
                };
                let username = null_terminated_str(&details.username);
                let ip = null_terminated_str(&details.source_ip);
                let status = null_terminated_str(&details.status);

                if status.to_lowercase() == "failure" {
                    let now = Utc::now().timestamp();
                    let mut attempts = self.ssh_attempts.entry(ip.clone()).or_insert_with(Vec::new);
                    attempts.push(now);
                    attempts.retain(|&t| now - t < 60);

                    if attempts.len() > 5 {
                        let len = attempts.len();
                        drop(attempts);

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
                                status: format!("IP {} blocked: {} SSH failures in 60s", ip, len),
                            },
                        };
                        log_and_dispatch(payload);
                        trigger_firewall_block(&ip);
                    }
                }
            }

            // ---------------------------------------------------------------
            // TerminalCommand — S-G: RCE pattern analysis + audit log
            // ---------------------------------------------------------------
            EventType::TerminalCommand => {
                let details: TerminalCommandDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const TerminalCommandDetails)
                };
                let tty = null_terminated_str(&details.tty_device);
                let cmd = null_terminated_str(&details.command);
                let cmd_lower = cmd.to_lowercase();

                // Always audit-log
                let log_entry = serde_json::json!({
                    "ts": Utc::now().to_rfc3339(),
                    "event": "TerminalCommand",
                    "pid": event_pid,
                    "tty": tty,
                    "command": cmd
                });
                if let Ok(s) = serde_json::to_string(&log_entry) {
                    let _ = write_to_audit_log(&s);
                }

                // Pattern analysis from config
                for pattern in self.config.terminal_rce_patterns() {
                    if cmd_lower.contains(pattern.as_str()) {
                        let alert_id = format!("tcmd-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));
                        let payload = crate::notifications::AlertPayload {
                            alert_id,
                            timestamp: Utc::now().to_rfc3339(),
                            threat_type: "Threat.Server.ShellSpawnAttempt".to_string(),
                            severity: "CRITICAL".to_string(),
                            container: None,
                            process: crate::notifications::ProcessInfo {
                                pid: event_pid,
                                exec_path: tty.clone(),
                                cmdline: cmd.clone(),
                                parent_exec_path: String::new(),
                                parent_pid: 0,
                            },
                            remediation: crate::notifications::RemediationInfo {
                                action: "LOG_ALERT".to_string(),
                                status: format!("Terminal command matched RCE pattern '{}': {}", pattern, cmd),
                            },
                        };
                        log_and_dispatch(payload);
                        break;
                    }
                }
            }

            _ => {}
        }
    }

    fn execute_containment(
        &self,
        child_pid: u32, child_exe: &str, child_cmdline: &str,
        parent_exe: &str, parent_pid: u32,
        threat_type: &str, action: &str, desc: &str
    ) {
        if action == "SIGKILL" {
            unsafe { libc::kill(child_pid as i32, libc::SIGKILL); }
        } else if action == "SIGSTOP" {
            unsafe { libc::kill(child_pid as i32, libc::SIGSTOP); }
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
                status: format!("Remediation: SUCCESSFUL. {}", desc),
            },
        };
        log_and_dispatch(payload);
    }

    fn emit_alert(
        &self,
        threat_type: &str, severity: &str,
        pid: u32, exe: &str, cmd: &str,
        parent_exe: &str, parent_pid: u32,
        action: &str, desc: &str,
    ) {
        let alert_id = format!("alt-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));
        let payload = crate::notifications::AlertPayload {
            alert_id,
            timestamp: Utc::now().to_rfc3339(),
            threat_type: threat_type.to_string(),
            severity: severity.to_string(),
            container: None,
            process: crate::notifications::ProcessInfo {
                pid,
                exec_path: exe.to_string(),
                cmdline: cmd.to_string(),
                parent_exec_path: parent_exe.to_string(),
                parent_pid,
            },
            remediation: crate::notifications::RemediationInfo {
                action: action.to_string(),
                status: desc.to_string(),
            },
        };
        log_and_dispatch(payload);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn null_terminated_str(buf: &[u8]) -> String {
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..len]).to_string()
}

fn log_and_dispatch(payload: crate::notifications::AlertPayload) {
    if let Ok(s) = serde_json::to_string(&payload) {
        let _ = write_to_audit_log(&s);
    }
    crate::notifications::dispatch_alert(payload);
}

fn trigger_firewall_block(ip: &str) {
    let ip_owned = ip.to_string();
    tokio::spawn(async move {
        let cmd = format!("iptables -A INPUT -s {} -j DROP", ip_owned);
        let _ = tokio::process::Command::new("sh").arg("-c").arg(&cmd).output().await;
        tokio::time::sleep(tokio::time::Duration::from_secs(2 * 3600)).await;
        let remove_cmd = format!("iptables -D INPUT -s {} -j DROP", ip_owned);
        let _ = tokio::process::Command::new("sh").arg("-c").arg(&remove_cmd).output().await;
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
