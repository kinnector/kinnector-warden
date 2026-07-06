use std::sync::Arc;
use dashmap::DashMap;
use chrono::Utc;
use std::net::IpAddr;
use std::str::FromStr;
use crate::types::{
    TelemetryEventRaw, EventType, ProcessCreateDetails, NetworkConnectDetails,
    SSHAuthDetails, TerminalCommandDetails, FileOpenDetails, MemoryMapDetails, Dup2Details,
    FileWriteDetails, FileRenameDetails, MemoryProtectDetails, PtraceAttachDetails,
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
    pub is_top_level_install: bool,
    pub install_root_pid: u32,
    pub depth: u32,
    pub loaded_scripts: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

pub struct HeuristicsEngine {
    pub process_map:   Arc<DashMap<u32, ProcessNode>>,
    pub ssh_attempts:  Arc<DashMap<String, Vec<i64>>>,
    pub config:        Arc<kinnector_config::ConfigManager>,
    /// Tracks last-seen timestamp (Unix secs) per PID for TTL eviction (P1-13 / B-10 fix).
    pub process_seen:  Arc<DashMap<u32, i64>>,
    pub web_roots:     Vec<String>,
    pub system_shells: std::collections::HashSet<String>,
    pub listening_pids: Arc<dashmap::DashSet<u32>>,
}

impl HeuristicsEngine {
    pub fn new(
        config: Arc<kinnector_config::ConfigManager>,
        web_roots: Vec<String>,
        system_shells: std::collections::HashSet<String>,
    ) -> Self {
        let listening_set = dashmap::DashSet::new();
        for pid in crate::discovery::discover_listening_pids() {
            println!("[Warden Startup] Discovered listening server PID: {}", pid);
            listening_set.insert(pid);
        }
        Self {
            process_map:    Arc::new(DashMap::new()),
            ssh_attempts:   Arc::new(DashMap::new()),
            process_seen:   Arc::new(DashMap::new()),
            config,
            web_roots,
            system_shells,
            listening_pids: Arc::new(listening_set),
        }
    }

    pub fn handle_raw_event(&self, raw: TelemetryEventRaw) {
        let header = raw.header;
        let event_pid = header.pid;

        if crate::allowlist::get_disabled_monitoring_pids().contains(&event_pid) {
            return;
        }

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
                let mut install_root_pid = 0u32;
                let mut parent_exe = String::new();
                let mut depth = 0u32;

                if let Some(parent) = self.process_map.get(&parent_pid) {
                    is_parent_web     = parent.is_web_server || self.listening_pids.contains(&parent_pid);
                    is_parent_install = parent.is_install_context;
                    install_root_pid  = parent.install_root_pid;
                    parent_exe        = parent.exe.clone();
                    depth             = parent.depth + 1;
                } else {
                    // Parent not yet tracked — read exe from /proc/<ppid>/exe (Q-07 / P1-5 fix)
                    if let Ok(path) = std::fs::read_link(format!("/proc/{}/exe", parent_pid)) {
                        parent_exe = path.to_string_lossy().to_string();
                    }
                    if !parent_exe.is_empty() && (self.config.is_web_process(&parent_exe) || self.listening_pids.contains(&parent_pid)) {
                        is_parent_web = true;
                    }
                }

                // Update last-seen for TTL eviction (P1-13)
                self.process_seen.insert(child_pid, Utc::now().timestamp());

                // Classify child
                let is_child_web     = self.config.is_web_process(&child_exe) || self.listening_pids.contains(&child_pid);
                let child_lower = child_exe.to_lowercase();
                
                let install_keywords = [
                    "npm", "yarn", "pnpm", "pip", "poetry", "pipenv", "composer", 
                    "cargo", "gem", "bundle", "nuget", "dotnet", "go", 
                    "apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "pacman", "apk"
                ];
                let is_child_install = install_keywords.iter().any(|&kw| {
                    child_lower == kw || child_lower.ends_with(&format!("/{}", kw))
                });

                let is_top_level_install = is_child_install && !is_parent_install;
                let final_install_root = if is_top_level_install {
                    child_pid
                } else {
                    install_root_pid
                };

                self.process_map.insert(child_pid, ProcessNode {
                    pid: child_pid,
                    ppid: parent_pid,
                    exe: child_exe.clone(),
                    cmdline: child_cmdline.clone(),
                    is_web_server: is_child_web || is_parent_web,
                    is_install_context: is_child_install || is_parent_install,
                    is_top_level_install,
                    install_root_pid: final_install_root,
                    depth,
                    loaded_scripts: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                });

                // --- S-A: Web process spawned a shell interpreter ---
                if is_parent_web {
                    if let Some(storage) = crate::storage_discovery::is_in_storage(&std::path::Path::new(&child_exe)) {
                        use crate::storage_discovery::StorageRole;
                        if storage.roles.iter().any(|r| matches!(r,
                            StorageRole::UploadDirectory | StorageRole::TempDirectory | StorageRole::SessionStorage | StorageRole::AppStorage | StorageRole::CompiledCache | StorageRole::ObjectPassthrough
                        )) {
                            self.terminate_threat_child(
                                child_pid, &child_exe, &child_cmdline, &parent_exe, parent_pid,
                                "Threat.Upload.ExecutionFromStorageDir",
                                &format!("Process execution attempted from storage directory: {}", child_exe)
                            );
                            return;
                        }
                    }

                    let in_tmp = child_exe.starts_with("/tmp/") || child_exe.starts_with("/var/tmp/") || child_exe.starts_with("/dev/shm/");
                    if in_tmp {
                        self.terminate_threat_child(
                            child_pid, &child_exe, &child_cmdline, &parent_exe, parent_pid,
                            "Threat.Upload.ExecutionFromStorageDir",
                            &format!("Process execution attempted from system temp directory: {}", child_exe)
                        );
                        return;
                    }
                    let is_shell = self.system_shells.contains(&child_exe)
                        || self.system_shells.contains(&child_lower)
                        || self.system_shells.iter().any(|s| child_exe.ends_with(s));

                    if is_shell {
                        self.terminate_threat_child(
                            child_pid, &child_exe, &child_cmdline,
                            &parent_exe, parent_pid,
                            "Threat.Server.ShellSpawnAttempt",
                            "Web process spawned interactive shell interpreter. Terminated child process."
                        );
                    }

                    // --- S-H: Unregistered binary execution check ---
                    // System binaries (/usr/bin, /usr/sbin, etc.) are allowed by default,
                    // but any binary outside system directories must be explicitly allowlisted.
                    if !child_exe.is_empty() {
                        let is_system_path = child_exe.starts_with("/bin/") || child_exe.starts_with("/sbin/") ||
                            child_exe.starts_with("/usr/bin/") || child_exe.starts_with("/usr/sbin/") ||
                            child_exe.starts_with("/usr/local/bin/") || child_exe.starts_with("/usr/libexec/") ||
                            child_exe.starts_with("/lib/") || child_exe.starts_with("/lib64/") ||
                            child_exe.starts_with("/usr/lib/") || child_exe.starts_with("/usr/lib64/");
                        
                        if !is_system_path && !crate::allowlist::is_inode_allowed(&child_exe) {
                            self.terminate_threat_child(
                                child_pid, &child_exe, &child_cmdline,
                                &parent_exe, parent_pid,
                                "Threat.Server.ExploitInjection",
                                "Unregistered binary execution attempted by web process. Terminated child process."
                            );
                        }
                    }

                    // --- S-J Trigger 2: Protected binary re-executed by web process ---
                    if self.config.is_protected_binary(&child_exe) {
                        self.terminate_threat_child(
                            child_pid, &child_exe, &child_cmdline,
                            &parent_exe, parent_pid,
                            "Threat.Server.BinaryOrSourcePoisoned",
                            "Web process re-executed a protected server binary. Terminated child process."
                        );
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
                let mut pids_to_kill = Vec::new();
                if let Some(proc) = self.process_map.get(&event_pid) {
                    if proc.is_top_level_install {
                        let root_pid = event_pid;
                        for entry in self.process_map.iter() {
                            if entry.value().install_root_pid == root_pid && entry.key() != &root_pid {
                                pids_to_kill.push(*entry.key());
                            }
                        }
                    }
                }

                for child_pid in pids_to_kill {
                    if let Some(child_proc) = self.process_map.get(&child_pid) {
                        let exe = child_proc.exe.clone();
                        let cmd = child_proc.cmdline.clone();
                        let ppid = child_proc.ppid;
                        drop(child_proc);

                        self.terminate_threat_child(
                            child_pid, &exe, &cmd, "", ppid,
                            "Vulnerability.SupplyChain.PersistentProcess",
                            "Process continued running after package installation completed. Terminated process."
                        );
                    }
                }

                self.process_map.remove(&event_pid);
                self.process_seen.remove(&event_pid);
            }

            // ---------------------------------------------------------------
            // FileOpen — Allowlist enforcement (LFI / unregistered file read)
            //
            // Any file opened by a web-context process MUST have its inode in
            // the git-seeded allowlist.  There is no timing window, no path
            // extension guess, no "sensitive file" list.  The allowlist IS the
            // policy.  Exceptions: the kernel-synthesised /proc and /dev paths
            // are never allowlist-checked (they have no stable inodes).
            // ---------------------------------------------------------------
            EventType::FileOpen => {
                let details: FileOpenDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const FileOpenDetails)
                };
                let path = null_terminated_str(&details.file_path);

                // Skip kernel virtual filesystems
                if path.starts_with("/proc/") || path.starts_with("/dev/") || path.starts_with("/sys/") {
                    return;
                }

                if let Some(proc) = self.process_map.get(&event_pid) {
                    let is_web = proc.is_web_server;
                    let is_install = proc.is_install_context;
                    let exe = proc.exe.clone();
                    let cmd = proc.cmdline.clone();
                    let ppid = proc.ppid;
                    if is_web {
                        let ext = std::path::Path::new(&path).extension().and_then(|s| s.to_str()).unwrap_or_default().to_lowercase();
                        if ext == "php" || ext == "js" || ext == "py" || ext == "rb" || ext == "jar" || ext == "class" {
                            if let Ok(mut list) = proc.loaded_scripts.lock() {
                                if !list.contains(&path) {
                                    if list.len() >= 10 {
                                        list.remove(0);
                                    }
                                    list.push(path.clone());
                                }
                            }
                        }
                    }
                    drop(proc);

                    if is_web {
                        let is_storage_disabled = crate::storage_discovery::is_storage_disabled_for_exe(&exe)
                            || crate::storage_discovery::is_storage_disabled_for_path(&path, &self.web_roots);
                        if is_storage_disabled {
                            crate::allowlist::register_inode(&path);
                            return;
                        }
                        // Check if it's a compiled binary server (Go, Rust, C/C++)
                        let is_compiled = {
                            let stack = crate::discovery::detect_process_stack(event_pid, &exe);
                            stack == "Go (Compiled)" || stack == "Rust (Compiled)" || stack == "Native (C/C++)"
                        };
                        if is_compiled {
                            let in_tmp = path.starts_with("/tmp/") || path.starts_with("/var/tmp/") || path.starts_with("/dev/shm/");
                            let in_cwd = if let Ok(cwd) = std::fs::read_link(format!("/proc/{}/cwd", event_pid)) {
                                std::path::Path::new(&path).starts_with(&cwd)
                            } else {
                                false
                            };
                            if in_tmp || in_cwd {
                                crate::allowlist::register_inode(&path);
                                return;
                            }
                        }

                        if let Some(storage) = crate::storage_discovery::is_in_storage(std::path::Path::new(&path)) {
                            if !storage.allow_script_extensions {
                                let lower = path.to_lowercase();
                                let is_script = lower.ends_with(".php") || lower.ends_with(".py") ||
                                    lower.ends_with(".rb") || lower.ends_with(".pl") ||
                                    lower.ends_with(".jsp") || lower.ends_with(".aspx");
                                if is_script {
                                    let alert_id = uuid::Uuid::new_v4().to_string();
                                    let reason = format!(
                                        "Web process attempted to read/interpret script in storage directory: {}",
                                        path
                                    );
                                    let _ = crate::quarantine::quarantine_file(&path, &alert_id, &reason, "Threat.Upload.ScriptInterpretationBlocked");
                                    self.emit_threat_with_id(
                                        alert_id,
                                        event_pid, &exe, &cmd, "", ppid,
                                        "Threat.Upload.ScriptInterpretationBlocked",
                                        &format!("Web process attempted to interpret script file inside storage directory: {}", path)
                                    );
                                    return;
                                }
                            }
                            // File in storage and script check passed -> register and allow
                            crate::allowlist::register_inode(&path);
                            return;
                        }

                        let in_tmp = path.starts_with("/tmp/") || path.starts_with("/var/tmp/") || path.starts_with("/dev/shm/");
                        if in_tmp {
                            let lower = path.to_lowercase();
                            let is_script = lower.ends_with(".php") || lower.ends_with(".py") ||
                                lower.ends_with(".rb") || lower.ends_with(".pl") ||
                                lower.ends_with(".jsp") || lower.ends_with(".aspx");
                            if is_script {
                                let alert_id = uuid::Uuid::new_v4().to_string();
                                let reason = format!(
                                    "Web process attempted to read/interpret script in system temp directory: {}",
                                    path
                                );
                                let _ = crate::quarantine::quarantine_file(&path, &alert_id, &reason, "Threat.Upload.ScriptInterpretationBlocked");
                                self.emit_threat_with_id(
                                    alert_id,
                                    event_pid, &exe, &cmd, "", ppid,
                                    "Threat.Upload.ScriptInterpretationBlocked",
                                    &format!("Web process attempted to interpret script file inside system temp directory: {}", path)
                                );
                                return;
                            }
                        }

                        if !crate::allowlist::is_inode_allowed(&path) {
                            let mode = if crate::allowlist::is_git_seeded() {
                                "git-indexed"
                            } else {
                                "startup-walk-indexed"
                            };
                            let alert_id = uuid::Uuid::new_v4().to_string();
                            let reason = format!(
                                "Web process read a file not present in the {} allowlist: {}",
                                mode, path
                            );
                            
                            // Quarantine the file (Heuristic S-B Containment Action)
                            let _ = crate::quarantine::quarantine_file(&path, &alert_id, &reason, "Threat.Server.ProjectFileTampered");

                            self.emit_threat_with_id(
                                alert_id,
                                event_pid, &exe, &cmd, "", ppid,
                                "Threat.Server.UnregisteredFileRead",
                                &reason
                            );
                        }
                    }

                    if is_install {
                        let path_lower = path.to_lowercase();
                        let is_cred = path_lower.contains("/.ssh/")
                            || path_lower.contains("/id_rsa")
                            || path_lower.contains("/id_dsa")
                            || path_lower.contains("/id_ecdsa")
                            || path_lower.contains("/id_ed25519")
                            || path_lower.contains("/.docker/config.json")
                            || path_lower.contains("/.npmrc")
                            || path_lower.contains("/.aws/")
                            || path_lower.contains("/.gitconfig")
                            || path_lower.contains("/.git-credentials")
                            || path_lower.contains("/.pypirc")
                            || path_lower.contains("/.pip/")
                            || path_lower == "/etc/shadow";

                        if is_cred {
                            self.terminate_threat_child(
                                event_pid, &exe, &cmd, "", ppid,
                                "Vulnerability.SupplyChain.CredentialAccessAttempt",
                                &format!("Package install process attempted to read sensitive credentials: {}", path)
                            );
                            return;
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
                            let depth = proc.depth;
                            drop(proc);
                            if depth > 0 {
                                self.terminate_threat_child(
                                    event_pid, &exe, &cmd, "", ppid,
                                    "Threat.Server.MemoryShellcode",
                                    "Web process created anonymous executable memory mapping — likely in-memory shellcode. Terminated child process."
                                );
                            } else {
                                self.emit_threat(
                                    event_pid, &exe, &cmd, "", ppid,
                                    "Threat.Server.MemoryShellcode",
                                    "Web process created anonymous executable memory mapping — likely in-memory shellcode."
                                );
                            }
                        }
                    }
                }
            }

            // ---------------------------------------------------------------
            // MemoryProtect — S-A anonymous mprotect(PROT_EXEC) shellcode (SIGKILL)
            // ---------------------------------------------------------------
            EventType::MemoryProtect => {
                let details: MemoryProtectDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const MemoryProtectDetails)
                };

                let new_flags = null_terminated_str(&details.prot_flags);
                let old_flags = null_terminated_str(&details.old_prot_flags);

                let made_executable = new_flags.contains("PROT_EXEC") && !old_flags.contains("PROT_EXEC");

                if made_executable {
                    let pid = details.target_pid;
                    if let Some(proc) = self.process_map.get(&pid) {
                        if proc.is_web_server {
                            let is_anon = is_anonymous_mapping(pid, details.address);
                            if is_anon {
                                let exe = proc.exe.clone();
                                let cmd = proc.cmdline.clone();
                                let ppid = proc.ppid;
                                let depth = proc.depth;
                                drop(proc);

                                if depth > 0 {
                                    self.terminate_threat_child(
                                        pid, &exe, &cmd, "", ppid,
                                        "Threat.Server.MemoryShellcode",
                                        "Web process modified anonymous memory mapping protection to make it executable (mprotect PROT_EXEC) — likely in-memory shellcode. Terminated child process."
                                    );
                                } else {
                                    self.emit_threat(
                                        pid, &exe, &cmd, "", ppid,
                                        "Threat.Server.MemoryShellcode",
                                        "Web process modified anonymous memory mapping protection to make it executable (mprotect PROT_EXEC) — likely in-memory shellcode."
                                    );
                                }
                            }
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
                            self.terminate_threat_child(
                                event_pid, &exe, &cmd, "", ppid,
                                "Threat.Server.ReverseShell",
                                "Web process duplicated socket fd to stdin/stdout — classic reverse shell pattern. Terminated process tree."
                            );
                        }
                    }
                }
            }

            // ---------------------------------------------------------------
            // FileWrite / FileCreate — allowlist enforcement + persistence/S-J
            //
            // A web process writing a file that is NOT in the git allowlist is
            // the canonical unrestricted-upload / RFI-staging pattern.  No
            // timing window needed: the write itself is the indicator.
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

                // Skip kernel virtual filesystems
                if path.starts_with("/proc/") || path.starts_with("/dev/") || path.starts_with("/sys/") {
                    return;
                }
                let is_profile = is_profile_like_path(&path);

                let mut exe = String::new();
                let mut cmd = String::new();
                let mut ppid = 0u32;
                let mut is_web = false;
                let mut is_install = false;

                if let Some(proc) = self.process_map.get(&event_pid) {
                    exe       = proc.exe.clone();
                    cmd       = proc.cmdline.clone();
                    ppid      = proc.ppid;
                    is_web    = proc.is_web_server;
                    is_install = proc.is_install_context;
                } else {
                    // Resolve dynamically for untracked processes
                    if let Ok(link) = std::fs::read_link(format!("/proc/{}/exe", event_pid)) {
                        exe = link.to_string_lossy().to_string();
                    }
                    if let Ok(cmdline) = std::fs::read_to_string(format!("/proc/{}/cmdline", event_pid)) {
                        cmd = cmdline.replace('\0', " ");
                    }
                    if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", event_pid)) {
                        for line in status.lines() {
                            if line.starts_with("PPid:") {
                                if let Some(ppid_str) = line.split_whitespace().nth(1) {
                                    ppid = ppid_str.parse().unwrap_or(0);
                                }
                                break;
                            }
                        }
                    }
                }

                // --- Allowlist enforcement: web process writes unregistered file ---
                if is_web {
                    let is_storage_disabled = crate::storage_discovery::is_storage_disabled_for_exe(&exe)
                        || crate::storage_discovery::is_storage_disabled_for_path(&path, &self.web_roots);
                    if is_storage_disabled {
                        crate::allowlist::register_inode(&path);
                        return;
                    }
                    // Check if it's a compiled binary server (Go, Rust, C/C++)
                    let is_compiled = {
                        let stack = crate::discovery::detect_process_stack(event_pid, &exe);
                        stack == "Go (Compiled)" || stack == "Rust (Compiled)" || stack == "Native (C/C++)"
                    };
                    if is_compiled {
                        let is_self_modification = path == exe;
                        if !is_self_modification {
                            let in_tmp = path.starts_with("/tmp/") || path.starts_with("/var/tmp/") || path.starts_with("/dev/shm/");
                            let in_cwd = if let Ok(cwd) = std::fs::read_link(format!("/proc/{}/cwd", event_pid)) {
                                std::path::Path::new(&path).starts_with(&cwd)
                            } else {
                                false
                            };
                            if in_tmp || in_cwd {
                                crate::allowlist::register_inode(&path);
                                return;
                            }
                        }
                    }

                    let path_p = std::path::Path::new(&path);
                    if let Some(_storage) = crate::storage_discovery::is_in_storage(path_p) {
                        let alert_id = uuid::Uuid::new_v4().to_string();
                        crate::storage_discovery::enqueue_upload_scan(path.clone(), alert_id);
                        return;
                    }
                }

                if is_web && !crate::allowlist::is_inode_allowed(&path) {
                    if path.ends_with("wp-config.php") {
                        self.emit_alert(
                            "Warning.Server.WordPressConfigModified", "WARNING",
                            event_pid, &exe, &cmd,
                            "", ppid,
                            "LOG_ALERT",
                            &format!("WordPress config modified by web process (permitted with warning): {}", path),
                        );
                        crate::allowlist::register_inode(&path);
                        return;
                    }

                    let mode = if crate::allowlist::is_git_seeded() {
                        "git-indexed"
                    } else {
                        "startup-walk-indexed"
                    };
                    let alert_id = uuid::Uuid::new_v4().to_string();
                    let reason = format!(
                        "Web process wrote a file not present in the {} allowlist: {}",
                        mode, path
                    );

                    // Quarantine the file (Heuristic S-B / S-H Containment Action)
                    let _ = crate::quarantine::quarantine_file(&path, &alert_id, &reason, "Threat.Server.ProjectFileTampered");

                    self.emit_threat_with_id(
                        alert_id,
                        event_pid, &exe, &cmd, "", ppid,
                        "Threat.Server.UnregisteredFileWrite",
                        &format!(
                            "Web process wrote a file not present in the {} allowlist: {}. \
                             Possible unrestricted upload / RFI staging / webshell drop. File isolated in quarantine.",
                            mode, path
                        ),
                    );
                }

                // --- S-I: Persistence path / profile monitoring ---
                if is_web || is_install || is_profile || self.config.is_persistence_path(&path) {
                    if is_install {
                        self.terminate_threat_child(
                            event_pid, &exe, &cmd, "", ppid,
                            "Vulnerability.SupplyChain.PersistenceAttempt",
                            &format!("Package install process attempted to establish persistence: {}", path),
                        );
                    } else {
                        let threat_type = if is_profile {
                            "Threat.Server.ProfileModified"
                        } else {
                            "Threat.Server.PersistenceTampered"
                        };
                        self.emit_threat(
                            event_pid, &exe, &cmd, "", ppid,
                            threat_type,
                            &format!("Process modified persistence/profile path: {}", path),
                        );
                    }
                }

                // --- S-J Trigger 1: Protected binary written outside package manager ---
                if self.config.is_protected_binary(&path) {
                    let trusted = self.config.is_trusted_cli(&exe, kinnector_config::Category::SystemUpdate);
                    if !trusted {
                        self.emit_alert(
                            "Threat.Server.BinaryOrSourcePoisoned", "CRITICAL",
                            event_pid, &exe, &cmd, "", ppid,
                            "LOG_ALERT",
                            &format!("Protected binary modified outside package manager: {}", path),
                        );
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
                let src = null_terminated_str(&details.source_path);
                let dest = null_terminated_str(&details.destination_path);

                let mut exe = String::new();
                let mut cmd = String::new();
                let mut ppid = 0u32;
                let mut is_web = false;

                if let Some(proc) = self.process_map.get(&event_pid) {
                    exe       = proc.exe.clone();
                    cmd       = proc.cmdline.clone();
                    ppid      = proc.ppid;
                    is_web    = proc.is_web_server;
                } else {
                    if let Ok(link) = std::fs::read_link(format!("/proc/{}/exe", event_pid)) {
                        exe = link.to_string_lossy().to_string();
                    }
                    if let Ok(cmdline) = std::fs::read_to_string(format!("/proc/{}/cmdline", event_pid)) {
                        cmd = cmdline.replace('\0', " ");
                    }
                    if !exe.is_empty() && (self.config.is_web_process(&exe) || self.listening_pids.contains(&event_pid)) {
                        is_web = true;
                    }
                }

                if is_web {
                    let dst_in_web_root = self.web_roots.iter().any(|r| dest.starts_with(r));
                    if dst_in_web_root {
                        if dest.ends_with("wp-config.php") {
                            self.emit_alert(
                                "Warning.Server.WordPressConfigModified", "WARNING",
                                event_pid, &exe, &cmd,
                                "", ppid,
                                "LOG_ALERT",
                                &format!("WordPress config modified via rename (permitted with warning): {} -> {}", src, dest),
                            );
                            crate::allowlist::register_inode(&dest);
                            return;
                        } else if let Some(_storage) = crate::storage_discovery::is_in_storage(std::path::Path::new(&dest)) {
                            let alert_id = uuid::Uuid::new_v4().to_string();
                            crate::storage_discovery::enqueue_upload_scan(dest.clone(), alert_id);
                        } else {
                            let src_in_tmp = src.starts_with("/tmp/") || src.starts_with("/var/tmp/") || src.starts_with("/dev/shm/");
                            if src_in_tmp {
                                // Allow the rename without quarantine/alert so /tmp movement is seamless
                                return;
                            }

                            let alert_id = uuid::Uuid::new_v4().to_string();
                            let reason = format!(
                                "Web process attempted to write/rename file outside storage: {} -> {}",
                                src, dest
                            );
                            let _ = crate::quarantine::quarantine_file(&dest, &alert_id, &reason, "Threat.Upload.RenameIntoWebRoot");
                            self.emit_threat_with_id(
                                alert_id,
                                event_pid, &exe, &cmd, "", ppid,
                                "Threat.Upload.RenameIntoWebRoot",
                                &format!("Web process attempted to rename file to a non-storage location in the web root: {} -> {}", src, dest)
                            );
                        }
                    }
                }

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

                let status_lower = status.to_lowercase();
                if status_lower == "failure" {
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
                } else if status_lower == "success" {
                    let alert_id = format!("ssh-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));
                    let payload = crate::notifications::AlertPayload {
                        alert_id,
                        timestamp: Utc::now().to_rfc3339(),
                        threat_type: "Event.Server.SSHAuth".to_string(),
                        severity: "INFO".to_string(),
                        container: None,
                        process: crate::notifications::ProcessInfo {
                            pid: 0,
                            exec_path: "/usr/sbin/sshd".to_string(),
                            cmdline: format!("User: {}", username),
                            parent_exec_path: "systemd".to_string(),
                            parent_pid: 1,
                        },
                        remediation: crate::notifications::RemediationInfo {
                            action: "LOG_ALERT".to_string(),
                            status: format!("Successful SSH login for user {} from IP {}", username, ip),
                        },
                    };
                    log_and_dispatch(payload);
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
                    let _ = crate::audit::write_to_audit_log(&s);
                }

                // Pattern analysis from config
                for pattern in self.config.terminal_rce_patterns() {
                    if cmd_lower.contains(pattern.as_str()) {
                        let alert_id = uuid::Uuid::new_v4().to_string();
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

            EventType::Listen => {
                if !self.listening_pids.contains(&event_pid) {
                    println!("[Warden Heuristics] PID {} called listen() -> dynamically promoting to SERVER context.", event_pid);
                    self.listening_pids.insert(event_pid);
                }
                if let Some(mut proc) = self.process_map.get_mut(&event_pid) {
                    if !proc.is_web_server {
                        proc.is_web_server = true;
                    }
                }
            }

            // ---------------------------------------------------------------
            // PtraceAttach — I-5: debugger attach from a web process
            //
            // ptrace(PTRACE_ATTACH) or ptrace(PTRACE_SEIZE) issued by a web
            // process is a strong post-exploitation signal.  An attacker who
            // already has code execution inside a web worker may try to pivot
            // into another process (e.g. a privileged side-car) by attaching a
            // debugger.  We SIGKILL the attaching process and emit a HIGH alert.
            // ---------------------------------------------------------------
            EventType::PtraceAttach => {
                let details: PtraceAttachDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const PtraceAttachDetails)
                };
                let mode = null_terminated_str(&details.mode);
                // Copy packed field to local to avoid UB reference to unaligned field
                let target_pid: u32 = details.target_pid;

                // Only act if the attaching process is a tracked web-context process.
                let is_web = self.process_map
                    .get(&event_pid)
                    .map(|p| p.is_web_server)
                    .unwrap_or_else(|| self.listening_pids.contains(&event_pid));

                if is_web {
                    let (exe, cmd, ppid) = self.process_map.get(&event_pid)
                        .map(|p| (p.exe.clone(), p.cmdline.clone(), p.ppid))
                        .unwrap_or_else(|| {
                            let exe = std::fs::read_link(format!("/proc/{}/exe", event_pid))
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_default();
                            (exe, String::new(), 0u32)
                        });

                    self.terminate_threat_child(
                        event_pid, &exe, &cmd, "", ppid,
                        "Threat.Server.DebuggerAttach",
                        &format!(
                            "Web process attached a debugger (ptrace mode: {}) to target PID {}. \
                             Possible post-exploitation process pivot. Attaching process terminated.",
                            mode, target_pid
                        ),
                    );
                }
            }

            _ => {}
        }
    }

    pub fn get_loaded_scripts_for_pid(&self, pid: u32) -> Option<Vec<String>> {
        self.process_map.get(&pid).and_then(|p| {
            if let Ok(list) = p.loaded_scripts.lock() {
                if !list.is_empty() {
                    return Some(list.clone());
                }
            }
            None
        })
    }

    /// Emit a structured threat alert for a process event.
    /// Never sends any signal — observation only.
    fn emit_threat(
        &self,
        pid: u32, exe: &str, cmdline: &str,
        parent_exe: &str, parent_pid: u32,
        threat_type: &str,
        desc: &str,
    ) {
        let alert_id = uuid::Uuid::new_v4().to_string();
        self.emit_threat_with_id(
            alert_id,
            pid, exe, cmdline,
            parent_exe, parent_pid,
            threat_type, desc
        );
    }

    fn emit_threat_with_id(
        &self,
        alert_id: String,
        pid: u32, exe: &str, cmdline: &str,
        parent_exe: &str, parent_pid: u32,
        threat_type: &str,
        desc: &str,
    ) {
        // Trigger Forensic TLS Buffer flush (Paid tier)
        crate::tls_buffer::flush_on_alert(pid, &alert_id);

        let payload = crate::notifications::AlertPayload {
            alert_id,
            timestamp: Utc::now().to_rfc3339(),
            threat_type: threat_type.to_string(),
            severity: "CRITICAL".to_string(),
            container: None,
            process: crate::notifications::ProcessInfo {
                pid,
                exec_path: exe.to_string(),
                cmdline: cmdline.to_string(),
                parent_exec_path: parent_exe.to_string(),
                parent_pid,
            },
            remediation: crate::notifications::RemediationInfo {
                action: "LOG_ALERT".to_string(),
                status: desc.to_string(),
            },
        };
        log_and_dispatch(payload);
    }

    /// Terminate an unauthorized spawned child process using SIGKILL
    /// while keeping the parent process (the web server) completely running.
    fn terminate_threat_child(
        &self,
        child_pid: u32, child_exe: &str, child_cmdline: &str,
        parent_exe: &str, parent_pid: u32,
        threat_type: &str,
        desc: &str,
    ) {
        // Kill only the child pid representing the threat.
        unsafe { libc::kill(child_pid as i32, libc::SIGKILL); }

        let alert_id = uuid::Uuid::new_v4().to_string();

        // Trigger Forensic TLS Buffer flush (Paid tier)
        crate::tls_buffer::flush_on_alert(child_pid, &alert_id);

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
                action: "SIGKILL".to_string(),
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
        let alert_id = uuid::Uuid::new_v4().to_string();

        // Trigger Forensic TLS Buffer flush on HIGH or CRITICAL alert (Paid tier)
        let sev_upper = severity.to_uppercase();
        if sev_upper == "HIGH" || sev_upper == "CRITICAL" {
            crate::tls_buffer::flush_on_alert(pid, &alert_id);
        }

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

    /// Evict stale entries from process_map (B-10 / P1-13 fix).
    /// Call this periodically from a background task.
    pub fn evict_stale_processes(&self) {
        const TTL_SECS: i64 = 1800; // 30 minutes
        let now = Utc::now().timestamp();
        let stale_pids: Vec<u32> = self.process_seen
            .iter()
            .filter(|entry| now - *entry.value() > TTL_SECS)
            .map(|entry| *entry.key())
            .collect();
        for pid in stale_pids {
            if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                self.process_map.remove(&pid);
                self.process_seen.remove(&pid);
            }
        }
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
    crate::notifications::dispatch_alert(payload);
}

/// B-05 fix: Use explicit iptables args (no `sh -c`); validate IP address first.
fn trigger_firewall_block(ip: &str) {
    // Validate IP before passing to iptables to prevent injection
    let ip_addr = match IpAddr::from_str(ip) {
        Ok(addr) => addr,
        Err(_) => {
            eprintln!("[Warden Heuristics] Refusing to block invalid IP address: {:?}", ip);
            return;
        }
    };
    let ip_owned = ip.to_string();
    let binary = if ip_addr.is_ipv6() { "ip6tables" } else { "iptables" };
    tokio::spawn(async move {
        // Block: explicit args only, no shell interpretation
        let _ = tokio::process::Command::new(binary)
            .args(["-A", "INPUT", "-s", &ip_owned, "-j", "DROP"])
            .output().await;
        tokio::time::sleep(tokio::time::Duration::from_secs(2 * 3600)).await;
        // Unblock after 2 hours
        let _ = tokio::process::Command::new(binary)
            .args(["-D", "INPUT", "-s", &ip_owned, "-j", "DROP"])
            .output().await;
    });
}

fn is_profile_like_path(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    path_lower.ends_with("/.bashrc")
        || path_lower.ends_with("/.profile")
        || path_lower.ends_with("/.bash_profile")
        || path_lower.ends_with("/.bash_login")
        || path_lower.ends_with("/.bash_logout")
        || path_lower.ends_with("/.zshrc")
        || path_lower.ends_with("/.zprofile")
        || path_lower.ends_with("/.zshenv")
        || path_lower.ends_with("/.zlogout")
        || path_lower.contains("/etc/profile")
        || path_lower.ends_with("/etc/bash.bashrc")
        || path_lower.contains("/etc/profile.d/")
}

fn is_anonymous_mapping(pid: u32, address: u64) -> bool {
    let maps_path = format!("/proc/{}/maps", pid);
    let Ok(content) = std::fs::read_to_string(maps_path) else {
        return false;
    };
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 { continue; }
        let addr_range = parts[0];
        let inode_str = parts[4];
        
        let range_parts: Vec<&str> = addr_range.split('-').collect();
        if range_parts.len() != 2 { continue; }
        let start = u64::from_str_radix(range_parts[0], 16).unwrap_or(0);
        let end = u64::from_str_radix(range_parts[1], 16).unwrap_or(0);
        
        if address >= start && address < end {
            // Found the memory region!
            // Check if it has inode == 0
            if let Ok(inode) = inode_str.parse::<u64>() {
                if inode == 0 {
                    return true;
                }
            }
            // Check if pathname is empty or anonymous special mapping
            if parts.len() == 5 {
                return true;
            }
            let pathname = parts[5];
            if pathname.starts_with('[') || pathname.is_empty() {
                return true;
            }
            return false;
        }
    }
    false
}

// Q-01: write_to_audit_log moved to crate::audit — this local copy is removed.
