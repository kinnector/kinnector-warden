use dashmap::DashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use serde::{Serialize, Deserialize};

/// Fine-grained classification — one path may have multiple roles.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StorageRole {
    UploadDirectory,   // User-uploaded files — allow write, block exec, ELF scan
    SessionStorage,    // PHP sessions, cookie stores — allow write, block exec
    TempDirectory,     // Runtime scratch — PID-scoped inode tracking, block exec
    AppStorage,        // Framework-managed storage — allow write, block exec, no script interp
    CompiledCache,     // Compiled views / opcache output — allow write AND script interpretation
    ObjectPassthrough, // Streaming buffer to remote object store — allow write+delete, block exec
}

impl StorageRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            StorageRole::UploadDirectory => "UploadDirectory",
            StorageRole::SessionStorage => "SessionStorage",
            StorageRole::TempDirectory => "TempDirectory",
            StorageRole::AppStorage => "AppStorage",
            StorageRole::CompiledCache => "CompiledCache",
            StorageRole::ObjectPassthrough => "ObjectPassthrough",
        }
    }
}

/// How confidently was this path discovered?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryConfidence {
    High,     // From system config (php.ini, -Djava.io.tmpdir)
    Medium,   // From framework config file (settings.py, storage.yml)
    Low,      // From .gitignore + writable dir heuristic
    Inferred, // From eBPF behavioral signals only — requires operator review
}

impl DiscoveryConfidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            DiscoveryConfidence::High => "High",
            DiscoveryConfidence::Medium => "Medium",
            DiscoveryConfidence::Low => "Low",
            DiscoveryConfidence::Inferred => "Inferred",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoragePath {
    pub path: PathBuf,
    pub roles: Vec<StorageRole>,
    pub confidence: DiscoveryConfidence,
    pub discovered_via: Vec<String>,
    pub web_uid: u32,
    pub allow_script_extensions: bool,
    pub max_file_size_hint: Option<u64>,
}

/// Global thread-safe storage registry.
/// Key: canonical resolved PathBuf (symlinks resolved).
static STORAGE_REGISTRY: OnceLock<Arc<DashMap<PathBuf, StoragePath>>> = OnceLock::new();

pub fn get_registry() -> &'static Arc<DashMap<PathBuf, StoragePath>> {
    STORAGE_REGISTRY.get_or_init(|| Arc::new(DashMap::new()))
}

/// Register a path in the storage registry.
pub fn register(storage: StoragePath) {
    let registry = get_registry();
    let canonical = std::fs::canonicalize(&storage.path)
        .unwrap_or_else(|_| storage.path.clone());
    
    tracing::info!(
        "[Warden Storage] Registering path: {} as {:?} (Confidence: {:?}, Via: {:?})",
        canonical.display(),
        storage.roles,
        storage.confidence,
        storage.discovered_via
    );
    registry.insert(canonical, storage);
}

/// Remove a path from the storage registry.
pub fn remove(path: &Path) -> bool {
    let registry = get_registry();
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    registry.remove(&canonical).is_some()
}

/// Returns true if `file_path`'s parent chain contains a registered storage path.
/// Uses prefix matching.
pub fn is_in_storage(file_path: &Path) -> Option<StoragePath> {
    let registry = get_registry();
    let canonical_path = std::fs::canonicalize(file_path)
        .unwrap_or_else(|_| file_path.to_path_buf());

    for entry in registry.iter() {
        if canonical_path.starts_with(entry.key()) {
            return Some(entry.value().clone());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Discovery Pass Implementation
// ---------------------------------------------------------------------------

/// P1: Scan process environ and cmdline for storage/temp configuration.
pub fn scan_process_env_for_storage(pid: u32) -> Vec<StoragePath> {
    let mut paths = Vec::new();
    let environ_path = format!("/proc/{}/environ", pid);
    let environ = std::fs::read(environ_path).unwrap_or_default();

    // Split on NUL byte
    for var_bytes in environ.split(|&b| b == 0) {
        if var_bytes.is_empty() {
            continue;
        }
        let var_str = String::from_utf8_lossy(var_bytes);
        let Some((key, val)) = var_str.split_once('=') else { continue; };
        if val.is_empty() {
            continue;
        }

        let path = PathBuf::from(val);
        match key {
            "TMPDIR" | "TEMP" | "TMP" | "UPLOAD_TMP_DIR" |
            "FILE_UPLOAD_TEMP_DIR" | "ASPNETCORE_TEMP" => {
                paths.push(StoragePath {
                    path,
                    roles: vec![StorageRole::TempDirectory],
                    confidence: DiscoveryConfidence::High,
                    discovered_via: vec![format!("env:{}={}", key, val)],
                    web_uid: 0,
                    allow_script_extensions: false,
                    max_file_size_hint: None,
                });
            }
            "MEDIA_ROOT" | "UPLOAD_DIR" | "STORAGE_PATH" | "UPLOAD_FOLDER" => {
                paths.push(StoragePath {
                    path,
                    roles: vec![StorageRole::UploadDirectory],
                    confidence: DiscoveryConfidence::High,
                    discovered_via: vec![format!("env:{}={}", key, val)],
                    web_uid: 0,
                    allow_script_extensions: false,
                    max_file_size_hint: None,
                });
            }
            _ => {}
        }
    }

    // Scan cmdline for Java -D flags
    if let Ok(cmdline) = std::fs::read(format!("/proc/{}/cmdline", pid)) {
        for arg_bytes in cmdline.split(|&b| b == 0) {
            let arg = String::from_utf8_lossy(arg_bytes);
            if let Some(path) = arg.strip_prefix("-Djava.io.tmpdir=") {
                paths.push(StoragePath {
                    path: PathBuf::from(path),
                    roles: vec![StorageRole::TempDirectory],
                    confidence: DiscoveryConfidence::High,
                    discovered_via: vec![format!("cmdline:-Djava.io.tmpdir={}", path)],
                    web_uid: 0,
                    allow_script_extensions: false,
                    max_file_size_hint: None,
                });
            }
        }
    }

    paths
}

struct FrameworkRule {
    file_name: &'static str,
    key_regex: &'static str,
    role: StorageRole,
    confidence: DiscoveryConfidence,
}

const FRAMEWORK_RULES: &[FrameworkRule] = &[
    FrameworkRule { file_name: "php.ini", key_regex: r"upload_tmp_dir\s*=\s*(.+)", role: StorageRole::TempDirectory, confidence: DiscoveryConfidence::High },
    FrameworkRule { file_name: "php.ini", key_regex: r"session\.save_path\s*=\s*(.+)", role: StorageRole::SessionStorage, confidence: DiscoveryConfidence::High },
    FrameworkRule { file_name: ".user.ini", key_regex: r"upload_tmp_dir\s*=\s*(.+)", role: StorageRole::TempDirectory, confidence: DiscoveryConfidence::Medium },
    FrameworkRule { file_name: "settings.py", key_regex: r#"MEDIA_ROOT\s*=\s*['"]?([^'")\s]+)"#, role: StorageRole::UploadDirectory, confidence: DiscoveryConfidence::Medium },
    FrameworkRule { file_name: "settings.py", key_regex: r#"FILE_UPLOAD_TEMP_DIR\s*=\s*['"]([^'"]+)['"]"#, role: StorageRole::TempDirectory, confidence: DiscoveryConfidence::Medium },
    FrameworkRule { file_name: "config/filesystems.php", key_regex: r#"'root'\s*=>\s*['"]([^'"]+)['"]"#, role: StorageRole::AppStorage, confidence: DiscoveryConfidence::Medium },
    FrameworkRule { file_name: "config/storage.yml", key_regex: r#"root:\s*(.+)"#, role: StorageRole::AppStorage, confidence: DiscoveryConfidence::Medium },
    FrameworkRule { file_name: "application.properties", key_regex: r#"spring\.servlet\.multipart\.location=(.+)"#, role: StorageRole::TempDirectory, confidence: DiscoveryConfidence::High },
    FrameworkRule { file_name: "application.yml", key_regex: r#"location:\s*(.+)"#, role: StorageRole::TempDirectory, confidence: DiscoveryConfidence::Medium },
    FrameworkRule { file_name: "appsettings.json", key_regex: r#""UploadPath"\s*:\s*"([^"]+)""#, role: StorageRole::UploadDirectory, confidence: DiscoveryConfidence::Medium },
    FrameworkRule { file_name: ".js", key_regex: r#"multer\(\s*\{[^}]*dest:\s*['"]([^'"]+)['"]"#, role: StorageRole::UploadDirectory, confidence: DiscoveryConfidence::Medium },
    FrameworkRule { file_name: "initializers/carrierwave.rb", key_regex: r#"config\.root\s*=\s*(.+)"#, role: StorageRole::UploadDirectory, confidence: DiscoveryConfidence::Medium },
];

/// P2: Framework Configuration Parser
pub fn run_framework_rules(web_root: &str) -> Vec<StoragePath> {
    let mut paths = Vec::new();
    let root_path = Path::new(web_root);
    if !root_path.exists() {
        return paths;
    }

    // Scan /etc/php for php.ini
    if Path::new("/etc/php").exists() {
        walk_dir_for_rules(Path::new("/etc/php"), "php.ini", &mut paths);
    }

    // Scan web root for the other configuration rules
    for rule in FRAMEWORK_RULES {
        if rule.file_name == "php.ini" { continue; }
        walk_dir_for_rules(root_path, rule.file_name, &mut paths);
    }

    paths
}

fn walk_dir_for_rules(dir: &Path, file_name: &str, paths: &mut Vec<StoragePath>) {
    let mut cb = |path: &Path| {
        let Ok(content) = std::fs::read_to_string(path) else { return; };
        for rule in FRAMEWORK_RULES {
            if path.to_string_lossy().ends_with(rule.file_name) {
                if let Ok(re) = regex::Regex::new(rule.key_regex) {
                    for cap in re.captures_iter(&content) {
                        if let Some(val) = cap.get(1) {
                            let clean_val = val.as_str().trim_matches(|c| c == '\'' || c == '"' || c == ' ');
                            if !clean_val.is_empty() {
                                paths.push(StoragePath {
                                    path: PathBuf::from(clean_val),
                                    roles: vec![rule.role.clone()],
                                    confidence: rule.confidence.clone(),
                                    discovered_via: vec![format!("config_file:{}:{}", rule.file_name, clean_val)],
                                    web_uid: 0,
                                    allow_script_extensions: matches!(rule.role, StorageRole::CompiledCache),
                                    max_file_size_hint: None,
                                });
                            }
                        }
                    }
                }
            }
        }
    };
    walk_dir_recursive(dir, file_name, &mut cb);
}

fn walk_dir_recursive<F>(dir: &Path, file_suffix: &str, cb: &mut F)
where F: FnMut(&Path)
{
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                if name == "node_modules" || name == ".git" || name == "vendor" || name == "proc" || name == "sys" || name == "dev" {
                    continue;
                }
                walk_dir_recursive(&path, file_suffix, cb);
            } else if path.is_file() {
                if path.to_string_lossy().ends_with(file_suffix) {
                    cb(&path);
                }
            }
        }
    }
}

/// Resolve the UID of the running web processes.
pub fn resolve_web_uid(_web_root: &str) -> u32 {
    let web_names = ["nginx", "apache2", "httpd", "php-fpm", "node", "gunicorn", "passenger"];
    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            if let Ok(pid) = name.to_string_lossy().parse::<u32>() {
                if let Ok(target) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
                    let exe_name = target.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    if web_names.iter().any(|&wn| exe_name.contains(wn)) {
                        use std::os::unix::fs::MetadataExt;
                        if let Ok(meta) = std::fs::metadata(format!("/proc/{}", pid)) {
                            return meta.uid();
                        }
                    }
                }
            }
        }
    }
    33 // www-data fallback
}

use std::os::unix::fs::MetadataExt;

fn is_writable_by_uid(path: &Path, uid: u32) -> bool {
    let Ok(meta) = std::fs::metadata(path) else { return false; };
    let mode = meta.mode();

    if meta.uid() == uid {
        return (mode & 0o200) != 0;
    }
    if (mode & 0o002) != 0 {
        return true;
    }
    if (mode & 0o020) != 0 {
        return true;
    }
    false
}

/// P3: UID-Writable + Git-Diff untracked directories
pub fn scan_uid_writable_untracked(web_root: &str, web_uid: u32) -> Vec<StoragePath> {
    let mut paths = Vec::new();
    let untracked_dirs = get_git_untracked_dirs(web_root);
    for dir in untracked_dirs {
        if is_writable_by_uid(&dir, web_uid) {
            paths.push(StoragePath {
                path: dir.clone(),
                roles: vec![StorageRole::UploadDirectory],
                confidence: DiscoveryConfidence::Low,
                discovered_via: vec!["git:untracked_writable".to_string()],
                web_uid,
                allow_script_extensions: false,
                max_file_size_hint: None,
            });
        }
    }
    paths
}

fn get_git_untracked_dirs(web_root: &str) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let output = std::process::Command::new("git")
        .args(&["ls-files", "--others", "--directory", "--exclude-standard"])
        .current_dir(web_root)
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    let path = Path::new(web_root).join(trimmed);
                    dirs.push(path);
                }
            }
        }
    }
    dirs
}

/// P4: gitignore cross-reference (confirmatory/qualification only)
pub fn cross_reference_gitignore(web_root: &str) {
    let gitignore_path = Path::new(web_root).join(".gitignore");
    if !gitignore_path.exists() { return; }

    let Ok(content) = std::fs::read_to_string(gitignore_path) else { return; };
    let registry = get_registry();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
        
        // Match simple gitignore rules against registry paths
        for mut entry in registry.iter_mut() {
            let path_str = entry.key().to_string_lossy();
            if path_str.contains(trimmed) {
                // Confirm the confidence
                entry.value_mut().discovered_via.push(format!("gitignore:{}", trimmed));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Upload Scan Pipeline Integration
// ---------------------------------------------------------------------------

pub fn enqueue_upload_scan(file_path: String, alert_id: String) {
    // Register inode immediately in allowlist so application doesn't get blocked
    crate::allowlist::register_inode(&file_path);

    tokio::spawn(async move {
        match crate::upload_scan::scan_uploaded_file(&file_path).await {
            crate::upload_scan::ScanResult::Elf => {
                // Retroactively quarantine ELF file
                crate::allowlist::deregister_inode(&file_path);
                let _ = crate::quarantine::quarantine_file(
                    &file_path,
                    &alert_id,
                    "ELF binary uploaded to storage directory",
                    "Threat.Upload.ElfBinaryDetected"
                );
            }
            crate::upload_scan::ScanResult::Suspicious(reason) => {
                // Log/alert but leave accessible (kernel will catch actual execve)
                emit_suspicious_upload_alert(&file_path, &reason, &alert_id);
            }
            crate::upload_scan::ScanResult::Clean => {}
        }
    });
}

fn emit_suspicious_upload_alert(file_path: &str, reason: &str, alert_id: &str) {
    let payload = crate::notifications::AlertPayload {
        alert_id: alert_id.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        threat_type: "Warning.Upload.SuspiciousFile".to_string(),
        severity: "HIGH".to_string(),
        container: None,
        process: crate::notifications::ProcessInfo {
            pid: 0,
            exec_path: "upload-scanner".to_string(),
            cmdline: format!("scan_uploaded_file({})", file_path),
            parent_exec_path: "wardend".to_string(),
            parent_pid: std::process::id(),
        },
        remediation: crate::notifications::RemediationInfo {
            action: "AUDIT_WARNING".to_string(),
            status: format!("Suspicious file upload detected: {} (Reason: {})", file_path, reason),
        },
    };
    crate::notifications::dispatch_alert(payload);
}

/// Zero storage paths detected warning alert
pub fn emit_no_storage_detected_warning(web_root: &str) {
    // Check if acknowledged-none flag is set
    let ack_file = "/etc/kinnector/storage_ack.json";
    if Path::new(ack_file).exists() {
        if let Ok(content) = std::fs::read_to_string(ack_file) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                if json.get("web_root").and_then(|r| r.as_str()) == Some(web_root) {
                    // Suppress warning
                    return;
                }
            }
        }
    }

    let payload = crate::notifications::AlertPayload {
        alert_id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        threat_type: "Warning.Storage.NoneDetected".to_string(),
        severity: "WARNING".to_string(),
        container: None,
        process: crate::notifications::ProcessInfo {
            pid: 0,
            exec_path: "wardend".to_string(),
            cmdline: format!("storage_discovery({})", web_root),
            parent_exec_path: String::new(),
            parent_pid: 0,
        },
        remediation: crate::notifications::RemediationInfo {
            action: "OPERATOR_ACTION_REQUIRED".to_string(),
            status: format!(
                "Warden could not auto-detect any upload, storage, or temp directories \
                 for web root '{web_root}'. If local dynamic storage is intentional, configure it manually: \
                 `warden-cli storage add <path> --role upload --web-root {web_root}`."
            ),
        },
    };
    crate::notifications::dispatch_alert(payload);
    eprintln!(
        "[Warden Storage] WARNING: No storage directories detected for web root '{}'.",
        web_root
    );
}

static DISABLED_STORAGE_WEB_ROOTS: OnceLock<Arc<dashmap::DashSet<String>>> = OnceLock::new();
static DISABLED_STORAGE_EXES: OnceLock<Arc<dashmap::DashSet<String>>> = OnceLock::new();

pub fn get_disabled_storage_web_roots() -> Arc<dashmap::DashSet<String>> {
    DISABLED_STORAGE_WEB_ROOTS.get_or_init(|| Arc::new(dashmap::DashSet::new())).clone()
}

pub fn get_disabled_storage_exes() -> Arc<dashmap::DashSet<String>> {
    DISABLED_STORAGE_EXES.get_or_init(|| Arc::new(dashmap::DashSet::new())).clone()
}

pub fn disable_storage_for_web_root(web_root: &str) {
    get_disabled_storage_web_roots().insert(web_root.to_string());
    tracing::warn!("[Warden Storage] Disabled all storage and FIM checks for web root: {}", web_root);
}

pub fn enable_storage_for_web_root(web_root: &str) {
    get_disabled_storage_web_roots().remove(web_root);
    tracing::info!("[Warden Storage] Enabled storage and FIM checks for web root: {}", web_root);
}

pub fn disable_storage_for_exe(exe: &str) {
    get_disabled_storage_exes().insert(exe.to_string());
    tracing::warn!("[Warden Storage] Disabled all storage and FIM checks for executable: {}", exe);
}

pub fn enable_storage_for_exe(exe: &str) {
    get_disabled_storage_exes().remove(exe);
    tracing::info!("[Warden Storage] Enabled storage and FIM checks for executable: {}", exe);
}

pub fn is_storage_disabled_for_exe(exe: &str) -> bool {
    get_disabled_storage_exes().contains(exe)
}

pub fn is_storage_disabled_for_path(path: &str, web_roots: &[String]) -> bool {
    let roots = get_disabled_storage_web_roots();
    for r in web_roots {
        if roots.contains(r) && path.starts_with(r) {
            return true;
        }
    }
    false
}
