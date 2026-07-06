use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsvVulnerability {
    pub id: String,
    pub package: String,
    pub ecosystem: String,          // npm, pip, pypi, composer, packagist
    pub vulnerable_version: String,  // semver request range
    pub patched_version: String,
    pub severity: String,
}

#[derive(Debug, Clone, Copy)]
enum LockFileType {
    PackageLock,
    Requirements,
    PipfileLock,
    ComposerLock,
    PoetryLock,
    YarnLock,
}

struct DetectedDependency {
    pub name: String,
    pub version: String,
    pub is_dev: bool,
    pub ecosystem_key: String, // npm, pip, composer etc.
    pub lock_file_path: String,
}

pub fn start_scanner(root_dir: String) {
    tokio::spawn(async move {
        loop {
            println!("[Warden Scanner] Starting dependency vulnerability check on: {}", root_dir);
            if let Err(e) = run_scan(&root_dir).await {
                eprintln!("[Warden Scanner] Scan failed: {}", e);
            }
            // Sleep for 12 hours
            tokio::time::sleep(tokio::time::Duration::from_secs(12 * 3600)).await;
        }
    });
}

/// Check whether `installed` falls within the vulnerability's `vuln_range`.
/// Accepts semver range expressions (e.g. ">=1.0.0, <1.2.3") or falls back
/// to exact string equality for non-semver version strings.
fn is_version_affected(installed: &str, vuln_range: &str) -> bool {
    if let (Ok(ver), Ok(req)) = (
        semver::Version::parse(installed),
        semver::VersionReq::parse(vuln_range),
    ) {
        return req.matches(&ver);
    }
    installed == vuln_range
}

pub(crate) async fn run_scan(root_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load OSV local cache
    let osv_path = Path::new("/etc/kinnector/osv.json");
    if !osv_path.exists() {
        return Ok(());
    }

    let osv_data = std::fs::read_to_string(osv_path)?;
    let vulnerabilities: Vec<OsvVulnerability> = serde_json::from_str(&osv_data)?;

    // 2. Discover all lock files recursively (P5-5)
    let lock_files = find_lock_files(Path::new(root_dir), 0);
    let mut dependencies = Vec::new();

    for (path, file_type) in lock_files {
        let path_str = path.to_string_lossy().to_string();
        match file_type {
            LockFileType::PackageLock => {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    parse_package_lock(&content, &mut dependencies, &path_str);
                }
            }
            LockFileType::Requirements => {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    parse_requirements(&content, &mut dependencies, &path_str);
                }
            }
            LockFileType::PipfileLock => {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    parse_pipfile_lock(&content, &mut dependencies, &path_str);
                }
            }
            LockFileType::ComposerLock => {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    parse_composer_lock(&content, &mut dependencies, &path_str);
                }
            }
            LockFileType::PoetryLock => {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    parse_poetry_lock(&content, &mut dependencies, &path_str);
                }
            }
            LockFileType::YarnLock => {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    parse_yarn_lock(&content, &mut dependencies, &path_str);
                }
            }
        }
    }

    // 3. Match detected dependencies against OSV vulnerabilities
    for dep in &dependencies {
        for vuln in &vulnerabilities {
            // Normalize ecosystem check (e.g. pip vs pypi, composer vs packagist)
            let is_match = match (dep.ecosystem_key.as_str(), vuln.ecosystem.to_lowercase().as_str()) {
                ("npm", "npm") => true,
                ("pip", "pip") | ("pip", "pypi") => true,
                ("composer", "composer") | ("composer", "packagist") => true,
                _ => false,
            };

            if is_match && vuln.package.to_lowercase() == dep.name.to_lowercase() {
                if is_version_affected(&dep.version, &vuln.vulnerable_version) {
                    // P5-6: Differentiate severity: production deps -> vuln.severity, devDeps -> WARNING
                    let severity = if dep.is_dev {
                        "WARNING".to_string()
                    } else {
                        vuln.severity.clone()
                    };

                    let alert_id = uuid::Uuid::new_v4().to_string();
                    let payload = crate::notifications::AlertPayload {
                        alert_id,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        threat_type: "Vulnerability.Dependency.Detected".to_string(),
                        severity,
                        container: None,
                        process: crate::notifications::ProcessInfo {
                            pid: 0,
                            exec_path: "dependency-scanner".to_string(),
                            cmdline: format!("Lockfile: {}", dep.lock_file_path),
                            parent_exec_path: "wardend".to_string(),
                            parent_pid: std::process::id(),
                        },
                        remediation: crate::notifications::RemediationInfo {
                            action: "LOG_ALERT".to_string(),
                            status: format!(
                                "Vulnerable package '{}' (v{}) matches {} in {} dependency of {}. Remediation: Upgrade to v{}.",
                                vuln.package, dep.version, vuln.id,
                                if dep.is_dev { "dev" } else { "production" },
                                dep.lock_file_path, vuln.patched_version
                            ),
                        },
                    };

                    if let Ok(json_str) = serde_json::to_string(&payload) {
                        let _ = crate::audit::write_to_audit_log(&json_str);
                    }
                    crate::notifications::dispatch_alert(payload);
                }
            }
        }
    }

    Ok(())
}

fn find_lock_files(dir: &Path, depth: usize) -> Vec<(PathBuf, LockFileType)> {
    if depth > 5 {
        return Vec::new();
    }
    let mut files = Vec::new();
    if let Ok(read_dir) = std::fs::read_dir(dir) {
        for entry in read_dir.flatten() {
            let path = entry.path();
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                if meta.is_dir() {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if name == "node_modules" || name == ".git" || name == "vendor" || name == "target" || name == "quarantine" {
                        continue;
                    }
                    files.extend(find_lock_files(&path, depth + 1));
                } else if meta.is_file() {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if name == "package-lock.json" {
                        files.push((path, LockFileType::PackageLock));
                    } else if name == "requirements.txt" {
                        files.push((path, LockFileType::Requirements));
                    } else if name == "Pipfile.lock" {
                        files.push((path, LockFileType::PipfileLock));
                    } else if name == "composer.lock" {
                        files.push((path, LockFileType::ComposerLock));
                    } else if name == "poetry.lock" {
                        files.push((path, LockFileType::PoetryLock));
                    } else if name == "yarn.lock" {
                        files.push((path, LockFileType::YarnLock));
                    }
                }
            }
        }
    }
    files
}

// ---------------------------------------------------------------------------
// Lockfile Parsers
// ---------------------------------------------------------------------------

fn parse_package_lock(content: &str, deps: &mut Vec<DetectedDependency>, path: &str) {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
        // v1/v2 format
        if let Some(dependencies) = json.get("dependencies").and_then(|d| d.as_object()) {
            for (name, info) in dependencies {
                if let Some(ver) = info.get("version").and_then(|v| v.as_str()) {
                    let is_dev = info.get("dev").and_then(|d| d.as_bool()).unwrap_or(false);
                    deps.push(DetectedDependency {
                        name: name.clone(),
                        version: ver.to_string(),
                        is_dev,
                        ecosystem_key: "npm".to_string(),
                        lock_file_path: path.to_string(),
                    });
                }
            }
        }
        // v2/v3 packages format
        if let Some(packages) = json.get("packages").and_then(|p| p.as_object()) {
            for (pkg_path, info) in packages {
                if pkg_path.is_empty() {
                    continue;
                }
                let name = pkg_path.trim_start_matches("node_modules/");
                if let Some(ver) = info.get("version").and_then(|v| v.as_str()) {
                    let is_dev = info.get("dev").and_then(|d| d.as_bool()).unwrap_or(false);
                    deps.push(DetectedDependency {
                        name: name.to_string(),
                        version: ver.to_string(),
                        is_dev,
                        ecosystem_key: "npm".to_string(),
                        lock_file_path: path.to_string(),
                    });
                }
            }
        }
    }
}

fn parse_requirements(content: &str, deps: &mut Vec<DetectedDependency>, path: &str) {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split("==").collect();
        if parts.len() == 2 {
            deps.push(DetectedDependency {
                name: parts[0].trim().to_lowercase(),
                version: parts[1].trim().to_string(),
                is_dev: false, // requirements.txt typically has no dev metadata
                ecosystem_key: "pip".to_string(),
                lock_file_path: path.to_string(),
            });
        }
    }
}

fn parse_pipfile_lock(content: &str, deps: &mut Vec<DetectedDependency>, path: &str) {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
        // "default" dependencies
        if let Some(default_deps) = json.get("default").and_then(|d| d.as_object()) {
            for (name, info) in default_deps {
                if let Some(ver_spec) = info.get("version").and_then(|v| v.as_str()) {
                    // ver_spec is typically "==1.2.3"
                    let ver = ver_spec.trim_start_matches('=').trim();
                    deps.push(DetectedDependency {
                        name: name.clone(),
                        version: ver.to_string(),
                        is_dev: false,
                        ecosystem_key: "pip".to_string(),
                        lock_file_path: path.to_string(),
                    });
                }
            }
        }
        // "develop" dependencies (devDeps)
        if let Some(develop_deps) = json.get("develop").and_then(|d| d.as_object()) {
            for (name, info) in develop_deps {
                if let Some(ver_spec) = info.get("version").and_then(|v| v.as_str()) {
                    let ver = ver_spec.trim_start_matches('=').trim();
                    deps.push(DetectedDependency {
                        name: name.clone(),
                        version: ver.to_string(),
                        is_dev: true,
                        ecosystem_key: "pip".to_string(),
                        lock_file_path: path.to_string(),
                    });
                }
            }
        }
    }
}

fn parse_composer_lock(content: &str, deps: &mut Vec<DetectedDependency>, path: &str) {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
        // "packages" array
        if let Some(packages) = json.get("packages").and_then(|p| p.as_array()) {
            for pkg in packages {
                if let (Some(name), Some(version)) = (
                    pkg.get("name").and_then(|n| n.as_str()),
                    pkg.get("version").and_then(|v| v.as_str()),
                ) {
                    deps.push(DetectedDependency {
                        name: name.to_string(),
                        version: version.trim_start_matches('v').to_string(),
                        is_dev: false,
                        ecosystem_key: "composer".to_string(),
                        lock_file_path: path.to_string(),
                    });
                }
            }
        }
        // "packages-dev" array
        if let Some(packages_dev) = json.get("packages-dev").and_then(|p| p.as_array()) {
            for pkg in packages_dev {
                if let (Some(name), Some(version)) = (
                    pkg.get("name").and_then(|n| n.as_str()),
                    pkg.get("version").and_then(|v| v.as_str()),
                ) {
                    deps.push(DetectedDependency {
                        name: name.to_string(),
                        version: version.trim_start_matches('v').to_string(),
                        is_dev: true,
                        ecosystem_key: "composer".to_string(),
                        lock_file_path: path.to_string(),
                    });
                }
            }
        }
    }
}

fn parse_poetry_lock(content: &str, deps: &mut Vec<DetectedDependency>, path: &str) {
    let mut current_name = String::new();
    let mut current_version = String::new();
    let mut is_dev = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            // Save preceding package
            if !current_name.is_empty() && !current_version.is_empty() {
                deps.push(DetectedDependency {
                    name: current_name.clone(),
                    version: current_version.clone(),
                    is_dev,
                    ecosystem_key: "pip".to_string(),
                    lock_file_path: path.to_string(),
                });
            }
            current_name.clear();
            current_version.clear();
            is_dev = false;
        } else if trimmed.starts_with("name =") {
            if let Some(n) = trimmed.split('"').nth(1) {
                current_name = n.to_string();
            }
        } else if trimmed.starts_with("version =") {
            if let Some(v) = trimmed.split('"').nth(1) {
                current_version = v.to_string();
            }
        } else if trimmed.starts_with("category =") {
            if let Some(c) = trimmed.split('"').nth(1) {
                if c == "dev" {
                    is_dev = true;
                }
            }
        }
    }

    // Save final package
    if !current_name.is_empty() && !current_version.is_empty() {
        deps.push(DetectedDependency {
            name: current_name,
            version: current_version,
            is_dev,
            ecosystem_key: "pip".to_string(),
            lock_file_path: path.to_string(),
        });
    }
}

fn parse_yarn_lock(content: &str, deps: &mut Vec<DetectedDependency>, path: &str) {
    let mut current_name = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Yarn 1.x dependency lines start with non-space and end with a colon or have commas
        if !line.starts_with(' ') && !line.starts_with('\t') {
            // Extract the package name before the first @
            // Example: "@babel/code-frame@^7.0.0", "@babel/code-frame@^7.8.3":
            let clean_line = trimmed.trim_matches('"').trim_end_matches(':');
            let first_dep = clean_line.split(',').next().unwrap_or("").trim().trim_matches('"');
            
            // Extract name (handle scoped names properly)
            let name = if first_dep.starts_with('@') {
                first_dep.split('@').take(2).collect::<Vec<_>>().join("@")
            } else {
                first_dep.split('@').next().unwrap_or("").to_string()
            };
            current_name = name;
        } else if trimmed.starts_with("version") {
            // Example: version "7.12.11"
            if let Some(version) = trimmed.split('"').nth(1) {
                if !current_name.is_empty() {
                    deps.push(DetectedDependency {
                        name: current_name.clone(),
                        version: version.to_string(),
                        is_dev: false, // yarn.lock has no explicit dev field
                        ecosystem_key: "npm".to_string(),
                        lock_file_path: path.to_string(),
                    });
                    current_name.clear();
                }
            }
        }
    }
}
