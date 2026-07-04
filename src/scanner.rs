use serde::{Deserialize, Serialize};
use std::path::Path;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsvVulnerability {
    pub id: String,
    pub package: String,
    pub ecosystem: String, // npm, pip
    pub vulnerable_version: String, // simple equality or simple checks
    pub patched_version: String,
    pub severity: String,
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

async fn run_scan(root_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load OSV local cache
    let osv_path = Path::new("/etc/kinnector/osv.json");
    if !osv_path.exists() {
        return Ok(());
    }

    let osv_data = std::fs::read_to_string(osv_path)?;
    let vulnerabilities: Vec<OsvVulnerability> = serde_json::from_str(&osv_data)?;

    let mut detected = Vec::new();

    // 2. Scan NPM package-lock.json if exists
    let package_lock_path = Path::new(root_dir).join("package-lock.json");
    if package_lock_path.exists() {
        if let Ok(lock_content) = std::fs::read_to_string(&package_lock_path) {
            if let Ok(lock_json) = serde_json::from_str::<serde_json::Value>(&lock_content) {
                if let Some(dependencies) = lock_json.get("dependencies").and_then(|d| d.as_object()) {
                    for (pkg_name, info) in dependencies {
                        if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                            // Match against vulnerability database
                            for vuln in &vulnerabilities {
                                if vuln.ecosystem == "npm" && vuln.package == *pkg_name && vuln.vulnerable_version == version {
                                    detected.push(vuln.clone());
                                }
                            }
                        }
                    }
                }
                // Handle packages key (NPM v2/v3 lockfile structure)
                if let Some(packages) = lock_json.get("packages").and_then(|p| p.as_object()) {
                    for (pkg_path, info) in packages {
                        if pkg_path.is_empty() { continue; }
                        let pkg_name = pkg_path.trim_start_matches("node_modules/");
                        if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                            for vuln in &vulnerabilities {
                                if vuln.ecosystem == "npm" && vuln.package == pkg_name && vuln.vulnerable_version == version {
                                    detected.push(vuln.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Scan requirements.txt (Pip)
    let requirements_path = Path::new(root_dir).join("requirements.txt");
    if requirements_path.exists() {
        if let Ok(req_content) = std::fs::read_to_string(&requirements_path) {
            for line in req_content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_matches('#') { continue; }
                let parts: Vec<&str> = trimmed.split("==").collect();
                if parts.len() == 2 {
                    let pkg_name = parts[0].trim().to_lowercase();
                    let version = parts[1].trim();
                    for vuln in &vulnerabilities {
                        if vuln.ecosystem == "pip" && vuln.package.to_lowercase() == pkg_name && vuln.vulnerable_version == version {
                            detected.push(vuln.clone());
                        }
                    }
                }
            }
        }
    }

    // 4. Dispatch alerts for all detected issues
    for vuln in detected {
        let alert_id = format!("vuln-{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
        let payload = crate::notifications::AlertPayload {
            alert_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
            threat_type: "Vulnerability.Dependency.Detected".to_string(),
            severity: vuln.severity,
            container: None,
            process: crate::notifications::ProcessInfo {
                pid: 0,
                exec_path: "dependency-scanner".to_string(),
                cmdline: format!("Scan path: {}", root_dir),
                parent_exec_path: "wardend".to_string(),
                parent_pid: std::process::id(),
            },
            remediation: crate::notifications::RemediationInfo {
                action: "LOG_ALERT".to_string(),
                status: format!("Vulnerable package '{}' (v{}) matches {}. Remediation: Upgrade to v{}.", vuln.package, vuln.vulnerable_version, vuln.id, vuln.patched_version),
            },
        };
        
        // Write to audit log
        if let Ok(json_str) = serde_json::to_string(&payload) {
            let _ = write_to_audit_log(&json_str);
        }
        
        // Dispatch to webhooks
        crate::notifications::dispatch_alert(payload);
    }

    Ok(())
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

// Simple backport helper
trait StartsMatches {
    fn starts_matches(&self, c: char) -> bool;
}
impl StartsMatches for &str {
    fn starts_matches(&self, c: char) -> bool {
        self.starts_with(c)
    }
}
impl StartsMatches for String {
    fn starts_matches(&self, c: char) -> bool {
        self.starts_with(c)
    }
}
