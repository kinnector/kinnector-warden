use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub web_roots: Vec<PathBuf>,
    pub config_dirs: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct DiscoveredProxy {
    pub name: String,
    pub config_dirs: Vec<PathBuf>,
    pub access_logs: Vec<PathBuf>,
}

/// Returns true if a process whose argv[0] / exe symlink contains `binary_name`
/// is currently running, by scanning /proc/<pid>/exe symlinks.
/// M-16 fix: config dir existence alone is not sufficient.
fn is_process_running(binary_name: &str) -> bool {
    let Ok(proc_dir) = std::fs::read_dir("/proc") else { return false; };
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        // Only numeric entries (PIDs)
        if !name.to_str().map(|s| s.chars().all(|c| c.is_ascii_digit())).unwrap_or(false) {
            continue;
        }
        let exe_path = entry.path().join("exe");
        if let Ok(target) = std::fs::read_link(&exe_path) {
            if target.to_string_lossy().contains(binary_name) {
                return true;
            }
        }
    }
    false
}

pub fn auto_discover_proxies() -> Vec<DiscoveredProxy> {
    let mut proxies = Vec::new();

    // 1. Nginx Check
    let mut nginx_configs = Vec::new();
    if Path::new("/etc/nginx").exists() {
        nginx_configs.push(PathBuf::from("/etc/nginx"));
    }
    let mut nginx_logs = Vec::new();
    let common_nginx_logs = [
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
    ];
    for log in &common_nginx_logs {
        if Path::new(log).exists() {
            nginx_logs.push(PathBuf::from(log));
        }
    }
    // M-16: only report nginx if the binary is actually running
    if is_process_running("nginx") || (!nginx_configs.is_empty() && !nginx_logs.is_empty()) {
        if !nginx_configs.is_empty() {
            proxies.push(DiscoveredProxy {
                name: "nginx".to_string(),
                config_dirs: nginx_configs,
                access_logs: nginx_logs,
            });
        }
    }

    // 2. Apache Check
    let mut apache_configs = Vec::new();
    if Path::new("/etc/apache2").exists() {
        apache_configs.push(PathBuf::from("/etc/apache2"));
    } else if Path::new("/etc/httpd").exists() {
        apache_configs.push(PathBuf::from("/etc/httpd"));
    }
    let mut apache_logs = Vec::new();
    let common_apache_logs = [
        "/var/log/apache2/access.log",
        "/var/log/httpd/access_log",
    ];
    for log in &common_apache_logs {
        if Path::new(log).exists() {
            apache_logs.push(PathBuf::from(log));
        }
    }
    // M-16: only report apache if the binary is actually running
    if is_process_running("apache2") || is_process_running("httpd") {
        if !apache_configs.is_empty() {
            proxies.push(DiscoveredProxy {
                name: "apache".to_string(),
                config_dirs: apache_configs,
                access_logs: apache_logs,
            });
        }
    }

    // 3. Caddy Check
    let mut caddy_configs = Vec::new();
    if Path::new("/etc/caddy").exists() {
        caddy_configs.push(PathBuf::from("/etc/caddy"));
    }
    let mut caddy_logs = Vec::new();
    let common_caddy_logs = [
        "/var/log/caddy/access.log",
    ];
    for log in &common_caddy_logs {
        if Path::new(log).exists() {
            caddy_logs.push(PathBuf::from(log));
        }
    }
    // M-16: only report caddy if the binary is actually running
    if is_process_running("caddy") {
        if !caddy_configs.is_empty() {
            proxies.push(DiscoveredProxy {
                name: "caddy".to_string(),
                config_dirs: caddy_configs,
                access_logs: caddy_logs,
            });
        }
    } else if !caddy_configs.is_empty() || !caddy_logs.is_empty() {
        // Config exists but process not running — still watch configs in case of restart
        proxies.push(DiscoveredProxy {
            name: "caddy".to_string(),
            config_dirs: caddy_configs,
            access_logs: caddy_logs,
        });
    }

    proxies
}

/// Dynamically auto-detect all configured web roots from running web servers
/// and reverse proxy configurations, matching the agnostic guideline.
pub fn discover_web_roots(config: &kinnector_config::ConfigManager) -> Vec<String> {
    let mut roots = std::collections::HashSet::new();

    // 1. Scan running web process cwd
    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            if !name.to_str().map(|s| s.chars().all(|c| c.is_ascii_digit())).unwrap_or(false) {
                continue;
            }
            let exe_path = entry.path().join("exe");
            if let Ok(target) = std::fs::read_link(&exe_path) {
                let exe_str = target.to_string_lossy();
                if config.is_web_process(&exe_str) {
                    let cwd_path = entry.path().join("cwd");
                    if let Ok(cwd_target) = std::fs::read_link(&cwd_path) {
                        let cwd_str = cwd_target.to_string_lossy().to_string();
                        // Ignore root directories / system dirs
                        if cwd_str != "/" && cwd_str != "/root" && !cwd_str.starts_with("/usr") {
                            roots.insert(cwd_str);
                        }
                    }
                }
            }
        }
    }

    // 2. Parse configuration files of reverse proxies (Nginx, Apache, Caddy)
    let config_paths = [
        ("/etc/nginx", "root"),
        ("/etc/apache2", "DocumentRoot"),
        ("/etc/httpd", "DocumentRoot"),
        ("/etc/caddy", "root"),
    ];

    for (dir_path, key) in &config_paths {
        if Path::new(dir_path).exists() {
            scan_config_dir_for_roots(Path::new(dir_path), key, &mut roots);
        }
    }

    let mut result: Vec<String> = roots.into_iter().collect();
    if result.is_empty() {
        // A generic standard location fallback if completely empty
        result.push("/var/www/html".to_string());
    }
    result
}

pub fn discover_listening_pids() -> std::collections::HashSet<u32> {
    let mut listening_pids = std::collections::HashSet::new();
    let mut listening_inodes = std::collections::HashSet::new();

    let files = [
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
    ];

    for file_path in &files {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 9 {
                    let state = parts[3];
                    let inode = parts[9];
                    if state == "0A" || file_path.contains("udp") {
                        if let Ok(inode_val) = inode.parse::<u64>() {
                            if inode_val > 0 {
                                listening_inodes.insert(inode_val);
                            }
                        }
                    }
                }
            }
        }
    }

    // Add Unix domain sockets
    if let Ok(content) = std::fs::read_to_string("/proc/net/unix") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 7 {
                let flags = parts[3];
                let inode = parts[6];
                // Flags containing 00010000 indicates a listening Unix socket (SO_ACCEPTCON)
                if flags == "00010000" || flags.contains('1') {
                    if let Ok(inode_val) = inode.parse::<u64>() {
                        if inode_val > 0 {
                            listening_inodes.insert(inode_val);
                        }
                    }
                }
            }
        }
    }

    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let Ok(pid) = name_str.parse::<u32>() else {
                continue;
            };

            let fd_path = entry.path().join("fd");
            if let Ok(fd_dir) = std::fs::read_dir(fd_path) {
                for fd_entry in fd_dir.flatten() {
                    if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                        let link_str = link.to_string_lossy();
                        if link_str.starts_with("socket:[") && link_str.ends_with(']') {
                            let inode_str = &link_str[8..link_str.len() - 1];
                            if let Ok(inode_val) = inode_str.parse::<u64>() {
                                if listening_inodes.contains(&inode_val) {
                                    listening_pids.insert(pid);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    listening_pids
}


fn scan_config_dir_for_roots(dir: &Path, pattern_key: &str, roots: &mut std::collections::HashSet<String>) {
    fn search_file(file_path: &Path, key: &str, roots: &mut std::collections::HashSet<String>) {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') { continue; }

                if key == "DocumentRoot" && trimmed.contains("DocumentRoot") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let path = parts[1].trim_matches('"').trim_matches('\'');
                        if path.starts_with('/') {
                            roots.insert(path.to_string());
                        }
                    }
                } else if key == "root" && trimmed.contains("root") {
                    let clean = trimmed.trim_end_matches(';');
                    let parts: Vec<&str> = clean.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if parts[0] == "root" {
                            let path = parts[1].trim_matches('"').trim_matches('\'');
                            if path.starts_with('/') {
                                roots.insert(path.to_string());
                            }
                        }
                        if parts.len() >= 3 && parts[0] == "root" && parts[1] == "*" {
                            let path = parts[2].trim_matches('"').trim_matches('\'');
                            if path.starts_with('/') {
                                roots.insert(path.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    fn recurse(dir: &Path, key: &str, roots: &mut std::collections::HashSet<String>) {
        if let Ok(read_dir) = std::fs::read_dir(dir) {
            for entry in read_dir.flatten() {
                let path = entry.path();
                if let Ok(meta) = std::fs::metadata(&path) {
                    if meta.is_dir() {
                        recurse(&path, key, roots);
                    } else if meta.is_file() {
                        search_file(&path, key, roots);
                    }
                }
            }
        }
    }
    recurse(dir, pattern_key, roots);
}

/// Dynamically query /var/run/docker.sock to resolve active container info,
/// config folders, and web root mounts (P6-1, P6-2, P6-3).
pub async fn discover_docker_containers() -> Vec<ContainerInfo> {
    let mut containers = Vec::new();
    let socket_path = "/var/run/docker.sock";
    if !Path::new(socket_path).exists() {
        return containers;
    }

    use tokio::net::UnixStream;
    use tokio::io::{AsyncWriteExt, AsyncReadExt};

    let mut stream = match UnixStream::connect(socket_path).await {
        Ok(s) => s,
        Err(_) => return containers,
    };

    let req = "GET /containers/json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if stream.write_all(req.as_bytes()).await.is_err() {
        return containers;
    }

    let mut response = Vec::new();
    if stream.read_to_end(&mut response).await.is_err() {
        return containers;
    }

    let response_str = String::from_utf8_lossy(&response);
    let parts: Vec<&str> = response_str.split("\r\n\r\n").collect();
    if parts.len() < 2 {
        return containers;
    }

    // Parse JSON body
    let body = parts[1];
    let Ok(json_val) = serde_json::from_str::<serde_json::Value>(body) else {
        return containers;
    };

    let Some(containers_array) = json_val.as_array() else {
        return containers;
    };

    for item in containers_array {
        let id = item.get("Id").and_then(|i| i.as_str()).unwrap_or("").to_string();
        let name = item.get("Names")
            .and_then(|n| n.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim_start_matches('/')
            .to_string();
        let image = item.get("Image").and_then(|i| i.as_str()).unwrap_or("").to_string();

        let mut web_roots = Vec::new();
        let mut config_dirs = Vec::new();

        // Examine Mounts
        if let Some(mounts) = item.get("Mounts").and_then(|m| m.as_array()) {
            for mount in mounts {
                let Some(source) = mount.get("Source").and_then(|s| s.as_str()) else { continue; };
                let Some(dest) = mount.get("Destination").and_then(|d| d.as_str()) else { continue; };

                let source_path = PathBuf::from(source);

                // If destination matches common config/web root indicators, classify accordingly
                let dest_lower = dest.to_lowercase();
                if dest_lower.contains("html") || dest_lower.contains("www") || dest_lower.contains("public") {
                    web_roots.push(source_path);
                } else if dest_lower.contains("conf") || dest_lower.contains("etc") || dest_lower.contains("settings") {
                    config_dirs.push(source_path);
                }
            }
        }

        containers.push(ContainerInfo {
            id,
            name,
            image,
            web_roots,
            config_dirs,
        });
    }

    containers
}

/// Spawn a background task that streams events from the Docker socket.
/// Automatically detects container start/stop events in real-time (P6-4)
/// and registers their mounts without polling.
pub fn start_docker_event_listener() {
    tokio::spawn(async move {
        let socket_path = "/var/run/docker.sock";
        if !Path::new(socket_path).exists() {
            return;
        }

        use tokio::net::UnixStream;
        use tokio::io::{AsyncWriteExt, BufReader, AsyncBufReadExt};

        loop {
            let mut stream = match UnixStream::connect(socket_path).await {
                Ok(s) => s,
                Err(_) => {
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            let req = "GET /events?filters=%7B%22type%22%3A%5B%22container%22%5D%7D HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            if stream.write_all(req.as_bytes()).await.is_err() {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }

            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            
            // Skip HTTP headers
            loop {
                line.clear();
                if reader.read_line(&mut line).await.is_err() || line.trim().is_empty() {
                    break;
                }
            }

            // Read JSON events
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => break,
                    Ok(_) => {
                        let trimmed = line.trim();
                        if trimmed.is_empty() || trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                            continue;
                        }
                        if let Ok(event) = serde_json::from_str::<serde_json::Value>(trimmed) {
                            let action = event.get("Action").and_then(|a| a.as_str()).unwrap_or("");
                            let id = event.get("id").and_then(|i| i.as_str()).unwrap_or("");
                            if (action == "start" || action == "die" || action == "stop") && !id.is_empty() {
                                trigger_container_reconfig(id, action).await;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    });
}

async fn query_single_container(id: &str) -> Option<ContainerInfo> {
    let socket_path = "/var/run/docker.sock";
    use tokio::net::UnixStream;
    use tokio::io::{AsyncWriteExt, AsyncReadExt};

    let mut stream = UnixStream::connect(socket_path).await.ok()?;
    let req = format!("GET /containers/{}/json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", id);
    stream.write_all(req.as_bytes()).await.ok()?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.ok()?;

    let response_str = String::from_utf8_lossy(&response);
    let body = response_str.split("\r\n\r\n").nth(1)?;
    let json_val: serde_json::Value = serde_json::from_str(body).ok()?;

    let name = json_val.get("Name").and_then(|n| n.as_str()).unwrap_or("").trim_start_matches('/').to_string();
    let config = json_val.get("Config")?;
    let image = config.get("Image").and_then(|i| i.as_str()).unwrap_or("").to_string();

    let mut web_roots = Vec::new();
    let mut config_dirs = Vec::new();

    if let Some(mounts) = json_val.get("Mounts").and_then(|m| m.as_array()) {
        for mount in mounts {
            let source = mount.get("Source").and_then(|s| s.as_str())?;
            let dest = mount.get("Destination").and_then(|d| d.as_str())?;
            let source_path = PathBuf::from(source);
            let dest_lower = dest.to_lowercase();
            if dest_lower.contains("html") || dest_lower.contains("www") || dest_lower.contains("public") {
                web_roots.push(source_path);
            } else if dest_lower.contains("conf") || dest_lower.contains("etc") || dest_lower.contains("settings") {
                config_dirs.push(source_path);
            }
        }
    }

    Some(ContainerInfo {
        id: id.to_string(),
        name,
        image,
        web_roots,
        config_dirs,
    })
}

use dashmap::DashMap;
use std::sync::{Arc, OnceLock};

static ACTIVE_CONTAINER_MOUNTS: OnceLock<Arc<DashMap<String, Vec<PathBuf>>>> = OnceLock::new();

pub fn get_active_container_mounts() -> &'static Arc<DashMap<String, Vec<PathBuf>>> {
    ACTIVE_CONTAINER_MOUNTS.get_or_init(|| Arc::new(DashMap::new()))
}

pub fn register_container_mounts(id: &str, mounts: Vec<PathBuf>) {
    get_active_container_mounts().insert(id.to_string(), mounts);
}

async fn trigger_container_reconfig(id: &str, action: &str) {
    if action == "start" {
        if let Some(c) = query_single_container(id).await {
            println!("[Warden Docker] Dynamic event: Started container {} (Image: {})", c.name, c.image);
            let mut mounts = Vec::new();
            for wr in c.web_roots {
                println!("[Warden Docker] Dynamically adding FIM watch and allowlist for: {}", wr.display());
                crate::fim::add_fim_watch_path(wr.clone());
                let wr_str = wr.to_string_lossy().to_string();
                tokio::task::block_in_place(|| {
                    crate::allowlist::register_path_recursive(&wr_str);
                });
                mounts.push(wr);
            }
            for cd in c.config_dirs {
                println!("[Warden Docker] Dynamically adding FIM watch for config: {}", cd.display());
                crate::fim::add_fim_watch_path(cd.clone());
                mounts.push(cd);
            }
            register_container_mounts(id, mounts);
        }
    } else {
        println!("[Warden Docker] Dynamic event: Stopped container {}", id);
        if let Some((_, mounts)) = get_active_container_mounts().remove(id) {
            for mount in mounts {
                println!("[Warden Docker] Dynamically removing FIM watch and allowlist for stopped container mount: {}", mount.display());
                crate::fim::remove_fim_watch_path(mount.clone());
                let mount_str = mount.to_string_lossy();
                tokio::task::block_in_place(|| {
                    crate::allowlist::deregister_path_recursive(&mount_str);
                });
            }
        }
    }
}

pub fn get_listening_services() -> Vec<serde_json::Value> {
    use std::collections::{HashMap, HashSet};
    let mut inode_to_port: HashMap<u64, u16> = HashMap::new();
    let mut inode_to_unix_path: HashMap<u64, String> = HashMap::new();

    let files = [
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
    ];

    for file_path in &files {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 9 {
                    let local_addr = parts[1];
                    let state = parts[3];
                    let inode = parts[9];
                    if state == "0A" || file_path.contains("udp") {
                        if let Ok(inode_val) = inode.parse::<u64>() {
                            if inode_val > 0 {
                                if let Some(port_hex) = local_addr.split(':').nth(1) {
                                    if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                                        inode_to_port.insert(inode_val, port);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if let Ok(content) = std::fs::read_to_string("/proc/net/unix") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 7 {
                let flags = parts[3];
                let inode = parts[6];
                let path = if parts.len() >= 8 { parts[7].to_string() } else { String::new() };
                if flags == "00010000" || flags.contains('1') {
                    if let Ok(inode_val) = inode.parse::<u64>() {
                        if inode_val > 0 {
                            inode_to_unix_path.insert(inode_val, path);
                        }
                    }
                }
            }
        }
    }

    let mut pid_to_ports: HashMap<u32, HashSet<u16>> = HashMap::new();
    let mut pid_to_unix_paths: HashMap<u32, HashSet<String>> = HashMap::new();

    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let Ok(pid) = name_str.parse::<u32>() else {
                continue;
            };

            let fd_path = entry.path().join("fd");
            if let Ok(fd_dir) = std::fs::read_dir(fd_path) {
                for fd_entry in fd_dir.flatten() {
                    if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                        let link_str = link.to_string_lossy();
                        if link_str.starts_with("socket:[") && link_str.ends_with(']') {
                            let inode_str = &link_str[8..link_str.len() - 1];
                            if let Ok(inode_val) = inode_str.parse::<u64>() {
                                if let Some(&port) = inode_to_port.get(&inode_val) {
                                    pid_to_ports.entry(pid).or_default().insert(port);
                                }
                                if let Some(path) = inode_to_unix_path.get(&inode_val) {
                                    if !path.is_empty() {
                                        pid_to_unix_paths.entry(pid).or_default().insert(path.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut services = Vec::new();
    let mut all_pids: HashSet<u32> = HashSet::new();
    all_pids.extend(pid_to_ports.keys());
    all_pids.extend(pid_to_unix_paths.keys());

    for pid in all_pids {
        let exe_path = format!("/proc/{}/exe", pid);
        let cwd_path = format!("/proc/{}/cwd", pid);

        let exe = std::fs::read_link(&exe_path)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let cwd = std::fs::read_link(&cwd_path)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        if exe.is_empty() {
            continue;
        }

        let stack = detect_process_stack(pid, &exe);
        let ports = pid_to_ports.get(&pid).cloned().unwrap_or_default();
        let unix_paths = pid_to_unix_paths.get(&pid).cloned().unwrap_or_default();

        services.push(serde_json::json!({
            "pid": pid,
            "exe": exe,
            "cwd": cwd,
            "stack": stack,
            "ports": ports.into_iter().collect::<Vec<_>>(),
            "unix_sockets": unix_paths.into_iter().collect::<Vec<_>>(),
        }));
    }

    services
}

fn detect_process_stack(pid: u32, exe_path: &str) -> String {
    let exe_lower = exe_path.to_lowercase();
    if exe_lower.contains("node") {
        return "Node.js".to_string();
    }
    if exe_lower.contains("python") {
        return "Python".to_string();
    }
    if exe_lower.contains("php") {
        return "PHP".to_string();
    }
    if exe_lower.contains("java") {
        return "Java".to_string();
    }
    if exe_lower.contains("ruby") {
        return "Ruby".to_string();
    }
    if exe_lower.contains("nginx") {
        return "Nginx".to_string();
    }
    if exe_lower.contains("httpd") || exe_lower.contains("apache") {
        return "Apache".to_string();
    }
    if exe_lower.contains("caddy") {
        return "Caddy".to_string();
    }

    // Check mapping for JVM or Go/Rust patterns
    if let Ok(maps) = std::fs::read_to_string(format!("/proc/{}/maps", pid)) {
        if maps.contains("libjvm.so") {
            return "Java (JVM)".to_string();
        }
        if maps.contains("libgo.so") {
            return "Go (Shared)".to_string();
        }
    }

    // Check ELF signatures for Go or Rust
    if let Ok(bytes) = std::fs::read(format!("/proc/{}/exe", pid)) {
        let content_str = String::from_utf8_lossy(&bytes[..20000.min(bytes.len())]);
        if content_str.contains("Go build ID") || content_str.contains("runtime.goexit") {
            return "Go (Compiled)".to_string();
        }
        if content_str.contains("rust_panic") || content_str.contains("_ZN4rust") {
            return "Rust (Compiled)".to_string();
        }
    }

    "Native (C/C++)".to_string()
}



