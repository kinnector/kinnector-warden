use std::path::{Path, PathBuf};
use std::collections::HashMap;
use tokio::io::AsyncBufReadExt;

#[derive(Debug, Clone)]
pub struct DiscoveredProxy {
    pub name: String,
    pub config_dirs: Vec<PathBuf>,
    pub access_logs: Vec<PathBuf>,
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
    if !nginx_configs.is_empty() || !nginx_logs.is_empty() {
        proxies.push(DiscoveredProxy {
            name: "nginx".to_string(),
            config_dirs: nginx_configs,
            access_logs: nginx_logs,
        });
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
    if !apache_configs.is_empty() || !apache_logs.is_empty() {
        proxies.push(DiscoveredProxy {
            name: "apache".to_string(),
            config_dirs: apache_configs,
            access_logs: apache_logs,
        });
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
    if !caddy_configs.is_empty() || !caddy_logs.is_empty() {
        proxies.push(DiscoveredProxy {
            name: "caddy".to_string(),
            config_dirs: caddy_configs,
            access_logs: caddy_logs,
        });
    }

    proxies
}
