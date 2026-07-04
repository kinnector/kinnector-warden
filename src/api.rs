use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Deserialize, Debug)]
struct VetPayloadRequest {
    client_ip: Option<String>,
    request_uri: Option<String>,
    headers: Option<serde_json::Value>,
    post_data: Option<String>,
}

#[derive(Deserialize, Debug)]
struct VetQueryRequest {
    query: String,
}

#[derive(Serialize, Debug)]
struct VetResponse {
    status: &'static str, // ALLOWED or BLOCKED
}

pub fn start_api_servers() {
    // 1. Start TCP server
    tokio::spawn(async move {
        let addr = "127.0.0.1:4080";
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[Warden API] Failed to bind TCP listener on {}: {}", addr, e);
                return;
            }
        };
        println!("[Warden API] Web API listening on TCP: http://{}", addr);

        loop {
            if let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = handle_http_connection(stream).await;
                });
            }
        }
    });

use std::os::unix::fs::PermissionsExt;

// 2. Start UNIX Socket server
    tokio::spawn(async move {
        let socket_path = "/var/run/kinnector/warden.sock";
        let path = Path::new(socket_path);
        
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        
        // Remove existing socket if any
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }

        let listener = match UnixListener::bind(socket_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[Warden API] Failed to bind UNIX listener on {}: {}", socket_path, e);
                return;
            }
        };
        
        // Restrict UNIX socket permissions so WP-Warden plugin can connect
        let _ = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666));
        println!("[Warden API] Web API listening on UNIX socket: {}", socket_path);

        loop {
            if let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = handle_http_connection(stream).await;
                });
            }
        }
    });
}

async fn handle_http_connection<S>(mut stream: S) -> Result<(), Box<dyn std::error::Error>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 8192];
    let mut total_read = 0;

    // Read initial HTTP request headers
    loop {
        let n = stream.read(&mut buffer[total_read..]).await?;
        if n == 0 {
            break;
        }
        total_read += n;
        if buffer[..total_read].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if total_read >= buffer.len() {
            break;
        }
    }

    if total_read == 0 {
        return Ok(());
    }

    let request_str = String::from_utf8_lossy(&buffer[..total_read]);
    let mut lines = request_str.lines();
    
    // Parse request line
    let req_line = match lines.next() {
        Some(l) => l,
        None => return Ok(()),
    };
    
    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 3 {
        send_http_response(&mut stream, 400, "Bad Request", "Invalid HTTP request").await?;
        return Ok(());
    }

    let method = parts[0];
    let uri = parts[1];

    if method != "POST" {
        send_http_response(&mut stream, 405, "Method Not Allowed", "Only POST requests allowed").await?;
        return Ok(());
    }

    // Extract Content-Length
    let mut content_length = 0;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let header_parts: Vec<&str> = line.splitn(2, ':').collect();
        if header_parts.len() == 2 {
            let name = header_parts[0].trim().to_lowercase();
            let value = header_parts[1].trim();
            if name == "content-length" {
                content_length = value.parse::<usize>().unwrap_or(0);
            }
        }
    }

    // Check where the body starts
    let header_end = request_str.find("\r\n\r\n").map(|idx| idx + 4).unwrap_or(total_read);
    let mut body = buffer[header_end..total_read].to_vec();

    // Read remaining body bytes if needed
    if body.len() < content_length {
        let mut remaining = content_length - body.len();
        let mut read_buf = vec![0u8; remaining];
        while remaining > 0 {
            let n = stream.read(&mut read_buf).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&read_buf[..n]);
            remaining -= n;
        }
    }

    let body_str = String::from_utf8_lossy(&body);

    // Route request
    let is_blocked = match uri {
        "/api/v1/vet-payload" => {
            if let Ok(req) = serde_json::from_str::<VetPayloadRequest>(&body_str) {
                let mut block = false;
                if let Some(ref request_uri) = req.request_uri {
                    block |= crate::vet::vet_string(request_uri);
                }
                if let Some(ref post_data) = req.post_data {
                    block |= crate::vet::vet_string(post_data);
                }
                if let Some(ref headers) = req.headers {
                    // Walk values inside JSON headers
                    if let Some(obj) = headers.as_object() {
                        for (_, val) in obj {
                            if let Some(val_str) = val.as_str() {
                                block |= crate::vet::vet_string(val_str);
                            }
                        }
                    }
                }
                block
            } else {
                false
            }
        }
        "/api/v1/vet-query" => {
            if let Ok(req) = serde_json::from_str::<VetQueryRequest>(&body_str) {
                crate::vet::check_sqli(&req.query)
            } else {
                false
            }
        }
        _ => {
            send_http_response(&mut stream, 404, "Not Found", "API endpoint not found").await?;
            return Ok(());
        }
    };

    let status = if is_blocked { "BLOCKED" } else { "ALLOWED" };
    let resp = VetResponse { status };
    let json_resp = serde_json::to_string(&resp)?;

    send_http_response(&mut stream, 200, "OK", &json_resp).await?;
    Ok(())
}

async fn send_http_response<S>(
    stream: &mut S,
    code: u16,
    reason: &str,
    body: &str,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        code,
        reason,
        body.len(),
        body
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}
