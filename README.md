# **kinnector** Warden

Warden (`wardend`) is the host and container security daemon for the **kinnector** server-side EDR ecosystem. It manages eBPF telemetry hooks, exposes a local Unix socket and HTTP API for vetting web requests, and executes process and network containment mitigations.

## Local API Interface

Warden runs a local listener at `/var/run/kinnector/warden.sock` and `127.0.0.1:4080` by default. Application servers and plugins can query this local API to vet incoming parameters or database queries.

### Vetting Request Payloads
Vets HTTP parameters and headers for command injection (CMD-i) or SQL injection (SQLi) patterns.

* **Endpoint**: `POST /api/v1/vet-payload`
* **Request**:
  ```json
  {
    "client_ip": "203.0.113.5",
    "request_uri": "/wp-admin/post.php?post=45",
    "headers": {
      "User-Agent": "Mozilla/5.0 ...",
      "Referer": "http://example.com/wp-admin/"
    },
    "post_data": "title=Hello&content=SELECT * FROM wp_users; --"
  }
  ```
* **Response**: Returns either `{"status": "ALLOWED"}` or `{"status": "BLOCKED"}`.

### Vetting Database Queries
Vets raw SQL query strings before they are executed against the database.

* **Endpoint**: `POST /api/v1/vet-query`
* **Request**:
  ```json
  {
    "query": "SELECT * FROM wp_users WHERE user_login = 'admin' OR '1'='1'"
  }
  ```
* **Response**: Returns either `{"status": "ALLOWED"}` or `{"status": "BLOCKED"}`.

## WordPress Integration (wpwarden)

The companion `wpwarden` plugin passes incoming query strings and raw HTTP input buffers to Warden's local socket before they are run. If Warden flags a payload as malicious, the plugin aborts execution and responds with a `403 Forbidden`.

## Daemon Lifecycle & Installation

The WordPress helper plugin attempts to auto-discover Warden on the server. If Warden is not running:
1. **Automatic Setup**: If the PHP environment has sufficient privileges (e.g., inside a Docker container), it copies the pre-compiled `wardend` binary to `/usr/local/bin/wardend` and configures the systemd service.
2. **Manual Setup**: If permissions are restricted, the plugin triggers an admin dashboard notice prompting the administrator to run the installer script:
   ```bash
   curl -sSL https://raw.githubusercontent.com/kinnector/kinnector-installer/main/install-warden.sh | sudo bash
   ```

## Compiling from Source

To build the `wardend` binary:

```bash
make build
```