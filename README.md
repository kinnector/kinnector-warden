# Kinnector Warden

Kinnector Warden (`wardend`) is the server-side host and container protection engine for the Kinnector security ecosystem. It integrates real-time web request vetting with system-level eBPF behavioral containment.

---

## What it protects

Web application servers and exposed backend services are primary targets for injection vulnerabilities and remote code execution (RCE). 

Kinnector Warden protects these workloads. It acts as a local security guard, analyzing HTTP request payloads and SQL queries before they run, while simultaneously monitoring the server kernel via eBPF to detect and block post-compromise actions like reverse shells, credential exfiltration, or unauthorized container escapes.

---

## Why WAFs and Antivirus are insufficient

Web Application Firewalls (WAFs) operate at the network layer and are blind to what happens inside the server, failing to detect obfuscated exploits or post-compromise behavior. Antivirus scanners only execute after files are written to disk, failing to detect memory-only attacks or shell duplication.

Kinnector Warden bridges this gap. It combines application-level vetting (SQL and HTTP input checking) with kernel-level enforcement, stopping attacks at the front door and neutralizing them if they bypass initial checks.

---

## Core Capabilities and API

Warden exposes a local Unix domain socket and an HTTP interface (`127.0.0.1:4080`) for application layers and CMS plugins to validate parameters:

### 1. HTTP Input Vetting
Validates query strings, parameters, and headers for common exploit patterns (such as CMD-i or SQLi) before the application processes them.

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
* **Response**: Returns `{"status": "ALLOWED"}` or `{"status": "BLOCKED"}`.

### 2. Database Query Vetting
Vets raw SQL statements before the database driver executes them, blocking injection attempts.

* **Endpoint**: `POST /api/v1/vet-query`
* **Request**:
  ```json
  {
    "query": "SELECT * FROM wp_users WHERE user_login = 'admin' OR '1'='1'"
  }
  ```
* **Response**: Returns `{"status": "ALLOWED"}` or `{"status": "BLOCKED"}`.

---

## Integrations (WordPress Companion)

Warden works with the `wpwarden` plugin. The plugin forwards incoming request buffers and SQL queries to Warden's local socket. If Warden flags a payload, the plugin aborts the PHP lifecycle and responds with a `403 Forbidden`.

---

## Installation and Execution

### Automated Script Deployment
Deploy and configure the `wardend` systemd service using the official installer script:

```bash
curl -sSL https://raw.githubusercontent.com/kinnector/kinnector-installer/main/install-warden.sh | sudo bash
```

### Compiling from Source
Build the `wardend` binary locally:

```bash
make build
```