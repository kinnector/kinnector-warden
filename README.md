# Kinnector Warden (warden / wardend)

Warden is the host and container security daemon (`wardend`) for the Kinnector server-side EDR. It manages eBPF telemetry hooks, exposes a local socket interface for web app request vetting, and runs process/network containment mitigations.

## Local API Interface
By default, the daemon binds to `/var/run/kinnector/warden.sock` and `127.0.0.1:4080`.

### Vetting Request Payloads (SQLi/CMD-i)
`POST /api/v1/vet-payload`
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
Returns `"status": "BLOCKED"` or `"status": "ALLOWED"`.

### Vetting Database Queries
`POST /api/v1/vet-query`
```json
{
  "query": "SELECT * FROM wp_users WHERE user_login = 'admin' OR '1'='1'"
}
```
Returns `"status": "BLOCKED"` or `"status": "ALLOWED"`.

## Integration with wpwarden
The `wpwarden` plugin passes incoming query strings and raw HTTP input buffers to the local Warden socket prior to execution. If blocked, `wpwarden` issues a `403 Forbidden` response to the client.

## Daemon Bootstrapping
If `wpwarden` detects that Warden is not running and permissions allow, it copies the pre-compiled `wardend` binary to `/usr/local/bin/wardend` and initializes the systemd service. 

Otherwise, `wpwarden` triggers a dashboard notice suggesting manual installation:
```bash
curl -sSL https://raw.githubusercontent.com/kinnector/kinnector-installer/main/install-warden.sh | sudo bash
```

## Compilation
```bash
make build
```