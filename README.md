<div align="center">
  <h1>S5Core</h1>
  <p><strong>A High-Performance, Production-Ready SOCKS5 Proxy Server & Go SDK with Traffic Obfuscation</strong></p>

  [![Latest Release](https://github.com/mazixs/S5Core/actions/workflows/release.yml/badge.svg)](https://github.com/mazixs/S5Core/actions)
  [![Go Report Card](https://goreportcard.com/badge/github.com/mazixs/S5Core)](https://goreportcard.com/report/github.com/mazixs/S5Core)
  [![License](https://img.shields.io/badge/License-GPL_2.0-blue.svg)](LICENSE)

</div>

## Overview

**S5Core** is a modern, lightweight, and extremely fast SOCKS5 server designed for high-load production environments. Written purely in Go, it features strict authentication, rate limiting, anti-bruteforce protection, zero-cost architecture with zero-allocation buffers, built-in observability with OpenTelemetry, **AES-256-GCM traffic obfuscation** that makes proxy traffic indistinguishable from random noise, and **full UDP relay support** that prevents WebRTC/DNS leaks.

S5Core can be run as a standalone executable via Docker/CLI or embedded directly into your own Go applications as an SDK Core (e.g., for building Web-UI proxy panels).

## Features

- **Traffic Obfuscation:** AES-256-GCM encryption with random padding on every frame. DPI systems cannot detect SOCKS5 signatures, domain names, or any protocol patterns on the wire.
- **UDP Relay & Anti-Leak Tunneling:** Full RFC 1928 UDP Associate (`0x03`) support. Additionally, `s5client` automatically tunnels all UDP traffic (WebRTC, DNS, QUIC) inside the obfuscated TCP connection via a custom command (`0x83`), making UDP leak attacks impossible.
- **Client & Server Architecture:** Includes `s5client` — a local proxy that accepts plain SOCKS5 and tunnels traffic through an encrypted obfuscation layer to the S5Core server.
- **Domain-Based Routing (Split Tunneling):** Route only specific domains or wildcards (e.g., `*.google.com`) through the encrypted tunnel.
- **Configurable MTU:** Control frame sizes to match your network topology and avoid fragmentation.
- **High Performance:** Uses `sync.Pool` for buffer reuse during I/O operations, practically eliminating Garbage Collector pauses.
- **SDK & Core Architecture:** Extracted core logic into `pkg/s5server`, allowing any external Go app to import S5Core, manage proxies programmatically, and hot-add/remove users or whitelists on the fly.
- **Built-in Fail2Ban:** In-memory tracking of authentication failures. Temporarily blocks IPs/Users attempting to bruteforce credentials.
- **Agnostic Observability:** Uses OpenTelemetry (`go.opentelemetry.io/otel`). Send metrics seamlessly to Prometheus, Datadog, Jaeger, or any OTel-compatible backend.
- **Rate Limiting:** Global connection limits (`netutil.LimitListener`) to protect your server from File Descriptor exhaustion and OOM errors.
- **I/O Deadlines (Slowloris Protection):** Strict Read/Write timeouts on raw TCP sockets prevent stale connections from draining resources.
- **Security First:** Authentication enabled by default, regex-based destination FQDN filtering, and strict IP Whitelisting.

---

## Traffic Obfuscation

S5Core implements a custom obfuscation layer inspired by [AmneziaWG](https://amnezia.org/), [XTLS Vision](https://github.com/XTLS/Xray-core), and [Hysteria v2 Salamander](https://hysteria.network/). The obfuscation wraps every TCP frame with AES-256-GCM encryption and random-length padding, making traffic indistinguishable from random noise.

### How It Works

```
TCP: App → s5client (plain SOCKS5) → [AES-256-GCM + random padding] → s5core → [decrypt] → SOCKS5 → Internet
                localhost:1080              encrypted tunnel (noise)        server:1443

UDP: App → s5client (UDP Associate) → [UDP-over-TCP mux + AES-256-GCM] → s5core → [demux] → UDP → Internet
                localhost:1080              same encrypted tunnel            server:1443
```

- **Client ISP sees:** random encrypted bytes to the server IP — no SOCKS5 signatures, no domains, no HTTP keywords.
- **Server ISP sees:** random encrypted bytes from the client IP — indistinguishable from banking app traffic with certificate pinning.

### Wire Protocol

Each frame on the wire:
```
[Frame Size (4B)] [Nonce (12B)] [AES-256-GCM Ciphertext]
                                 └─ encrypts: [PayloadLen (2B)] [Payload] [PaddingLen (2B)] [Random Padding]
```

### Measured Results (from automated tests)

The following data is captured by our integration benchmarks that test raw TCP throughput and connection latency:

#### Connection Performance

| Metric | Plain (No Obfuscation) | Obfuscated (AES-256-GCM) |
|--------|------------------------|--------------------------|
| **Throughput (1MB Stream)** | ~400 – 500 MB/s | ~30 – 35 MB/s |
| **Handshake Latency** | ~110 – 130 µs | ~160 – 190 µs |

> **Note on Performance:** The obfuscation throughput of ~35 MB/s (approx 280 Mbps) is more than sufficient for modern VPS connections. The handshake overhead is virtually negligible (~50 microseconds difference) compared to real-world internet routing latency (20–100+ ms).

#### Shannon Entropy (bits/byte)

| Data | Plain | Obfuscated |
|------|-------|------------|
| SOCKS5 Greeting | **1.58** | **6.75** |
| SOCKS5 CONNECT | **3.84** | **5.45** |
| HTTP Request | **4.32** | **6.75** |

> Theoretical maximum: 8.0 bits/byte (perfectly random). Plain SOCKS5 at 1.58 bits/byte is trivially detectable by DPI.

#### DPI Signature Detection

| Check | Result |
|-------|--------|
| SOCKS5 signature `0x050100` on wire | ❌ **Not found** |
| HTTP keyword on wire | ❌ **Not found** |
| Domain name `example.com` on wire | ❌ **Not found** |

---

## Authentication & Multi-Account Management

S5Core utilizes a high-performance, lock-free JSON user store capable of tracking per-user traffic limits without impacting the hot path.

By defining an optional `USERS_FILE`, you can enable multi-account support with expiration dates and traffic quotas. If no file is provided, S5Core falls back to the legacy `PROXY_USER`/`PROXY_PASSWORD` environment variables.

### Example `users.json`

```json
{
  "users": [
    {
      "id": "u-001",
      "username": "premium_user",
      "password": "secure123",
      "comment": "100GB limit, expires in 2027",
      "valid_until": "2027-01-01T00:00:00Z",
      "traffic_limit_bytes": 107374182400,
      "traffic_used_bytes": 0,
      "enabled": true
    },
    {
      "id": "u-002",
      "username": "unlimited_user",
      "password": "anotherpassword",
      "enabled": true
    }
  ]
}
```

> **Hot Reloading:** Send `SIGHUP` to the S5Core process to reload `users.json` on the fly without dropping connections! Traffic metrics are preserved and merged during reload.

---

## Architecture

S5Core consists of two binaries:

| Binary | Role | Description |
|--------|------|-------------|
| `s5core` | **Server** | SOCKS5 proxy with optional obfuscation layer. Deployed on the remote server. |
| `s5client` | **Client** | Local SOCKS5 proxy that wraps traffic in an obfuscation tunnel. Runs on the user's machine. |

### Without Obfuscation (Standard Mode)
```
TCP: App → s5core:1080 (plain SOCKS5) → Internet
UDP: App → s5core:1080 (UDP Associate) → s5core (UDP relay) → Internet
```

### With Obfuscation (Dual-Port Mode)
```
TCP: App → s5client:1080 → [encrypted tunnel] → s5core:1443 → Internet
UDP: App → s5client:1080 → [UDP-over-TCP mux] → s5core:1443 → Internet   ← no UDP leaks!
```

> **Important:** When obfuscation is enabled, the server listens on **two ports simultaneously**:  
> - `PROXY_PORT` (default `1080`) — plain SOCKS5 for direct/local connections  
> - `OBFS_PORT` (default `1443`) — obfuscated connections from `s5client` only  

---

## SDK Usage (Embedding in your Go App)

S5Core is built to be the networking engine for your custom proxy managers or Web-UIs. You can import it and control the proxy programmatically.

```go
package main

import (
	"context"
	"log/slog"
	
	"github.com/mazixs/S5Core/pkg/s5server"
)

func main() {
	cfg := s5server.DefaultConfig()
	cfg.Port = "1080"
	cfg.RequireAuth = true
	// Enable modern user store
	cfg.UsersFile = "users.json"
	cfg.TrafficFlushInterval = 30 * time.Second

	// Enable obfuscation
	cfg.ObfsEnabled = true
	cfg.ObfsPort = "1443"
	cfg.ObfsPSK = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH" // 32 bytes
	cfg.ObfsMaxPadding = 256
	cfg.ObfsMTU = 1400

	// Initialize the server
	srv, err := s5server.NewServer(cfg)
	if err != nil {
		panic(err)
	}

	// Update whitelisted IPs on the fly
	srv.UpdateWhitelist([]string{"192.168.1.100"})

	// Start the server (blocks until context is canceled)
	slog.Info("Starting S5Core SDK...")
	if err := srv.Start(context.Background()); err != nil {
		panic(err)
	}
}
```

---

## Standalone Configuration (Environment Variables)

When running the standalone binary or Docker image, configuration is entirely driven by environment variables.

### Server (`s5core`)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `USERS_FILE` | String | *Empty* | Path to `users.json`. Enables multi-account support with quotas. |
| `PROXY_PORT` | String | `1080` | Port to listen for SOCKS5 connections. |
| `PROXY_LISTEN_IP` | String | `0.0.0.0` | IP address to bind the proxy server to. |
| `REQUIRE_AUTH` | Boolean | `true` | Enforce Username/Password authentication. Highly recommended. |
| `PROXY_USER` | String | *Empty* | Legacy: Username for proxy authentication. Overridden by `USERS_FILE`. |      
| `PROXY_PASSWORD` | String | *Empty* | Legacy: Password for proxy authentication. Overridden by `USERS_FILE`. |  
| `ALLOWED_IPS` | String | *Empty* | Comma-separated list of IP addresses allowed to connect to the proxy. |   
| `ALLOWED_DEST_FQDN` | String | *Empty* | Regex pattern to filter allowed destination FQDNs. Empty allows all destinations. |
| `READ_TIMEOUT` | Duration | `30s` | Maximum duration before a read operation times out. |
| `WRITE_TIMEOUT` | Duration | `30s` | Maximum duration before a write operation times out. |
| `MAX_CONNECTIONS` | Integer | `10000` | Global limit for concurrent active connections. |
| `FAIL2BAN_RETRIES` | Integer | `5` | Number of failed auth attempts before temporarily banning a user. Set to 0 to disable. |
| `FAIL2BAN_TIME` | Duration | `5m` | How long a user/IP is banned after failing authentication. |
| `TRAFFIC_FLUSH_INTERVAL` | Duration | `30s` | Interval to flush user traffic metrics to disk (if `USERS_FILE` is used). |
| `METRICS_PORT` | String | `8080` | Port to expose OpenTelemetry/Prometheus `/metrics` and `/health` endpoints. |
| `OBFS_ENABLED` | Boolean | `false` | Enable traffic obfuscation on a separate port. |
| `OBFS_PORT` | String | `1443` | Separate port for obfuscated connections from `s5client`. |
| `OBFS_PSK` | String | *Empty* | Pre-shared key for obfuscation. **Must be exactly 32 bytes.** |
| `OBFS_MAX_PADDING` | Integer | `256` | Maximum random padding per frame (bytes). Higher = more noise, more overhead. |
| `OBFS_MTU` | Integer | `1400` | Maximum transmission unit for obfuscated frames. Set below your network MTU to avoid fragmentation. |

### Client (`s5client`)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `CLIENT_LISTEN_ADDR` | String | `127.0.0.1:1080` | Local address to accept plain SOCKS5 connections. |
| `SERVER_ADDR` | String | *Required* | Remote S5Core server obfs address (e.g., `1.2.3.4:1443`). |
| `PROXY_USER` | String | *Empty* | Username for authenticating with the S5Core server. |
| `PROXY_PASS` | String | *Empty* | Password for authenticating with the S5Core server. |
| `OBFS_PSK` | String | *Required* | Pre-shared key. **Must match the server's PSK exactly.** |
| `OBFS_MAX_PADDING` | Integer | `256` | Must match the server configuration. |
| `OBFS_MTU` | Integer | `1400` | Must match the server configuration. |
| `ROUTE_DOMAINS` | String | *Empty* | Comma-separated domain patterns for split tunneling. Empty = tunnel all traffic. |

> **UDP support:** `s5client` transparently handles UDP Associate requests from applications. When an app sends a SOCKS5 UDP Associate command (`0x03`), `s5client` opens a local UDP socket, multiplexes all UDP packets inside the encrypted TCP tunnel (command `0x83`), and the server relays them to the internet as native UDP. No additional configuration is needed.

> **Domain routing examples:** `example.com` (exact match), `*.google.com` (all subdomains + base domain), `*.youtube.com,*.googlevideo.com` (multiple patterns).

*Note on durations:* Use standard Go duration strings like `30s`, `1m`, `1.5h`.

---

## Getting Started

### Using Docker (Recommended)

You can spin up the S5Core proxy in seconds using Docker. The images are built on distroless static scratch images, guaranteeing minimal footprint and maximum security.

#### Basic Usage (With Authentication)
```bash
docker run -d \
  --name s5core \
  -p 1080:1080 \
  -e PROXY_USER=myuser \
  -e PROXY_PASSWORD=mypassword \
  ghcr.io/mazixs/s5core:latest
```

#### With Obfuscation
```bash
docker run -d \
  --name s5core \
  -p 1080:1080 \
  -p 1443:1443 \
  -e PROXY_USER=myuser \
  -e PROXY_PASSWORD=supersecure \
  -e OBFS_ENABLED=true \
  -e OBFS_PORT=1443 \
  -e OBFS_PSK=AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH \
  -e OBFS_MAX_PADDING=256 \
  -e OBFS_MTU=1400 \
  ghcr.io/mazixs/s5core:latest
```

Then on the client machine, run the local proxy:
```bash
SERVER_ADDR=your-server-ip:1443 \
OBFS_PSK=AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH \
ROUTE_DOMAINS="*.google.com,*.youtube.com" \
./s5client
```

#### Advanced Usage (With Whitelisting, Limits and Metrics)
```bash
docker run -d \
  --name s5core \
  -p 1080:1080 \
  -p 8080:8080 \
  -e PROXY_USER=myuser \
  -e PROXY_PASSWORD=supersecure \
  -e ALLOWED_IPS=192.168.1.10,10.0.0.5 \
  -e MAX_CONNECTIONS=5000 \
  -e FAIL2BAN_RETRIES=3 \
  -e FAIL2BAN_TIME=15m \
  ghcr.io/mazixs/s5core:latest
```

### Using Docker Compose
Create a `.env` file based on `.env.example` and run:
```bash
docker compose up -d
```

#### Routing Another Service Through S5Core
You can easily route traffic of another Docker container through S5Core without exposing it to the host network. This is useful when you want to anonymize or proxy a specific application.

```yaml
services:
  s5core:
    # Image is automatically pulled from GitHub Packages
    image: ghcr.io/mazixs/s5core:latest
    restart: always
    ports:
      - "1080:1080"
    environment:
      - REQUIRE_AUTH=false # Disable auth for internal network, or use PROXY_USER/PROXY_PASSWORD
      - MAX_CONNECTIONS=5000

  my_app:
    image: curlimages/curl
    command: ["curl", "-s", "https://ipinfo.io"]
    environment:
      # Tell the application to use the S5Core SOCKS5 proxy
      - HTTP_PROXY=socks5://s5core:1080
      - HTTPS_PROXY=socks5://s5core:1080
      - ALL_PROXY=socks5://s5core:1080
    depends_on:
      - s5core
```

---

## Monitoring & Metrics

S5Core utilizes OpenTelemetry. By default, the standalone app runs an OTel Prometheus exporter. If `METRICS_PORT` is set (default `8080`), it exposes metrics at `http://<IP>:8080/metrics`.

Available metrics:
- `s5core_connections_active` (UpDownCounter): Current number of active TCP sessions.
- `s5core_connections_total` (Counter): Total number of accepted connections since start.
- `s5core_auth_failures_total` (Counter): Total number of failed authentication attempts.
- `s5core_traffic_bytes_in` (Counter): Total volume of incoming traffic in bytes (TCP + UDP).
- `s5core_traffic_bytes_out` (Counter): Total volume of outgoing traffic in bytes (TCP + UDP).

> **Note:** UDP traffic flowing through the standard UDP Associate relay is tracked with batched counters (flushed every 1 MB) to minimize performance overhead. UDP traffic tunneled via `s5client` (command `0x83`) is automatically counted as TCP bytes since it flows through the obfuscated TCP connection.

You can also use `http://<IP>:8080/health` as a readiness/liveness probe for your orchestration systems (e.g., Kubernetes).

---

## Hot Reloading

You can update specific configuration parameters without restarting the S5Core standalone process or breaking existing connections.
Currently supports hot-reloading for: `ALLOWED_IPS`, `READ_TIMEOUT`, and `WRITE_TIMEOUT`.

**How to reload:**
1. Update your `.env` file or environment variables.
2. Send a `SIGHUP` signal to the process:
```bash
kill -HUP $(pgrep s5core)
```
*If running in Docker:*
```bash
docker kill -s HUP s5core
```

---

## Testing the Proxy

**With cURL (no obfuscation):**
```bash
curl --socks5 <PROXY_IP>:1080 -U myuser:mypassword https://ipinfo.io
```

**With obfuscation (via s5client):**
```bash
# Terminal 1: Start local client
SERVER_ADDR=<PROXY_IP>:1443 OBFS_PSK=AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH ./s5client

# Terminal 2: Use it as a regular SOCKS5 proxy
curl --socks5 127.0.0.1:1080 https://ipinfo.io
```

**Testing UDP relay (DNS over SOCKS5):**
```bash
# Via s5client — DNS traffic tunneled through encrypted TCP
proxychains4 dig @1.1.1.1 example.com

# Or with direct UDP Associate (no obfuscation)
proxychains4 -f /etc/proxychains-udp.conf dig @8.8.8.8 example.com
```

> **WebRTC leak test:** After configuring your browser to use `s5client` as SOCKS5 proxy (with remote DNS), visit [browserleaks.com/webrtc](https://browserleaks.com/webrtc). With UDP tunneling enabled, your real IP should not appear in any WebRTC candidates.

### Helper Scripts

We provide practical bash scripts in the `scripts/` directory to help you test and manage the proxy:

- **`check_proxy.sh`**: A comprehensive health-check script that automatically tests TCP connectivity, proxy authentication, retrieves IP Geo-information, checks Prometheus endpoints, and validates DNS resolution behavior.
- **`vpn_test.sh`**: Creates a **full transparent VPN** using `tun2socks`. It intercepts all L3 traffic (TCP and UDP) on your system using a `tun0` interface, routes it to the local `s5client`, and encrypts it through the obfs tunnel to the server. This guarantees 100% protection against WebRTC, UDP, and DNS leaks without manual application configuration. Ensure you edit the config variables at the top of the scripts before running them!

---

## License

This project is licensed under the GNU General Public License v2.0 (GPL-2.0) - see the [LICENSE](LICENSE) file for details.

---
*Based on the foundational work by Sergey Bogayrets and the go-socks5 community, highly optimized and refactored for modern high-load deployments and SDK integration by the S5Core contributors.
https://github.com/serjs/socks5-server*
