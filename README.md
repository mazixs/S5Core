<div align="center">
  <h1>S5Core</h1>
  <p><strong>A High-Performance, Production-Ready SOCKS5 Proxy Server & Go SDK</strong></p>

  [![Latest Release](https://github.com/mazixs/S5Core/workflows/Latest%20tag%20from%20master%20branch/badge.svg)](https://github.com/S5Core/S5Core/actions)
  [![Go Report Card](https://goreportcard.com/badge/github.com/S5Core/S5Core)](https://goreportcard.com/report/github.com/S5Core/S5Core)
  [![License](https://img.shields.io/badge/License-GPL_2.0-blue.svg)](LICENSE)

</div>

## Overview

**S5Core** is a modern, lightweight, and extremely fast SOCKS5 server designed for high-load production environments. Written purely in Go, it features strict authentication, rate limiting, anti-bruteforce protection, zero-cost architecture with zero-allocation buffers, and built-in observability with OpenTelemetry.

S5Core can be run as a standalone executable via Docker/CLI or embedded directly into your own Go applications as an SDK Core (e.g., for building Web-UI proxy panels).

## Features

- **High Performance:** Uses `sync.Pool` for buffer reuse during I/O operations, practically eliminating Garbage Collector pauses.
- **SDK & Core Architecture:** Extracted core logic into `pkg/s5server`, allowing any external Go app to import S5Core, manage proxies programmatically, and hot-add/remove users or whitelists on the fly.
- **Built-in Fail2Ban:** In-memory tracking of authentication failures. Temporarily blocks IPs/Users attempting to bruteforce credentials.
- **Agnostic Observability:** Uses OpenTelemetry (`go.opentelemetry.io/otel`). Send metrics seamlessly to Prometheus, Datadog, Jaeger, or any OTel-compatible backend.
- **Rate Limiting:** Global connection limits (`netutil.LimitListener`) to protect your server from File Descriptor exhaustion and OOM errors.
- **I/O Deadlines (Slowloris Protection):** Strict Read/Write timeouts on raw TCP sockets prevent stale connections from draining resources.
- **Security First:** Authentication enabled by default, regex-based destination FQDN filtering, and strict IP Whitelisting.

---

## SDK Usage (Embedding in your Go App)

S5Core is built to be the networking engine for your custom proxy managers or Web-UIs. You can import it and control the proxy programmatically.

```go
package main

import (
	"context"
	"log/slog"
	
	"github.com/S5Core/S5Core/pkg/s5server"
)

func main() {
	cfg := s5server.DefaultConfig()
	cfg.Port = "1080"
	cfg.RequireAuth = true

	// Initialize the server
	srv, err := s5server.NewServer(cfg)
	if err != nil {
		panic(err)
	}

	// Add users dynamically (e.g., from your database or Web-UI)
	srv.AddUser("admin", "secret")

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

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `PROXY_PORT` | String | `1080` | Port to listen for SOCKS5 connections. |
| `PROXY_LISTEN_IP` | String | `0.0.0.0` | IP address to bind the proxy server to. |
| `REQUIRE_AUTH` | Boolean | `true` | Enforce Username/Password authentication. Highly recommended. |
| `PROXY_USER` | String | *Empty* | Username for proxy authentication. Required if `REQUIRE_AUTH=true`. |      
| `PROXY_PASSWORD` | String | *Empty* | Password for proxy authentication. Required if `REQUIRE_AUTH=true`. |  
| `ALLOWED_IPS` | String | *Empty* | Comma-separated list of IP addresses allowed to connect to the proxy. |   
| `ALLOWED_DEST_FQDN` | String | *Empty* | Regex pattern to filter allowed destination FQDNs. Empty allows all destinations. |
| `READ_TIMEOUT` | Duration| `30s` | Maximum duration before a read operation times out. |
| `WRITE_TIMEOUT`| Duration| `30s` | Maximum duration before a write operation times out. |
| `MAX_CONNECTIONS`| Integer | `10000` | Global limit for concurrent active connections. |
| `FAIL2BAN_RETRIES`| Integer | `5` | Number of failed auth attempts before temporarily banning a user. Set to 0 to disable. |
| `FAIL2BAN_TIME` | Duration| `5m` | How long a user/IP is banned after failing authentication `FAIL2BAN_RETRIES` times. |
| `METRICS_PORT` | String | `8080` | Port to expose OpenTelemetry/Prometheus `/metrics` and `/health` endpoints. Set to empty string to disable. |                                                                                        
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
  s5core/s5core
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
  s5core/s5core
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
    # Вариант 1: Сборка из локальной директории (если вы скачали этот репозиторий)
    build: .
    # Вариант 2: Прямая сборка из репозитория GitHub (если вы не качали код)
    # build: https://github.com/mazixs/S5Core.git#master
    image: s5core/s5core:latest
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
- `s5core_traffic_bytes_in` (Counter): Total volume of incoming traffic in bytes.
- `s5core_traffic_bytes_out` (Counter): Total volume of outgoing traffic in bytes.

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

**With cURL:**
```bash
curl --socks5 <PROXY_IP>:1080 -U myuser:mypassword https://ipinfo.io
```

**Using a Dockerized cURL:**
```bash
docker run --rm curlimages/curl:latest -s --socks5 myuser:mypassword@<PROXY_IP>:1080 https://ipinfo.io
```

---

## License

This project is licensed under the GNU General Public License v2.0 (GPL-2.0) - see the [LICENSE](LICENSE) file for details.

---
*Based on the foundational work by Sergey Bogayrets and the go-socks5 community, highly optimized and refactored for modern high-load deployments and SDK integration by the S5Core contributors.
https://github.com/serjs/socks5-server*
