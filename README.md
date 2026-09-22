<div align="center">

# S5Core

**SOCKS5 proxy server and Go SDK with optional encrypted transports.**

[![CI](https://github.com/mazixs/S5Core/actions/workflows/ci.yml/badge.svg)](https://github.com/mazixs/S5Core/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/mazixs/S5Core)](https://github.com/mazixs/S5Core/releases/latest)
[![License](https://img.shields.io/badge/License-GPL_2.0-blue.svg)](LICENSE)

[Quick start](#quick-start) · [Documentation](docs/README.md) · [Configuration](docs/guides/configuration.md) · [Releases](https://github.com/mazixs/S5Core/releases)

</div>

S5Core runs as a standalone proxy server or as part of a Go application.
Clients can connect directly over SOCKS5 or use the obfs/WSS transports through
a compatible implementation. The bundled `s5client` is an optional adapter for
applications that need a local SOCKS5 endpoint.

| Capability | What you get |
| --- | --- |
| Encrypted transports | AES-256-GCM or ChaCha20-Poly1305, padding, optional WebSocket over TLS |
| TCP and UDP | SOCKS5 CONNECT and UDP Associate; the client carries UDP inside the tunnel |
| Access control | Passwords or individual tunnel keys, account quotas, expiry and source restrictions |
| Operations | Prometheus metrics, structured logs, configuration reload and persistent account usage |
| Go integration | Embed the server and manage accounts through the [SDK](docs/guides/sdk.md) |

Obfuscation does not guarantee resistance to every classifier. Applications must
actually use the proxy; system-wide routing needs a [full-tunnel setup](docs/guides/testing.md#helper-scripts).

## Quick start

### 1. Start the server

Requires Docker Engine with Compose v2+ and OpenSSL. Run on a Linux server;
replace `YOUR_SERVER_IP` with its reachable address. Allow inbound TCP **28479**
in the host firewall and provider firewall.

```bash
git clone https://github.com/mazixs/S5Core.git
cd S5Core
./scripts/init-env.sh YOUR_SERVER_IP:28479
docker compose up -d
docker compose logs --tail=30
curl --fail http://127.0.0.1:8789/health
```

The setup script generates a random password and a 32-character PSK, then writes
`.env` and `.env.client` with owner-only permissions. It refuses to replace existing
files. Plain SOCKS5 (**28173**) and metrics (**8789**) are published on host loopback;
only the encrypted obfs port is public. `/health` checks the metrics HTTP service;
verify the complete proxy path using your chosen client.

### 2. Choose how to connect

| Connection | When to use it |
| --- | --- |
| Direct SOCKS5 | Your application supports SOCKS5 and can reach the server over a trusted network |
| obfs / WSS | Your client or integration implements the [encrypted transport](docs/veil-spec.md) |
| Local SOCKS5 via `s5client` | An application needs an adapter to reach the encrypted transport; see the [optional client setup](docs/guides/testing.md#connect-via-s5client) |

The Docker quick start exposes obfs publicly. Direct SOCKS5 access depends on
your network setup; it is published on host loopback by default. A local listener
on port 1080 is specific to the `s5client` setup, not required by S5Core.

### 3. Update

```bash
docker compose pull
docker compose up -d
```

Keep the generated credentials. The image follows `latest`; updating the Git
checkout alone does not update the running container. Use the same Compose
`-f` arguments for updates if you enable an override.

## Choose your setup

| Need | Next step |
| --- | --- |
| HTTPS / WSS on port 443 | [Certificates and WSS](docs/guides/docker.md#wss-on-port-443) |
| Multiple users and persistent quotas | [Account storage](docs/guides/docker.md#persistent-accounts) |
| Manual env configuration or a local image build | [Docker deployment](docs/guides/docker.md) |
| Timeouts, node IDs, limits or client routing | [Configuration reference](docs/guides/configuration.md) |
| Metrics, reload and shutdown | [Operations](docs/guides/operations.md) |
| Performance evidence | [Measured results](docs/benchmarks/results.md), [WAN comparison](docs/benchmarks/wan-2026-09-22/README.md) |
| Protocol and implementation details | [Documentation index](docs/README.md) |

**Upgrading from 1.x:** update clients before servers. See the
[migration guide](docs/field/migration.md) and [changelog](CHANGELOG.md).
The generated client config targets current servers with `OBFS_FORMAT=v1`.

## Credits

- [armon/go-socks5](https://github.com/armon/go-socks5) - the original SOCKS5 implementation, now maintained as an extended internal fork.
- [serjs/socks5-server](https://github.com/serjs/socks5-server) - the starting point for the standalone server configuration and destination filtering.

## License

[GPL-2.0](LICENSE). Third-party license notices are preserved in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [internal/socks5/LICENSE](internal/socks5/LICENSE).
