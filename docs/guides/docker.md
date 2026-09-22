# Docker deployment

The base Compose setup runs an authenticated obfs server on public TCP port
28479. Plain SOCKS5 and metrics are published only on host loopback.
Use Docker Engine with Compose v2+ on Linux. The image supports amd64 and arm64.

## Quick setup

From the repository root, on the server:

```bash
./scripts/init-env.sh server.example.com:28479
docker compose config --quiet
docker compose up -d
docker compose logs --tail=30
curl --fail http://127.0.0.1:8789/health
```

Replace the address with your server's reachable hostname or IP. Open that TCP
port in both host and provider firewalls. OpenSSL generates fresh credentials;
the script writes `.env` and `.env.client` with permissions `600`, never prints
secrets and refuses to overwrite either file. A custom port in the argument
sets both the server listener and client destination. `[IPv6]:28479` is accepted;
actual IPv6 reachability also depends on the host and Docker network.

If you use the optional `s5client` adapter, copy `.env.client` securely to the
client machine and follow the [adapter setup](testing.md#connect-via-s5client). Neither executable reads
dotenv files itself: Compose loads `.env` for the server, while the client example
exports its file into the process environment. Only source a file you trust.

Existing installations should keep their `.env`. Explicit port values still
win over the Compose defaults. If an older installation relied on implicit
ports, set `PROXY_PORT=1080`, `OBFS_PORT=1443` and `METRICS_PORT=8080`
before updating to keep them.
Otherwise update the client destination and firewall for the new ports.

## Manual configuration

```bash
cp .env.example .env
chmod 600 .env
openssl rand -hex 24
openssl rand -base64 24
```

Put the first generated value into `PROXY_PASSWORD` and the second into
`OBFS_PSK`. The PSK is **exactly 32 literal bytes**, not a base64-encoded 32-byte
key: `openssl rand -base64 24` produces the required 32 ASCII characters.
Use single quotes around manually supplied values containing `$` or `#`.
Copy `.env.client.example` to `.env.client` on the client and set the same
credentials (`PROXY_PASS` there), PSK and server address.

The minimal template deliberately leaves secrets empty. Missing credentials or
an invalid PSK stop server startup with a configuration error in the logs;
there is no shared default password. Run `docker compose config --quiet` for
syntax validation; it does not validate the application's credentials.

`OBFS_NODE_ID` is optional and commented out. Empty on both peers works. A node
ID binds key derivation to one node, which is useful when several servers share
a PSK. It is not a secret, registration token or generated server identity.
If set, copy the exact same value to each client. A mismatch causes tunnel
setup to fail. Migration uses `OBFS_ACCEPT_NODE_IDS` on the server; see the
[configuration reference](configuration.md).

For local plain SOCKS5 only, set `OBFS_ENABLED=false`; a PSK is then unnecessary
unless WSS is enabled. Do not expose unencrypted SOCKS5 over an untrusted network.

## Port selection

Docker defaults are TCP **28173** for plain SOCKS5 (host loopback only) and
TCP **28479** for obfs. These are fixed defaults, not randomly reassigned on
restart. Both were unassigned in the
[IANA registry](https://www.iana.org/assignments/service-names-port-numbers/)
when checked on 2026-09-22. They can still be occupied by a local application;
choose different `PROXY_PORT` / `OBFS_PORT` values if needed. Changing a port
does not make the service invisible to scanning.

These Docker settings do not change the standalone binaries' built-in defaults
or the optional `s5client` local listener.

## Defaults and overrides

| Setting | Default in this setup | Reason / when to change |
| --- | --- | --- |
| Authentication | Required; generated password | Use persistent accounts for per-user keys and quotas |
| Public listener | obfs TCP 28479 | Use WSS when TLS transport is needed |
| Plain SOCKS / metrics | Host `127.0.0.1:28173` / `127.0.0.1:8789` | Do not publish administrative metrics publicly |
| Container listener addresses | `0.0.0.0`, managed by Compose | Port publishing cannot reach container loopback |
| Restart | `unless-stopped` | Recover after failure/reboot; honor an explicit stop |
| Shutdown grace | 30 seconds | Give the process time to close sessions and flush account usage |
| Logs | Docker `local`, 3 x 10 MiB | Bound log storage; readable with `docker compose logs` |
| Container privileges | UID 65532, read-only root, no capabilities, no new privileges | Only the account data mount needs writes |
| Limits | 10000 connections; 256 MiB KDF budget | These are ceilings, not a promise that every host can sustain that load |
| Relay timeouts | 30 seconds idle; 15 seconds setup | Active traffic refreshes idle timeouts |
| Keepalive | Client 10-20 seconds; server off | Keep an idle tunnel alive without duplicate heartbeat traffic |
| Framing | MTU 1400, padding up to 256, no WS jitter | Keep the measured application defaults; tune against your real path |

Optional variables use the binary's built-in defaults when absent. The
[full reference](configuration.md) separates server and client settings so a
client-only flag is not mistaken for a server option. For a small VPS, start
with a lower `MAX_CONNECTIONS` (for example 1024) and size
`KDF_MEMORY_BUDGET_MB` alongside RAM needed for connections and the OS. One
concurrent Argon2id check needs 64 MiB. Do not impose a generic container RAM
limit below the authentication budget.

Compose synchronizes `PROXY_PORT`, `OBFS_PORT` and `METRICS_PORT` between the
container and host, including shell overrides. Other settings come from `.env`;
merely exporting an arbitrary variable in the host shell does not replace a
service's `env_file` value. To use a different server file, set both Compose's
interpolation input and service env file (the latter is `.env` in the base file).

Containers on the same Docker network can reach plain SOCKS5 and metrics at the
service address. Host-loopback publishing does not isolate them from that network.
For another application container, configure its SOCKS support with
`socks5h://USER:PASSWORD@s5core:28173` on a shared trusted network. Application
support for `ALL_PROXY` varies. Do not disable authentication for this shortcut.

## WSS on port 443

Prepare a TLS certificate for your hostname. Put `fullchain.pem` and `privkey.pem`
in a directory readable by UID/GID `65532:65532`; the key must not be public.
Include any symlink targets inside the mounted directory. Add to `.env`:

```dotenv
S5CORE_CERTS_DIR=./certs
WS_PORT=443
```

```bash
docker compose -f docker-compose.yml -f docker-compose.wss.yml up -d
```

The override mounts certificates read-only and listens on container port 8443,
so it needs no privileged-port capability. It requires the same 32-byte
`OBFS_PSK`. Open TCP 443 in the firewall. On the client set:

```dotenv
WS_URL=wss://server.example.com/ws
TRANSPORT=ws
```

The certificate must match the hostname. For a private CA, configure `WS_CA_FILE`
on the client. Obfs remains enabled too unless `.env` sets `OBFS_ENABLED=false`.
Certificate renewal requires recreating/restarting the service to reload the
key pair. Missing certificate directories fail instead of being auto-created.

## Persistent accounts

Prepare `users.json` using the [account format](accounts.md#example-usersjson).
Mount the whole directory, because updates use a temporary file and atomic
rename. For initial setup with the default nonroot image:

```bash
sudo install -d -o 65532 -g 65532 -m 750 ./data
sudo install -o 65532 -g 65532 -m 600 users.json ./data/users.json
```

Set `S5CORE_DATA_DIR=./data` in `.env`, then run:

```bash
docker compose -f docker-compose.yml -f docker-compose.users.yml up -d
```

The override sets `USERS_FILE=/var/lib/s5core/users.json` and requires
authentication. Accounts in the file replace the single env account; client
credentials must match one of those accounts. The data mount remains writable
with a read-only container root. Back up the directory and do not rerun the
initial `install` commands over existing traffic data. Rootless Docker or user
namespace remapping may require different host ownership for container UID 65532.

Both overrides can be combined with all three `-f` arguments. Use the same file
list for `up`, `pull`, `logs` and `down`.

## Updates and local builds

```bash
docker compose pull
docker compose up -d
```

The base service follows `ghcr.io/mazixs/s5core:latest`. It does not build source.
To run your checkout, create `compose.local.yml`:

```yaml
services:
  s5core:
    image: s5core:local
    build:
      context: .
    pull_policy: never
```

```bash
docker compose -f docker-compose.yml -f compose.local.yml up -d --build
```

Keep this local override out of Git (for example in `.git/info/exclude`). The
Dockerfile uses native Go cross-compilation for the release targets amd64/arm64,
a separate dependency layer and a BuildKit compilation cache. The runtime is
still distroless/nonroot, with no shell or package manager.

## Checks and troubleshooting

| Symptom | Check |
| --- | --- |
| Container keeps restarting | `docker compose logs --tail=50`; check credentials, PSK length and port conflicts |
| Health responds, client does not connect | Check the firewall, public address, matching PSK/node ID, client credentials and clocks |
| Client cannot bind port 1080 | Another local service uses it; set `CLIENT_LISTEN_ADDR=127.0.0.1:1081` |
| WSS fails | Check certificate name, expiry, mount permissions and `WS_URL` path |
| Accounts do not persist | Check directory ownership and writable bind mount, not just file permissions |
| Idle connections drop | Keep the client keepalive interval below the shortest path idle timeout |

`/health` is HTTP liveness, not an authenticated tunnel test. The image has no
Docker HEALTHCHECK; container state `running` alone is not proof of connectivity.
Verify an actual request through `s5client`, including DNS (`socks5h://`).
Changing `.env` requires `docker compose up -d`; a restart or SIGHUP does not
replace an existing container's environment. File-based reload options are in
[operations](operations.md).

Docker references: [environment interpolation](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/),
[local log rotation](https://docs.docker.com/engine/logging/drivers/local/),
[build cache](https://docs.docker.com/build/cache/optimize/),
[cross-compilation](https://docs.docker.com/build/building/multi-platform/#cross-compilation).

[Documentation index](../README.md)
