# Testing the proxy

Start the server using the [quick start](../../README.md#quick-start).
If you use the optional `s5client` adapter described below, make a request in a
second terminal with destination DNS resolved through the proxy:

```bash
curl --fail --proxy socks5h://127.0.0.1:1080 https://example.com
```

For the Docker server's local plain SOCKS5 listener (default port 28173), use its credentials:

```bash
curl --fail --proxy socks5h://127.0.0.1:28173 --proxy-user USER:PASSWORD https://example.com
```

For UDP, run the project's echo probe on a controlled reachable destination:

```bash
# Destination machine, allowing UDP 9999 from the proxy server:
go run ./cmd/udpprobe -echo :9999
# Client machine, with s5client already running:
go run ./cmd/udpprobe -target ECHO_HOST:9999 -socks 127.0.0.1:1080 -n 100
```

Application proxy settings do not guarantee that WebRTC, UDP or system DNS use
the tunnel. Verify those paths separately using the
[leak matrix](../../scripts/leak_matrix.py) and your target application.

## Connect via s5client

This optional adapter exposes a local SOCKS5 endpoint and carries its traffic
over obfs or WSS. It is useful for applications or router setups that cannot
speak the encrypted transport directly. Other integrations do not need this
local listener.

Download `s5client` for your OS/architecture from the
[latest release](https://github.com/mazixs/S5Core/releases/latest), rename it to
`s5client`, and securely copy `.env.client` from the server to the same directory.
On Linux or macOS:

```bash
chmod 600 .env.client
chmod +x ./s5client
set -a
. ./.env.client
set +a
./s5client
```

In another terminal, test it and then configure your application to use
`127.0.0.1:1080` as SOCKS5 with remote DNS:

```bash
curl --fail --proxy socks5h://127.0.0.1:1080 https://example.com
```

The Docker server uses port 28173 for plain SOCKS5, so it does not conflict with
the client's default local port 1080. If another service occupies 1080, set
`CLIENT_LISTEN_ADDR=127.0.0.1:1081` and use port 1081 in the client test.
Windows and system-wide routing: [client/VPN guide](#windows-full-tunnel-s5vpn-winps1).

### Timing tests run on a fake clock

Read and write timeouts default to 30 seconds, so checking them the obvious way
costs 30 seconds of wall clock per assertion - which is why, for a long time,
nothing checked them. `pkg/s5server/timeouts_synctest_test.go` runs them inside
a `testing/synctest` bubble, where the clock is virtual: about 490 seconds and
one full day of simulated silence pass in roughly a millisecond, and every
assertion can be exact ("at 30s", not "somewhere after 29s").

```bash
go test -race -count=100 -run 'Timeout|Deadline' ./pkg/s5server/   # 100 repeats in ~1.4s
```

| Behaviour | Simulated wait | What it pins down |
|---|---|---|
| Read times out on a silent peer | 30 s | The idle timeout fires at the deadline, not near it |
| Write times out on a peer that stopped reading | 10 s | A stalled reader cannot pin a writer forever |
| The read deadline slides with every byte | 430 s | `ReadTimeout` is an idle timeout, not a cap on connection lifetime - a long download is safe, a long silence is not |
| Zero timeouts never expire | 24 h | `ReadTimeout=0` really means no deadline, and a late byte still arrives |
| `UpdateTimeouts` applies from the next accept | 30 s | "On the fly" means the next connection; running ones keep the values they were accepted with |

The third row is why keepalive matters: a tunnel that is legitimately quiet for
31 seconds is indistinguishable, to this layer, from a dead one.

The rule for new timing tests: `net.Pipe`, never a real socket. Pipe deadlines
are built on `time.AfterFunc` and follow the bubble clock, while a kernel
socket's timers know nothing about it.

### Helper Scripts

We provide practical helper scripts in the `scripts/` directory to help you test and manage the proxy:

- **`check_proxy.sh`**: A comprehensive health-check script that automatically tests TCP connectivity, proxy authentication, retrieves IP Geo-information, checks Prometheus endpoints, and validates DNS resolution behavior.
- **`vpn_test.sh`**: Creates a **full transparent VPN** using `tun2socks`. It intercepts all L3 traffic (TCP and UDP) on your system using a `tun0` interface, routes it to the local `s5client`, and encrypts it through the obfs tunnel to the server. Verify DNS, WebRTC and IPv6 routing on the target machine before relying on leak protection. Ensure you edit the config variables at the top of the scripts before running them!
- **`s5vpn-win.ps1`**: Windows 11 full-tunnel wrapper around `tun2socks` and local `s5client`. It builds `s5client`, creates a Wintun adapter, routes all IPv4 traffic through the local SOCKS endpoint, keeps the obfuscated hop between `s5client` and `s5core:28479`, disables physical IPv6 during the session, and restores the original routes on `stop`.

### Windows Full-Tunnel (`s5vpn-win.ps1`)

Use this when you want all Windows traffic to go through:

`apps -> Wintun -> tun2socks -> 127.0.0.1:1080 -> obfs -> s5core:28479`

This mode is intended for anti-leak operation: DNS, WebRTC/UDP, and regular TCP traffic are forced into the local tunnel instead of relying on per-app proxy settings.

#### Requirements

1. Install `tun2socks` on Windows, for example with `winget`:
   ```powershell
   winget install xjasonlyu.tun2socks
   ```
2. Make sure `wintun.dll` is present next to `tun2socks.exe`, or set `WintunDll` manually in the script.
3. Run PowerShell as Administrator.

#### Configure the Script

Set `ServerPort` to the actual server port (28479 for the Docker quick start).
Edit the config block at the top of [`scripts/s5vpn-win.ps1`](../../scripts/s5vpn-win.ps1):

```powershell
$Config = [ordered]@{
    ServerHost        = "YOUR_SERVER_IP"
    ServerPort        = 28479
    ObfsPsk           = "YOUR_32_BYTE_PSK_REPLACE_ME_1234"
    ObfsMaxPadding    = 256
    ObfsMtu           = 1400
    ProxyUser         = "YOUR_PROXY_USERNAME"
    ProxyPass         = "YOUR_PROXY_PASSWORD"
    ClientListenAddr  = "127.0.0.1:1080"
    TunName           = "wintun"
    TunIp             = "198.18.0.1"
    TunPrefixLength   = 15
    DnsServers        = @("1.1.1.1", "1.0.0.1")
    DisableIPv6       = $true
    RouteLanRanges    = $true
    AutoBuildS5Client = $true
    S5ClientExe       = (Join-Path $RepoRoot "build\s5client.exe")
    Tun2SocksExe      = ""
    WintunDll         = ""
}
```

Notes:
- Leave `Tun2SocksExe` empty to let the script auto-detect a `winget` installation.
- Leave `WintunDll` empty if `wintun.dll` is already next to `tun2socks.exe`.
- The `ObfsPsk` placeholder above is exactly 32 bytes long; replace it with your real PSK.

#### Commands

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\s5vpn-win.ps1 start
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\s5vpn-win.ps1 status
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\s5vpn-win.ps1 test
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\s5vpn-win.ps1 stop
```

What the script does:
- builds `s5client` from local source if needed;
- starts local SOCKS on `127.0.0.1:1080`;
- starts `tun2socks` on a Wintun adapter;
- pins the route to your server outside the tunnel;
- installs split default routes (`0.0.0.0/1` and `128.0.0.0/1`) so all other IPv4 traffic goes into the tunnel;
- removes the ordinary default route during the session and restores it on `stop`.

This keeps the obfuscation intact: `tun2socks` talks only to local `s5client`, and only `s5client` talks to the remote obfuscated port.

[Documentation index](../README.md) · [Project home](../../README.md)
