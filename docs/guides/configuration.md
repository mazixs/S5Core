# Standalone Configuration (Environment Variables)

Both executables read process environment variables, not dotenv files directly.
Compose loads the server's `.env`; see [Docker deployment](docker.md) for setup.
The tables below list **binary defaults**. The quick-start template additionally
enables obfs and the generator supplies credentials. Omitted options use these
defaults, so they do not need to be copied into every `.env`.

`OBFS_NODE_ID` is optional: leave it absent on both peers for a single-server
setup. If you configure one, the exact same value must be present on the client.
It is a key-derivation context, not a registration or provisioning step.

### Server (`s5core`)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `USERS_FILE` | String | *Empty* | Path to `users.json`. Enables multi-account support with quotas. |
| `PROXY_PORT` | String | `1080` | Port to listen for SOCKS5 connections. |
| `PROXY_LISTEN_IP` | String | `0.0.0.0` | IP address to bind the proxy server to. |
| `REQUIRE_AUTH` | Boolean | `true` | Enforce Username/Password authentication. Highly recommended. |
| `PROXY_USER` | String | *Empty* | Legacy: Username for proxy authentication. Overridden by `USERS_FILE`. |
| `PROXY_PASSWORD` | String | *Empty* | Legacy: Password for proxy authentication. Overridden by `USERS_FILE`. |
| `PROXY_PASS` | String | *Empty* | Alias for `PROXY_PASSWORD`, which is what the client calls it. Accepted with a warning so that an `.env` copied from the client still starts the server; `PROXY_PASSWORD` wins if both are set. |
| `ALLOWED_IPS` | String | *Empty* | Comma-separated list of client IP addresses allowed to connect, on every listener. Single addresses only, v4 or v6: a network in CIDR form is refused by name, as is any entry that is not an address, and the server does not start. Empty means no restriction - which is why a list that cannot be read is an error rather than an empty list. On the WebSocket transport it gates the tunnel, not the decoy site: the decoy keeps answering everyone, because a site that answers only a few addresses is itself a signature. |
| `ALLOWED_DEST_FQDN` | String | *Empty* | Regex allow-list for destinations. Empty allows everything. Anchored to the whole destination unless the pattern anchors itself; names are matched without regard to case - see [Destination allow-list](#destination-allow-list). |
| `ALLOW_PRIVATE_DEST` | Boolean | `false` | Let clients reach the machine the server runs on and the network behind it. Off by default: a destination that is loopback, link-local (a cloud's metadata service, `192.0.2.209`), private (RFC 1918, `fc00::/7`), carrier-grade NAT (`100.64.0.0/10`), multicast, unspecified or one of the server's own interface addresses is refused, whatever name or address the client asked for - see [Private destinations](#private-destinations). |
| `READ_TIMEOUT` | Duration | `30s` | Idle timeout for the relay phase: how long a connection may stay silent once traffic is flowing. Inbound data and successful outbound stream writes refresh the pending read deadline. A blocked write retains its separate `WRITE_TIMEOUT`; setup, incomplete-frame and quota-grace budgets remain absolute. |
| `WRITE_TIMEOUT` | Duration | `30s` | Idle timeout for writes in the relay phase. |
| `HANDSHAKE_TIMEOUT` | Duration | `15s` | Absolute budget for the setup phase: version byte, authentication and the reply to `CONNECT`. Unlike the idle timeouts it is not refreshed by traffic, so a client that dribbles one byte per second is dropped instead of being kept alive. With obfuscation or WebSocket on, a value of `10s` or less is logged as a warning at start and on reload: the budget runs from the accept, and a client with `PREWARM` keeps a spare connection up to 10 s before a tunnel takes it. |
| `DIAL_TIMEOUT` | Duration | `10s` | Budget for reaching the destination: resolution plus connect, from the moment the request is parsed to the reply to `CONNECT`. It is cut out of `HANDSHAKE_TIMEOUT`, so a destination that never answers no longer holds a slot for the whole setup budget - see [Connection states](operations.md#connection-states). CONNECT covers up to 32 checked, family-interleaved DNS candidates with at most six attempts in flight and five additional backup sockets in total. A failed attempt releases its slot; candidates go before backups, and silent attempts retain the common deadline. |
| `FRAME_TIMEOUT` | Duration | `10s` | How long a half-read obfuscation frame may stay half-read. It applies only between a frame header and its body, so it bounds a peer that stops mid-frame without touching a tunnel that is legitimately silent. Ignored on the plain listener, which has no frames. |
| `QUOTA_GRACE` | Duration | `5s` | How long a session whose account just ran out may keep draining what is already in flight. `0` ends the session where the quota is noticed. Nothing new is sent to the destination either way. |
| `UDP_TUNNEL_TCP_TUNING` | Boolean | `true` | Retransmit sooner on a connection that has become a UDP tunnel (`0x83` or `0x84`), and only on such a connection: `CONNECT` streams carry bulk traffic and are left as the kernel set them. The socket gets `TCP_THIN_LINEAR_TIMEOUTS` and a retransmission timer floor of 20 ms (`TCP_RTO_MIN_US`). The cap of the timer (`TCP_RTO_MAX_MS`) stays as the kernel set it: Linux derives from the cap how long a connection may retransmit before it is closed, and a cap of 1 s closed tunnels during 200 ms outages. Each side tunes the socket it sends from, so this setting speeds up the server-to-client direction and the client's the other one. An option the kernel lacks is skipped with one debug line: linear timeouts exist since Linux 2.6.34, the floor since 6.15. `false` turns it off without a rebuild. What it buys on a lossy link: [game session tuning](../benchmarks/game-tuning.md). |
| `UDP_PORT` | Port | *Empty* | Enables the shared native UDP endpoint for authenticated `0x84` associations. Empty disables it. `0` is rejected at startup, because an ephemeral port is not open in the firewall and changes on every restart; set a port from 1 to 65535. Open the same UDP port in the host firewall and container mapping. It may have the same number as `OBFS_PORT` because the protocols use different sockets. The client probes it and uses `0x83` until a verified UDP reply arrives. On a wildcard `PROXY_LISTEN_IP` the server answers from the address the client writes to, on Linux only; that address moves with the client's, after two newest datagrams in a row, so a copied datagram sent to another address of the host does not move it; on other systems a host with several addresses needs a specific `PROXY_LISTEN_IP`. It requires an obfs or ws listener (`OBFS_ENABLED` or `WS_ENABLED`), because `0x84` is accepted only on those: without one the server does not start and says `UDP_PORT requires an obfs or ws listener`. |
| `MAX_CONNECTIONS` | Integer | `10000` | Limit for concurrent connections, shared by all three listeners. A connection that arrives at the ceiling is closed immediately and counted in `s5core_connections_rejected_total`. |
| `FAIL2BAN_RETRIES` | Integer | `5` | Failed authentication attempts from one source before that source is banned. Set to 0 to disable. |
| `FAIL2BAN_TIME` | Duration | `5m` | How long a source stays banned, and how long the per-account failure counter remembers. |
| `TRAFFIC_FLUSH_INTERVAL` | Duration | `60s` | Interval to flush user traffic metrics to disk (if `USERS_FILE` is used). |
| `KDF_MEMORY_BUDGET_MB` | Integer | `0` | Memory that concurrent password checks may use, in MiB. Argon2id asks for 64 MiB a run, so `0` (the default, 256 MiB) means four at once plus a queue four deep per running check; a check that finds both full is refused without running and counted as `s5core_auth_verifications_total{path="overloaded"}`. A negative value removes the bound. |
| `LOG_LEVEL` | String | `info` | `debug`, `info`, `warn` or `error`. `debug` enables protocol diagnostics - see [docs/design/observability-policy.md](../design/observability-policy.md) for what may appear in logs. |
| `LOG_LEVEL_FILE` | String | *Empty* | Path to a file holding a single level word. Takes precedence over `LOG_LEVEL` and is re-read on `SIGHUP`, which is what lets the level change on a running process. |
| `SESSION_LOG` | String | `off` | The session journal: one JSON line per connection (`conn_end`) and per UDP association (`assoc_end`), plus `account_minute` per active account and `process_start`/`config_reload`/`process_stop`. `all` writes every connection, `abnormal` only failures, resets, server timeouts, dials that opened a backup socket and connections that got no byte back, and every association. `off` writes nothing. The journal holds account names and destination networks, which the service log never does: read [the journal section of the policy](../design/observability-policy.md#журнал-сессий) before turning it on. |
| `SESSION_LOG_FILE` | String | *Required unless `SESSION_LOG=off`* | Path of the journal. A file the server creates gets `0600`, and a directory it has to create gets `0700`; an existing file or directory keeps its mode. A path that cannot be opened, or is not a regular file (`/dev/stdout`, a directory, a symbolic link), stops the server at startup. Reopened on `SIGHUP`, for an outside logrotate. In a `read_only` container it needs a volume. |
| `SESSION_LOG_MAX_SIZE_MB` | Integer | `20` | Size at which the journal is moved to `<name>-<time>.jsonl` next to it and compressed with gzip in the background. `0` means the default. |
| `SESSION_LOG_MAX_FILES` | Integer | `10` | Rotated journal files kept. `0` means the default: the journal is never kept without a bound. |
| `SESSION_LOG_MAX_AGE` | Duration | `168h` | Rotated journal files older than this are deleted at the next rotation. `0` means the default. |
| `SESSION_LOG_DST` | String | `net` | What the journal keeps of the destination: `net` - the `/24` (IPv4) or `/48` (IPv6) of the address dialled and the port, never a host name; `none` - nothing. |
| `METRICS_PORT` | String | `8080` | Port to expose OpenTelemetry/Prometheus `/metrics` and `/health` endpoints. |
| `METRICS_BIND_ADDR` | String | `127.0.0.1` | Bind address for the metrics endpoint. **Warning:** do not expose to the public internet without a reverse proxy or firewall. Set to `0.0.0.0` only inside a trusted network or VPN. |
| `OBFS_ENABLED` | Boolean | `false` | Enable traffic obfuscation on a separate port. |
| `OBFS_PORT` | String | `1443` | Separate port for obfuscated connections from `s5client`. The default is kept for compatibility; set a port outside the 443 family (see the note in [Dual-Port Mode](sdk.md#with-obfuscation-dual-port-mode)). |
| `OBFS_PSK` | String | *Empty* | Pre-shared key for obfuscation. **Must be exactly 32 bytes.** |
| `OBFS_MAX_PADDING` | Integer | `256` | Maximum random padding this side adds to each frame it sends (bytes). Sending-side only: the receiver takes the payload length from the decrypted header and never looks at this setting. Padding is capped at half of what a frame can carry, so a large value here cannot squeeze the payload out of the frame. |
| `OBFS_MTU` | Integer | `1400` | Largest frame this side puts on the wire, header and tag included. Writes are cut to fit it, and the send and receive buffers are sized from it (16 and 8 frames, capped at 32 and 16 KiB). It is the size of a frame inside the TCP stream, not the IP MTU: the kernel cuts the tunnel's IP packets by the connection's MSS, and one frame may span several segments, so a PPPoE or VPN path is no reason to change it. A tunnel that connects but stalls on large transfers is diagnosed in the [Docker guide](docker.md#tunnel-up-bulk-transfer-stalls). |
| `KEEPALIVE_MIN` / `KEEPALIVE_MAX` | Duration | `0s` | Make the **server** send a frame carrying nothing after a silence drawn from this range. Off by default: one end holding the path open is enough, and `s5client` is that end. Turn it on when the clients are not `s5client`. Same shape as the client setting - see [Keepalive](../design/transports.md#keepalive). |
| `OBFS_REPLAY_WINDOW` | Integer | `100000` | Capacity of the authenticated prologue history shared by obfuscated listeners. Entries remain for the full default epoch interval (five hours). A full history refuses fresh sessions with `history_full` instead of evicting live entries. Size for the expected number of new sessions over that interval. Unauthenticated frames consume no capacity. `0` disables replay protection. This in-memory history is lost on restart. |
| `OBFS_NODE_ID` | String | *Empty* | Binds this node's keys to this node. It is never sent: it goes into the prologue MAC and the key derivation, so a client configured for another node is refused exactly the way noise is. Must match the client's `OBFS_NODE_ID`. Empty is itself an identity - a client with a name set cannot reach a server without one. What it buys: a recording made against one node is worthless against another, so no node needs to know what the others have seen. What it costs: anycast, and moving a client between nodes without editing its configuration. |
| `OBFS_ACCEPT_NODE_IDS` | String | *Empty* | Comma-separated node identifiers this server still answers to besides its own, for the window in which clients are being moved from one name to another. Each costs one extra HMAC, and only on a connection that did not match the first. Drop the old name once the clients are gone. |
| `OBFS_REQUIRE_MEMBER_KEY` | Boolean | `false` | Whether a client must hold a `tunnel_key` of an account. `false` is the migration setting: clients without one still connect with the deployment PSK and a password. Set it to `true` once every client has a key - after that the PSK alone no longer reaches the tunnel, and a leaked PSK costs a decoy page instead of an account. |
| `OBFS_TFO` | Boolean | `false` | Lets the obfs listener accept data in a SYN (TCP Fast Open, `TCP_FASTOPEN`, Linux only). A client with the same setting then sends the opening, the greeting and the request in the SYN from its second connection to the node on, and setup loses a round trip. The kernel needs `net.ipv4.tcp_fastopen` with the server bit (`3` = client and server): the default `1` takes the option and does nothing, which the server says at startup in a WARN line; in Docker the value belongs to the container ([Docker guide](docker.md#tcp-fast-open)). Off by default and meant for a field measurement. Limitations, written up in [stealth](../field/stealth.md#tcp-fast-open-obfs_tfo-ограничения): the listener answers a SYN that asks for a cookie with one, so an active probe tells this port from one without Fast Open; the cookie travels in the clear SYN and links a client's connections; the field numbers of the filter were taken without data in a SYN; a SYN with data can be replayed from a spoofed address, and the prologue history catches it only while it holds the prologue (not after a restart, not with `OBFS_REPLAY_WINDOW=0`). Some paths drop SYNs with data, and the kernel does not stop sending them by itself; the client does (see its `OBFS_TFO`). Elsewhere than Linux, or on a kernel that refuses the option, the listener works without it and the server writes one DEBUG line. Accepted connections are counted in `s5core_tcp_fastopen_passive_total`, the kernel's `TCPFastOpenPassive` of the server's network namespace. The WebSocket listener is not affected. |
| `WS_ENABLED` | Boolean | `false` | Enable the WebSocket-over-TLS stealth transport (TLS → WebSocket → obfs → SOCKS5). |
| `WS_ADDR` | String | `<PROXY_LISTEN_IP>:443` | Address for the TLS listener. |
| `WS_CERT_FILE` | String | *Required if `WS_ENABLED`* | PEM certificate for the TLS listener. |
| `WS_KEY_FILE` | String | *Required if `WS_ENABLED`* | PEM private key for the TLS listener. |
| `WS_PATH` | String | `/ws` | Path of the WebSocket endpoint. Every other path serves the decoy site. It must be one exact, literal, already-canonical path: starting with `/`, not `/` or `/favicon.ico`, no trailing slash, no whitespace or control characters, no `?`/`#`, no percent-encoding, no `.`/`..`/`//` segments and none of the router's wildcard syntax (`{}`). Anything else is refused at startup, with a message about `WS_PATH`, before the socket is opened. The endpoint is compared literally against the request path, so a wildcard would be matched by the router and then refused by the upgrade - a tunnel that starts and never answers. |
| `WS_SUBPROTOCOL` | String | *Empty* | Required `Sec-WebSocket-Protocol`. Empty means none is required. |
| `WS_EARLY_DATA` | String | `auto` | `auto` takes tunnel frames a client sends behind its upgrade request, before the `101`, and announces that inside the tunnel, so a 2.4 client stops waiting a round trip for the `101` from its next connection on. `off` refuses such frames and does not announce. Behind a front (nginx, CDN) set `off` until the front itself has been checked to pass early frames (R4-7): a front that answers `101` and drops what came before it costs each client one connection that waits out the client's `HANDSHAKE_TIMEOUT`, after which the client distrusts the node for 10 minutes, doubling with every repeat up to a day. A front that answers the early upgrade with another HTTP status costs nothing: the client sets the connection up once more with an ordinary upgrade, together with what an `OPTIMISTIC_CONNECT` application or a UDP association already sent, and distrusts the node the same way. Any other value is refused at startup. See section 8.5 of [docs/veil-spec.md](../veil-spec.md). |
| `WS_DECOY_UPSTREAM` | String | *Empty* | The site every non-tunnel request is reverse-proxied to: its status, headers and body are returned unchanged, including its own 404 for `WS_PATH` when the request is not a WebSocket upgrade. Empty serves the built-in static page instead, which answers only three paths and always the same way - weaker cover against probing (see [docs/design/decoy.md](../design/decoy.md)). Must be `http://` or `https://` with a host and no query or fragment, or startup is refused. The upstream never learns who is visiting: `X-Forwarded-*` and `Forwarded` are stripped on the way up, and any `Location`/`Set-Cookie` that names the upstream is rewritten so it does not leak on the way down. |
| `TRANSPORT_ADVICE` | String | *Empty* | What the server tells every client inside its tunnel, once the tunnel is up: the transport to use from its next connection and the traffic shape to adopt. A bare `ws` or `obfs`, or fields separated by spaces or commas: `transport=ws min_frame=512 max_frame=2048 jitter_ms=5 padding=128 keepalive=10s-20s`. The advised transport must be one this server listens on, or startup is refused. Read at startup; to change it on a running server set `TRANSPORT_ADVICE_FILE`. Empty sends nothing. See [Changing the transport in the field](../design/transports.md#changing-the-transport-in-the-field). |
| `TRANSPORT_ADVICE_FILE` | String | *Empty* | Path to a file holding one line of `TRANSPORT_ADVICE` syntax. Takes precedence over `TRANSPORT_ADVICE` and is re-read on `SIGHUP`, which is what makes moving a fleet one edit and one signal: the environment of a running process cannot be changed from outside it. A missing file means no advice, which is how a recommendation is withdrawn; a file that cannot be read or does not parse leaves the previous advice in force and is logged. |
| `WS_MIN_FRAME` | Integer | `256` | Lower edge of the band the shaper cuts to. Every write is cut into at least two frames, so this is what makes a small write stop being one frame of its own size; it is not padding, a frame below the band is never filled out. Sending-side only - the peer reassembles a byte stream and does not care how it was framed. |
| `WS_MAX_FRAME` | Integer | `4096` | Upper edge of the band: no frame this side sends is larger. `0` disables shaping, and then every write goes out whole, which puts the obfuscated frame length on the wire. Sending-side only. |
| `WS_MAX_JITTER_MS` | Integer | `0` | Maximum random delay before a frame this side sends, in milliseconds. Sending-side only. |

#### Destination allow-list

`ALLOWED_DEST_FQDN` is a Go regular expression. Three details decide whether it
does what it looks like it does.

**It is anchored.** A pattern that does not anchor itself is wrapped as
`^(?:pattern)$` and matched against the whole destination. Unanchored,
`example\.com` also matched `evil-example.community` - an allow-list letting
through the one kind of host it exists to keep out, and doing it silently.
A pattern that anchors itself is left exactly as written, so the usual idiom
for a domain and its subdomains keeps working:

```bash
ALLOWED_DEST_FQDN='example\.com'            # example.com and nothing else
ALLOWED_DEST_FQDN='(^|\.)example\.com$'     # example.com and its subdomains
ALLOWED_DEST_FQDN='(example|test)\.com'     # both, thanks to the (?:) wrapper
ALLOWED_DEST_FQDN='[^.]+\.example\.com'     # one label deep, still anchored
```

Whether a pattern anchors itself is decided by parsing it, not by looking for
the characters `^` and `$`. In `[^.]` the caret negates a character class and
`\$` is a dollar sign; neither is an anchor, and the last example above used
to be left unanchored because of it - so the stricter-looking rule was the one
that allowed `ok.example.com.attacker.invalid`.

**It ignores the case of a name.** DNS names are case-insensitive over ASCII,
so the name is lower-cased before matching and `EXAMPLE.COM` is the same
destination as `example.com`. Write patterns in lower case: an upper-case
letter in a literal never matches. The fold is ASCII-only on purpose - a
Unicode fold would let a name built from lookalikes satisfy an ASCII pattern.

**It matches what the client asked for.** A name request is matched against the
name, with a trailing root dot stripped; an address request is matched against
the literal, `203.0.113.5` as text. A client that resolves names itself sends
addresses, so a name-only pattern refuses it - deliberately. Allow addresses by
naming them: `ALLOWED_DEST_FQDN='203\.0\.113\.\d+'`.

**It is checked before DNS.** A refused destination is never looked up, so the
query does not leave the host and the name does not appear in the resolver's
logs or in the traffic of whoever is watching the server.

#### Private destinations

A proxy that connects wherever it is asked is also a way into the machine it
runs on. Without a rule, an authenticated client could open the server's own
loopback (a metrics port, a database, an admin panel), the metadata service of
a cloud (`192.0.2.209`, where the machine's credentials are kept) or any
host of the network behind the server. `ALLOW_PRIVATE_DEST=false`, the default,
closes that:

- the check is made on the **address the destination resolves to**, not on what
  the client wrote, so a name that points to `127.0.0.1` and an address written
  as `::ffff:10.0.0.1` are refused like the plain literal;
- besides those ranges, multicast and the addresses of the server's own
  interfaces are refused, the public one included on a machine that holds it:
  a connection to it leaves by the loopback, where a firewall that guards the
  machine from outside usually lets it reach every service the machine runs.
  The list is re-read once a minute. The IPv4 address inside a NAT64 address
  (`64:ff9b::/96`) is checked as well, and only that prefix: a network-specific
  NAT64 prefix is an ordinary public IPv6 address to the server;
- it covers `CONNECT` and the UDP datagrams of every UDP command (`0x03`, the
  tunnel `0x83` and native `0x84`), where the address of every datagram is
  checked before it is sent;
- a refused `CONNECT` is answered with "connection not allowed by ruleset"
  (`0x02`), a refused datagram is dropped, as a filtered one would be, and the
  log says so once per association: a game whose UDP stopped after an upgrade
  is found by that line. In the session journal and in
  `s5core_connections_ended_total` a refused `CONNECT` is `private_dest`, not
  `rules_denied`, so the two settings are told apart.

Set `ALLOW_PRIVATE_DEST=true` when clients are meant to reach the inner
network: a server inside a company network, a lab, a test stand. The two settings are
independent: `ALLOWED_DEST_FQDN` narrows what is allowed and never lifts the
ban, so a pattern that names a private address needs `ALLOW_PRIVATE_DEST=true`
as well. In a
container, "private" includes the addresses of the Docker network, so a server
that is meant to reach a neighbouring container needs the switch too.

Two limits to know. The server's own addresses are those of the machine the
process sees: in a container on a bridge network that is the container's, not
the host's, so the host's public address is not refused by this check - the
host's firewall (the `DOCKER-USER` and `INPUT` chains) is what guards the
host's services from a container, as it does from any other. And the reply
tells a refused address from an unresolvable name (`0x02` against `0x04`), so a
client can find out that a name resolves into the private range; on a server
whose resolver knows an inner zone, that includes the names of the zone.

An application embedding the server through `pkg/s5server` keeps the old
behaviour: `Config.DenyPrivateDest` is false unless the application sets it.

> `TLS_FINGERPRINT` is a **client-side** setting: it selects the TLS Client Hello the client imitates. Setting it on the server changes nothing, so the server logs a warning if it finds it - believing your server traffic is shaped when it is not is worse than not shaping it.

> TLS session resumption follows from the same choice. A browser preset never resumes: every WSS connection is a full handshake with the preset's JA4. Without `TLS_FINGERPRINT` the client resumes TLS 1.3 sessions, and connections opened before a fresh ticket arrives offer the same ticket, whose identity is sent in clear text - an observer can link those connections to one client. Set `TLS_FINGERPRINT` where that matters.

### Client (`s5client`)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `CLIENT_LISTEN_ADDR` | String | `127.0.0.1:1080` | Local address to accept plain SOCKS5 connections. There is no local authentication: a non-loopback address exposes a proxy to anyone who can reach it. Bind to loopback unless access is restricted externally. |
| `CLIENT_MAX_CONNECTIONS` | Integer | `1024` | Maximum active local connections, including incomplete handshakes. Excess connections are closed. Non-positive values use the default. |
| `SERVER_ADDR` | String | *Required* | Remote S5Core server obfs address (e.g., `203.0.113.10:27015`) - the host and port the server's `OBFS_PORT` listens on. |
| `PROXY_USER` | String | *Empty* | Username for authenticating with the S5Core server. |
| `PROXY_AUTH_MODE` | String | `auto` | `auto` preserves existing negotiation; `member-only` requires a valid member ID/key and no password fields, and pipelines CONNECT; `password-fallback` requires user/pass and waits for the selected method (one additional greeting RTT when member authentication wins). It cannot recover from an invalid tunnel key. |
| `PROXY_PASS` | String | *Empty* | Password for authenticating with the S5Core server. The server calls the same setting `PROXY_PASSWORD`; it also accepts `PROXY_PASS` and says so in its log. |
| `OBFS_PSK` | String | *Required* | Pre-shared key. **Must match the server's PSK exactly.** |
| `OBFS_MAX_PADDING` | Integer | `256` | Padding this side adds to the frames it sends. Independent of the server's setting. |
| `OBFS_MTU` | Integer | `1400` | Largest frame this side sends, and the size its buffers are built from. Independent of the server's setting: each side reads whatever frame length the other declares. As on the server, a frame size inside the TCP stream, not the IP MTU: lowering it does not help a narrow path ([Docker guide](docker.md#tunnel-up-bulk-transfer-stalls), [router](testing.md#s5client-on-a-router)), and it does not size native UDP datagrams either. |
| `OBFS_CIPHER` | String | *Automatic* | `aes` or `chacha`. Empty - the normal setting - lets the client take the one its processor is good at: AES where AES instructions exist, ChaCha20 where they do not. The server accepts either and learns the choice from the prologue, so this does not have to match anything; it is a knob for measuring. On MIPS the automatic choice is ChaCha20, run in pure Go; those builds are experimental ([router guide](testing.md#s5client-on-a-router)). |
| `OBFS_PROLOGUE` | String | `printable` | How the prologue looks on the wire. `printable` encodes it with base64 and adds a secret-derived pad, so the connection opens with 43-63 printable characters and the first packet is exempt from a fully-encrypted-traffic policy; `raw`, the pre-phase-5 wire, is refused at startup since 2.2. A server still reads both, so 2.0 and 2.1 clients configured with `raw` keep working. |
| `OBFS_SPLIT_OPENING` | Boolean | `false` | Sends the opening in a packet of its own, ahead of the first frames. The filter measured in `docs/field/stealth.md` classifies first packets of 100 bytes and up, and the opening alone is 43-72 bytes where the client's first write is 125 and up; with a raw prologue, which has no printable exemption, this moved a live tunnel from 14 of 26 connections to 26 of 26. It costs no round trip - the write does not wait for an answer. Off by default: a short packet at a fixed place is a shape of its own, and on the measured path the printable opening passes without one. The server needs no matching setting. |
| `OBFS_NODE_ID` | String | *Empty* | Must match the server's `OBFS_NODE_ID`. It is not sent anywhere - it goes into the key derivation, so a wrong value fails exactly like a wrong PSK: the server accepts the connection, says nothing and closes it. |
| `OBFS_MEMBER_ID` | String | *Empty* | The account this client belongs to. Set it together with `OBFS_MEMBER_KEY`; it never reaches the wire and is only what the client's own log calls itself. |
| `OBFS_MEMBER_KEY` | String | *Empty* | This account's `tunnel_key` from the server's `users.json`, base64, 32 bytes. With it the server knows who is calling before the first frame and asks for no password. Without it the client uses the shared account, which works until the server sets `OBFS_REQUIRE_MEMBER_KEY`. A key that is not in the server's list fails the way a wrong PSK fails - silence, then a closed connection. |
| `ROUTE_DOMAINS` | String | *Empty* | Comma-separated domain patterns for split tunneling. Empty = tunnel all traffic. |
| `TIMEZONE_CHECK` | Boolean | `false` | Ask ipapi.co which timezone the server's address is in and warn when the system timezone differs. Off by default: the lookup tells a third party that this client is about to use this proxy, and puts a recognisable request on the wire right before every connection to it. Run `s5client timezone` to do the check once, by hand. |
| `DIAL_TIMEOUT` | Duration | `10s` | Budget for connecting to the server, including DNS, TCP, TLS and HTTP Upgrade on WSS. The smaller positive value of this and `HANDSHAKE_TIMEOUT` bounds the transport dial. CONNECT covers up to 32 checked, family-interleaved DNS candidates with at most six attempts in flight and five additional backup sockets in total. A failed attempt releases its slot; candidates go before backups, and silent attempts retain the common deadline. |
| `HANDSHAKE_TIMEOUT` | Duration | `15s` | Separate budgets of this duration cover the local SOCKS5 handshake and remote tunnel setup (transport dial including WSS, greeting, authentication and CONNECT reply). Each deadline is cleared when its phase finishes. A non-positive value still gives the local handshake a 15s limit; established idle tunnels are unaffected. |
| `OPTIMISTIC_CONNECT` | Boolean | `true` | Answers the application's `CONNECT` with success right after the request is read and checked against `ROUTE_DOMAINS`, before the tunnel is dialled, and sends the application's bytes into the tunnel behind the request without waiting for the server's reply; the server keeps them until the destination is connected. This saves one round trip per new stream. The client does not wait for the application's first bytes either, so protocols where the server speaks first (SSH, SMTP) work as before, and the first packet on the wire is unchanged. `HANDSHAKE_TIMEOUT` still bounds the setup. The cost: a refused destination (`0x05`, `0x02` and the rest) or a failed setup can no longer reach the application as a reply code, so the application sees its connection reset; the client log still has the line with `closed_by=server` and `reply`, or the failed setup with its phase. `false` restores the reply code for an application that needs it. Works with any server version: the server is unchanged. For `UDP ASSOCIATE` the client binds the local UDP port and answers the application with success at once, opens the tunnel meanwhile and sends the datagrams that arrive before the server's reply right behind the request (up to 32 datagrams and 64 KiB are held until the request is out, and for the `0x83` retry after a refused `0x84`); a server refusal then ends the association by closing the application's SOCKS5 connection. `false` answers after the server, with its reply code. |
| `PREWARM` | Boolean | `true` | Keeps at most one spare transport to the server (TCP for obfs; TCP, TLS and the WebSocket upgrade for WSS, waiting for the `101` even on a node that takes early frames) while the client is busy, so a new tunnel skips those round trips. A spare is ordered only by a new tunnel that comes within 30 s of the previous one, so a lone tunnel after a quiet spell or a once-a-minute poll orders nothing. A spare is closed unused at an age drawn from 6-10 s, by whichever of the monotonic and the wall clock says more (a laptop that slept), and is not replaced; it is taken only for the transport, address and WebSocket frame shape it was dialed for. `HANDSHAKE_TIMEOUT` counts from the moment a tunnel takes it. A tunnel whose spare turns out dead (the server closed it, the machine slept, the network changed) does not rest the transport, and is set up once more on a fresh dial only where the server is proven not to have got the request: the failure came before the request was written, the stream ended without an answer to the greeting, or the kernel (`TCP_INFO`, Linux only) says the server acknowledged nothing of the spare since it was taken; otherwise, and on every platform without `TCP_INFO`, the tunnel fails. On a repeat the request is written again, with `OPTIMISTIC_CONNECT` together with up to 64 KiB of what the application already sent and its end of stream, so the application notices nothing, and past 64 KiB its connection is reset instead; the early UDP datagrams of an association on a spare are held until the server answers, within the same 32 datagrams and 64 KiB, and follow the request to the fresh dial. A timeout on a spare counts against the transport as on a fresh dial. The server's `HANDSHAKE_TIMEOUT` must be above 10 s, the oldest a spare gets, or the server closes spares before they are used; the server warns about it at start. The client's minute summary reports `prewarm_used` (the server answered the greeting on a spare) and `prewarm_wasted`. A 2.4 server counts an unused spare in `s5core_obfs_idle_closes_total` and does not drain it; a 2.3 server counts it as `eof_before_frame`, and its drain ends at once on the same end of stream. Neither counts it against the source. `false` dials every tunnel as before. |
| `SHUTDOWN_TIMEOUT` | Duration | `10s` | How long a shutdown waits for connections that are still carrying traffic. Before this the wait had no end, so a client asked to stop kept running for as long as one tunnel stayed open. |
| `UDP_TUNNEL_TCP_TUNING` | Boolean | `true` | The client half of the server setting of the same name: the same socket options on the tunnel that carries a UDP association, for the client-to-server direction. On an older kernel, as on many routers, only `TCP_THIN_LINEAR_TIMEOUTS` applies. |
| `OBFS_TFO` | Boolean | `false` | Sends the first write of an obfs tunnel - the opening, the greeting and the request - in its SYN (TCP Fast Open, `TCP_FASTOPEN_CONNECT`, Linux 4.11 and newer), which saves a round trip of every setup. It works from the second connection to a node on: the first fetches the server's cookie. The server needs `OBFS_TFO=true` as well, and the client's `net.ipv4.tcp_fastopen` the client bit (`1`, the kernel default; a value without it is said at startup in a WARN line). With a cookie the connect returns before the handshake, and the SYN leaves with the first write: a node that is down is still reported at the `dial` phase, without the hint about the PSK and the clock, and the wait for its SYN-ACK is bounded by `DIAL_TIMEOUT`. For the same reason a name with several addresses is not tried address by address once the kernel holds a cookie for the first one: that address is taken whether it answers or not. Some paths drop SYNs with data, and Linux does not stop sending them by itself: it records a lost SYN per destination without reading the record, and its global switch-off is disabled since 5.14 (`net.ipv4.tcp_fastopen_blackhole_timeout_sec = 0`). The client does: a node where a SYN sent with a cookie went unanswered and was sent again without its data (`tcpi_fastopen_client_fail`, Linux 5.5 and newer), or where such a connection did not reach the server at all, is dialled without Fast Open for 10 minutes, with one INFO line that says which of the two it was. A server whose key changed (a new container, a new network namespace) takes the SYN without its data and hands out a new cookie; that is not counted, and the next SYN carries data again. A kernel older than 5.5 does not tell the two apart, and there any SYN with a cookie whose data was not acknowledged counts. One lost SYN also reads as a retransmit, so one loss on the path rests Fast Open to the node for 10 minutes. With `OBFS_SPLIT_OPENING=true` the SYN carries the opening alone and the frames wait for the handshake, so the round trip is not saved. Off by default and meant for a field measurement; the limitations for stealth (the cookie in the clear SYN links the client's connections, the filter numbers were taken without data in a SYN) are in [stealth](../field/stealth.md#tcp-fast-open-obfs_tfo-ограничения). On Windows, macOS and an older kernel (a router on 4.9) the client dials without it and writes one DEBUG line. At DEBUG level every `CONNECT` tunnel says whether its SYN carried data (`syn_data`). The WebSocket transport is not affected. |
| `TUNNEL_DEAD_TIMEOUT` | Duration | `45s` | How long the tunnel of a `CONNECT` stream may keep what the client sent on it unacknowledged before the kernel closes it (`TCP_USER_TIMEOUT` on Linux, `TCP_MAXRTMS` on Windows). A path that lost its state - a NAT, a provider - swallows the segments of streams already open, and without this the kernel retransmits for up to a quarter of an hour while the application waits. The server closes a stream that is silent for `READ_TIMEOUT` (30 s) anyway, so the default is above that and above `WRITE_TIMEOUT`: raise it together with them. The stream ends with `closed_by=timeout` at WARN and the application reconnects. It counts data that is waiting for an acknowledgement (the keepalive frames are such data, and with the kernel's own TCP keepalive an idle dead tunnel is closed without them) and, on Linux 5.1 and newer, time spent against a peer's zero window. Accepted values: `0` or from `1s` up to about 596 hours. `0` leaves the kernel's rule; other systems than Linux and Windows keep the kernel's rule too. UDP tunnels (`0x83`, `0x84`) are not affected: they keep the kernel's timeout on purpose ([game session tuning](../benchmarks/game-tuning.md)). |
| `UDP_NATIVE` | Boolean | `false` | Set `true` on clients selected for native UDP game testing when the server has `UDP_PORT`. The client then sends command `0x84`. A 2.3 node without `UDP_PORT` answers with port 0 and the association uses `0x83` on the same connection; the client remembers such a node for 10 minutes, by transport and the address it dials (`WS_URL` or `SERVER_ADDR`), and opens its next associations with `0x83` directly. A 2.2 server refuses the command, and the client asks again with `0x83` on a new connection by the same transport. It remembers that server for 10 minutes only when the retry is accepted: a 2.3 server whose rules refuse UDP answers `0x84` with the same refusal (`0x02`), so the association ends for the application and the next association asks for `0x84` again. Until the UDP probe succeeds, application datagrams use `0x83`. After that a datagram goes natively while the client hears the server: the path is verified, and a server packet came less than a second ago or fewer than two probes in a row are unanswered (the second counts as unanswered after 250 ms or twice the smoothed probe round trip, whichever is longer). A datagram sent while the client does not hear the server uses `0x83`, and once it stops hearing, the client tells the server by TCP to answer by TCP too - at that moment while datagrams flow either way, with the next datagram otherwise. The server places the client's words by the client's datagram counter, not by arrival, so a notice and a native datagram that overtake each other leave the answers where the later one put them. Datagrams that go by TCP have one writer per association, with a queue of 1024 frames and 2 MiB of buffers, which holds a wave of game answers twice over ([burst stand](../benchmarks/udp-burst-2026-09-28.md)); a frame that waited 250 ms is dropped, as UDP would drop it, so a large datagram waiting for the send buffer holds up neither probes nor native datagrams. After three probes in a row go unanswered (about 2 s), the association moves to `0x83`; the client repeats the notice with every retry probe (1-10 s) until the path is back, so a native datagram that arrives late cannot keep the answers on the dead path. A later answered probe brings native back, and the probe after it tells the server that the client hears it, which moves the answers back to native for an application that only listens. The notice carries the counter of the client's next datagram and the server replies with its own, so a path that lost more than 512 datagrams in a row still comes back. When a path that was never verified goes unanswered by the same rule, the client logs one Info line with the address its probes go to: the host of the tunnel connection, which behind a front on another host, as with WSS, is the front's address. Native carries a datagram up to the limit the client finds on the path at the start of each association: at most 1374 bytes of SOCKS5 UDP datagram, 1366-1374 on a 1500-byte path. On a verified, heard native path a longer one is dropped both ways, so a QUIC stack settles below the limit; the eighth dropped in one direction moves long datagrams to `0x83` to the end of the association. When native is unavailable or no longer heard, large datagrams use the working TCP fallback immediately ([limit of native](../design/transports.md#native-udp-for-games)). The closing `UDP Tunnel closed` line counts the association's datagrams by path: `native_sent`, `tcp_sent_oversize` (longer than the limit: immediately when native is unavailable, after the eighth dropped on a verified path), `tcp_sent_other` (path not verified or lost, server not heard, or a failed send), `native_received`, `tcp_received`, and `tunnel_drops` for frames the TCP writer dropped; `native_limit` (on the wire) and `size_probes` show the search, `dropped_oversize_sent` and `dropped_oversize_received` the dropped long datagrams. The server counts the same in `s5core_native_udp_datagrams_total` and the two metrics next to it ([metrics policy](../design/observability-policy.md)). |
| `UDP_DIAGNOSTICS_INTERVAL` | Duration | `0` | Client and server: opt-in periodic UDP diagnostics. `0` disables; positive intervals below `1s` are refused. Read at startup. |
| `KEEPALIVE_MIN` | Duration | `10s` | Lower bound of the idle interval after which the client sends a frame carrying nothing, so that nothing on the path drops the connection for being silent. `0` disables it. See [Keepalive](../design/transports.md#keepalive) for the measurements the range comes from. |
| `KEEPALIVE_MAX` | Duration | `20s` | Upper bound of the same interval. A fresh draw is made for every frame: a fixed period would identify the protocol without anyone having to decrypt it. Must be at least `KEEPALIVE_MIN`. |
| `WS_URL` | String | *Empty* | `wss://host/path` of the server's WebSocket endpoint. Setting it makes the client use the stealth transport instead of `SERVER_ADDR`. |
| `WS_HOST` | String | *Empty* | Overrides the `Host` header (domain fronting). It also decides the SNI unless `SERVER_NAME` is set. |
| `WS_ORIGIN` | String | *Empty* | `Origin` header sent with the upgrade request. |
| `WS_USER_AGENT` | String | *Empty* | `User-Agent` header sent with the upgrade request. |
| `TLS_FINGERPRINT` | String | *Empty* | Browser TLS fingerprint to imitate (`chrome`, `firefox`, ...). Empty uses Go's own Client Hello, which is itself a fingerprint. |
| `WS_TLS_SESSION_CACHE` | Bool | `true` | Bounded TLS session caches scoped to this client configuration, separately for Go TLS and uTLS. Certificate and pin checks remain active. Browser presets without a resumption extension keep full handshakes. Set `false` for an A/B baseline. |
| `SERVER_NAME` | String | *Empty* | SNI to present, and the name the certificate is verified against, when it must differ from the host in `WS_URL`. Falls back to `WS_HOST` and then to the host in `WS_URL`; setting it is how you move the SNI without moving the `Host` header. |
| `WS_CA_FILE` | String | *Empty* | PEM file with the certificate authority (or the server certificate itself) to trust. It **replaces** the system roots, which is what a self-signed deployment wants. |
| `WS_PIN_SHA256` | String | *Empty* | Comma-separated SHA-256 hashes of the server's public key (SPKI), hex, colons optional. The chain must still verify; a pin only narrows what is accepted. |
| `WS_MIN_FRAME` | Integer | `256` | Framing of what this side sends. Independent of the server's setting. |
| `WS_MAX_FRAME` | Integer | `4096` | Framing of what this side sends. Independent of the server's setting. |
| `WS_MAX_JITTER_MS` | Integer | `0` | Delay before the frames this side sends. Independent of the server's setting. |
| `TRANSPORT` | String | `auto` | Which transport to use: `obfs`, `ws`, or `auto`. Auto is the configured default - `ws` when `WS_URL` is set, `obfs` otherwise - overridden by the server's advice when it sends one, with the other configured transport tried when the chosen one fails to set up. A pinned transport is used regardless of both. `ws` requires `WS_URL`. See [Changing the transport in the field](../design/transports.md#changing-the-transport-in-the-field). |
| `TRANSPORT_COOLDOWN` | Duration | `5m` | How long a transport that failed to set up (no connection, or a server that accepted it and never answered) is rested while the other one carries the traffic. `0` turns the switch off. A destination refusing `CONNECT` does not count: that is the destination, not the path. |
| `OBFS_FORMAT` | String | `auto` | The obfuscation wire format. `auto` and `v1` both mean the current one ([docs/veil-spec.md](../veil-spec.md)). `legacy` was removed in 2.2 and stops the client at startup; a fleet still on 1.x servers migrates through 2.1 - [docs/field/migration.md](../field/migration.md). |
| `LOG_LEVEL` | String | `info` | Same as on the server, including `SIGHUP` reload. On a router, where restarting the client drops every live connection, this is the only way to look at a failure while it is happening. |
| `LOG_FILE` | String | *Empty* | Writes the log as JSON to this file at `LOG_LEVEL`, and to the console only as short text at `LOG_CONSOLE_LEVEL`. At every start the previous file moves to `archive/` next to it, so each run has a file of its own; within a run the file rotates at `LOG_MAX_SIZE_MB`. The rotation is the client's own, which also works on Windows, where a file the process holds open cannot be renamed from outside. Empty keeps the old behaviour: JSON on stdout. |
| `LOG_KEEP` | Integer | `40` | Archived files kept in `archive/`, runs and in-run rotations together. `0` keeps all. |
| `LOG_MAX_SIZE_MB` | Integer | `10` | Size at which the log file rotates within a run. `0` turns it off. |
| `LOG_CONSOLE_LEVEL` | String | `warn` | Console level when `LOG_FILE` is set. |

> **Certificate verification:** the WebSocket transport verifies the server
> certificate against the system roots. Until now it did not: the uTLS dialer
> was built with `InsecureSkipVerify` and a comment saying the caller should
> pin the certificate, and no caller did - the one transport whose purpose is
> to look exactly like HTTPS was the one that accepted any certificate at all.
> A deployment with a self-signed certificate now names it through
> `WS_CA_FILE`, and `WS_PIN_SHA256` narrows trust down to a single key. Get
> the pin from the server's certificate with:
>
> ```bash
> openssl x509 -in cert.pem -pubkey -noout \
>   | openssl pkey -pubin -outform der \
>   | openssl dgst -sha256
> ```

> **When the server goes silent:** a server that accepts the TCP connection and
> then answers nothing used to leave the application hanging forever with not a
> single line in the log. With these two timeouts the client answers the
> application with a SOCKS5 error (`0x06`, TTL expired) and writes one WARN
> naming the destination and the phase that expired: `dial`, `greeting`, `auth`,
> `connect` or `connect_reply`. An explicit credential refusal is `auth_rejected`; it confirms a completed encrypted SOCKS5 exchange and is not evidence that UDP or the tunnel format failed.

> **UDP support:** `s5client` handles an application's SOCKS5 UDP Associate
> (`0x03`) through a local UDP socket. With `UDP_PORT` enabled on the server
> and `UDP_NATIVE=true` on the client, the client probes command `0x84` and
> moves application datagrams to
> authenticated native UDP after a verified response. Until then, and whenever
> that path stops answering, the same association uses the encrypted TCP
> tunnel (`0x83`). A server without native UDP carries the association by `0x83`,
> on the same connection for a 2.3 node and on a new one for 2.2. See the [local game-loss results](../benchmarks/nativeudp-game-loss-2026-09-25.md).
> Every relay UDP socket asks for a 2 MiB receive buffer, and both binaries
> log at startup what the kernel gave. A server without `CAP_NET_ADMIN` needs
> `net.core.rmem_max` of at least 2097152 on the host, or bursts of game
> answers overflow the buffer ([Docker guide](docker.md#game-udp-loses-answers-in-bursts)).
> While an association carries traffic, the client writes `UDP Tunnel running`
> once a minute by default with its age and totals so far (`sent`, `sent_bytes`,
> `received`, `received_bytes`), so a client that is killed still leaves what
> its long associations carried. The closing `UDP Tunnel closed` line names
> `closed_by`: `application` (the application closed its SOCKS5 connection,
> the normal end), `tunnel` (the connection to the server failed) or `local`
> (the client's own UDP socket failed). It is written at WARN unless the
> application ended the association, and also when one direction carried less
> than a hundredth of the other after at least 100 datagrams (`quiet=sent` or
> `quiet=received`), so a client logging at WARN still shows a game that lost
> its association. The server counts the end of every association in
> `s5core_udp_associations_ended_total{kind, reason}` ([metrics policy](../design/observability-policy.md)).

> **Domain routing examples:** `example.com` (exact match), `*.google.com` (all subdomains + base domain), `*.youtube.com,*.googlevideo.com` (multiple patterns).

`HANDSHAKE_TIMEOUT=0`, `DIAL_TIMEOUT=0` and `FRAME_TIMEOUT=0` select their
published defaults both at startup and on reload. Zero idle read/write budgets
still disable that idle limit, and zero quota grace ends the session immediately.

Server failures name a fixed `stage` and `op`. Client setup phases use the
underscore form above. A completed local UDP send only means socket acceptance;
none of these counters proves delivery to a remote application.

## Temporary UDP diagnostics

`UDP_DIAGNOSTICS_INTERVAL=0` is the default on both binaries. Set it to `5s`
for a short incident recording; positive values below `1s` are refused. The
setting is read at startup. Use `LOG_LEVEL=info` on the client and
`LOG_LEVEL=debug` on the server, then start the new builds with those settings.
Restore the interval to `0` and the server log level to `info` after recording.
Neither intervals of native probes nor packet routing change.

The client writes `UDP Tunnel running` every selected period after the first
activity, including idle periods. `sent_period` and `received_period` are
datagram counts during that period; the existing `sent` and `received` remain
cumulative. Additional cumulative fields are:

- `local_udp_in`, `source_drops`, `header_drops`: packets received on the local
  UDP socket, refused source IPs and invalid SOCKS5 headers;
- `app_port_changes`: changes after the first learned application UDP port;
- `app_write_errors`, `app_unknown_drops`: failures writing an answer to the
  application, or answers discarded before its address is known;
- `tcp_sent`: successful direct TCP frame writes on associations without a
  native client. Native associations retain their `native_sent`,
  `tcp_sent_other`, `tcp_sent_oversize` and `tunnel_drops` counters; TCP path
  selection is not confirmation that the queued frame was written;
- `native_up`, `native_heard`, `native_data_write_errors`, `native_read_errors`,
  `native_rejected_packets`: current native path state and local data-send,
  socket-read and incoming validation failures. Healthy probes do not confirm
  delivery to the application or target.
- `native_probes_sent`: control probes accepted by the local socket;
  `size_probes`: attempted size probes; `size_probes_sent`: size probes
  accepted by the local socket; `size_probe_too_big`: size probes rejected
  with `EMSGSIZE`, an expected MTU search boundary;
- `native_probe_write_errors`: cumulative probe send failures excluding
  size-probe `EMSGSIZE`. The `probe_write_errors` field in a path-loss Warn
  is the increase since the first unanswered probe of that episode. Neither
  counter alone establishes the cause of a path loss or remote delivery.

During a prolonged initial native UDP block, the existing retry probes also
request counter synchronization over the live tunnel. The retry cadence
remains unchanged; recovery does not require an earlier verified native path.

The server writes Debug `UDP relay running` for each active `0x83`/`0x84`
association with the same secret-derived `conn` ID as the client. It contains
cumulative and `_period` counts for `client_in`, `target_out`, `target_in`,
`client_out`, `udp_drops` and `target_write_errors`. The four stages mean a
complete data frame read from the tunnel, a successful UDP write to the target,
a UDP reply read, and a successful native or TCP write toward the client.
There are no account names, addresses or packet contents in these reports.
The optional session journal retains those counts in `assoc_end` as
`udp_client_in`, `udp_target_out`, `udp_target_in`, `udp_client_out`, `udp_drops`
and `target_write_errors`.

`s5core_udp_relay_datagrams_total{stage}` exposes the four stages for all UDP
commands, including plain SOCKS5. For plain SOCKS5, `client_in` counts packets
after source validation. `s5core_udp_drops_total{reason}` distinguishes DNS
overload and failure, invalid headers, source/rule/private-target rejection,
missing client addresses, failed client writes, oversized frames and target
write failures (`closed`, `timeout`, `too_large`, `no_buffer`, `unreachable`,
`other`, each prefixed with `target_write_`). All reasons are present at zero
before the first event. Native hub queue losses and TCP writer queue/age
losses remain in their separate existing metrics and are not included in
the relay's `udp_drops` total.

For a voice incident, compare the client and server by `conn` and time. If the
client's `sent_period` stops during deliberate speech, investigate the
application or TUN input. If the server sees input without corresponding target
writes, inspect the drop reasons. A successful target write only confirms local
kernel acceptance, not receipt or audible voice in Discord. Counters are read
independently, queues can be in flight, and report windows on two hosts are not
aligned: compare sustained differences and recovery, not one snapshot. Quiet
periods can be normal voice silence, so they do not automatically trigger a
fallback or a new warning.

*Note on durations:* Use standard Go duration strings like `30s`, `1m`, `1.5h`.

[Documentation index](../README.md) · [Project home](../../README.md)

Source lockout maps retain at most 256 entries in each of 256 shards. Expired entries are removed before admission; unexpired bans are preserved. A full source shard temporarily refuses a new source without reporting a wrong password. Account-alert maps are also bounded; saturation does not evict source bans.
