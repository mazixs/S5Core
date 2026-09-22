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
| `READ_TIMEOUT` | Duration | `30s` | Idle timeout for the relay phase: how long a connection may stay silent once traffic is flowing. Inbound data and successful outbound stream writes refresh the pending read deadline. A blocked write retains its separate `WRITE_TIMEOUT`; setup, incomplete-frame and quota-grace budgets remain absolute. |
| `WRITE_TIMEOUT` | Duration | `30s` | Idle timeout for writes in the relay phase. |
| `HANDSHAKE_TIMEOUT` | Duration | `15s` | Absolute budget for the setup phase: version byte, authentication and the reply to `CONNECT`. Unlike the idle timeouts it is not refreshed by traffic, so a client that dribbles one byte per second is dropped instead of being kept alive. |
| `DIAL_TIMEOUT` | Duration | `10s` | Budget for reaching the destination: resolution plus connect, from the moment the request is parsed to the reply to `CONNECT`. It is cut out of `HANDSHAKE_TIMEOUT`, so a destination that never answers no longer holds a slot for the whole setup budget - see [Connection states](operations.md#connection-states). |
| `FRAME_TIMEOUT` | Duration | `10s` | How long a half-read obfuscation frame may stay half-read. It applies only between a frame header and its body, so it bounds a peer that stops mid-frame without touching a tunnel that is legitimately silent. Ignored on the plain listener, which has no frames. |
| `QUOTA_GRACE` | Duration | `5s` | How long a session whose account just ran out may keep draining what is already in flight. `0` ends the session where the quota is noticed. Nothing new is sent to the destination either way. |
| `MAX_CONNECTIONS` | Integer | `10000` | Limit for concurrent connections, shared by all three listeners. A connection that arrives at the ceiling is closed immediately and counted in `s5core_connections_rejected_total`. |
| `FAIL2BAN_RETRIES` | Integer | `5` | Failed authentication attempts from one source before that source is banned. Set to 0 to disable. |
| `FAIL2BAN_TIME` | Duration | `5m` | How long a source stays banned, and how long the per-account failure counter remembers. |
| `TRAFFIC_FLUSH_INTERVAL` | Duration | `60s` | Interval to flush user traffic metrics to disk (if `USERS_FILE` is used). |
| `KDF_MEMORY_BUDGET_MB` | Integer | `0` | Memory that concurrent password checks may use, in MiB. Argon2id asks for 64 MiB a run, so `0` (the default, 256 MiB) means four at once plus a queue four deep per running check; a check that finds both full is refused without running and counted as `s5core_auth_verifications_total{path="overloaded"}`. A negative value removes the bound. |
| `LOG_LEVEL` | String | `info` | `debug`, `info`, `warn` or `error`. `debug` enables protocol diagnostics - see [docs/design/observability-policy.md](../design/observability-policy.md) for what may appear in logs. |
| `LOG_LEVEL_FILE` | String | *Empty* | Path to a file holding a single level word. Takes precedence over `LOG_LEVEL` and is re-read on `SIGHUP`, which is what lets the level change on a running process. |
| `METRICS_PORT` | String | `8080` | Port to expose OpenTelemetry/Prometheus `/metrics` and `/health` endpoints. |
| `METRICS_BIND_ADDR` | String | `127.0.0.1` | Bind address for the metrics endpoint. **Warning:** do not expose to the public internet without a reverse proxy or firewall. Set to `0.0.0.0` only inside a trusted network or VPN. |
| `OBFS_ENABLED` | Boolean | `false` | Enable traffic obfuscation on a separate port. |
| `OBFS_PORT` | String | `1443` | Separate port for obfuscated connections from `s5client`. The default is kept for compatibility; set a port outside the 443 family (see the note in [Dual-Port Mode](sdk.md#with-obfuscation-dual-port-mode)). |
| `OBFS_PSK` | String | *Empty* | Pre-shared key for obfuscation. **Must be exactly 32 bytes.** |
| `OBFS_MAX_PADDING` | Integer | `256` | Maximum random padding this side adds to each frame it sends (bytes). Sending-side only: the receiver takes the payload length from the decrypted header and never looks at this setting. Padding is capped at half of what a frame can carry, so a large value here cannot squeeze the payload out of the frame. |
| `OBFS_MTU` | Integer | `1400` | Largest frame this side puts on the wire, header and tag included. Writes are cut to fit it, and the send and receive buffers are sized from it (16 and 8 frames, capped at 32 and 16 KiB). |
| `KEEPALIVE_MIN` / `KEEPALIVE_MAX` | Duration | `0s` | Make the **server** send a frame carrying nothing after a silence drawn from this range. Off by default: one end holding the path open is enough, and `s5client` is that end. Turn it on when the clients are not `s5client`. Same shape as the client setting - see [Keepalive](../design/transports.md#keepalive). |
| `OBFS_REPLAY_WINDOW` | Integer | `10000` | How many session prologues the server remembers, shared by every obfuscated listener, so a recorded connection cannot be replayed on a fresh socket. About 16 bytes per entry - a few hundred KB for the whole server, against 82 KB per connection for the per-connection nonce window it replaces. The oldest entry is dropped when the history is full, so this is how many connections a replay must outlive. `0` disables the check. Meaningless on the client, which is the side that draws the salt. |
| `OBFS_NODE_ID` | String | *Empty* | Binds this node's keys to this node. It is never sent: it goes into the prologue MAC and the key derivation, so a client configured for another node is refused exactly the way noise is. Must match the client's `OBFS_NODE_ID`. Empty is itself an identity - a client with a name set cannot reach a server without one. What it buys: a recording made against one node is worthless against another, so no node needs to know what the others have seen. What it costs: anycast, and moving a client between nodes without editing its configuration. |
| `OBFS_ACCEPT_NODE_IDS` | String | *Empty* | Comma-separated node identifiers this server still answers to besides its own, for the window in which clients are being moved from one name to another. Each costs one extra HMAC, and only on a connection that did not match the first. Drop the old name once the clients are gone. |
| `OBFS_REQUIRE_MEMBER_KEY` | Boolean | `false` | Whether a client must hold a `tunnel_key` of an account. `false` is the migration setting: clients without one still connect with the deployment PSK and a password. Set it to `true` once every client has a key - after that the PSK alone no longer reaches the tunnel, and a leaked PSK costs a decoy page instead of an account. |
| `WS_ENABLED` | Boolean | `false` | Enable the WebSocket-over-TLS stealth transport (TLS → WebSocket → obfs → SOCKS5). |
| `WS_ADDR` | String | `<PROXY_LISTEN_IP>:443` | Address for the TLS listener. |
| `WS_CERT_FILE` | String | *Required if `WS_ENABLED`* | PEM certificate for the TLS listener. |
| `WS_KEY_FILE` | String | *Required if `WS_ENABLED`* | PEM private key for the TLS listener. |
| `WS_PATH` | String | `/ws` | Path of the WebSocket endpoint. Every other path serves the decoy site. It must be one exact, literal, already-canonical path: starting with `/`, not `/` or `/favicon.ico`, no trailing slash, no whitespace or control characters, no `?`/`#`, no percent-encoding, no `.`/`..`/`//` segments and none of the router's wildcard syntax (`{}`). Anything else is refused at startup, with a message about `WS_PATH`, before the socket is opened. The endpoint is compared literally against the request path, so a wildcard would be matched by the router and then refused by the upgrade - a tunnel that starts and never answers. |
| `WS_SUBPROTOCOL` | String | *Empty* | Required `Sec-WebSocket-Protocol`. Empty means none is required. |
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

> `TLS_FINGERPRINT` is a **client-side** setting: it selects the TLS Client Hello the client imitates. Setting it on the server changes nothing, so the server logs a warning if it finds it - believing your server traffic is shaped when it is not is worse than not shaping it.

### Client (`s5client`)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `CLIENT_LISTEN_ADDR` | String | `127.0.0.1:1080` | Local address to accept plain SOCKS5 connections. |
| `CLIENT_MAX_CONNECTIONS` | Integer | `1024` | Maximum active local connections, including incomplete handshakes. Excess connections are closed. Non-positive values use the default. |
| `SERVER_ADDR` | String | *Required* | Remote S5Core server obfs address (e.g., `1.2.3.4:27015`) - the host and port the server's `OBFS_PORT` listens on. |
| `PROXY_USER` | String | *Empty* | Username for authenticating with the S5Core server. |
| `PROXY_AUTH_MODE` | String | `auto` | `auto` preserves existing negotiation; `member-only` requires a valid member ID/key, `OBFS_FORMAT=v1`, and no password fields, and pipelines CONNECT; `password-fallback` requires user/pass and waits for the selected method (one additional greeting RTT when member authentication wins). It cannot recover from an invalid tunnel key. |
| `PROXY_PASS` | String | *Empty* | Password for authenticating with the S5Core server. The server calls the same setting `PROXY_PASSWORD`; it also accepts `PROXY_PASS` and says so in its log. |
| `OBFS_PSK` | String | *Required* | Pre-shared key. **Must match the server's PSK exactly.** |
| `OBFS_MAX_PADDING` | Integer | `256` | Padding this side adds to the frames it sends. Independent of the server's setting. |
| `OBFS_MTU` | Integer | `1400` | Largest frame this side sends, and the size its buffers are built from. Independent of the server's setting: each side reads whatever frame length the other declares. |
| `OBFS_CIPHER` | String | *Automatic* | `aes` or `chacha`. Empty - the normal setting - lets the client take the one its processor is good at: AES where AES instructions exist, ChaCha20 where they do not. The server accepts either and learns the choice from the prologue, so this does not have to match anything; it is a knob for measuring. |
| `OBFS_PROLOGUE` | String | `printable` | How the prologue looks on the wire. `printable` encodes it with base64 and adds a secret-derived pad, so the connection opens with 43-63 printable characters and the first packet is exempt from a fully-encrypted-traffic policy; `raw` is the pre-phase-5 wire. A server recognises both without being configured, so lower this only when the server is older than the client. |
| `OBFS_SPLIT_OPENING` | Boolean | `false` | Sends the opening in a packet of its own, ahead of the first frames. The filter measured in `docs/field/stealth.md` classifies first packets of 100 bytes and up, and the opening alone is 43-72 bytes where the client's first write is 125 and up; with a raw prologue, which has no printable exemption, this moved a live tunnel from 14 of 26 connections to 26 of 26. It costs no round trip - the write does not wait for an answer. Off by default: a short packet at a fixed place is a shape of its own, and on the measured path the printable opening passes without one. The server needs no matching setting. |
| `OBFS_NODE_ID` | String | *Empty* | Must match the server's `OBFS_NODE_ID`. It is not sent anywhere - it goes into the key derivation, so a wrong value fails exactly like a wrong PSK: the server accepts the connection, says nothing and closes it. |
| `OBFS_MEMBER_ID` | String | *Empty* | The account this client belongs to. Set it together with `OBFS_MEMBER_KEY`; it never reaches the wire and is only what the client's own log calls itself. |
| `OBFS_MEMBER_KEY` | String | *Empty* | This account's `tunnel_key` from the server's `users.json`, base64, 32 bytes. With it the server knows who is calling before the first frame and asks for no password. Without it the client uses the shared account, which works until the server sets `OBFS_REQUIRE_MEMBER_KEY`. A key that is not in the server's list fails the way a wrong PSK fails - silence, then a closed connection. |
| `ROUTE_DOMAINS` | String | *Empty* | Comma-separated domain patterns for split tunneling. Empty = tunnel all traffic. |
| `TIMEZONE_CHECK` | Boolean | `false` | Ask ipapi.co which timezone the server's address is in and warn when the system timezone differs. Off by default: the lookup tells a third party that this client is about to use this proxy, and puts a recognisable request on the wire right before every connection to it. Run `s5client timezone` to do the check once, by hand. |
| `DIAL_TIMEOUT` | Duration | `10s` | Budget for connecting to the server, including DNS, TCP, TLS and HTTP Upgrade on WSS. The smaller positive value of this and `HANDSHAKE_TIMEOUT` bounds the transport dial. |
| `HANDSHAKE_TIMEOUT` | Duration | `15s` | Separate budgets of this duration cover the local SOCKS5 handshake and remote tunnel setup (transport dial including WSS, greeting, authentication and CONNECT reply). Each deadline is cleared when its phase finishes. A non-positive value still gives the local handshake a 15s limit; established idle tunnels are unaffected. |
| `SHUTDOWN_TIMEOUT` | Duration | `10s` | How long a shutdown waits for connections that are still carrying traffic. Before this the wait had no end, so a client asked to stop kept running for as long as one tunnel stayed open. |
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
| `OBFS_FORMAT` | String | `auto` | The obfuscation wire format: `v1` ([docs/veil-spec.md](../veil-spec.md)), `legacy` (the format before it, for a server that has not been updated), or `auto` - `v1` first, `legacy` for `OBFS_FORMAT_REPROBE` after a server accepted the connection and did not answer, then `v1` again. Set `v1` once every server is updated: the legacy format is detectable, and `auto` shows it to anyone who accepts a connection and stays silent. Scheduled for removal - [docs/field/migration.md](../field/migration.md). |
| `OBFS_FORMAT_REPROBE` | Duration | `10m` | How long `OBFS_FORMAT=auto` stays on the legacy format after falling back to it before it tries `v1` again, so that an updated server is noticed without restarting the client. |
| `LOG_LEVEL` | String | `info` | Same as on the server, including `SIGHUP` reload. On a router, where restarting the client drops every live connection, this is the only way to look at a failure while it is happening. |

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
> `connect` or `connect-reply`.

> **UDP support:** `s5client` transparently handles UDP Associate requests from applications. When an app sends a SOCKS5 UDP Associate command (`0x03`), `s5client` opens a local UDP socket, multiplexes all UDP packets inside the encrypted TCP tunnel (command `0x83`), and the server relays them to the internet as native UDP. No additional configuration is needed. What that costs on a lossy link is measured in [UDP over TCP: what it costs](../design/transports.md#udp-over-tcp-what-it-costs).

> **Domain routing examples:** `example.com` (exact match), `*.google.com` (all subdomains + base domain), `*.youtube.com,*.googlevideo.com` (multiple patterns).

*Note on durations:* Use standard Go duration strings like `30s`, `1m`, `1.5h`.

[Documentation index](../README.md) · [Project home](../../README.md)
