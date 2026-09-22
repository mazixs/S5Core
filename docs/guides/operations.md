# Monitoring & Metrics

S5Core utilizes OpenTelemetry. By default, the standalone app runs an OTel Prometheus exporter. If `METRICS_PORT` is set (default `8080`), it exposes metrics at `http://<IP>:8080/metrics`.

Available metrics:
- `s5core_connections_active` (UpDownCounter): Current number of active TCP sessions.
- `s5core_connections_total` (Counter): Total number of accepted connections since start.
- `s5core_connections_rejected_total` (Counter, labels `transport`, `reason`): Connections closed on arrival. `reason="limit"` is the server at `MAX_CONNECTIONS` - without it a server at its ceiling looks exactly like a server nobody is using. `reason="setup_failed"` is a connection the transport layer could not wrap at all; the listener stays up, so this is the only place a listener that refuses everything it accepts becomes visible.
- `s5core_auth_failures_total` (Counter): Total number of failed authentication attempts.
- `s5core_traffic_bytes_in` (Counter): Total volume of incoming traffic in bytes (TCP + UDP).
- `s5core_traffic_bytes_out` (Counter): Total volume of outgoing traffic in bytes (TCP + UDP).
- `s5core_obfs_handshake_failures_total` (Counter, labels `reason`, `transport`): Obfuscated frames rejected before they reached SOCKS5.
- `s5core_obfs_bytes_before_failure` (Histogram, bytes, same labels): How much a peer sent before its connection was rejected.
- `s5core_obfs_clock_skew_total` (Counter, labels `transport`, `direction`): Connections whose prologue authenticated against an hour outside the accepted window - a peer whose clock is wrong, not a scanner. The exact number of hours goes to the log, not to a label. Anything here is a client that cannot connect and does not know why.
- `s5core_connection_phase_seconds` (Histogram, seconds, labels `phase`, `outcome`): How long each stage of a connection took.
- `s5core_connections_in_phase` (UpDownCounter, label `phase`): How many connections are sitting in each stage right now.
- `s5core_build_info` (Gauge, always 1, labels `version`, `go_version`, `transports`): Which build is running and which transports it listens on.
- `s5core_client_connections_total` (Counter, labels `client_version`, `transport`): Tunnels whose client introduced itself, by the client's build and the listener it arrived on. This is the distribution a migration is steered by: which builds are still out there and whether a `TRANSPORT_ADVICE` is being followed. `transport` is the listener's label, not the client's claim. `client_version` is cut to build-identifier characters and the server names at most 32 distinct builds; every later one is `other`, an empty version is `unknown`. Clients that send no hello - older builds - are the difference between `s5core_connections_total` and this counter on the same transport.
- `s5core_sessions` (Gauge, labels `region`, `state`, `transport`): How many connections are in each state of each region of the connection state machine right now - see [Connection states](#connection-states). Read at scrape time from the registry of open sessions, so a transition costs one atomic store and nothing per metric.
- `s5core_session_transitions_total` (Counter, labels `region`, `from`, `to`, `transport`, `illegal`): Every state change the sessions made. `illegal="true"` is a move the state machine refused, i.e. a bug in whatever drove the connection; on a healthy server it stays at zero.
- `s5core_half_close_failures_total` (Counter, labels `side`, `transport`): Connections whose write side could not be shut down.
- `s5core_auth_verifications_total` (Counter, label `path`): Password checks, by what answered them - `kdf` (Argon2id ran), `cache` (remembered verifier), `coalesced` (waited for a KDF run already in flight) or `overloaded` (the KDF memory budget was full, so the check was refused without running - see `KDF_MEMORY_BUDGET_MB`).

### Where the time goes

`s5core_connection_phase_seconds` records six phases, modelled on HAProxy's timing fields:

| `phase` | Measured from | Measured to |
| --- | --- | --- |
| `handshake` | handler starts waiting for the version byte | an authentication method is agreed |
| `auth` | credentials are requested | credentials are accepted or rejected |
| `dns` | resolver is called for a domain | lookup succeeds or fails |
| `dial` | checked destination addresses are ready | TCP connection succeeds or all attempts fail |
| `first_byte` | success reply is sent to the client | destination sends its first byte |
| `session` | SOCKS handler is entered | handler returns |

`session` overlaps the other phases. These observations do not add up to HTTP latency: request parsing, rules, rewriting and reply writes have their own gaps. `dns` is absent for numeric destinations and includes failed lookups; `dial` excludes DNS. `first_byte` starts after the SOCKS success reply and ends on the first destination TCP byte. For HTTPS that is usually the TLS handshake, not HTTP TTFB. `outcome` is `ok` or `fail`, so a phase that is slow only when it fails does not hide inside the average.

Measure an actual HTTPS response from the client with the probe:

```bash
go run ./cmd/httpsprobe -url https://example.com/ -count 3
go run ./cmd/httpsprobe -url https://example.com/ -socks 127.0.0.1:1080 -count 3 -reuse
```

Each JSON line contains `started_unix_ns` for trace correlation, `connect_setup_ms` (direct DNS/TCP or proxy TCP plus SOCKS negotiation/CONNECT), `tls_handshake_ms`, `http_first_response_ms` (request start to `httptrace.GotFirstResponseByte`), `total_ms` (through complete body reading and SHA-256), bytes, hash, status, negotiated protocol and connection reuse. `client_dns_ms` covers only local DNS and overlaps setup; remote DNS is part of SOCKS setup and is visible separately in the server metric. Reused requests have no new setup or TLS duration. Failures include partial byte counts and no completed-body hash. The probe verifies certificates, accepts an additional CA with `-ca`, follows no redirects, and limits every request including its body with `-timeout`. `-http2=false` forces HTTP/1.1; `-http2=true` permits HTTP/2 and reports the protocol actually negotiated. For obfs/WSS, point `-socks` at the local s5client listener.

The [performance acceptance guide](../performance-validation.md) describes separate-process A/B runs, diagnostic builds, isolated netem, and release gates.

CONNECT retains all addresses supplied by the built-in resolver, removes duplicates and alternates address families. It tries at most two addresses concurrently with staggered starts and one shared DNS/connect budget. Per-attempt shares have a 2-second minimum, capped by the remaining shared budget, as in Go net.Dialer. A short budget may expire before every unresponsive address is tried. Every candidate is checked against `Rules` before dialing a numeric IP; fallback does not resolve the domain again. A legacy custom `NameResolver` still supplies one address. Custom resolvers may additionally implement `MultiNameResolver.ResolveAll`. When an address `Rewriter` is configured, its single returned destination remains authoritative and pre-rewrite addresses are not used as fallback.

`s5core_build_info` is always 1; its labels carry `version`, `go_version` and `transports` (e.g. `plain,obfs,ws`). Together with the startup line

```
INFO Active transports summary="plain:1080, obfs:27015, ws:off" version=v1.2.3 go_version=go1.26.6
```

it answers the two questions that cannot be checked from outside the host: which build is running, and which transports it actually listens on. A server whose operator believes it is stealthy while it only listens on the plain port is a configuration failure that used to be invisible until someone read the logs line by line.

`s5core_connections_active` and `s5core_connections_total` carry a `transport` label (`plain`, `obfs`, `ws`), so the split of clients across transports is visible - which is also the first input for deciding how much of a migration any protocol change costs. The client's own version is not visible to the server yet: nothing in the current handshake carries it. That arrives with the S5Veil handshake (plan task Ф5).

`s5core_auth_verifications_total` is the health of the password path. `kdf` should stay nearly flat: it moves when the users file is reloaded or a new password appears, not with the connection rate. If `rate(kdf)` starts tracking `rate(s5core_connections_total)`, the verifier cache has stopped working and every login is back to 110 ms and 64 MiB - the state measured in [docs/benchmarks/argon2-cost.md](../benchmarks/argon2-cost.md) before plan task Ф3-6. `overloaded` should be zero: it means password checks were refused because the KDF memory budget was full, which is either a burst of accounts nobody has logged in with yet or someone guessing, and it is answered with `KDF_MEMORY_BUDGET_MB` and with `FAIL2BAN_RETRIES` respectively.

`s5core_half_close_failures_total` should stay at zero. It was added when half-close worked over plain TCP and over obfs but not over WebSocket, because `ws.Conn` has no `CloseWrite`: a destination that closed its side left the client waiting for a timeout. The signal now lives in the obfuscation format as a frame kind, so both transports carry it ([docs/design/half-close.md](../design/half-close.md)), and this counter has become an alarm for the next transport added without it - it names the side and the transport that could not pass the end of the stream on.

#### How many round trips a connection costs

The phase histograms say where the time goes on one deployment; this says how
much of it is the protocol rather than the link. `scripts/conn_latency.sh`
puts three containers behind `tc netem` with a symmetric 50 ms round trip and
measures the setup with `cmd/connlat`, whose target writes its first byte the
moment it accepts:

| Path | dial | setup | first byte | total |
|---|---|---|---|---|
| straight to the destination | 1.01 RTT | - | 1.00 RTT | **2.01 RTT** (100.5 ms) |
| plain SOCKS5 on the server | 1.01 RTT | 3.01 RTT | 1.00 RTT | **5.02 RTT** (251.2 ms) |
| obfs through `s5client` | 0.00 RTT | 3.02 RTT | 1.00 RTT | **4.03 RTT** (201.3 ms) |
| WSS through `s5client` | 0.00 RTT | 5.06 RTT | 1.00 RTT | **6.06 RTT** (303.2 ms) |

The obfuscated path spends one round trip on the TCP handshake, half of one
sending everything the server needs - session salt, SOCKS5 greeting and the
CONNECT request, pipelined into a single frame - one while the server dials
the destination, half getting the reply back, and one on the destination's
first byte. The obfuscation layer itself costs none: it has no handshake of
its own. WSS adds two, TLS 1.3 and the WebSocket upgrade.

Two things follow. A deployment reporting 0.31 s to the first byte over WSS is
reporting 6 round trips on a 50 ms link, not slow code - the remainder after
the chain is within a few percent of zero. And a future handshake has nothing
to win by being 0-RTT, because this one already is; what it has to do is not
lose the property. Adding one server reply before the client may send payload
costs 4.03 → 5.03 RTT, 25% of the setup. The full reasoning is in
[docs/gates/g4-first-frame.md](../gates/g4-first-frame.md).

```bash
DELAY=25ms RUNS=20 ./scripts/conn_latency.sh   # ~2 min, needs docker
```

`s5core_connections_in_phase` is the one to alert on: "a third of the connections are parked in `first_byte`" is an anomaly you can see in Prometheus, whereas the same situation in the logs is just a quiet server.

### Connection states

The phase histograms measure elapsed time. `s5core_sessions` measures
something else: which state each connection is in at this instant. A
connection is in three states at once, in three regions that change
independently (plan task Ф6-1):

| `region` | `state` values | What it is |
| --- | --- | --- |
| `protocol` | `accepted`, `handshake`, `dialing`, `relay`, `half_closed`, `closed` | Where the SOCKS5 conversation has got to. |
| `frames` | `await_header`, `await_body`, `deliver`, `frame_error` | What the obfuscation reader is waiting for. Published only on the framed transports (`obfs`, `ws`); the plain listener has no such region, so it reports no cells for it. |
| `account` | `within_quota`, `grace`, `quota_exceeded`, `expired` | Whether the account behind the connection may still transfer. |

Each state carries its own deadline instead of one `READ_TIMEOUT` covering
everything: `HANDSHAKE_TIMEOUT` for `handshake`, `DIAL_TIMEOUT` for `dialing`,
`READ_TIMEOUT`/`WRITE_TIMEOUT` for `relay`, `FRAME_TIMEOUT` for `await_body`,
`QUOTA_GRACE` for `grace`. A tunnel in `relay` has no idle timeout at all -
it is silent whenever the application has nothing to send - but a tunnel
stuck mid-frame still has one, which is the distinction a single idle timeout
could not express.

The regions are independent except in one place, and that one is the point:
an account running out (`within_quota` → `grace`) moves the protocol region
to `half_closed`. The quota takes effect during the connection, not at the
next one - what is already in flight drains for `QUOTA_GRACE`, nothing new
goes to the destination.

This is also the metric bug 1 of the [field report](../reports/v1.4.4-field-run.md) needed. `s5core_connections_active`
counts every connection the same, so a server whose destinations stopped
answering and a busy server produce the same number. `s5core_sessions` splits
them: connections piling up in `protocol/dialing` while `protocol/relay` stays
healthy is a destination problem, and it is one PromQL expression away:

```promql
s5core_sessions{region="protocol", state="dialing"}
  / ignoring(state) sum without(state) (s5core_sessions{region="protocol"})
```

`s5core_session_transitions_total` is the same picture as rates - how many
connections reached `relay` per second, how many ended in `half_closed`
rather than `closed`. Its `illegal` label is the self-check: the state
machine refuses a move it has no edge for and counts it instead of
pretending, so a driver that starts relaying without dialing shows up as a
number rather than as confusing latency.



### Telling obfuscation failures apart

`reason` is one of four values, and together with the byte histogram they separate the cases that used to look identical in the logs:

| `reason` | What it means | Typical cause |
| --- | --- | --- |
| `decrypt_fail` | Frame is well formed but AES-GCM rejects it | A tampered frame. A PSK typo no longer lands here: the frame length is masked with a key derived from the PSK, so a peer with the wrong key does not produce a frame the server can even find the end of - it looks like a scanner and ends as `eof_before_frame` |
| `replay` | The frame authenticates, but the connection's session salt has been seen before | A recorded connection replayed onto a fresh socket. The refusal is issued only after the frame has been decrypted, so a prober cannot tell it apart from a bad tag by timing |
| `short_frame` | Frame or plaintext is shorter than the format allows | Truncated or hand-crafted frame |
| `eof_before_frame` | Stream ended before a frame was complete | Ordinary disconnect, a connect-and-drop scan, a plaintext probe, or a peer with the wrong PSK |
| `bad_opening` | The opening was read in full, but no session came out of it | A scheme that refused the prologue. With the schemes shipped today this counter stays at zero: an unrecognised client is given a wrong secret rather than a refusal, so it fails one frame later as `decrypt_fail` or `eof_before_frame` |

Each connection reports at most one failure, so a peer that keeps retrying on one socket cannot inflate the counters.

`transport` is `obfs` or `ws`. There is deliberately no label for the source address: it would both leak who connects and make the metric unbounded in cardinality. For the full rule see [docs/design/observability-policy.md](../design/observability-policy.md). Per-connection detail is available on demand at `LOG_LEVEL=debug` (see [Hot Reloading](#hot-reloading)), which logs the reason and the byte count - still without the address.

> **Note:** UDP traffic flowing through the standard UDP Associate relay is tracked with batched counters (flushed every 1 MB) to minimize performance overhead. UDP traffic tunneled via `s5client` (command `0x83`) is automatically counted as TCP bytes since it flows through the obfuscated TCP connection.

> **Security Warning:** By default, the metrics endpoint binds to `127.0.0.1:8080` and is not exposed outside the host. If you change `METRICS_BIND_ADDR` to `0.0.0.0`, ensure the port is protected by a firewall, VPN, or reverse proxy with authentication. The `/metrics` endpoint may reveal internal counters and connection details.

`http://<IP>:8080/health` is an HTTP liveness probe for the metrics service. It does not authenticate a tunnel or check destination reachability; use a request through `s5client` to verify the complete proxy path.

---

## Hot Reloading

`SIGHUP` makes the process re-read what it can re-read while running, without breaking existing connections.

**What a reload can actually change** is what has a source outside the process:

| Source | What it changes |
| --- | --- |
| `USERS_FILE` | accounts, quotas, expiry and roles; accumulated traffic is merged rather than lost |
| `LOG_LEVEL_FILE` | the log level (`SIGUSR1` toggles debug without any file at all) |
| `TRANSPORT_ADVICE_FILE` | what the server advises every client, from the next accepted connection |

**What it cannot change is the environment.** A running process keeps the environment it was started with: editing `.env` or exporting a variable in another shell does not reach it, and a reload re-applies the values the process already had. `ALLOWED_IPS`, `READ_TIMEOUT`, `WRITE_TIMEOUT`, `HANDSHAKE_TIMEOUT`, `DIAL_TIMEOUT`, `FRAME_TIMEOUT` and `QUOTA_GRACE` are re-parsed on `SIGHUP` and therefore change only if the process is restarted - or, for an embedding application, through `UpdateWhitelist`, `UpdateTimeouts`, `UpdateHandshakeTimeout` and `UpdateSessionTimeouts` on the SDK, which take values from the caller rather than from the environment. `TRANSPORT_ADVICE` used to be documented as reloadable and was not, for exactly this reason; `TRANSPORT_ADVICE_FILE` is the changeable source it needed. An advice that cannot be read or does not parse is logged and the previous one kept.

**How to reload:**
1. Edit the file whose setting you are changing (`users.json`, the log level file, the advice file).
2. Send a `SIGHUP` signal to the process:
```bash
kill -HUP $(pgrep s5core)
```
*If running in Docker:*
```bash
docker compose kill -s HUP s5core
```

---

## Shutdown

`SIGTERM` (or `SIGINT`) stops the server in this order: the listeners close, the live connections are closed, the connection handlers finish, and the traffic counters are written to `USERS_FILE`. Only then does the process exit, so the traffic accumulated since the last periodic flush - up to `TRAFFIC_FLUSH_INTERVAL` of it - survives a restart.

Sessions are closed rather than waited for. A tunnelled session can last hours; waiting for one is not a shutdown, and an orchestrator that gave the process ten seconds would kill it anyway.

The WSS listener also cancels active decoy requests, closes their HTTP sockets,
and joins in-flight upgrade handlers before draining unaccepted WebSockets.
A decoy upstream that stops sending its response body cannot hold shutdown open.
If WS shaping jitter is enabled, closing the connection or expiring its write
deadline interrupts that pause too.

The client stops on its own terms. `SIGTERM` closes the local listener and then waits up to `SHUTDOWN_TIMEOUT` (10 s by default) for the sessions still carrying traffic. It used to wait without a bound, and one stuck relay was enough to keep a client running long after it was asked to stop: the relay copied in both directions and ended only when both copies ended, while the far end had no way to learn that the application had closed its half. Each direction now ends its own copy - when the application closes, the client half-closes the tunnel, the server sees the end of the stream and closes the destination, and the reply still comes back the other way. Both transports now signal the end of one direction the same way: the end of the stream is a frame kind inside the obfuscation format (`kindFIN`), not a property of the transport under it, so the WebSocket path - which has no half-close of its own - no longer has to close the whole connection and cut off a reply the server had not finished sending. That was task Ф4-9; the cost in benchstat and the write deadline race found along the way are in [docs/design/half-close.md](../design/half-close.md).

Embedding applications get the same behaviour from `Stop()`, which returns once everything above has happened.

> **The order is load-bearing, not cosmetic.** A relay reports the bytes it moved in batches of up to 64 KiB and hands over the last, unreported one only when the direction ends. Saving the file before the handlers finish therefore writes it as if that batch had never happened - silently, on every restart, for every live session. `TestStopPersistsWhatALiveSessionMoved` keeps a session alive across `Stop()` and checks the file afterwards.

[Documentation index](../README.md) · [Project home](../../README.md)
