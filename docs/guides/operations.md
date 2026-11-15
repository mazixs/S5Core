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
- `s5core_obfs_idle_closes_total` (Counter, label `transport`): Obfuscated connections the peer closed without sending a byte: a client's spare connection that was not needed (`PREWARM`) or a connect-and-drop scan. They are not failures and are not counted in `s5core_obfs_handshake_failures_total`.
- `s5core_obfs_clock_skew_total` (Counter, labels `transport`, `direction`): Connections whose prologue authenticated against an hour outside the accepted window - a peer whose clock is wrong, not a scanner. The exact number of hours goes to the log, not to a label. Anything here is a client that cannot connect and does not know why.
- `s5core_connection_phase_seconds` (Histogram, seconds, labels `phase`, `outcome`): How long each stage of a connection took.
- `s5core_connections_in_phase` (UpDownCounter, label `phase`): How many connections are sitting in each stage right now.
- `s5core_build_info` (Gauge, always 1, labels `version`, `go_version`, `transports`): Which build is running and which transports it listens on.
- `s5core_client_connections_total` (Counter, labels `client_version`, `transport`): Tunnels whose client introduced itself, by the client's build and the listener it arrived on. This is the distribution a migration is steered by: which builds are still out there and whether a `TRANSPORT_ADVICE` is being followed. `transport` is the listener's label, not the client's claim. `client_version` is cut to build-identifier characters and the server names at most 32 distinct builds; every later one is `other`, an empty version is `unknown`. Clients that send no hello - older builds - are the difference between `s5core_connections_total` and this counter on the same transport.
- `s5core_sessions` (Gauge, labels `region`, `state`, `transport`): How many connections are in each state of each region of the connection state machine right now - see [Connection states](#connection-states). Read at scrape time from the registry of open sessions, so a transition costs one atomic store and nothing per metric.
- `s5core_session_transitions_total` (Counter, labels `region`, `from`, `to`, `transport`, `illegal`): Every state change the sessions made. `illegal="true"` is a move the state machine refused, i.e. a bug in whatever drove the connection; on a healthy server it stays at zero.
- `s5core_half_close_failures_total` (Counter, labels `side`, `transport`): Connections whose write side could not be shut down.
- `s5core_auth_verifications_total` (Counter, label `path`): Password checks, by what answered them - `kdf` (Argon2id ran), `cache` (remembered verifier), `coalesced` (waited for a KDF run already in flight) or `overloaded` (the KDF memory budget was full, so the check was refused without running - see `KDF_MEMORY_BUDGET_MB`).

### Go runtime and process metrics

`/metrics` serves one registry owned by the `s5core` binary: the OTel exporter with the `s5core_*` families, a Go collector, a process collector and the handler's own `promhttp_metric_handler_*` counters. Collectors registered on the global `prometheus.DefaultRegisterer`, for example by a dependency, do not appear on this port. The SDK (`pkg/s5server`) registers no Go or process collectors: an embedding application exports its own.

The Go collector keeps its default families (`go_gc_duration_seconds`, `go_memstats_*`, `go_goroutines`, `go_threads`, `go_info`, `go_gc_gogc_percent`, `go_gc_gomemlimit_bytes`, `go_sched_gomaxprocs_threads`), the process collector keeps `process_*`. On top of them the server exports eleven [runtime/metrics](https://pkg.go.dev/runtime/metrics) sources. They are process-wide and carry no labels:

| Runtime source | Family | Type |
| --- | --- | --- |
| `/sched/pauses/total/gc:seconds` | `go_sched_pauses_total_gc_seconds` | Histogram |
| `/sched/latencies:seconds` | `go_sched_latencies_seconds` | Histogram |
| `/gc/cycles/total:gc-cycles` | `go_gc_cycles_total_gc_cycles_total` | Counter |
| `/gc/cycles/forced:gc-cycles` | `go_gc_cycles_forced_gc_cycles_total` | Counter |
| `/cpu/classes/gc/total:cpu-seconds` | `go_cpu_classes_gc_total_cpu_seconds_total` | Counter |
| `/cpu/classes/gc/mark/assist:cpu-seconds` | `go_cpu_classes_gc_mark_assist_cpu_seconds_total` | Counter |
| `/cpu/classes/gc/mark/idle:cpu-seconds` | `go_cpu_classes_gc_mark_idle_cpu_seconds_total` | Counter |
| `/cpu/classes/total:cpu-seconds` | `go_cpu_classes_total_cpu_seconds_total` | Counter |
| `/gc/heap/live:bytes` | `go_gc_heap_live_bytes` | Gauge |
| `/gc/limiter/last-enabled:gc-cycle` | `go_gc_limiter_last_enabled_gc_cycle` | Gauge |
| `/sync/mutex/wait/total:seconds` | `go_sync_mutex_wait_total_seconds_total` | Counter |

Both histograms have seven finite buckets, from 64 ns to about 117 ms, so their quantiles are interpolated: everything between 0.92 ms and 10.5 ms falls into one bucket.

[`docs/operations/runtime.rules.yml`](../operations/runtime.rules.yml) holds recording rules over these families, per `job` and `instance`, named `instance:go_*`: GC pause and scheduler latency p95/p99 over five minutes (no sample when the window has no observations), GC cycle and allocation rates, the GC share of runtime CPU, mutex wait rate, runtime-managed memory and its share of `GOMEMLIMIT` when a limit is set, and whether the GC CPU limiter was activated. To use them, put the file next to the Prometheus configuration and list it under `rule_files`:

```yaml
rule_files:
  - runtime.rules.yml
```

The fixtures in [`runtime.rules.test.yml`](../operations/runtime.rules.test.yml) run in CI. Locally, from the repository root:

```bash
promtool check rules docs/operations/runtime.rules.yml
promtool test rules docs/operations/runtime.rules.test.yml
```

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

`session` overlaps the other phases. These observations do not add up to HTTP latency: request parsing, rules, rewriting and reply writes have their own gaps. `dns` is absent for numeric destinations and includes failed lookups; `dial` excludes DNS. `first_byte` starts after the SOCKS success reply and ends on the first destination TCP byte. For HTTPS that is usually the TLS handshake, not HTTP TTFB. `outcome` is `ok` or `fail`, so a phase that is slow only when it fails does not hide inside the average. A UDP association that the client closed (the normal end) is a `session` that is `ok`; any other end of an association is `fail`. A connection that never sends the SOCKS5 version byte - a probe, or a client's spare connection that was not needed - records no phase at all, the same rule the session journal follows; `s5core_connections_in_phase` still counts it while it is open.

Measure an actual HTTPS response from the client with the probe:

```bash
go run ./cmd/httpsprobe -url https://example.com/ -count 3
go run ./cmd/httpsprobe -url https://example.com/ -socks 127.0.0.1:1080 -count 3 -reuse
```

Each JSON line contains `started_unix_ns` for trace correlation, `connect_setup_ms` (direct DNS/TCP or proxy TCP plus SOCKS negotiation/CONNECT), `tls_handshake_ms`, `http_first_response_ms` (request start to `httptrace.GotFirstResponseByte`), `total_ms` (through complete body reading and SHA-256), bytes, hash, status, negotiated protocol and connection reuse. `client_dns_ms` covers only local DNS and overlaps setup; remote DNS is part of SOCKS setup and is visible separately in the server metric. Reused requests have no new setup or TLS duration. Failures include partial byte counts and no completed-body hash. The probe verifies certificates, accepts an additional CA with `-ca`, follows no redirects, and limits every request including its body with `-timeout`. `-http2=false` forces HTTP/1.1; `-http2=true` permits HTTP/2 and reports the protocol actually negotiated. For obfs/WSS, point `-socks` at the local s5client listener.

The [performance acceptance guide](../benchmarks/performance-validation.md) describes separate-process A/B runs, diagnostic builds, isolated netem, and release gates.

CONNECT retains all addresses supplied by the built-in resolver, removes duplicates and alternates address families. It tries at most two addresses concurrently with staggered starts and one shared DNS/connect budget. Per-attempt shares have a 2-second minimum, capped by the remaining shared budget, as in Go net.Dialer. A short budget may expire before every unresponsive address is tried. Every candidate is checked against `Rules` before dialing a numeric IP; fallback does not resolve the domain again. A legacy custom `NameResolver` still supplies one address. Custom resolvers may additionally implement `MultiNameResolver.ResolveAll`. When an address `Rewriter` is configured, its single returned destination remains authoritative and pre-rewrite addresses are not used as fallback.

`s5core_build_info` is always 1; its labels carry `version`, `go_version` and `transports` (e.g. `plain,obfs,ws`). Together with the startup line

```
INFO Active transports summary="plain:1080, obfs:27015, ws:off" version=v1.2.3 go_version=go1.27.4
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

`reason` is a bounded value, and together with the byte histogram it separates the cases that used to look identical in the logs:

| `reason` | What it means | Typical cause |
| --- | --- | --- |
| `decrypt_fail` | Frame is well formed but AES-GCM rejects it | A tampered frame. A PSK typo no longer lands here: the frame length is masked with a key derived from the PSK, so a peer with the wrong key does not produce a frame the server can even find the end of - it looks like a scanner and ends as `eof_before_frame` |
| `replay` | The frame authenticates, but the connection's session salt has been seen before | A recorded connection replayed onto a fresh socket. The refusal is issued only after the frame has been decrypted, so a prober cannot tell it apart from a bad tag by timing |
| `history_full` | The authenticated opening cannot be retained without evicting a live replay record | The process has exhausted its replay-history capacity. It refuses the opening through the same path as an invalid tag; unauthenticated openings do not consume this capacity |
| `short_frame` | Frame or plaintext is shorter than the format allows | Truncated or hand-crafted frame |
| `eof_before_frame` | Stream ended before a frame was complete | A disconnect after some bytes, a plaintext probe, a peer with the wrong PSK, or a silent peer that outlived the handshake budget. A peer that closes without sending a byte is not here: it is `s5core_obfs_idle_closes_total` |
| `bad_opening` | The opening was read in full, but no session came out of it | A scheme that refused the prologue. With the schemes shipped today this counter stays at zero: an unrecognised client is given a wrong secret rather than a refusal, so it fails one frame later as `decrypt_fail` or `eof_before_frame` |

Each connection reports at most one failure, so a peer that keeps retrying on one socket cannot inflate the counters.

`transport` is `obfs` or `ws`. There is deliberately no label for the source address: it would both leak who connects and make the metric unbounded in cardinality. For the full rule see [docs/design/observability-policy.md](../design/observability-policy.md). Per-connection detail is available on demand at `LOG_LEVEL=debug` (see [Hot Reloading](#hot-reloading)), which logs the reason and the byte count - still without the address.

`s5core_traffic_bytes_in` and `s5core_traffic_bytes_out` count forwarded payload for CONNECT and UDP. UDP uses the same payload level for standard Associate, TCP fallback (`0x83`) and native UDP (`0x84`); SOCKS5 headers are excluded. The fallback payload is counted once. These definitions replace the previous counters that also included TCP framing and could count fallback UDP payload twice; comparisons across that change require the corresponding version and metric definition.

`s5core_tcp_stream_bytes_in` and `s5core_tcp_stream_bytes_out` separately count the decrypted TCP stream, including SOCKS5 negotiation and UDP framing. They exclude obfuscation and TLS overhead. Neither counter proves delivery to the remote application: a successful write only establishes local acceptance of the bytes.

Per-account traffic accounting is separate from telemetry. Its batching threshold is 64 KiB, with an additional one-second check while packets arrive and a final flush when the relay ends. Idle CONNECT sessions also check account status every second; revocation, expiry and quota apply through the configured grace period. Batched spend and the polling interval allow a bounded accounting delay, so telemetry totals are not an exact instantaneous quota balance.

> **Security Warning:** By default, the metrics endpoint binds to `127.0.0.1:8080` and is not exposed outside the host. If you change `METRICS_BIND_ADDR` to `0.0.0.0`, ensure the port is protected by a firewall, VPN, or reverse proxy with authentication. The `/metrics` endpoint may reveal internal counters and connection details.

`http://<IP>:8080/health` is an HTTP liveness probe for the metrics service. It does not authenticate a tunnel or check destination reachability; use a request through `s5client` to verify the complete proxy path.

---

## Latency diagnostics

The latency recorder is a black box for latency that comes and goes. While it is on, it keeps the last two minutes of measurements of the outer sockets, of the other side of their CONNECT relays and of the queue in front of the socket of a native UDP association in memory. When a spike starts or the operator asks, it saves those two minutes and the 90 seconds after to disk as an incident. It is off unless `S5_DIAGNOSTICS_DIR` is set, and it works the same in `s5core` and `s5client`. Off, it costs one atomic load per accepted connection, per tunnel, per CONNECT relay and per native UDP association. On, it also reads the clock twice on every read and write of a recorded socket, and the writer of a recorded queue updates three atomics per frame without reading the clock again.

### Turning it on

| Variable | Meaning |
|---|---|
| `S5_DIAGNOSTICS_DIR` | The directory for incidents. The recorder creates it if it is missing; on POSIX it gets `0700`, on Windows an access list for the process user, `SYSTEM` and `Administrators` that passes on to the files inside. A directory that exists must be as private already: on POSIX no group or other bits and owned by the effective user; on Windows owned by one of those three, with a protected access list that grants nobody else. A symbolic link or a junction is refused. |
| `S5_DIAGNOSTICS_RUN_ID` | Names the run in every manifest, so the incidents of the server and the client of one test can be matched. At most 256 bytes; a new UUID by default. |
| `S5_DIAGNOSTICS_TRACE` | `1` also keeps a flight recorder of the Go execution trace and saves its last 30 seconds with each incident. Up to 32 MiB more memory. |

The recorder starts in the background after the logging is set up. It writes `Latency diagnostics are on` or, if the directory cannot be used, `Latency diagnostics are off` with the reason; forwarding goes on either way.

One directory serves one process. The budget and the rotation count the whole directory and there is one `trigger.json`, so two processes in one directory would take the same marker and write over each other's files of one incident. To match the incidents of several processes, give each its own directory and write the same UUID into the marker of each.

### What it records

The server records each connection accepted on its listeners: plain SOCKS5, obfs and WebSocket. The client records the transport of each tunnel; an idle spare connection is not recorded until a tunnel takes it. On both ends the recorder's wrapper sits under the obfuscation, the deadlines and the server's limit. A recorded socket is a *flow*, numbered from 1 in each run of the process.

At most 32 outer sockets are recorded at once: the first to arrive take the slots, and a closed socket gives its slot back. New sockets are admitted at a burst of 32, then eight a second. A socket closed under a wrapper nobody closed is noticed at the next sample and gives its slot back too.

When a recorded outer socket carries a CONNECT, the other side of the relay is recorded as a flow of its own, a *related* flow: on the server the connection to the destination (`leg` `target`), on the client the application's connection (`leg` `application`). Its `flow_open` names the outer flow in `outer_flow`. A related flow takes no slot and no admission token. An outer flow has one at a time, and at most 32 related flows are recorded at once, counting one that outlives its outer flow. Its samples never start an incident: on the server its path is the destination's network, not the tunnel's. An incident started by its outer flow or by hand holds it like any other flow.

When a recorded outer socket carries a native UDP association (`0x84`), the queue in front of it is recorded too. The datagrams that do not go natively travel in `0x83` frames on that socket, and its writer holds them in a queue of up to 1024 frames and 2 MiB until the socket takes them: a frame past the queue is dropped, and so is a frame that waited 250 ms when its turn comes. The queue is part of the outer flow: it takes no slot and no token, a socket has at most one, and it never starts an incident. A `0x83` association, and a `0x84` one that a node without native UDP carries as `0x83`, has no such queue: its frames are written to the socket as they come, and a slow write shows in the socket's stage records.

For each flow the recorder keeps:

- **stage records**: one read and one write in 512, and every write that took 25 ms or more. A read waits for the peer, so a long read is not recorded on its own; the longest read between two samples goes into the next socket sample instead;
- **socket samples**: the kernel's counters at the open, every 500 ms, and at the close;
- **queue records**, for an outer flow with a native UDP association: its queue every 500 ms, right after the socket sample;
- **flow records**: the addresses at the open, the number of reads and writes at the close.

For the process it keeps the Go runtime metrics every 500 ms.

To tell on which side of the relay a delay arose, read the samples of an outer flow and its related flow side by side, sample by sample:

- `rtt_us`, `retransmits` and `bytes_retrans` that grow on one flow only point to the path of that socket: the tunnel's for the outer flow, the destination's or the application's for the related one;
- `read_wait_max_ns` is how long the peer of that socket kept the relay waiting for data;
- a `slow` write on a flow, or `not_sent_bytes` that pile up on it, means that socket's peer or path did not take the data as fast as the other side of the relay delivered it.

A datagram that goes by the stream of a native UDP association waits twice: in the writer's queue, which the queue records show, and in the socket's send buffer, which `not_sent_bytes` of the socket sample before them shows. Read the two records of a sample together:

- `frame_wait_max_ns` is the longest a frame written since the sample before waited in the queue. It is at most 250 ms: a frame that waited longer was dropped and counted in `dropped_age_frames`;
- `writing` with `write_elapsed_ns` is a write that has not returned yet, and `queued_frames` are the frames waiting behind it. Held over several samples while `not_sent_bytes` is high, it is a stream that does not send: the socket's `cwnd_segments`, `send_window_bytes` and `retransmits` say why;
- `frame_wait_max_ns` that grows while `not_sent_bytes` stays near zero and no write is held: the socket takes each frame at once, so the wait arose in front of it. The frames came faster than the writer wrote them (`queued_frames`), or the writer waited for a CPU (the runtime's `/sched/latencies:seconds`);
- `not_sent_bytes` that grows while `frame_wait_max_ns` stays low: a write returns once the kernel holds the bytes, so the frames leave the queue at once and wait in the send buffer instead, where the queue does not see them;
- both growing, with `writing` set: the send buffer is full, frames pile up behind the held write, and `dropped_age_frames` or `dropped_full_frames` grow once they wait 250 ms or fill the queue.

The write is timed from the writer down, through the obfuscation; the socket's stage records time the part below the recorder's wrapper. A write held for long with no `slow` write on the socket when it ends spent its time above the socket. On Windows a socket sample has no `not_sent_bytes`; there a held write and `slow` writes are what shows a stream that does not take the data.

### Incidents

An incident starts in one of two ways:

- **by hand**: write `{"incident_id":"<UUID>"}` to `trigger.json` in the directory. The recorder looks at it every 500 ms and takes each marker once. A marker whose incident a previous process saved starts nothing;
- **automatically**, per socket and against that socket's own floor:
  - the round trip time is at least 20 ms above the lowest round trip time of the socket and at least one and a half times it, for three samples in a row in which the socket moved data;
  - or the retransmit timer fired: on Linux a sample taken while it keeps firing, on Windows one more timeout episode than at the sample before.

  One socket starts at most one incident in two minutes.

Only one incident is written at a time. A marker during an automatic incident takes it over: the incident gets the marker's ID, keeps the history already saved, and its 90 seconds start again at the marker. Any other trigger while an incident is written is counted in the manifest and dropped.

An incident is the records from up to two minutes before its trigger to 90 seconds after it. The recorder streams them into a partial file while they come, then renames it and writes the manifest last. Each incident has these files:

| File | Contents |
|---|---|
| `<id>.events.jsonl` | one JSON object per record, in order |
| `<id>.manifest.json` | what is the same for every record; an incident with a manifest is complete |
| `<id>.trace` | with `S5_DIAGNOSTICS_TRACE=1`: the execution trace; `go tool trace` reads it |

A file ending in `.partial` is an incident the process did not finish: it was killed, or it ran out of room. It stays until its room is needed.

### Disk budget

The directory may hold up to 256 MiB, and the recorder leaves at least 256 MiB free on the volume. One events or trace file takes at most 64 MiB. When an incident needs room, the oldest incident that may go is removed with all its files: an automatic incident, by its trigger, or the files of one without a manifest, such as `.partial` files, by when they were last written. A manual incident is never removed, nor the automatic incident it took over, nor what the process is still writing, nor an incident whose manifest cannot be read. The budget counts the files directly in the directory: a subdirectory is neither counted nor touched. When nothing is left to remove, the recorder stops with one line in the log, `Latency diagnostics stopped`, and forwarding goes on. An incident that reaches its share of the budget ends early and its manifest says `truncated`.

In memory the recorder keeps a ring of 32 768 records of 64 bytes, 2 MiB. Socket samples (about 150 bytes each), queue records (64 bytes each) and runtime samples (about 3 KiB each) come on top. With the most there can be, 32 outer flows each with its queue and 32 related flows, two minutes without traffic are about 23 400 records, under three quarters of the ring, with about 2.1 MiB of socket samples, 0.5 MiB of queue records and 0.7 MiB of runtime samples.

### Event schema

Every line has these fields:

| Field | Meaning |
|---|---|
| `seq` | the record's number in the run, without gaps |
| `elapsed_ns` | nanoseconds since the recorder started, by the monotonic clock |
| `utc` | the wall clock at the same moment; it may jump, `elapsed_ns` does not |
| `flow` | the flow, `0` for the process |
| `leg` | `outer` for an outer flow, `target` (server) or `application` (client) for a related flow, `process` for the process |
| `transport` | the flow's transport, `tcp` for a related flow; no transport for the process |
| `kind` | what `data` holds, below |

| `kind` | `data` |
|---|---|
| `stage` | `boundary` (`transport_read`, `transport_write`), `duration_ns`, `bytes`, `error`, `periodic` (one in 512), `slow` (a write of 25 ms or more) |
| `socket` | `reason` (`open`, `periodic`, `close`), `available` (whether the kernel answered), `read_wait_max_ns` (periodic samples only: the longest read since the sample before), `tcp` |
| `flow_open` | `local`, `remote`; for a related flow `outer_flow`, the outer flow it belongs to |
| `flow_close` | `read_calls`, `write_calls`, and `evicted: true` for a socket closed under its wrapper |
| `runtime` | each [runtime metric](https://pkg.go.dev/runtime/metrics) by its name: a number, `null` where this Go version lacks it, or for a histogram its bucket counts |
| `spike` | `reason` (`rtt_excess`, `retransmit_timeout`), `incident_id` |
| `queue` | `queued_frames` and `queued_buffer_bytes` (the frames waiting in the queue at the sample and the buffers they take, by which the queue is bounded: 2 KiB for a frame of up to 2 KiB, 64 KiB for a longer one), `dropped_full_frames` and `dropped_age_frames` (frames dropped since the writer started: past the queue, or after waiting 250 ms), `frame_wait_max_ns` (the longest a frame written since the sample before waited in the queue), `writing` (a write to the socket has not returned yet), `write_elapsed_ns` (with `writing` only: how long that write has taken so far) |

`tcp` holds only the counters the kernel gave; a counter that an older kernel or another system does not have is left out rather than written as zero. Each name includes its unit:

| Name | Linux | Windows |
|---|---|---|
| `rtt_us`, `min_rtt_us` | smoothed and lowest round trip time | the same |
| `rttvar_us`, `rto_us` | round trip variance, retransmit timeout | - |
| `since_data_ms`, `since_ack_ms` | time since the peer's last data and last acknowledgement | - |
| `state` | TCP state, Linux numbering | - |
| `retransmits` | retransmit timeouts in a row | - |
| `unacked_segments`, `total_retrans_segments`, `cwnd_segments` | in segments | - |
| `cwnd_bytes`, `in_flight_bytes` | - | congestion window and bytes in flight |
| `not_sent_bytes` | written, not yet sent | - |
| `send_window_bytes`, `receive_window_bytes` | the peer's and our window | the same |
| `bytes_acked` | over the life of the connection | - |
| `bytes_received`, `bytes_sent`, `bytes_retrans` | over the life of the connection | the same; `bytes_retrans` is 32 bits wide |
| `timeout_episodes` | - | retransmit timeouts of the connection |

### Manifest schema

| Field | Meaning |
|---|---|
| `schema` | `3`; an incident of schema `2` has no queue records, one of schema `1` holds outer flows only |
| `incident_id`, `run_id`, `boot_id` | the incident; the run (`S5_DIAGNOSTICS_RUN_ID`); this start of the process |
| `process_id`, `go_version`, `build_version`, `goos`, `goarch` | the process and its build |
| `recorder_start_utc` | the wall clock at `elapsed_ns` 0 |
| `trigger` | `source` (`manual`, `automatic`), `utc`, `elapsed_ns`; for an automatic incident `reason` and `flow`; for a takeover `prior_automatic_incident` (its trace, if any, is `<prior>.trace`) |
| `window` | `first_seq`, `last_seq`, `start_elapsed_ns`, `end_elapsed_ns`, `start_utc`, `end_utc` of the records saved; `lost_before_capture` (records the ring gave up before they were saved); `shutdown_before_post_end`; `truncated` |
| `trace` | `disabled`, `captured`, `failed`, `skipped` (an earlier incident's trace was still being written) or `writing` (the manifest was written before the trace was done, as when the process stops; a `<id>.trace` there is complete) |
| `flows` | each flow in the records: `flow`, `leg`, `transport`, `local`, `remote`, and for a related flow `outer_flow` |
| `limits` | every constant that shaped the records, from `sample_interval_ns` to `trace_max_bytes` |
| `health` | since the start of the process: `overwritten` (records a full ring pushed out before their two minutes), `rejected_marker` (polls of a marker that could not be read), `rejected_while_manual`, `rejected_while_automatic`, `failed_snapshots`, `rotated_incidents`, and `selection`: `admitted`, `omitted_rate`, `omitted_active` of the outer sockets, and `evicted_closed` (flows found closed under their wrapper, related ones included) |
| `runtime_histogram_bounds` | the bucket bounds of each runtime histogram; `null` is an open end |

### Limits

- Besides the outer sockets only the other side of a CONNECT relay and the queue in front of the socket of a native UDP association are recorded. The datagrams themselves are not: neither the UDP sockets of a standard Associate or of a `0x83` or `0x84` association, nor native UDP packets, nor the datagrams the client holds until the server answers an association.
- A queue record shows the queue at the moment of its sample: a burst that comes and goes between two samples shows only in `frame_wait_max_ns` and in the drops.
- On the client, an optimistic CONNECT whose tunnel is set up again on a fresh transport keeps its application flow tied to the flow of the first transport.
- The first 32 outer sockets keep their slots for as long as they live, so on a busy server the recorded ones are not a sample of all of them.
- A stage record times the call into the transport where the wrapper sits, TLS and WebSocket framing included. A write returns once the kernel took the bytes, not once the peer got them.
- On Windows the counters are those of `SIO_TCP_INFO` version 0 (Windows 10 1703 and later); elsewhere but Linux and Windows a socket sample says `available: false`.
- On Windows the clock the durations are measured by advances in steps, about 0.5 ms on the machine this was checked on: a wait or a write shorter than a step reads as 0, so a `frame_wait_max_ns` of 0 there means a wait under a step, not none.
- A socket's lowest round trip time only goes down, so a path that became longer for good goes on starting automatic incidents, at most one in two minutes per socket.
- The recorder shares the process: an incident is written by the same process whose latency it records.

---

## Hot Reloading

`SIGHUP` makes the process re-read what it can re-read while running, without breaking existing connections.

**What a reload can actually change** is what has a source outside the process:

| Source | What it changes |
| --- | --- |
| `USERS_FILE` | accounts, quotas, expiry and roles; accumulated traffic is merged rather than lost |
| `LOG_LEVEL_FILE` | the log level (`SIGUSR1` toggles debug without any file at all) |
| `TRANSPORT_ADVICE_FILE` | what the server advises every client, from the next accepted connection; an empty or removed file sends an explicit withdrawal |

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
