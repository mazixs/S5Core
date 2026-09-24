# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Experimental `s5client` builds for MIPS routers (MT7621, MT7628 and
  similar): `s5client-linux-mipsle-softfloat` and
  `s5client-linux-mips-softfloat`. They have no FPU and no AES instructions,
  so the client takes ChaCha20-Poly1305 by itself and runs it in pure Go. The
  builds pass the client's tests under emulation and talk to an amd64 server,
  but speed, latency and CPU load have not been measured on MIPS hardware and
  are not guaranteed. No server setting is needed. How to pick the binary:
  [router guide](docs/guides/testing.md#s5client-on-a-router).

### Fixed

- The client's test servers accepted AES only. On a processor without AES
  instructions the client picks ChaCha, so three tests failed or hung there
  while passing in CI. They now accept both ciphers like a real server, and a
  new test connects with each one, so the gap shows up on AES hardware too.
- A relay half that ended cleanly after the other half had failed tried to
  move the session from `closed` to `half_closed`. The state table refused the
  move and counted it in `s5core_session_transitions_total{illegal="true"}`.
  A benchmark hour caught one such refusal among idle connections cut by
  `READ_TIMEOUT`. Nothing changed on the wire, because the connection was
  already closed, but the counter reported a driver bug that was real.

### Tooling

- `scripts/pre-commit.sh` builds every target listed in the release workflow,
  reading them from `.github/workflows/release.yml`, so a build that breaks on
  one of them fails before a tag instead of in the release job.
- `scripts/matrix` has a game session scenario, `game/64hz-200b`: one hour of
  64 Hz UDP with a direct stream running at the same time as control. It runs
  only when named. Plain SOCKS5 now runs in WAN mode too (real UDP through
  `0x03`, behind the stand's IP filter), and the report names each illegal
  session transition instead of only counting them.

## [2.2.0] - 2026-09-24

### Upgrade notes

- The wire format does not change for a fleet already on 2.x: a 2.2 client
  talks to 2.0 and 2.1 servers, and a 2.2 server accepts 2.0 and 2.1 clients,
  including those configured with `OBFS_PROLOGUE=raw`.
- A client configuration with `OBFS_FORMAT=legacy` or `OBFS_PROLOGUE=raw`
  now fails at startup with a message naming the fix: remove the variable.
  `OBFS_FORMAT_REPROBE` is ignored.
- A 2.2 client cannot reach a 1.x server. Move such a fleet through 2.1
  first ([migration](docs/field/migration.md), 4.2).
- SDK: the `pkg/obfs/legacy` package is gone.

### Removed

- The previous obfuscation format (`pkg/obfs/legacy`) and the client's
  `OBFS_FORMAT=legacy` and `OBFS_FORMAT_REPROBE`. No 2.x server accepts that
  format. `OBFS_FORMAT=auto` and `v1` keep working and mean the same thing;
  `legacy` is now a startup error that says what to set instead. A fleet
  still on 1.x moves through 2.1 ([migration](docs/field/migration.md), 4.2).
- The client's `OBFS_PROLOGUE=raw`: every 2.x server reads the printable
  opening, and a filtering path blocks the raw one. Servers still accept
  both encodings from 2.0 and 2.1 clients.

### Performance

- Bound the obfs relay's scheduling point by time: at most one
  `runtime.Gosched()` per 100 microseconds per direction, and only after a
  batch longer than one frame. Removing the yield entirely raised mixed-load
  p99 by 4.7-66 times in the process benchmark. Against yielding after every
  batch, the bound takes 13-21% off bulk CPU per GiB and leaves mixed-load p99
  where it was; against no yield at all it costs 7-27% of bulk CPU per GiB
  ([measurements](docs/benchmarks/yield.md)). On the ARM router one batch
  takes longer than the interval, so there the bound behaves like yielding
  after every batch: the same CPU, and 16-31% lower mixed-load p99 than no
  yield.
- Size the WebSocket write buffer on both ends to the shaper's
  `WS_MAX_FRAME` (never below 4096). With `WS_MAX_FRAME` above 4096, every
  larger frame used to leave as a full 4096-byte buffer plus a remainder,
  which gave the stream one constant-length record.
- Take the client's relay buffers from a pool instead of allocating
  32 KiB per direction per tunnel.
- Compute each obfs frame's length mask once. A coalescing read unmasked
  every buffered frame twice, once to see that it is whole and once to
  parse it.
- Dial a single resolved address inline, without a goroutine, channel or
  timer. A derived dial deadline no longer parks one goroutine per attempt.
- Encode SOCKS5 addresses with one function (`socks5.AppendAddr`) for
  replies, UDP headers and the client's UDP associate reply.

### Fixed

- The client's UDP associate no longer lets a datagram without a SOCKS5 UDP
  header decide where answers go. The answer port follows the application's
  last datagram, and a late reply from a UDP reflector to a reused port used
  to take it: the association's answers went to the reflector, the server
  logged `invalid udp-tcpmux header`, and the application saw a timeout
  ([matrix run](docs/benchmarks/matrix-2026-09-22/README.md)).
- The client no longer logs a warning per answer still in the tunnel when a
  UDP association closes, and a connection that closes before the SOCKS5
  greeting (a port check) is logged at debug level instead of as an error.
- When one address family fails with "network unreachable" and the other
  meets a real error, the client now gets the real error.
- `isTimeout` in the UDP associate path now recognises wrapped timeouts.
- A failed reply write after a rule rejection is classified as a
  connection failure, like other reply writes.

### Documentation

- TLS session resumption: browser fingerprints never resume, so the session
  cache only affects clients without `TLS_FINGERPRINT`. Those clients present
  the same PSK identity on parallel connections, so a passive observer can
  link the connections. Tests record this behaviour
  (`pkg/transport/ws/session_cache_test.go`).
- WAN comparison of 2.2 against 2.1.0 on a third node (RTT 51 ms, router
  client): connection setup matches to the millisecond, zero errors in all
  cells, equal CPU and RSS, and the one upload flag from three rounds did not
  hold on eight (19.0 against 19.0 MB/s). Every number has a control without
  the tunnel ([field notes](docs/field/nodes.md)).
- Measurements behind the relay's scheduling bound
  ([yield](docs/benchmarks/yield.md)), the protocol matrix of 2026-09-22 and
  the version comparison of 2026-09-23 (`docs/benchmarks/`).

### Tooling

- `scripts/matrix`: one benchmark pipeline for comparing builds from git refs
  and the working tree against a run without the proxy. A TOML plan covers
  TCP, HTTP, HTTPS, HTTP/2, HTTP/3, UDP and soak over loopback, netem or a
  real WAN path. Each cell runs in its own unprivileged network namespace
  under three timeout levels (operation, scenario, cell), and hung, stalled
  and crashed cells are recorded as such instead of stopping the run. Runs
  resume after a failure, and the HTML report gives a paired verdict per
  round. The WAN mode runs the server as transient systemd units behind an IP
  filter and cleans up after itself
  ([README](scripts/matrix/README.md)).

## [2.1.0] - 2026-09-22

### Docker and installation

- Simplify server/client env templates and add `scripts/init-env.sh HOST:PORT`
  to generate matching credentials with owner-only file permissions, without
  overwriting an existing configuration.
- Change Docker defaults to SOCKS5 `28173`, obfs `28479` and metrics `8789`.
  Plain SOCKS5 and metrics remain published on host loopback. Explicit env
  values override these defaults. Standalone binary defaults are unchanged.
- Enable obfs in the quick-start template; remove shared example credentials.
- Add log rotation, a read-only container root, reduced privileges and a
  30-second shutdown grace period. Keep pull-based updates using `latest`.
- Cache Go dependencies and compilation, and cross-compile amd64/arm64 images
  without QEMU in the build stage.
- Shorten the README and move configuration, SDK, transport and operational
  details into focused guides. Document inherited components in Credits and
  third-party notices.

**Existing Docker installations:** if your `.env` previously omitted port
settings, add the values below before updating to preserve the old endpoints:

```dotenv
PROXY_PORT=1080
OBFS_PORT=1443
METRICS_PORT=8080
```

Otherwise update the firewall, client destination and monitoring configuration
for the new ports. Keep existing credentials; do not rerun initialization over
a working configuration. See the [Docker guide](docs/guides/docker.md).

### Performance

- Drain complete, already-buffered obfs frames in one read without waiting for
  more network data. Yield outside read/write locks after large batches to
  preserve interactive latency during bulk transfers. The wire format, cipher,
  padding and shaping are unchanged.
- Give the WebSocket upgrader an explicit 4096-byte payload buffer, reducing
  allocations on a representative 22752-byte batch from 8 to 6. The measured
  cost is about 768 additional retained heap bytes per idle WS pair and
  4.80 KiB additional allocation when creating a pair, without TLS/obfs.
- Compile domain routes once into exact and label-boundary suffix maps.
  With 10000 rules, lookup decreased from about 728 microseconds to 77
  nanoseconds; a separate process test confirmed lower CONNECT latency.
- Add explicit `PROXY_AUTH_MODE=member-only` and `password-fallback` modes.
  Member-only saves one greeting RTT for applicable new tunnels, keeps
  authentication required, and fails closed on incompatible configuration.
- Reuse bounded TLS session caches per immutable client configuration, with
  separate Go TLS and uTLS caches and preserved certificate/pin validation.
  `WS_TLS_SESSION_CACHE=false` disables reuse. Browser fingerprints without
  a resumption extension retain full handshakes.

Desktop process A/B measurements of complete 8 MiB HTTPS responses showed
obfs throughput gains of 145-206% across download/upload and new/reused
connections, and WSS gains of 26-28%. Obfs download CPU/GiB decreased by
37-40%; WSS download CPU/GiB increased by 3-13%. These are laboratory
results, not WAN guarantees. Real ARM execution and a 10200-request-per-case
obfs tail-latency comparison passed the specified latency threshold.
The [implementation report](docs/reports/performance-implementation-2026-09-22.md)
records samples, tradeoffs, rejected experiments and remaining release gates.
DNS caching and PGO were evaluated but not enabled without demonstrated benefit.

### Fixed

- Keep active HTTPS downloads alive by refreshing the pending stream read
  deadline on successful outbound writes. Blocked writes and incomplete obfs
  frames retain independent, bounded deadlines.
- Schedule suppressed keepalives from the latest activity instead of adding a
  second full interval; stop service frames on write half-close.
- Try validated DNS address candidates within one shared budget, with at most
  two concurrent attempts and a two-second minimum per-attempt allowance
  capped by the remaining time. Preserve custom resolver and rewriter policy.
- Bound WSS DNS/TCP/TLS/HTTP Upgrade by the caller's context, interrupt canceled
  upgrades, and include transport dialing in the tunnel handshake budget.
- Preserve data returned with a transport error and keep terminal obfs read
  failures sticky. Validate the SOCKS greeting response version.

The [HTTPS remediation report](docs/reports/socks5-https-remediation-2026-09-21.md)
documents H01-H05 and the subsequent R01 address-budget correction.

### Diagnostics and validation

- Add `httpsprobe` with actual HTTP response timing, complete-body verification,
  upload support and new/reused HTTP/1.1/2 connections; expose DNS as a separate
  server phase instead of conflating TCP first-byte timing with HTTP TTFB.
- Add opt-in process ABBA benchmarks, CPU/RSS accounting, isolated netem,
  mixed traffic and long-stream checks. Diagnostic builds write local profiles
  without publishing a pprof HTTP endpoint.
- Validate old/new client-server combinations, authentication modes, uTLS
  profiles, 4/16/64 request concurrency, UDP under simulated loss, full race
  checks and both release binaries across all five supported platform targets.

See the [validation guide](docs/performance-validation.md) for reproduction.
Publication of these changes is not a production deployment: representative
WAN/VPS acceptance, peak-load budgets and a limited canary remain outstanding.

## [2.0.0] - 2026-09-21

A major release: the obfuscated wire format changed and the pre-2.0 one is no
longer accepted by the server. Configuration and metrics did not break - every
environment variable and every metric of 1.4.x still exists and still means the
same thing - but **a 1.4.x client cannot connect to a 2.0 server**.

### Upgrade order - clients first

1. **Clients.** A 2.0 client with `OBFS_FORMAT=auto` (the default) speaks to
   both a 1.4.x server and a 2.0 server, falling back on its own.
2. **Servers.** Once a server is upgraded, clients on `auto` stop falling back:
   their next probe of the current format succeeds, at the latest after
   `OBFS_FORMAT_REPROBE`.
3. **Pin the format.** Set `OBFS_FORMAT=v1` on clients, or wait for the release
   that drops the old one.

Watch `s5core_client_connections_total{client_version}` to see when the last
1.4.x client is gone. The reverse order - servers first - leaves 1.4.x clients
with no connectivity, and no server setting fixes that.

Details and the removal schedule: `docs/field/migration.md`.

### Breaking

- **Wire format.** Frames are now `[MaskedLen 2B][AEAD(kind|len|payload|pad)]`
  behind a 32-byte prologue, with per-session, per-direction keys derived with
  HKDF-SHA256 and a frame counter as the nonce. The 1.4.x format (4-byte length,
  random nonce, AES-GCM straight on the PSK) survives only in the client, under
  `OBFS_FORMAT=legacy`; the server refuses it. Specification:
  `docs/veil-spec.md`.
- **A non-zero `FRAG` in a SOCKS5 UDP header is refused** instead of being
  forwarded. There is no fragment reassembly, and forwarding a piece of a
  datagram hands the target part of a message as if it were the whole one.
  Clients that put garbage in that byte now see their datagrams dropped, which
  surfaces as a timeout in the application rather than a corrupted answer.
- **`users.json` is validated strictly at load.** A password hash that cannot be
  parsed, or a role that is not `user`, `operator` or `admin`, rejects the whole
  file - at startup or on the `SIGHUP` that brought it. Argon2id panics on some
  parameter sets rather than returning an error, and a negative memory cost used
  to turn into a terabyte-sized allocation.
- **Accounts without `tunnel_key` are migrated on load**: each gets 32 random
  bytes and the file is rewritten, with a warning naming the accounts but never
  the keys. `SIGHUP` migrates in memory only and does not touch the file.

### Added

- **`pkg/veil`** - first-frame authentication and key derivation as a
  replaceable scheme. `Symmetric` (bare random salt), `Clocked` (salt plus an
  HMAC over the hour epoch, the default, tolerating about two hours of clock
  skew) and `Roster` (eight of the random bytes carry a member identity, so two
  members sharing a PSK cannot read each other's traffic). A member lookup is
  one map read: 1240 ns with 8 members, 1231 ns with 262 144.
- **Cipher agility.** The client picks AES-256-GCM where the CPU has hardware
  AES and ChaCha20-Poly1305 where it does not; the server accepts both and
  learns the choice from the prologue MAC. Key, nonce and tag sizes match, so
  the frame shape does not change.
- **Printable prologue** (`OBFS_PROLOGUE=printable`, the default). The opening
  goes on the wire base64-encoded with a padding length derived from the session
  secret, so it is printable and its boundary is not at a fixed offset. On a
  filtering path this took first-packet refusals from 45 out of 48 to 0 out of
  78.
- **WebSocket/TLS transport** (`pkg/transport/ws`) with frame shaping: every
  write is split into at least two frames at variable cut points, so an
  obfuscated frame length does not reach the wire as a TLS record length.
- **TLS decoy listener** (`pkg/transport/tlsdecoy`). One socket serves the
  tunnel on `WS_PATH` and a decoy everywhere else - a built-in static page, or,
  with `WS_DECOY_UPSTREAM`, a reverse proxy to a real site. An unauthenticated
  request gets the upstream's status, headers and body, including its 404.
- **Half-close as a frame** (`kindFIN`), identical on TCP and WebSocket, plus
  keepalive frames whose padding tracks recent data frames and whose interval is
  redrawn from `[KEEPALIVE_MIN, KEEPALIVE_MAX]`.
- **Replay protection** (`OBFS_REPLAY_WINDOW`): a ring of recent prologues,
  shared by all obfuscated listeners. The refusal is issued after the first
  frame is decrypted, not when the prologue is parsed, so a replay is not faster
  to refuse than a wrong PSK.
- **Refusals cost the same as noise.** A refused obfuscated connection is not
  reset: the server reads and discards bytes until the handshake budget expires,
  so a wrong PSK, a replay and plain garbage all take the same time to close.
- **Explicit connection state** (`internal/session`): three orthogonal regions
  (protocol, frames, account) with their own transition tables. Deadlines are
  asked of the session rather than set by a mode, and a quota that runs out
  half-closes the connection in flight instead of at the next one.
- **Roles and tunnel keys.** `role` in `users.json` (`user`/`operator`/`admin`)
  with a closed permission table; `tunnel_key` identifies an account before the
  SOCKS5 handshake, in constant time and without a password. In the SDK,
  permissions are checked on `Server.As(username)`, not on `*Server`.
- **Transport advice** (`TRANSPORT_ADVICE`, `TRANSPORT_ADVICE_FILE`): the server
  recommends a transport inside the tunnel and the client applies it to the next
  connection - no binary replacement, no extra round trip. The file wins over
  the variable and is re-read on `SIGHUP`, because the environment of a running
  process cannot be changed from outside.
- **TLS fingerprint control** (`TLS_FINGERPRINT`, uTLS) and **certificate
  pinning** (`WS_PIN_SHA256`).
- **Observability**: `s5core_session_transitions_total`, `s5core_sessions`,
  `s5core_client_connections_total{client_version,transport}`,
  `s5core_obfs_handshake_failures_total`, `s5core_obfs_clock_skew_total`,
  `s5core_connection_phase_seconds`, `s5core_connections_rejected_total`,
  `s5core_auth_verifications_total`, `s5core_build_info` and others. No 1.4.x
  metric was removed or renamed. Label sets are closed in code, with one
  documented exception (`client_version`), fenced to 32 named builds.
- **Measurement tools**: `cmd/fpprobe` (what the path does to a first packet,
  judged by `bytes_acked` from `TCP_INFO`), `cmd/fpcollect` (JA3/JA4 receiver),
  `cmd/connlat` (round trips per connection setup), `cmd/idleprobe`,
  `cmd/udpprobe`, `cmd/wirebench`, `cmd/stealthcheck`, `scripts/leak_matrix.py`.
- **Documentation** reorganised by the question each document answers:
  `docs/veil-spec.md` (the wire format, the single source of truth, read from
  disk by tests), `docs/design/`, `docs/benchmarks/`, `docs/field/`,
  `docs/gates/`. New in this release: `docs/field/mihomo.md`, a guide to running
  the client as the exit node of a proxy core that knows nothing about s5core.

### Changed

- **One authentication mechanism.** `PROXY_USER`/`PROXY_PASSWORD` no longer live
  in a separate password map: the user store is always created when
  authentication is required, just without a file. Argon2id, quotas, expiry and
  roles now apply to every deployment, not only to the ones with `USERS_FILE`.
- **Passwords are Argon2id** (`internal/passwordhash`); plaintext is accepted
  only to be migrated on the first successful login, and the migration hashes
  with the lock released.
- **UDP Associate holds two sockets per association**: the one announced to the
  client talks only to the client, and a second one talks to targets.
- **DNS resolution fits inside a single datagram's budget** on UDP paths, and
  shares one deadline with the dial on the CONNECT path.
- **`Server.Stop` ordering**: cancel, close listeners, wait, and only then flush
  traffic counters - the relay hands over its last batch when a half finishes.
- **CI and release** run the same script (`scripts/pre-commit.sh`) in the same
  container, so a local run and CI give one verdict. Nothing is published before
  the checks pass.

### Fixed

Thirty-four confirmed defects, each closed with a regression test that was
verified by reverting the fix. The full list lived in `docs/fix-plan.md`; the
audit that found nineteen of them is `docs/reports/code-quality-audit-2026-09-20.md`.

Highlights:

- Removing an account did not revoke its tunnel key (F01).
- An allowed address in a UDP request opened access to denied destinations (F02).
- UDP traffic bypassed quotas, expiry and accounting (F03).
- An active `0x83` tunnel could block shutdown (F04).
- An unauthenticated WebSocket message was not bounded in memory (F05).
- A cold Argon2id path allowed unbounded distinct verifications (F06).
- An admin handle kept its rights after the role was lowered or the account
  removed (F07); `operator` could read every account's keys (F08).
- The release workflow could not build the Windows binaries, and published the
  image before the build failed (F09).
- A bad initial `ALLOWED_IPS` disabled access control instead of failing (F10).
- The client accepted a truncated reply to the UDP tunnel command and then read
  the rest of it as frame lengths (F14).
- Incomplete PHC validation could panic or exhaust memory (F15).
- A `WS_PATH` the validator accepted could crash startup (F16).
- A partial startup failure left already-started listeners running (F17).
- `SIGHUP` re-read the transport advice from a source that cannot change (F19).
- A certificate pin was not checked on a resumed TLS session, because
  `VerifyPeerCertificate` is not called there; pinning moved to
  `VerifyConnection` and is chained onto the caller's own check (gosec G123).
- Three unchecked type assertions on the UDP paths turned a caller that is not a
  socket into a panic mid-association instead of a refusal at its start.

### Security

- Timing of refusals is uniform across wrong PSK, replay and garbage.
- Tunnel keys are never written to logs.
- Metrics bind to localhost by default.
- `govulncheck` and `golangci-lint` run in CI on every commit.

## [1.4.4] - 2026-03-05

Last release of the 1.x line. See the field report in
`docs/reports/v1.4.4-field-run.md`.

[Unreleased]: https://github.com/mazixs/S5Core/compare/v2.2.0...HEAD
[2.2.0]: https://github.com/mazixs/S5Core/releases/tag/v2.2.0
[2.1.0]: https://github.com/mazixs/S5Core/releases/tag/v2.1.0
[2.0.0]: https://github.com/mazixs/S5Core/releases/tag/v2.0.0
[1.4.4]: https://github.com/mazixs/S5Core/releases/tag/v1.4.4
