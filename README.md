<div align="center">
  <h1>S5Core</h1>
  <p><strong>A High-Performance, Production-Ready SOCKS5 Proxy Server & Go SDK with Traffic Obfuscation</strong></p>

  [![Latest Release](https://github.com/mazixs/S5Core/actions/workflows/release.yml/badge.svg)](https://github.com/mazixs/S5Core/actions)
  [![Go Report Card](https://goreportcard.com/badge/github.com/mazixs/S5Core)](https://goreportcard.com/report/github.com/mazixs/S5Core)
  [![License](https://img.shields.io/badge/License-GPL_2.0-blue.svg)](LICENSE)

</div>

## Overview

**S5Core** is a modern, lightweight, and extremely fast SOCKS5 server designed for high-load production environments. Written purely in Go, it features strict authentication, rate limiting, anti-bruteforce protection, zero-cost architecture with zero-allocation buffers, built-in observability with OpenTelemetry, **AES-256-GCM traffic obfuscation** that leaves no protocol markers on the wire, and **full UDP relay support** that prevents WebRTC/DNS leaks.

S5Core can be run as a standalone executable via Docker/CLI or embedded directly into your own Go applications as an SDK Core (e.g., for building Web-UI proxy panels).

> **Upgrading from 1.x?** The obfuscated wire format changed in 2.0 and the server no longer accepts the old one, so **upgrade clients before servers**: a 2.0 client with `OBFS_FORMAT=auto` talks to both. Every environment variable and every metric of 1.4.x still works. See [CHANGELOG.md](CHANGELOG.md) and [`docs/field/migration.md`](docs/field/migration.md).

## Features

- **Traffic Obfuscation:** AES-256-GCM encryption with random-length padding on every frame, and frames cut to the MTU so that the wire never carries a packet the network could not have produced. DPI systems cannot detect SOCKS5 signatures, domain names, or any protocol patterns on the wire.
- **UDP Relay & Anti-Leak Tunneling:** Full RFC 1928 UDP Associate (`0x03`) support. Additionally, `s5client` automatically tunnels all UDP traffic (WebRTC, DNS, QUIC) inside the obfuscated TCP connection via a custom command (`0x83`), making UDP leak attacks impossible.
- **Client & Server Architecture:** Includes `s5client` - a local proxy that accepts plain SOCKS5 and tunnels traffic through an encrypted obfuscation layer to the S5Core server.
- **Domain-Based Routing (Split Tunneling):** Route only specific domains or wildcards (e.g., `*.google.com`) through the encrypted tunnel.
- **Configurable MTU:** Control frame sizes to match your network topology and avoid fragmentation.
- **High Performance:** Uses `sync.Pool` for buffer reuse during I/O operations, practically eliminating Garbage Collector pauses.
- **SDK & Core Architecture:** Extracted core logic into `pkg/s5server`, allowing any external Go app to import S5Core, manage proxies programmatically, and hot-add/remove users or whitelists on the fly.
- **Built-in Fail2Ban:** In-memory tracking of authentication failures. The hard limit is keyed on the source address (IPv6 by /64), so a run from one client is stopped and nobody can lock another account's owner out by guessing at their user name. An account collecting failures from many sources raises an alert (`s5core_auth_account_alerts_total`) and gets a short delay per attempt - never a refusal.
- **Agnostic Observability:** Uses OpenTelemetry (`go.opentelemetry.io/otel`). Send metrics seamlessly to Prometheus, Datadog, Jaeger, or any OTel-compatible backend.
- **Rate Limiting:** Global connection limits (`netutil.LimitListener`) to protect your server from File Descriptor exhaustion and OOM errors.
- **I/O Deadlines (Slowloris Protection):** Strict Read/Write timeouts on raw TCP sockets prevent stale connections from draining resources.
- **Security First:** Authentication enabled by default, regex-based destination FQDN filtering, and strict IP Whitelisting.

---

## Traffic Obfuscation

S5Core implements a custom obfuscation layer inspired by [AmneziaWG](https://amnezia.org/), [XTLS Vision](https://github.com/XTLS/Xray-core), and [Hysteria v2 Salamander](https://hysteria.network/). The obfuscation wraps every TCP frame with AES-256-GCM encryption and random-length padding, so nothing on the wire names the protocol being carried. A write is cut into equal parts that each fit `OBFS_MTU`, so the frame size follows the configured MTU rather than the size of whatever buffer handed the data over.

### How It Works

```
TCP: App → s5client (plain SOCKS5) → [AES-256-GCM + random padding] → s5core → [decrypt] → SOCKS5 → Internet
                localhost:1080              encrypted tunnel (noise)      server:OBFS_PORT

UDP: App → s5client (UDP Associate) → [UDP-over-TCP mux + AES-256-GCM] → s5core → [demux] → UDP → Internet
                localhost:1080              same encrypted tunnel         server:OBFS_PORT
```

- **On the wire, in both directions:** a 4-byte length, then high-entropy bytes. No SOCKS5 greeting, no domain names, no HTTP keywords, no TLS handshake.
- **What that is not:** cover. High entropy from the first byte, with no handshake in front of it, is itself a description a classifier can hold: it matches no common protocol rather than matching a popular one. It defeats keyword and signature matching; it does not make the connection look like a banking app, and a policy of "allow what I recognise" stops it.
- **When the channel has to look like something,** use the WebSocket transport (`WS_ENABLED`): a real TLS handshake, a real HTTP upgrade, and a decoy site on every other path. The obfuscation then rides inside it.

### Wire Protocol

Each frame on the wire:
```
[Prologue (32B)]                          client only, in front of its first frame
[Masked Length (2B)] [AES-256-GCM Ciphertext]
                      └─ encrypts: [Kind (1B)] [PayloadLen (2B)] [Payload] [PaddingLen (2B)] [Padding]
```

The kind byte says what the frame is: `0` data, `1` keepalive, `2` FIN. It sits
inside the AEAD, so the wire shows a frame of the usual length either way - a
keepalive and a FIN are padded to the length of a frame the connection has
already sent. The FIN is what gives the tunnel a half-close: a WebSocket has
none of its own (its close frames end both directions at once), so without it
an application closing its request half forced the whole connection shut and
cut off the reply. Both transports now end a stream the same way, and the
counter that measured the difference (`s5core_half_close_failures_total`)
should stay at zero.

The length is masked with a keystream, and the nonce is gone from the wire:
both ends count frames and derive the nonce from the counter, so a frame costs
23 bytes of overhead instead of 36 and nothing on the wire sits at a fixed
offset. The client opens the connection with a 32-byte prologue; from the PSK
and that prologue, HKDF-SHA256 derives four keys - an AEAD and a length mask
per direction - so the two directions share no key and no nonce space, and two
connections under the same PSK have no bytes in common. What this does not
give is forward secrecy: the prologue is public, so whoever learns the PSK can
still open a recorded session. That needs a key exchange, and
[docs/gates/g4-first-frame.md](docs/gates/g4-first-frame.md) records what it would cost.

The prologue is also what makes a replay visible, and it expires on its own.
Twenty-four of its bytes are random and eight are a MAC over those bytes and
the current hour, so a recording stops being accepted a few hours later
without the server remembering anything about it. Within that window the
server still keeps a history of the prologues it has accepted
(`OBFS_REPLAY_WINDOW`), shared by every obfuscated listener, and a connection
that arrives with one already in it is refused - but only after its first
frame has been decrypted, so that a prober replaying a captured handshake
waits exactly as long, and hears exactly as much, as one sending a frame with
a corrupted tag.

#### Clocks

The hour inside the prologue is the one thing a deployment can get wrong
without touching a config file. The server accepts an hour two on either side
of its own, so about two hours of clock skew is fine and a device that came
back from a power cut with no time at all is not: it will dial, get silence,
and time out. That silence is deliberate - a server that answered a stale
prologue faster than a wrong payload would be telling a prober it exists - so
the cause surfaces on the two ends instead:

- the server logs `Peer clock is out of step` with the number of hours and
  counts it in `s5core_obfs_clock_skew_total`;
- the client prints a hint naming both possible causes (PSK and clock), since
  from its side the two are the same event.

An hour is coarse on purpose. VMess authenticated a timestamp to within 90
seconds and turned every unsynchronised clock into an `invalid user` error;
VLESS dropped time from the handshake entirely because of it. The failure was
the precision, not the clock - so this follows obfs4 instead, where the epoch
is an hour wide and the window is measured in hours.

#### Ciphers

The payload cipher is not a constant, because the machines at the two ends of
a tunnel are rarely the same kind of machine. AES-256-GCM is the fastest thing
available on a processor with AES instructions and one of the slowest without
them. On a real aarch64 router with its AES instructions switched off,
ChaCha20-Poly1305 moves **5.9 times** more traffic (96 MB/s against 16 MB/s on
a default frame); with those instructions on, the ordering reverses and AES is
3.4 times faster. Real hardware moved both ratios away from the 1.7x/12x an
x86 stand-in suggested - the penalty for choosing ChaCha with AES instructions
is twice as wide, the penalty for choosing AES without them half as wide - so
the ordering the stand-in gave was right and its magnitudes were not. Either
way the client asks the processor instead of asking the operator. The numbers
and how they were taken are in
[docs/benchmarks/ciphers.md](docs/benchmarks/ciphers.md) and
[docs/benchmarks/arm-router.md](docs/benchmarks/arm-router.md).

So the client picks by its own processor and the server accepts either. The
choice is never negotiated: it goes into the prologue MAC, so the server reads
it in one HMAC before deriving anything, and nothing about it reaches the
wire. Both ciphers use a 32-byte key, a 12-byte nonce and a 16-byte tag, so
the frame is the same shape and the same size under either one - which is what
makes the choice free to make. `OBFS_CIPHER` pins it if you want to measure
the other one.

#### Who is calling, before the first frame

An account can carry a key of its own (`tunnel_key` in `users.json`). A client
that has one stamps a per-hour tag of it into the prologue, masked with the
deployment PSK so it looks like the random bytes around it. The server unmasks
the tag, finds it in a table it rebuilt in the background, and knows which
account is calling **before it decrypts anything** - then answers the SOCKS5
handshake with no-auth and accounts the session to that name.

The table is rebuilt once an hour off the connection path, so the lookup is one
map read: measured at 1240 ns with 8 members and 1231 ns with 262 144 - a
32 768x growth that changes the time by 3%. The password leaves the connection
path entirely, and with it one round trip of the SOCKS5 handshake; Argon2id
stays where it belongs, at the control panel. Numbers and method:
[docs/benchmarks/roster.md](docs/benchmarks/roster.md), format in section 3.4
of [docs/veil-spec.md](docs/veil-spec.md).

The member key is part of the session secret, so two members with the same PSK
derive different keys and cannot read each other's traffic. What it does not
hide: anyone holding the PSK - that is, any member - can unmask the identity
field and tell which member a connection belongs to. Members are not anonymous
to each other.

Accounts without a key keep working with a password, which is what makes this
a migration rather than a flag day. Set `OBFS_REQUIRE_MEMBER_KEY=true` on the
server once every client has a key: after that a stolen PSK on its own no
longer reaches the tunnel.

> **Wire format change.** This is not compatible with S5Core before the
> segmenting, header, frame-kind and hour-binding work: update `s5client` and
> `s5core` together.

The paragraphs above are a summary. The format itself - every field, the key
derivation labels, the padding rules, the frame kinds, the failure reasons and
the UDP-over-TCP framing of command `0x83` - is specified in
[docs/veil-spec.md](docs/veil-spec.md), which is the source of truth an
independent implementation works from. Changing the format means changing that
document first: `pkg/obfs/spec_test.go` fails when the code and the document
disagree.

A frame is never larger than `OBFS_MTU`: padding is drawn first, the payload
takes what is left of the budget, and a longer write becomes several frames of
roughly equal size rather than full frames plus a short remainder. The padding
bytes themselves are zeros - they sit inside the AEAD, so the wire carries
ciphertext either way and only the peer holding the PSK ever sees them, which
is how TLS 1.3 pads its records (RFC 8446, section 5.4). What is random is the
padding *length*, and that is what the wire sees.

#### The decoy site (WebSocket transport only)

On the WebSocket transport the tunnel shares a TLS listener with a decoy: the
WebSocket upgrade on `WS_PATH` is the tunnel, and every other request has to
look like an ordinary web server, because a server that answers only its one
secret path - or drops everything else - is a server that has confirmed it is
hiding something.

By default the decoy is a small built-in page. It answers three things (the
root, `/favicon.ico`, everything else as a 404) and answers each the same way
every time, which is enough to look like a site to a casual glance but thin
against a prober comparing responses. Set `WS_DECOY_UPSTREAM` to a real site
and the listener becomes a reverse proxy to it: an unauthenticated request -
including a plain GET of `WS_PATH` itself - gets that site's own status,
headers and body, down to its own 404. There is nothing left to compare
against a real server, because the answer *is* a real server.

The upstream is a screen, not a mirror. It is never told who is visiting -
`X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto` and `Forwarded` are
removed on the way up - and it is not allowed to name itself on the way down: a
`Location` header or a `Set-Cookie` `Domain=` that points at the upstream host
is rewritten so a redirect or a cookie cannot leak where the traffic really
goes. What it does not do is rewrite links inside HTML, so pick an upstream
whose pages are same-origin relative rather than a single-page app that
hard-codes its own domain. The full behaviour, the header table and what the
proxy deliberately does *not* hide are in [docs/design/decoy.md](docs/design/decoy.md).

An obfuscated connection that fails to authenticate is handled the same way in
spirit: the server does not hang up on it. It reads and discards until the
handshake budget (`HANDSHAKE_TIMEOUT`) runs out, so a probe measuring the time
to close cannot tell a complete-but-wrong frame from bytes that never became a
frame at all - both simply time out. This costs a held connection slot for the
duration; the reasoning is in [docs/design/decoy.md](docs/design/decoy.md) and the guarantee
is pinned by `pkg/s5server/replay_probe_test.go` and
`pkg/s5server/decoy_probe_test.go`.

### Changing the transport in the field

Clients live on routers and are updated by hand, so the transport they use has
to be changeable without a new binary. Three levers do that, none of them a
release:

- **`TRANSPORT_ADVICE` on the server.** Inside every tunnel, in the same write
  that carries the SOCKS5 greeting reply (no extra round trip), the server tells
  the client which transport to use from its next connection and which shape to
  adopt - `transport=ws min_frame=512 max_frame=2048 jitter_ms=5 padding=128
  keepalive=10s-20s`. The frame is inside the AEAD session, so only a peer with
  the PSK can send it. Put it in `TRANSPORT_ADVICE_FILE` and `SIGHUP` re-reads
  it, which is what makes this a lever on a running server rather than a
  restart. A client in `TRANSPORT=auto` follows
  the advised transport if it can reach it (`ws` needs `WS_URL`, so a client
  that should be able to move has both `SERVER_ADDR` and `WS_URL` set in
  advance); a pinned client ignores the transport but still takes the shape.
- **`TRANSPORT` and `TRANSPORT_COOLDOWN` on the client.** In `auto` a transport
  that fails to set up rests for the cooldown while the other one carries the
  traffic; a pinned transport never switches.
- **`OBFS_FORMAT` on the client.** `auto` speaks the current wire format and
  falls back to the previous one for `OBFS_FORMAT_REPROBE` when a server accepts
  the connection and stays silent, so a new client reaches a server that has not
  been updated yet. Update clients first, then servers, then pin `OBFS_FORMAT=v1`:
  the previous format is detectable, and `auto` shows it to anyone who accepts
  a connection and says nothing. The previous format is removed two minor
  releases after the first release with the current one.

Whether a migration is working is read off `s5core_client_connections_total`
(builds and transports of the clients that introduced themselves) against
`s5core_connections_total` (everyone). The order of operations, the cost of each
fallback, the removal schedule and the constants that deliberately stay in the
code are in [docs/field/migration.md](docs/field/migration.md).

### Stealth checklist

Stealth is measured by a checklist, not by entropy. The test that used to stand
here computed Shannon entropy over one frame and failed below 5.0 bits per
byte - a bar every encrypted or compressed stream clears, so it was green
exactly when the transport was easiest to detect.

The policy that actually matters treats a fully encrypted stream as the thing
to block unless it looks like something recognisable, so maximum entropy is the
signature rather than the defence. The checklist follows it
([USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/wu-mingshi)):

- **Level 1 - the first packet.** Five exemptions: one-bit density outside
  [3.4, 4.6] per byte, six printable bytes at the start, more than half the
  packet printable, a printable run over twenty bytes, or a known protocol
  prefix. A stream matching none of them is a stream the policy drops.
- **Level 2 - structure across connections.** Over a corpus of 1000: no byte
  value over-represented at any of the first 64 offsets, no narrow peak in the
  frame-length distribution, no constant interval between frames.
- **Level 3 - the field.** Connection success by transport and country, and
  the reports at net4people/bbs, GFW Report and OONI, read as a routine rather
  than once.

**Recorded today.** Level 2 is green on both transports. No byte value is
over-represented at any of the first 64 offsets: the frame length is masked
with a stream key and no nonce goes on the wire at all, so nothing sits at a
fixed position any more. Frame lengths are spread by padding - 252 distinct
first-packet lengths over 1000 connections, the most common covering 1.0%; for
the WebSocket transport the shaper does the same, 1738 distinct frame lengths
over 200 connections with the most common at 1.7%. The intervals between
frames carry no period either: the busiest millisecond holds 9% of them
against a 35% threshold.

**Level 1 is green on both transports.** Over WSS the first packet is a real
TLS ClientHello and is exempt - `Ex5` with crypto/tls and a Chrome
fingerprint, `Ex1` with a Firefox one. On the obfuscated port the prologue
goes out base64-encoded, followed by a pad whose length comes from the session
secret, so a connection opens with 43-63 printable bytes: 0 of 1000 first
packets match no exemption, against 98.9% before that change. The frames
behind the opening are untouched, and the positional check now runs past it -
aligned the way an analyst would align it - and still finds no repeated value.

This is not a model. On a real filtering path measured 19.09.2026, a 256-byte
random first packet was delivered in 19% of probes and the same packet opening
with 16 printable bytes in 98 probes out of 98. Two clients differing only in
`OBFS_PROLOGUE`, run against one server in the same minutes: 78 connections
with the encoded opening, zero failures; 48 with the raw prologue, 45
failures. Method, numbers and the probe that reproduces it on any path:
[docs/field/stealth.md](docs/field/stealth.md) and `cmd/fpprobe`.

> **Choosing a transport is no longer forced.** Both pass level 1, so the
> choice is back to cost: WSS needs a certificate and spends 6.06 RTT on
> setup against 4.03 for the obfuscated port. A server accepts either
> prologue encoding without being configured for it, so a fleet updates
> server first, clients after ([docs/field/migration.md](docs/field/migration.md)).

```bash
go test ./pkg/obfs/ -run TestTheStealthChecklist -v          # the checklist
S5CORE_STEALTH_CORPUS=/tmp/corpus go test ./pkg/obfs/ -run TestTheStealthChecklist
go run ./cmd/stealthcheck -max-blocked 0.5 /tmp/corpus       # any corpus, incl. a capture
go test -race -run TestTheFirstPacketOfAWSSClientIsExempt ./pkg/transport/ws/ -v
```

> A green checklist means **no known signature**, not undetectability. The
> rules are public, they change, and feedback from a blocked network arrives
> after the fact. That is the strongest claim this section makes.

### Measured Results

Every number below states the command that produced it and the machine it ran
on. A performance figure without those two things is not admissible in this
README (plan task Ф0-6): three mutually incompatible throughput numbers used to
coexist here precisely because nothing forced the methodology to be written down.

**Reference bench:** Intel Core i7-11700K (16 threads), 30 GB RAM, Linux,
Go 1.26.6, loopback, `USERS_FILE` with Argon2id (m=64 MiB, t=3, p=1).
Measured 18.09.2026 and re-measured 19.09.2026 on `main`, after phase 6 (plan
task Ф6-6). Stream and latency figures are the median of three runs.

#### Connection performance

| Metric | Plain SOCKS5 | Obfuscated (AES-256-GCM) | How it was produced |
|--------|--------------|--------------------------|---------------------|
| Throughput, 1 MB echo stream | 978 MB/s | 44.7 MB/s | `go test -run TestIntegration_FullSuite -v ./pkg/s5server/` (subtests `Bench_*Echo`) |
| Handshake latency, avg of 20 | 0.14 ms | 0.15 ms | same run, subtests `Latency_*Handshake` |
| WebSocket transport, 1 MB stream | 1605 MB/s (plain) | 1094 MB/s (shaped) | `go test -run XXX -bench=Throughput ./pkg/transport/ws/` |
| WebSocket transport, one 1422-byte write | 1.75 µs (plain) | 10.7 µs (shaped) | `go test -run XXX -bench=WriteLatency ./pkg/transport/ws/` |

> **What shaping costs is frames, not cycles.** The gap in the two WebSocket
> rows is one syscall per frame, and it is the disguise itself: frames batched
> into a single write would arrive as a single TLS record of the original
> length. On the wire, where the shaper adds only headers and never payload,
> the cost is 0.9-7.4%. `docs/benchmarks/frame-shaping.md` has the breakdown.

> **Read the handshake number before the throughput number.** 0.14 ms is what
> a login costs once the verifier cache holds that password (plan task Ф3-6).
> It used to be 97 ms, because Argon2id ran on every connection: a browser
> opening 6-10 connections per page paid it 6-10 times, along with 64 MiB of
> peak memory each. The first login of each password after start still runs the
> full KDF - 220 ms on this bench, and the phase table below is that
> connection - which is where a strong KDF belongs. Method and full numbers:
> [docs/benchmarks/argon2-cost.md](docs/benchmarks/argon2-cost.md).

The phase histograms say the same thing without any guessing. One run of
`go test -race -v -run TestPhaseMetricsExplainTimeToFirstByte ./pkg/s5server/`
on the reference bench breaks the **first** connection for a password - the one
that runs the KDF - down as:

| Phase | Duration | Share |
|-------|----------|-------|
| `handshake` | 0.036 ms | 0.02% |
| `auth` | 220.0 ms | 99.7% |
| `dial` | 0.153 ms | 0.07% |
| `first_byte` | 0.129 ms | 0.06% |
| unexplained remainder | 0.298 ms | 0.14% |

(The absolute value is inflated by `-race`; the proportions are the point.)
On that first connection authentication is not one contributor among several -
it is the connection setup cost, and everything else together is under half a
millisecond. Every later connection with the same password is answered from the
verifier cache and lands in the 0.14 ms of the table above. The test
fails if the phases stop adding up to what a client observes within 20 ms, so
this decomposition cannot quietly go stale.

> **Loopback is not the internet.** These runs have no packet loss, ~0.05 ms
> RTT and a 65536-byte MTU, so they measure allocation and scheduler cost, not
> transport behaviour. They are a regression signal between two commits, not a
> prediction of what a VPS will deliver. The only number that answers "how fast
> is my tunnel" is an `iperf3` baseline against the same VPS, compared with the
> same transfer through the tunnel (plan task Ф2-1).

> **Low-end VPS warning:** a `1 vCPU / 1 GB RAM` box is not recommended for
> responsive browsing with obfuscation enabled. Throughput can still look fine
> while first-byte latency degrades, because every new connection is wrapped in
> userspace encryption plus per-frame padding - and, with `USERS_FILE`, an
> Argon2id verification. Start by lowering `OBFS_MAX_PADDING`.

#### Obfuscation layer, three levels

`pkg/obfs/bench_test.go` measures the layer at three levels, so that a slowdown has an address instead of a suspicion: the cipher alone, the framing on top of it, and the full path over a real socket. Payload sizes are the ones that actually occur: 1400 bytes (one frame), 4 KiB (a typical response) and 32 KiB (what `io.CopyBuffer` hands over in the relay).

```bash
go test -run XXX -bench=. -benchmem ./pkg/obfs/          # all three levels
./scripts/bench.sh save                                  # record a baseline on this machine
./scripts/bench.sh                                       # re-measure and compare with benchstat
```

On the reference bench, per operation:

| Level | 1400 B | 4 KiB | 32 KiB |
|-------|--------|-------|--------|
| AES-GCM only | 338 ns (4148 MB/s) | 659 ns (6218 MB/s) | 5096 ns (6430 MB/s) |
| ChaCha20-Poly1305 only | 695 ns (2014 MB/s) | 1725 ns (2374 MB/s) | 13216 ns (2479 MB/s) |
| Framing, no padding | 526 ns (2663 MB/s) | 1109 ns (3694 MB/s) | 8854 ns (3701 MB/s) |
| Framing, 256 B padding | 621 ns (2256 MB/s) | 1547 ns (2648 MB/s) | 11302 ns (2899 MB/s) |
| End to end over TCP | 4214 ns (332 MB/s) | 5549 ns (738 MB/s) | 19297 ns (1698 MB/s) |

Three things follow, and none of them was visible before the numbers existed:

1. **AES-GCM is roughly twice ChaCha20-Poly1305 here, and that reverses on hardware without AES-NI** - which is most routers. The cipher choice for the S5Veil handshake (plan task Ф5) has to account for both.
2. **Padding is not free**: 256 bytes of padding costs about 18% on a 1400-byte frame. That is the price of the traffic shape, and it should be paid deliberately.
3. **A large block costs what its frames cost.** Since segmenting (plan task
   Ф4-2), a 32 KiB write is ~24 frames, so it pays ~24 AEAD operations instead
   of one: framing 32 KiB went from 6.1 to 11.3 µs against a baseline that had
   no right to that number, because it put a 32 KiB frame on a 1400-byte MTU.
   Against the cipher's own cost for the same 24 blocks (24 × 338 ns = 8.1 µs)
   the framing layer adds little. The 1400-byte column, which is what the
   network actually carries, is unchanged.
4. **Both paths allocate nothing now.** The gates are
   `TestARelaySizedWriteIsAllocationFree` (a 32 KiB write and its read) and
   `TestSmallReadsDoNotAllocate` (the short reads the UDP multiplexer does).

The performance gates in CI are assertions about allocations and ratios (`pkg/obfs/alloc_test.go`), not about nanoseconds: allocation counts are the same on any machine, so the gate catches a real regression and does not fail because a runner was busy.

A profile of the full relay is where the microbenchmarks stop being the whole
story. Eight connections downloading 1 GiB each through the obfuscated port
used to allocate 16 GB in total - two bytes of allocation per byte of payload,
99.93% of it inside `pkg/obfs.(*conn).Read`. The same run now allocates 9.4 MB
and moves 5041 MiB/s instead of 3571 MiB/s: segmenting made each frame more
expensive and the connection as a whole 41% faster, because what the relay was
actually spending was GC pressure. Method and full output:
[docs/benchmarks/relay-profile.md](docs/benchmarks/relay-profile.md).

```bash
PROFILE_CONNS=8 PROFILE_MB=1024 go test -tags loadtest -run TestObfsRelayProfile ./pkg/s5server/
go tool pprof -list='Read$' -sample_index=alloc_space bench/profiles/obfs-relay.alloc
```

#### On ARM: measured on a router, 19.09.2026

Most numbers above come from an x86 desktop, but the machine that matters for a
client is a router. That one is now measured rather than extrapolated: a
three-core aarch64 router with hardware AES, 1 GB of RAM and a gigabit port,
with the client cross-compiled to a static binary. Full write-up:
[docs/benchmarks/arm-router.md](docs/benchmarks/arm-router.md).

- **Throughput.** Through the tunnel the router moves 95.6-98.7 MB/s against a
  112 MB/s ceiling on the same path without it - **85-88% of the channel**, so
  the SLO below is met on this path. A plain SOCKS5 listener on that same
  router and that same path reaches 98-99%, which prices framing and encryption
  at **11 points of channel** here against 9.6 on the VPS: the cost of
  obfuscation barely moves between the two, and what does move is the path.
- **CPU.** One core out of three downstream, a little over half upstream - but
  those are the process's own ticks. Counted across the whole router, including
  the softirq context where packet handling lives, the same transfer costs
  about 1.8 cores downstream and 1.2 upstream. Raw encryption on one core runs
  at 324 MB/s, so neither figure is a ceiling.
- **Memory.** 6.6 MB idle, 14 MB across 50 concurrent connections, 25 MB across
  200 - 73-92 kB per connection. Under half of that is obfuscation: 37 kB of
  `pkg/obfs` buffers sized from `OBFS_MTU`, plus two 32 KiB `io.Copy` buffers
  the client's relay allocates because `obfs.conn` implements neither
  `ReadFrom` nor `WriteTo`. Under a deliberately tight `GOMEMLIMIT=32MiB` the
  same 200 connections run with zero failures, no OOM anywhere in the kernel
  log, and - measured against the same load without the limit - no measurable
  CPU cost at all.
- **Cipher choice.** `veil.PreferredCipher()` returns `aes` on this router and
  `chacha` under `GODEBUG=cpu.aes=off`, as designed. The real hardware corrects
  two ratios taken from the x86 substitute: with hardware AES, AES is **3.4
  times** faster than ChaCha20 (not 1.7), and without it ChaCha20 is **5.9
  times** faster than AES (not 12). Picking by CPU is right either way, but on
  ARM the expensive mistake is picking ChaCha where AES acceleration exists.
- **Still not measured:** weak ARM without crypto extensions - single-core
  access points and older SoCs. For those, read the "no extensions" row: about
  96 MB/s per core on ChaCha20, 16 MB/s if AES is chosen wrongly.

To take these numbers on your own device - no Go toolchain needed on the
router, the test binary is static:

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o obfs-arm64.test ./pkg/obfs/
# GOARCH=arm GOARM=7 instead, for a 32-bit router
scp obfs-arm64.test router:/opt/tmp/
ssh router '/opt/tmp/obfs-arm64.test -test.run=XXX -test.bench=TunnelByCipher -test.benchtime=3s'
```

`BenchmarkTunnelByCipher` is the whole frame path - padding, length mask, AEAD,
header - which is what bounds a router's throughput. The binary is about 5 MB.

#### Service level objectives

These are the thresholds the project holds itself to. Each one names its
instrument, so "is it good enough" has an answer that does not depend on who is
asking.

| Objective | Threshold | Instrument | State |
|-----------|-----------|------------|-------|
| Successful connection setup rate | ≥ 99.5% over 24 h | phase counters | measurable (task Ф1-3) |
| Time to first byte, p95 | ≤ 1.5 RTT above the analytical minimum of the chain | phase histograms | measurable (task Ф1-3) |
| Share of channel bandwidth available through the tunnel | ≥ 85% of the `iperf3` baseline | `iperf3` + same transfer through the tunnel | measured 19.09.2026 on a deployed VPS: **80.3% down, 73.3% up** through the obfuscated tunnel, 89.9%/83.2% through plain SOCKS5. The threshold is met by the plain listener and missed by the obfuscated one; the gap is framing and encryption, not a bottleneck in the code - CPU stays at 5-6.5% of one core. On a short path the same obfuscated listener does meet it: 87.1% on the ARM router bench, where a plain control on the same path reaches 98.3%. That control splits the shortfall: framing costs 9.6-11.2 points on either path, while RTT and the TCP window cost 1.7 points on the short one and 10.1 on the long one. Verdict and full numbers in [docs/gates/README.md](docs/gates/README.md) and [docs/benchmarks/arm-router.md](docs/benchmarks/arm-router.md) |
| Obfuscation handshake rejection rate | background known and stable; a spike is a probing signal | `obfs_handshake_failures_total` | measurable (task Ф1-2) |

For stealth the equivalent of a threshold is the acceptance checklist (levels 1
and 2 of the plan): it certifies the absence of *known* signatures, not
undetectability.

#### Rules for changing these numbers

- A change on the hot path (`pkg/obfs`, framing, buffers) is accompanied by a
  `benchstat` comparison before and after. `CLAUDE.md` has required this all
  along; task Ф2-2 made it executable by adding the benchmarks and
  `scripts/bench.sh`.
- A change to the frame format is accompanied by a run of the stealth checklist.
- Any number added to this section carries its command and its machine.

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

### Keepalive

An idle tunnel is only idle from the inside. Everything on the path - the
server itself, a reverse proxy, a CDN, a carrier NAT - keeps a table entry for
the connection and drops the entry when nothing arrives for a while. Neither
end is told. The application finds out on its next write, as a stall rather
than an error, and a tunnel that was quiet for a minute looks exactly like one
that is dead.

The client answers that by sending, after a silence, a frame that carries no
payload. Three rules keep it from becoming a signature of its own: the interval
is drawn anew from `KEEPALIVE_MIN`-`KEEPALIVE_MAX` before every frame, real
traffic suppresses it (a frame goes out only if the connection has been silent
for the whole interval), and the frame is padded to the size of a frame this
connection has already sent, so it is neither shorter nor rounder than the
data around it. It lives in the obfuscation layer, not in the WebSocket one:
a WebSocket ping is its own opcode with a length of its own, and the plain
obfuscated listener has no WebSocket layer at all while having exactly the same
problem.

#### What the path actually allows

Measured with `scripts/keepalive_matrix.sh`, which stands up s5core with
WebSocket and obfuscation, puts an nginx `stream` proxy in front of it in the
second row group, and then leaves a tunnel completely silent while
`cmd/idleprobe` waits to be disconnected. Idle budget 150 s: "alive" means the
probe was still able to complete a round trip after that.

| Path | Shortest idle timeout on it | No keepalive | `10s`-`20s` | Fixed `90s` |
|---|---|---|---|---|
| Direct, server `READ_TIMEOUT=600s` | none within the budget | alive > 2m30s | alive > 2m30s | alive > 2m30s |
| Behind nginx `proxy_timeout 60s`, server `READ_TIMEOUT=600s` | 60 s, nginx | **broken at 1m0s** | alive > 2m30s | **broken at 1m0s** |
| Direct, server `READ_TIMEOUT=30s` (the default) | 30 s, **ours** | **broken at 30s** | alive > 2m30s | **broken at 30s** |
| Behind nginx, server `READ_TIMEOUT=30s` | 30 s, **ours** | **broken at 30s** | alive > 2m30s | **broken at 30s** |
| Behind a CDN | ~100 s published (Cloudflare Free and Pro) | not measured here | - | - |
| Mobile CGNAT | 30-300 s, operator-specific | not measured here | - | - |

The last two rows need a real deployment, the same way the throughput numbers
do; they are named here so the gap is visible rather than implied.

#### Why the default is 10-20 s and not the 45-60 s the plan assumed

The first run used 45-75 s, against published figures for CDNs and reverse
proxies. Every one of the six rows came back `broken at 30s`. The shortest
idle timeout on the path was not a CDN or a carrier: it was `READ_TIMEOUT`,
ours, 30 seconds by default. Raising it is not the fix - that timeout is what
stops dead slots from accumulating, and a keepalive works *with* it rather than
against it: a client that has actually died stops sending frames, and the slot
is still reclaimed after `READ_TIMEOUT`.

So the range has to clear our own 30 seconds first, and the published network
figures only matter after that. 10-20 s is the same order as the tunnels that
had to solve this before us - WireGuard's persistent keepalive is 25 s,
OpenVPN's default ping is 10 s.

What it costs: one frame the size of a data frame (about 1.5 KB on the wire
with the default MTU) per interval, so roughly 0.8 kbit/s, or about 9 MB per
day, for a connection that is doing nothing at all. On a metered link raise
both bounds, keeping the maximum under the shortest timeout on the path.

The server-side setting exists and is off: one end holding the path open is
enough, and `s5client` is that end. Turn it on for clients that are not
`s5client`.

#### The intervals do not form a pattern

The same check as the frame-length one: `stealth.Intervals` buckets the gaps
between frames and reports the tallest bucket. Over an idle connection the
gaps spread across the configured range instead of landing on a period -
`TestTheIntervalsAreNotAConstant` in `pkg/obfs/keepalive_test.go` fails if any
single millisecond holds more than 35% of them (measured: 9%).

```bash
go test -race -run 'Keepalive|Interval|Idle' ./pkg/obfs/ ./pkg/s5server/
PROXY_TIMEOUT=60s BUDGET=150s ./scripts/keepalive_matrix.sh   # ~15 min, needs docker
```

### UDP over TCP: what it costs

`s5client` does not relay UDP as UDP. Every datagram of a session - DNS,
QUIC, WebRTC - is multiplexed into the single obfuscated TCP connection under
command `0x83`, and that is precisely what makes a UDP leak impossible: there
is no second socket to leak from. The price is the one every tunnel of this
shape pays. TCP delivers in order, so a segment that is lost holds back
everything queued behind it - across all the multiplexed flows - until it is
retransmitted.

Measured with `scripts/udp_loss_matrix.sh`: three containers in one docker
network, `tc netem` on the client's and the target's egress so that the direct
path and the tunnelled path cross exactly two lossy hops and the same 100 ms
round trip. `cmd/udpprobe` sends 60-byte packets to a UDP echo and records the
round trip of each one; the `direct` rows are the control, the same loss and
the same path without the tunnel.

| Loss per hop | Profile | Path | Datagrams lost | p50 | p95 | p99 | max | Jitter |
|---|---|---|---|---|---|---|---|---|
| 0% | DNS-like, 120 pkt 200 ms apart | direct | 0.0% | 50.2 ms | 50.6 ms | 51.3 ms | 100.3 ms | 0.1 ms |
| 0% | DNS-like | **tunnel** | 0.0% | 50.4 ms | 50.9 ms | 51.6 ms | 51.9 ms | 0.1 ms |
| 0% | Stream, 1500 pkt 20 ms apart | direct | 0.0% | 50.1 ms | 50.3 ms | 50.8 ms | 51.4 ms | 0.0 ms |
| 0% | Stream | **tunnel** | 0.0% | 50.4 ms | 50.8 ms | 51.1 ms | 52.3 ms | 0.1 ms |
| 1% | DNS-like | direct | 0.8% | 50.2 ms | 50.5 ms | 50.7 ms | 50.9 ms | 0.1 ms |
| 1% | DNS-like | **tunnel** | **0.0%** | 50.5 ms | 51.3 ms | 75.5 ms | **275.8 ms** | 0.4 ms |
| 1% | Stream | direct | 2.1% | 50.2 ms | 50.5 ms | 50.9 ms | 52.8 ms | 0.1 ms |
| 1% | Stream | **tunnel** | **0.7%** | 50.4 ms | 50.9 ms | 75.5 ms | 96.6 ms | 2.8 ms |
| 3% | DNS-like | direct | 3.3% | 50.2 ms | 50.3 ms | 50.5 ms | 51.1 ms | 0.1 ms |
| 3% | DNS-like | **tunnel** | 3.3% | 50.4 ms | 50.8 ms | 51.0 ms | 51.1 ms | 0.1 ms |
| 3% | Stream | direct | 6.3% | 50.1 ms | 50.4 ms | 50.7 ms | 51.8 ms | 0.1 ms |
| 3% | Stream | **tunnel** | **3.8%** | 50.4 ms | **75.4 ms** | 96.2 ms | 141.2 ms | 1.7 ms |

The 100.3 ms in the first row is the very first packet of the whole run, before
any ARP or route cache exists; every other outlier in the table is the effect
being measured.

**What the tunnel gives.** Fewer datagrams are lost, not more. TCP retransmits
the client-to-server hop, so only the server-to-target hop - native UDP, with
nothing to recover it - can drop anything: 2.1% against 0.7% at 1% per hop,
6.3% against 3.8% at 3%. An application that treats a lost datagram as a
failure fails less often through the tunnel than beside it.

**What it costs.** Nothing at the median - 0.3 ms, the cost of encrypting and
multiplexing - and everything in the tail. A dense flow keeps enough packets in
flight for duplicate ACKs to trigger a fast retransmit, so a loss costs about
one round trip: p99 of 75.5 ms against 50.9 ms, worst case 96.6 ms. A sparse
flow has no such luck. One DNS query every 200 ms never produces three
duplicate ACKs, so the lost segment waits for the retransmission timeout, and
Linux will not set that below 200 ms. 200 ms of `TCP_RTO_MIN` plus the round
trip is the 275.8 ms in the table - 5.4 times the direct path. A smaller run
(40 packets) put the same outlier at p99 rather than at max; the number is the
same, its frequency is what the sample size changes.

> **Warning - latency-sensitive UDP on a lossy link.** An application that
> times a single round trip will occasionally see a 200+ ms outlier through
> the tunnel that it would not see without one: a DNS resolver with a 100 ms
> timeout will retry, a voice codec with a short jitter buffer will drop a
> frame. This is inherent to carrying UDP over TCP and is not tuned away by
> configuration. There is no bypass mode by design - a UDP flow outside the
> tunnel is exactly the leak `0x83` exists to close. What *can* be adjusted is
> on the application side: give the resolver a timeout above 300 ms, and give a
> jitter buffer room for one retransmission.

The plan's threshold for "this needs its own mode" was p95 doubling at 1% loss.
It does not: 50.5 ms against 51.3 ms, 1.02x. The tail crosses it and the median
does not, which is why this is a documented warning and not a second transport.

```bash
./scripts/udp_loss_matrix.sh                                    # ~4 min, needs docker
DNS_PACKETS=120 DNS_INTERVAL=200ms PACKETS=1500 INTERVAL=20ms \
  ./scripts/udp_loss_matrix.sh                                  # the table above, ~12 min
```

---

## Authentication & Multi-Account Management

S5Core utilizes a high-performance, lock-free JSON user store capable of tracking per-user traffic limits without impacting the hot path.

By defining an optional `USERS_FILE`, you can enable multi-account support with expiration dates and traffic quotas. If no file is provided, `PROXY_USER`/`PROXY_PASSWORD` fill the same store with a single account.

> **One mechanism, not two.** `PROXY_USER` used to be a plain map of passwords
> beside the store, which meant Argon2id, quotas, expiry dates and roles
> existed for a deployment with a file and not for one without it, and
> `AddUser` did something different depending on which one you had. Since plan
> task Ф6-3 there is one store either way: without a file it simply has no
> file, so it starts empty and `AddUser` fills it. What `USERS_FILE` still adds
> is persistence and the tunnel member directory - keys cannot be resolved from
> accounts that are not written down.

> **The KDF runs once per password, not once per connection.** SOCKS5
> authenticates on every TCP connection, and a browser opens six to ten of them
> per page, so running Argon2id (64 MiB, three passes) per login used to cost
> 261 ms to first byte and +514 MiB of RSS for a single page - and 18.7 GiB of
> peak RSS at 100 connections per second. The store now verifies a password
> with the full KDF once, then remembers a keyed hash of it (HMAC under a key
> generated at startup, never persisted) and compares that in constant time.
> Concurrent logins with the same credentials collapse into a single KDF run,
> which is the case that matters: a cold cache and ten simultaneous
> connections.
>
> | Load | Legacy `PROXY_USER` | `USERS_FILE` + Argon2id |
> |---|---|---|
> | One burst of 10 connections (one browser page) | 0.5 ms to first byte | 0.4 ms to first byte |
> | 100 connections/s for 10 s | 0.3 ms p50, +5 MiB RSS | 0.3 ms p50, +1 MiB RSS |
>
> An entry records the exact hash it was verified against, so changing a
> password in `users.json` invalidates it with no cache to clear by hand, and a
> wrong password is answered from the entry too - guessing cannot make the
> server spend 64 MiB per attempt. Method and full numbers:
> [docs/benchmarks/argon2-cost.md](docs/benchmarks/argon2-cost.md). What stays expensive by design is
> the first login of each password after start: one 110 ms KDF run, which is
> where a strong KDF belongs.

### Example `users.json`

```json
{
  "users": [
    {
      "id": "u-001",
      "username": "premium_user",
      "password_hash": "$argon2id$v=19$m=65536,t=3,p=1$...",
      "comment": "100GB limit, expires in 2027",
      "valid_until": "2027-01-01T00:00:00Z",
      "traffic_limit_bytes": 107374182400,
      "traffic_used_bytes": 0,
      "enabled": true
    },
    {
      "id": "u-002",
      "username": "unlimited_user",
      "password_hash": "$argon2id$v=19$m=65536,t=3,p=1$...",
      "tunnel_key": "9Qm2t0s0cW1Zr7Yb3kF6uH8aJ4nP1xV5dS7gK0lE2oM=",
      "enabled": true
    },
    {
      "id": "u-003",
      "username": "noc",
      "password_hash": "$argon2id$v=19$m=65536,t=3,p=1$...",
      "tunnel_key": "Zr7Yb3kF6uH8aJ4nP1xV5dS7gK0lE2oM9Qm2t0s0cW1=",
      "role": "operator",
      "enabled": true
    }
  ]
}
```

> **Security:** Passwords are stored as **Argon2id** hashes. Plaintext `password` fields are supported for backward compatibility but are automatically migrated to hashes on the first successful login.

> **Hash portability:** the hash is a standard PHC string - `base64` with the
> standard alphabet and no padding - so any other Argon2id implementation can
> verify it. Builds before this one used the URL-safe alphabet (`-_` instead of
> `+/`); such a file is rewritten in the standard spelling when it is read, with
> a log line naming the accounts. Nothing about a password changes: the salt and
> the hash are the same bytes, only spelled differently, and both spellings keep
> verifying.

> **A hash is checked when the file is read, not when someone logs in.**
> Argon2id answers some malformed parameters with a panic rather than an error
> - no rounds, no parallelism, an empty tag - and a negative one used to ask
> the allocator for terabytes, so a hash S5Core could not check would have
> taken the process down on whichever connection first tried to use it. Such a
> file is refused whole, at startup or at the `SIGHUP` that introduced it, with
> the account named in the error; a reload that fails leaves the accounts
> already serving traffic exactly as they were.

> **A migration can be dropped, and that is the point.** Hashing a legacy
> plaintext password happens with the store unlocked, because 110 ms with the
> lock held would stall every other connection - and `SIGHUP` can re-read the
> file during those 110 ms. If the account has meanwhile been removed, been
> given a hash by something else, or been given a different plaintext, the hash
> is discarded with a log line instead of being written: the operator's edit
> wins, and the next login migrates from whatever the file says by then.

> **`tunnel_key`** is optional and independent of the password: 32 random bytes
> in base64 (`openssl rand -base64 32`), never derived from anything the user
> chose. An account that has one is recognised by the obfuscated transport
> before the SOCKS5 handshake and is never asked for a password there; an
> account without one behaves exactly as before. Give the same value to that
> user's client as `OBFS_MEMBER_KEY`. Deleting the key, or the account, stops
> it resolving at the next `SIGHUP`.

#### Roles

`role` says what an account may do besides passing traffic. It is checked by
the SDK and by whatever control panel sits on top of it, never on the
connection path - a role has no effect on whether bytes flow, which is the
policy's job (`enabled`, `valid_until`, `traffic_limit_bytes`).

| Role | Connect | View accounts | Manage the server | Manage accounts |
|---|---|---|---|---|
| `user` (default, and any account with no `role`) | yes | - | - | - |
| `operator` | yes | yes | yes | - |
| `admin` | yes | yes | yes | yes |

"Manage the server" is the client whitelist, the timeouts and reloading the
account file; "manage accounts" is creating, removing and re-roling them. An
operator cannot promote itself, because promoting is managing accounts. A
`role` that is not one of the three is refused when the file is read, rather
than resolved to something convenient later.

The roles are enforced on `Server.As(username)`, not on `Server` itself - see
[SDK](#acting-on-behalf-of-an-account).

#### Migration of an existing `users.json`

An account file written before tunnel keys existed is migrated when it is
read: every account without a `tunnel_key` is given one - 32 bytes from
`crypto/rand`, not derived from the password - and the file is written back,
so the keys survive a restart. Nothing else about the accounts changes, and no
client is affected until you hand it a key: an account whose client does not
have one keeps authenticating with its password over the shared account.

The server logs a warning naming the accounts it changed and where to read
their keys. It does not log the keys themselves - a log line is shipped,
rotated and read by people who are not the account's owner. Read them from
`users.json` and give each one to its client as `OBFS_MEMBER_KEY`.

A `SIGHUP` reload migrates in memory only and does not rewrite the file: you
have just edited it, and a signal handler does not get to write over that.

#### Quotas and validity dates during a session

A quota, a `valid_until` date and the `enabled` flag are checked at login and
again while the session runs. The relay re-checks them on the boundary where it
already publishes its traffic counter, so a session that runs out of quota in
the middle of a transfer ends within 64 KiB of the byte that exhausted it, and
does not have to wait for the client to reconnect.

The check counts the bytes that have not been written to `users.json` yet, so it
is not affected by `TRAFFIC_FLUSH_INTERVAL`. An account disabled or removed by
`SIGHUP` also stops transferring within the same 64 KiB, rather than keeping its
current sessions until they end on their own.

UDP is metered the same way, in both modes - the RFC 1928 association and the
`0x83` tunnel. An association asks the account on the same 64 KiB boundary, and
also whenever a second has passed since it last asked, because an association
that moves 60 bytes per query would otherwise reach the byte boundary hours
later and keep running on an account that has expired in the meantime. An
association that may no longer transfer ends: unlike a stream, a datagram has
no exchange in flight worth draining, so there is no grace period here.

**What counts against a quota:** the payload, in both directions, counted once
each. The SOCKS5 UDP header this server adds and strips does not count, and
neither does the two-byte length prefix of the `0x83` tunnel. A header is 10
bytes for an IPv4 destination, 22 for IPv6 and 7 plus the name for an FQDN, so
billing it would make the same transfer cost different amounts of quota
depending on how the client spelled the address.

> **Hot Reloading:** Send `SIGHUP` to the S5Core process to reload `users.json` on the fly without dropping connections! Traffic metrics are preserved and merged during reload. The same signal re-reads the log level (`LOG_LEVEL_FILE`, falling back to `LOG_LEVEL`).
>
> **Diagnostics on a live process:** `SIGUSR1` toggles `debug` on and off, on both `s5core` and `s5client`, with no configuration prepared in advance. An unreadable or misspelled level is reported and the previous level is kept - a reload must never silently turn diagnostics off in the middle of an incident.
>
> **On Windows** neither signal exists: there is no `SIGUSR1` at all, and nothing delivers `SIGHUP`. Both binaries build and run there, and both stop cleanly on Ctrl-C, but the configuration they started with is the configuration they keep - reloading means restarting the process, and the log level is whatever `LOG_LEVEL` or `LOG_LEVEL_FILE` said at startup. The signal names live in `internal/signals`, one file per platform, so this is a stated difference rather than a build that fails at release time.

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

> **The UDP relay uses two sockets per association.** The port `s5core` hands
> back in its `UDP ASSOCIATE` reply speaks to the client and to nobody else:
> a datagram arriving there from any other address is dropped, not forwarded.
> Targets are reached from a second socket, on a port of its own, bound to the
> same `BIND_IP`. With one socket for both sides the relay had to guess from
> the source address whether a datagram was a command or a reply, so any host
> that found the advertised port could have its datagrams delivered to the
> client, and a client asking for a service on its own address got the replies
> parsed as commands.

Both UDP modes resolve domain destinations outside the packet reader. Each
association coalesces pending requests for the same name, keeps at most four
lookups and 64 queued domain packets, and reuses up to 256 successful results
for 30 seconds. The resolver interface supplies no DNS TTL; this is a local
reuse interval. A full DNS queue drops domain packets. IP packets keep their
direct send path and do not compete for that queue. Closing the association
cancels its lookups; destination rules are checked before resolution.

> **A fragmented datagram is dropped, on both UDP paths.** `FRAG` other than
> zero says the datagram is one piece of a larger one, and nothing here puts
> the pieces back together, so RFC 1928 section 7 says to drop it. This used
> to forward the piece instead, on the grounds that some clients write
> something other than zero there - which handed the target part of a message
> as though it were all of it. A DNS query cut in two is not a shorter query.
> If an application really does set `FRAG`, its datagrams now time out at the
> application instead of being answered wrongly by the destination.

### With Obfuscation (Dual-Port Mode)
```
TCP: App → s5client:1080 → [encrypted tunnel] → s5core:OBFS_PORT → Internet
UDP: App → s5client:1080 → [UDP-over-TCP mux] → s5core:OBFS_PORT → Internet   ← no UDP leaks!
```

> **Important:** When obfuscation is enabled, the server listens on **two ports simultaneously**:  
> - `PROXY_PORT` (default `1080`) - plain SOCKS5 for direct/local connections  
> - `OBFS_PORT` (default `1443`) - obfuscated connections from `s5client` only  
>
> **Pick `OBFS_PORT` yourself, outside the 443 family.** On 443, 8443 and 1443
> a middlebox expects a TLS ClientHello: a version byte, a length, a session
> id, a server name. This transport sends 32-bit length prefixes and
> high-entropy bytes from the first one, so the very port that is supposed to
> look ordinary is where the traffic stands out most. An unremarkable high
> port (say `27015`) draws no such expectation. If you want the tunnel on 443,
> use the WebSocket transport (`WS_ENABLED`), which speaks real TLS and serves
> a decoy site to everyone else.

### Packages

| Package | What it owns |
|---|---|
| `pkg/s5server` | The SDK: lifecycle, listeners, configuration, telemetry. What an embedder imports. |
| `pkg/obfs` | The obfuscation format - frames, keys, keepalive, replay history. |
| `pkg/veil` | The prologue scheme and key derivation the format is parameterised by. |
| `pkg/transport/ws`, `pkg/transport/tlsdecoy` | Delivering bytes: WebSocket with frame shaping, and the TLS listener that shares a socket between the tunnel and a decoy site. |
| `internal/socks5` | The SOCKS5 message codec (a much-extended fork of `armon/go-socks5`). |
| `internal/relay` | Copying and metering bytes, and passing on the end of a stream. |
| `internal/session` | The connection state machine - three orthogonal regions; see [Connection states](#connection-states). |
| `internal/identity` | The access decision: credentials, and the lockout that keys on the client rather than on the account. |
| `internal/userstore` | The accounts file, quotas and validity dates. |

The boundaries between them are not a convention: `internal/arch/arch_test.go`
asks `go list` what each package actually reaches and fails by name when one
reaches somewhere it should not - the codec into telemetry, a transport into
the payload cryptography, the relay into either. Each rule carries its reason
in one line, which is what a failure prints.

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
	cfg.ObfsPort = "27015"
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

`NewServer` validates the configuration before anything is listening, so a
mistake is a returned error and not a panic on the first connection. In
particular, `Config.Telemetry` must come from `s5server.InitTelemetry`: it is a
struct of OpenTelemetry instruments, and one assembled by hand - or carried
over from a version with fewer fields - is rejected by name rather than
dereferenced later. Leaving it nil is fine and disables metrics.

`Start` returns when the context is canceled; call `Stop` afterwards to flush
the traffic counters and wait for the live sessions (see [Shutdown](#shutdown)).

### Acting on behalf of an account

`Server.AddUser`, `RemoveUser`, `SetRole` and `UpdateWhitelist` are the process
owner's API: they perform no role check, because a caller holding a `*Server`
can also call `Stop`. That is the right answer for a program that embeds the
server and the wrong one for what usually sits in front of it - a control
panel or an HTTP API, where a request arrives on behalf of an account and the
account is not the process.

`Server.As(username)` returns the same actions bound to an account, each
checked against that account's [role](#roles) first:

```go
admin, err := srv.As(requestUser) // fails for a name that is not an account
if err != nil {
	return err
}
if err := admin.AddUser("bob", password); err != nil {
	// *s5server.ErrNotAllowed when the role may not; 403 belongs here
	return err
}
accounts, err := admin.Accounts() // names, roles and quotas - no hashes, no keys
key, err := admin.TunnelKey("bob") // admin only: this is OBFS_MEMBER_KEY
if admin.Can(s5server.ManageAccountsAction) {
	err = admin.SetRole("bob", s5server.RoleOperator)
}
```

The account model - `Role`, `Action`, `Account`, `Policy`, `ErrNotAllowed` and
the role and action constants - is named in this package. The types themselves
live in `internal/identity`, where the connection path uses them, and these are
aliases rather than copies, so a value passed in is the value the server
checks. They exist because an external module cannot import `internal/...`: a
method taking `identity.Action` would be callable from this repository's tests
and from nowhere else.

`Admin.Can(action)` answers the same question without performing it, for a
panel deciding what to show. `Admin.Actor()` is the account itself, without its
key, and `Admin.Role()` is what it may do.

A handle holds a name, not a role. Every call re-reads the account, so a
demotion, a removal or a disabling reaches the handles that were issued before
it: an admin that demotes itself has demoted itself, and a handle to an account
that is gone fails rather than falling back to the least privileged role.
Issuing a handle is not authentication - the embedding application still has to
establish who the request is from.

The tunnel key never travels with the account list. It is what an account is on
the wire, so a listing that carried one would let anyone with
`view accounts` raise a tunnel as any member; handing a key out is
`manage accounts`, which only `admin` has.


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
| `PROXY_PASS` | String | *Empty* | Alias for `PROXY_PASSWORD`, which is what the client calls it. Accepted with a warning so that an `.env` copied from the client still starts the server; `PROXY_PASSWORD` wins if both are set. |
| `ALLOWED_IPS` | String | *Empty* | Comma-separated list of client IP addresses allowed to connect, on every listener. Single addresses only, v4 or v6: a network in CIDR form is refused by name, as is any entry that is not an address, and the server does not start. Empty means no restriction - which is why a list that cannot be read is an error rather than an empty list. On the WebSocket transport it gates the tunnel, not the decoy site: the decoy keeps answering everyone, because a site that answers only a few addresses is itself a signature. |   
| `ALLOWED_DEST_FQDN` | String | *Empty* | Regex allow-list for destinations. Empty allows everything. Anchored to the whole destination unless the pattern anchors itself; names are matched without regard to case - see [Destination allow-list](#destination-allow-list). |
| `READ_TIMEOUT` | Duration | `30s` | Idle timeout for the relay phase: how long a connection may stay silent once traffic is flowing. Refreshed by every byte. |
| `WRITE_TIMEOUT` | Duration | `30s` | Idle timeout for writes in the relay phase. |
| `HANDSHAKE_TIMEOUT` | Duration | `15s` | Absolute budget for the setup phase: version byte, authentication and the reply to `CONNECT`. Unlike the idle timeouts it is not refreshed by traffic, so a client that dribbles one byte per second is dropped instead of being kept alive. |
| `DIAL_TIMEOUT` | Duration | `10s` | Budget for reaching the destination: resolution plus connect, from the moment the request is parsed to the reply to `CONNECT`. It is cut out of `HANDSHAKE_TIMEOUT`, so a destination that never answers no longer holds a slot for the whole setup budget - see [Connection states](#connection-states). |
| `FRAME_TIMEOUT` | Duration | `10s` | How long a half-read obfuscation frame may stay half-read. It applies only between a frame header and its body, so it bounds a peer that stops mid-frame without touching a tunnel that is legitimately silent. Ignored on the plain listener, which has no frames. |
| `QUOTA_GRACE` | Duration | `5s` | How long a session whose account just ran out may keep draining what is already in flight. `0` ends the session where the quota is noticed. Nothing new is sent to the destination either way. |
| `MAX_CONNECTIONS` | Integer | `10000` | Limit for concurrent connections, shared by all three listeners. A connection that arrives at the ceiling is closed immediately and counted in `s5core_connections_rejected_total`. |
| `FAIL2BAN_RETRIES` | Integer | `5` | Failed authentication attempts from one source before that source is banned. Set to 0 to disable. |
| `FAIL2BAN_TIME` | Duration | `5m` | How long a source stays banned, and how long the per-account failure counter remembers. |
| `TRAFFIC_FLUSH_INTERVAL` | Duration | `60s` | Interval to flush user traffic metrics to disk (if `USERS_FILE` is used). |
| `KDF_MEMORY_BUDGET_MB` | Integer | `0` | Memory that concurrent password checks may use, in MiB. Argon2id asks for 64 MiB a run, so `0` (the default, 256 MiB) means four at once plus a queue four deep per running check; a check that finds both full is refused without running and counted as `s5core_auth_verifications_total{path="overloaded"}`. A negative value removes the bound. |
| `LOG_LEVEL` | String | `info` | `debug`, `info`, `warn` or `error`. `debug` enables protocol diagnostics - see [docs/design/observability-policy.md](docs/design/observability-policy.md) for what may appear in logs. |
| `LOG_LEVEL_FILE` | String | *Empty* | Path to a file holding a single level word. Takes precedence over `LOG_LEVEL` and is re-read on `SIGHUP`, which is what lets the level change on a running process. |
| `METRICS_PORT` | String | `8080` | Port to expose OpenTelemetry/Prometheus `/metrics` and `/health` endpoints. |
| `METRICS_BIND_ADDR` | String | `127.0.0.1` | Bind address for the metrics endpoint. **Warning:** do not expose to the public internet without a reverse proxy or firewall. Set to `0.0.0.0` only inside a trusted network or VPN. |
| `OBFS_ENABLED` | Boolean | `false` | Enable traffic obfuscation on a separate port. |
| `OBFS_PORT` | String | `1443` | Separate port for obfuscated connections from `s5client`. The default is kept for compatibility; set a port outside the 443 family (see the note in [Dual-Port Mode](#with-obfuscation-dual-port-mode)). |
| `OBFS_PSK` | String | *Empty* | Pre-shared key for obfuscation. **Must be exactly 32 bytes.** |
| `OBFS_MAX_PADDING` | Integer | `256` | Maximum random padding this side adds to each frame it sends (bytes). Sending-side only: the receiver takes the payload length from the decrypted header and never looks at this setting. Padding is capped at half of what a frame can carry, so a large value here cannot squeeze the payload out of the frame. |
| `OBFS_MTU` | Integer | `1400` | Largest frame this side puts on the wire, header and tag included. Writes are cut to fit it, and the send and receive buffers are sized from it (16 and 8 frames, capped at 32 and 16 KiB). |
| `KEEPALIVE_MIN` / `KEEPALIVE_MAX` | Duration | `0s` | Make the **server** send a frame carrying nothing after a silence drawn from this range. Off by default: one end holding the path open is enough, and `s5client` is that end. Turn it on when the clients are not `s5client`. Same shape as the client setting - see [Keepalive](#keepalive). |
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
| `WS_DECOY_UPSTREAM` | String | *Empty* | The site every non-tunnel request is reverse-proxied to: its status, headers and body are returned unchanged, including its own 404 for `WS_PATH` when the request is not a WebSocket upgrade. Empty serves the built-in static page instead, which answers only three paths and always the same way - weaker cover against probing (see [docs/design/decoy.md](docs/design/decoy.md)). Must be `http://` or `https://` with a host and no query or fragment, or startup is refused. The upstream never learns who is visiting: `X-Forwarded-*` and `Forwarded` are stripped on the way up, and any `Location`/`Set-Cookie` that names the upstream is rewritten so it does not leak on the way down. |
| `TRANSPORT_ADVICE` | String | *Empty* | What the server tells every client inside its tunnel, once the tunnel is up: the transport to use from its next connection and the traffic shape to adopt. A bare `ws` or `obfs`, or fields separated by spaces or commas: `transport=ws min_frame=512 max_frame=2048 jitter_ms=5 padding=128 keepalive=10s-20s`. The advised transport must be one this server listens on, or startup is refused. Read at startup; to change it on a running server set `TRANSPORT_ADVICE_FILE`. Empty sends nothing. See [Changing the transport in the field](#changing-the-transport-in-the-field). |
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
| `DIAL_TIMEOUT` | Duration | `10s` | How long the client waits for the connection to the server to be established. |
| `HANDSHAKE_TIMEOUT` | Duration | `15s` | Separate budgets of this duration cover the local SOCKS5 handshake and remote tunnel setup (greeting, authentication and CONNECT reply). Each deadline is cleared when its phase finishes. A non-positive value still gives the local handshake a 15s limit; established idle tunnels are unaffected. |
| `SHUTDOWN_TIMEOUT` | Duration | `10s` | How long a shutdown waits for connections that are still carrying traffic. Before this the wait had no end, so a client asked to stop kept running for as long as one tunnel stayed open. |
| `KEEPALIVE_MIN` | Duration | `10s` | Lower bound of the idle interval after which the client sends a frame carrying nothing, so that nothing on the path drops the connection for being silent. `0` disables it. See [Keepalive](#keepalive) for the measurements the range comes from. |
| `KEEPALIVE_MAX` | Duration | `20s` | Upper bound of the same interval. A fresh draw is made for every frame: a fixed period would identify the protocol without anyone having to decrypt it. Must be at least `KEEPALIVE_MIN`. |
| `WS_URL` | String | *Empty* | `wss://host/path` of the server's WebSocket endpoint. Setting it makes the client use the stealth transport instead of `SERVER_ADDR`. |
| `WS_HOST` | String | *Empty* | Overrides the `Host` header (domain fronting). It also decides the SNI unless `SERVER_NAME` is set. |
| `WS_ORIGIN` | String | *Empty* | `Origin` header sent with the upgrade request. |
| `WS_USER_AGENT` | String | *Empty* | `User-Agent` header sent with the upgrade request. |
| `TLS_FINGERPRINT` | String | *Empty* | Browser TLS fingerprint to imitate (`chrome`, `firefox`, ...). Empty uses Go's own Client Hello, which is itself a fingerprint. |
| `SERVER_NAME` | String | *Empty* | SNI to present, and the name the certificate is verified against, when it must differ from the host in `WS_URL`. Falls back to `WS_HOST` and then to the host in `WS_URL`; setting it is how you move the SNI without moving the `Host` header. |
| `WS_CA_FILE` | String | *Empty* | PEM file with the certificate authority (or the server certificate itself) to trust. It **replaces** the system roots, which is what a self-signed deployment wants. |
| `WS_PIN_SHA256` | String | *Empty* | Comma-separated SHA-256 hashes of the server's public key (SPKI), hex, colons optional. The chain must still verify; a pin only narrows what is accepted. |
| `WS_MIN_FRAME` | Integer | `256` | Framing of what this side sends. Independent of the server's setting. |
| `WS_MAX_FRAME` | Integer | `4096` | Framing of what this side sends. Independent of the server's setting. |
| `WS_MAX_JITTER_MS` | Integer | `0` | Delay before the frames this side sends. Independent of the server's setting. |
| `TRANSPORT` | String | `auto` | Which transport to use: `obfs`, `ws`, or `auto`. Auto is the configured default - `ws` when `WS_URL` is set, `obfs` otherwise - overridden by the server's advice when it sends one, with the other configured transport tried when the chosen one fails to set up. A pinned transport is used regardless of both. `ws` requires `WS_URL`. See [Changing the transport in the field](#changing-the-transport-in-the-field). |
| `TRANSPORT_COOLDOWN` | Duration | `5m` | How long a transport that failed to set up (no connection, or a server that accepted it and never answered) is rested while the other one carries the traffic. `0` turns the switch off. A destination refusing `CONNECT` does not count: that is the destination, not the path. |
| `OBFS_FORMAT` | String | `auto` | The obfuscation wire format: `v1` ([docs/veil-spec.md](docs/veil-spec.md)), `legacy` (the format before it, for a server that has not been updated), or `auto` - `v1` first, `legacy` for `OBFS_FORMAT_REPROBE` after a server accepted the connection and did not answer, then `v1` again. Set `v1` once every server is updated: the legacy format is detectable, and `auto` shows it to anyone who accepts a connection and stays silent. Scheduled for removal - [docs/field/migration.md](docs/field/migration.md). |
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

> **UDP support:** `s5client` transparently handles UDP Associate requests from applications. When an app sends a SOCKS5 UDP Associate command (`0x03`), `s5client` opens a local UDP socket, multiplexes all UDP packets inside the encrypted TCP tunnel (command `0x83`), and the server relays them to the internet as native UDP. No additional configuration is needed. What that costs on a lossy link is measured in [UDP over TCP: what it costs](#udp-over-tcp-what-it-costs).

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
  -p 127.0.0.1:1080:1080 \
  -p 27015:27015 \
  -e PROXY_USER=myuser \
  -e PROXY_PASSWORD=supersecure \
  -e OBFS_ENABLED=true \
  -e OBFS_PORT=27015 \
  -e OBFS_PSK=AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH \
  -e OBFS_MAX_PADDING=256 \
  -e OBFS_MTU=1400 \
  ghcr.io/mazixs/s5core:latest
```

Then on the client machine, run the local proxy:
```bash
SERVER_ADDR=your-server-ip:27015 \
OBFS_PSK=AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH \
ROUTE_DOMAINS="*.google.com,*.youtube.com" \
./s5client
```

#### Advanced Usage (With Whitelisting, Limits and Metrics)
```bash
docker run -d \
  --name s5core \
  -p 1080:1080 \
  -p 127.0.0.1:8080:8080 \
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

`s5core_connection_phase_seconds` splits a connection into five stages, modelled on HAProxy's timing fields:

| `phase` | Measured from | Measured to |
| --- | --- | --- |
| `handshake` | first byte read from the client | an authentication method is agreed |
| `auth` | credentials are requested | credentials are accepted or rejected |
| `dial` | destination is resolved | TCP connection to the destination is up |
| `first_byte` | success reply is sent to the client | destination sends its first byte |
| `session` | connection is accepted | handler returns |

`session` overlaps the other four by construction; the first four are disjoint and sum to the latency a client sees, up to a small remainder. `outcome` is `ok` or `fail`, so a phase that is slow only when it fails does not hide inside the average.

`s5core_build_info` is always 1; its labels carry `version`, `go_version` and `transports` (e.g. `plain,obfs,ws`). Together with the startup line

```
INFO Active transports summary="plain:1080, obfs:27015, ws:off" version=v1.2.3 go_version=go1.26.6
```

it answers the two questions that cannot be checked from outside the host: which build is running, and which transports it actually listens on. A server whose operator believes it is stealthy while it only listens on the plain port is a configuration failure that used to be invisible until someone read the logs line by line.

`s5core_connections_active` and `s5core_connections_total` carry a `transport` label (`plain`, `obfs`, `ws`), so the split of clients across transports is visible - which is also the first input for deciding how much of a migration any protocol change costs. The client's own version is not visible to the server yet: nothing in the current handshake carries it. That arrives with the S5Veil handshake (plan task Ф5).

`s5core_auth_verifications_total` is the health of the password path. `kdf` should stay nearly flat: it moves when the users file is reloaded or a new password appears, not with the connection rate. If `rate(kdf)` starts tracking `rate(s5core_connections_total)`, the verifier cache has stopped working and every login is back to 110 ms and 64 MiB - the state measured in [docs/benchmarks/argon2-cost.md](docs/benchmarks/argon2-cost.md) before plan task Ф3-6. `overloaded` should be zero: it means password checks were refused because the KDF memory budget was full, which is either a burst of accounts nobody has logged in with yet or someone guessing, and it is answered with `KDF_MEMORY_BUDGET_MB` and with `FAIL2BAN_RETRIES` respectively.

`s5core_half_close_failures_total` should stay at zero. It was added when half-close worked over plain TCP and over obfs but not over WebSocket, because `ws.Conn` has no `CloseWrite`: a destination that closed its side left the client waiting for a timeout. The signal now lives in the obfuscation format as a frame kind, so both transports carry it ([docs/design/half-close.md](docs/design/half-close.md)), and this counter has become an alarm for the next transport added without it - it names the side and the transport that could not pass the end of the stream on.

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
[docs/gates/g4-first-frame.md](docs/gates/g4-first-frame.md).

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

This is also the metric bug 1 of the [field report](docs/reports/v1.4.4-field-run.md) needed. `s5core_connections_active`
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

`transport` is `obfs` or `ws`. There is deliberately no label for the source address: it would both leak who connects and make the metric unbounded in cardinality. For the full rule see [docs/design/observability-policy.md](docs/design/observability-policy.md). Per-connection detail is available on demand at `LOG_LEVEL=debug` (see [Hot Reloading](#hot-reloading)), which logs the reason and the byte count - still without the address.

> **Note:** UDP traffic flowing through the standard UDP Associate relay is tracked with batched counters (flushed every 1 MB) to minimize performance overhead. UDP traffic tunneled via `s5client` (command `0x83`) is automatically counted as TCP bytes since it flows through the obfuscated TCP connection.

> **Security Warning:** By default, the metrics endpoint binds to `127.0.0.1:8080` and is not exposed outside the host. If you change `METRICS_BIND_ADDR` to `0.0.0.0`, ensure the port is protected by a firewall, VPN, or reverse proxy with authentication. The `/metrics` endpoint may reveal internal counters and connection details.

You can also use `http://<IP>:8080/health` as a readiness/liveness probe for your orchestration systems (e.g., Kubernetes).

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
docker kill -s HUP s5core
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

The client stops on its own terms. `SIGTERM` closes the local listener and then waits up to `SHUTDOWN_TIMEOUT` (10 s by default) for the sessions still carrying traffic. It used to wait without a bound, and one stuck relay was enough to keep a client running long after it was asked to stop: the relay copied in both directions and ended only when both copies ended, while the far end had no way to learn that the application had closed its half. Each direction now ends its own copy - when the application closes, the client half-closes the tunnel, the server sees the end of the stream and closes the destination, and the reply still comes back the other way. Both transports now signal the end of one direction the same way: the end of the stream is a frame kind inside the obfuscation format (`kindFIN`), not a property of the transport under it, so the WebSocket path - which has no half-close of its own - no longer has to close the whole connection and cut off a reply the server had not finished sending. That was task Ф4-9; the cost in benchstat and the write deadline race found along the way are in [docs/design/half-close.md](docs/design/half-close.md).

Embedding applications get the same behaviour from `Stop()`, which returns once everything above has happened.

> **The order is load-bearing, not cosmetic.** A relay reports the bytes it moved in batches of up to 64 KiB and hands over the last, unreported one only when the direction ends. Saving the file before the handlers finish therefore writes it as if that batch had never happened - silently, on every restart, for every live session. `TestStopPersistsWhatALiveSessionMoved` keeps a session alive across `Stop()` and checks the file afterwards.

---

## Testing the Proxy

**With cURL (no obfuscation):**
```bash
curl --socks5 <PROXY_IP>:1080 -U myuser:mypassword https://ipinfo.io
```

**With obfuscation (via s5client):**
```bash
# Terminal 1: Start local client
SERVER_ADDR=<PROXY_IP>:27015 OBFS_PSK=AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH ./s5client

# Terminal 2: Use it as a regular SOCKS5 proxy
curl --socks5 127.0.0.1:1080 https://ipinfo.io
```

**Testing UDP relay (DNS over SOCKS5):**
```bash
# Via s5client - DNS traffic tunneled through encrypted TCP
proxychains4 dig @1.1.1.1 example.com

# Or with direct UDP Associate (no obfuscation)
proxychains4 -f /etc/proxychains-udp.conf dig @8.8.8.8 example.com
```

> **WebRTC leak test:** After configuring your browser to use `s5client` as SOCKS5 proxy (with remote DNS), visit [browserleaks.com/webrtc](https://browserleaks.com/webrtc). With UDP tunneling enabled, your real IP should not appear in any WebRTC candidates.

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
- **`vpn_test.sh`**: Creates a **full transparent VPN** using `tun2socks`. It intercepts all L3 traffic (TCP and UDP) on your system using a `tun0` interface, routes it to the local `s5client`, and encrypts it through the obfs tunnel to the server. This guarantees 100% protection against WebRTC, UDP, and DNS leaks without manual application configuration. Ensure you edit the config variables at the top of the scripts before running them!
- **`s5vpn-win.ps1`**: Windows 11 full-tunnel wrapper around `tun2socks` and local `s5client`. It builds `s5client`, creates a Wintun adapter, routes all IPv4 traffic through the local SOCKS endpoint, keeps the obfuscated hop between `s5client` and `s5core:1443`, disables physical IPv6 during the session, and restores the original routes on `stop`.

### Windows Full-Tunnel (`s5vpn-win.ps1`)

Use this when you want all Windows traffic to go through:

`apps -> Wintun -> tun2socks -> 127.0.0.1:1080 -> obfs -> s5core:1443`

This mode is intended for anti-leak operation: DNS, WebRTC/UDP, and regular TCP traffic are forced into the local tunnel instead of relying on per-app proxy settings.

#### Requirements

1. Install `tun2socks` on Windows, for example with `winget`:
   ```powershell
   winget install xjasonlyu.tun2socks
   ```
2. Make sure `wintun.dll` is present next to `tun2socks.exe`, or set `WintunDll` manually in the script.
3. Run PowerShell as Administrator.

#### Configure the Script

Edit only the config block at the top of [`scripts/s5vpn-win.ps1`](scripts/s5vpn-win.ps1):

```powershell
$Config = [ordered]@{
    ServerHost        = "YOUR_SERVER_IP"
    ServerPort        = 1443
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

---

## Documentation

`docs/` is organised by the question a document answers, not by the package it
belongs to. [docs/README.md](docs/README.md) is the index; the short version:

| Directory | What is in it |
| --- | --- |
| [docs/veil-spec.md](docs/veil-spec.md) | The wire format, the single source of truth both sides are implemented against |
| [docs/design/](docs/design/) | Why it is built this way: the connection state machine, half-close, write serialisation, the decoy, the observability policy |
| [docs/benchmarks/](docs/benchmarks/) | What it costs, with the bench described: Argon2id, ciphers, the member roster, frame shaping, the relay profile, local bandwidth, the ARM router, UDP over TCP |
| [docs/field/](docs/field/) | What happens on a real path, every number with a control measured without the tunnel |
| [docs/gates/](docs/gates/) | The verdicts of the five plan gates |
| [docs/plan/](docs/plan/) | The planning material as self-contained HTML: audit, blockers, research, plan, DPI research, result |
| [docs/reports/](docs/reports/), [docs/archive/](docs/archive/) | Records of past state, kept as records and not as descriptions of the code |
| [docs/backlog.md](docs/backlog.md) | Decided and justified, not started |

---

## License

This project is licensed under the GNU General Public License v2.0 (GPL-2.0) - see the [LICENSE](LICENSE) file for details.

---
*Based on the foundational work by Sergey Bogayrets and the go-socks5 community, highly optimized and refactored for modern high-load deployments and SDK integration by the S5Core contributors.
https://github.com/serjs/socks5-server*
