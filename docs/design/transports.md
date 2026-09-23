# Traffic Obfuscation

S5Core implements a custom obfuscation layer inspired by [AmneziaWG](https://amnezia.org/), [XTLS Vision](https://github.com/XTLS/Xray-core), and [Hysteria v2 Salamander](https://hysteria.network/). The obfuscation wraps every TCP frame with AES-256-GCM encryption and random-length padding, so nothing on the wire names the protocol being carried. A write is cut into equal parts that each fit `OBFS_MTU`, so the frame size follows the configured MTU rather than the size of whatever buffer handed the data over.

### How It Works

```
TCP: App → s5client (plain SOCKS5) → [AES-256-GCM + random padding] → s5core → [decrypt] → SOCKS5 → Internet
                localhost:1080              encrypted tunnel (noise)      server:OBFS_PORT

UDP: App → s5client (UDP Associate) → [UDP-over-TCP mux + AES-256-GCM] → s5core → [demux] → UDP → Internet
                localhost:1080              same encrypted tunnel         server:OBFS_PORT
```

- **On the wire:** the client sends a prologue (printable-encoded by default), followed by frames with a masked 2-byte length and encrypted payload. Application SOCKS5 greetings and destination names stay inside the encryption. Raw obfs has no TLS handshake.
- **What that is not:** cover. An unfamiliar opening without a standard handshake is itself a description a classifier can hold: it matches no common protocol rather than matching a popular one. It defeats keyword and signature matching; it does not make the connection look like a banking app, and a policy of "allow what I recognise" stops it.
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
[docs/gates/g4-first-frame.md](../gates/g4-first-frame.md) records what it would cost.

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
[docs/benchmarks/ciphers.md](../benchmarks/ciphers.md) and
[docs/benchmarks/arm-router.md](../benchmarks/arm-router.md).

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
[docs/benchmarks/roster.md](../benchmarks/roster.md), format in section 3.4
of [docs/veil-spec.md](../veil-spec.md).

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
[docs/veil-spec.md](../veil-spec.md), which is the source of truth an
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
proxy deliberately does *not* hide are in [docs/design/decoy.md](decoy.md).

An obfuscated connection that fails to authenticate is handled the same way in
spirit: the server does not hang up on it. It reads and discards until the
handshake budget (`HANDSHAKE_TIMEOUT`) runs out, so a probe measuring the time
to close cannot tell a complete-but-wrong frame from bytes that never became a
frame at all - both simply time out. This costs a held connection slot for the
duration; the reasoning is in [docs/design/decoy.md](decoy.md) and the guarantee
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
- **`OBFS_FORMAT` on the client.** Until 2.1, `auto` fell back to the previous
  wire format when a server accepted the connection and stayed silent, so a new
  client reached a server that had not been updated yet. The previous format was
  removed in 2.2, two minor releases after 2.0, as scheduled: `auto` and `v1`
  now name the same format and `legacy` stops the client at startup. A fleet
  still on 1.x servers migrates through 2.1 (`docs/field/migration.md`, 4.2).

Whether a migration is working is read off `s5core_client_connections_total`
(builds and transports of the clients that introduced themselves) against
`s5core_connections_total` (everyone). The order of operations, the cost of each
fallback, the removal schedule and the constants that deliberately stay in the
code are in [docs/field/migration.md](../field/migration.md).

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
[docs/field/stealth.md](../field/stealth.md) and `cmd/fpprobe`.

> **Choosing a transport is no longer forced.** Both pass level 1, so the
> choice is back to cost: WSS needs a certificate and spends 6.06 RTT on
> setup against 4.03 for the obfuscated port. A server accepts either
> prologue encoding without being configured for it, so a fleet updates
> server first, clients after ([docs/field/migration.md](../field/migration.md)).

```bash
go test ./pkg/obfs/ -run TestTheStealthChecklist -v          # the checklist
S5CORE_STEALTH_CORPUS=/tmp/corpus go test ./pkg/obfs/ -run TestTheStealthChecklist
go run ./cmd/stealthcheck -max-blocked 0.5 /tmp/corpus       # any corpus, incl. a capture
go test -race -run TestTheFirstPacketOfAWSSClientIsExempt ./pkg/transport/ws/ -v
```

> A green checklist means **no known signature**, not undetectability. The
> rules are public, they change, and feedback from a blocked network arrives
> after the fact. That is the strongest claim this section makes.
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

[Documentation index](../README.md) · [Project home](../../README.md)
