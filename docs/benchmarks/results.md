### Measured Results

#### HTTPS implementation results, 22.09.2026

The latest [implementation report](../reports/performance-implementation-2026-09-22.md)
compares the final client/server changes with the working-tree baseline,
including the [HTTPS correctness fixes](../reports/socks5-https-remediation-2026-09-21.md).
Six independent ABBA runs on Linux amd64 measured complete, verified 8 MiB
HTTPS responses: obfs throughput improved by **145-206%** across download/upload
and new/reused connections; WSS improved by **26-28%**. Obfs download CPU/GiB
fell by **37-40%**, while WSS download CPU/GiB rose by **3-13%**.

The final desktop series used 10200 observations per small-response scenario
and variant, including simultaneous bulk traffic, without exceeding the
`max(5%, 1 ms)` p95/p99 regression threshold. Real ARM testing also covered
HTTP/1.1/2 and bulk traffic; a separate six-run direct/obfs comparison with
10200 small requests per case did not reproduce an initial new-connection
tail regression. Shorter ARM mixed/WSS samples remain diagnostic.

These gains come from draining already-buffered frames, fair scheduling between
large operations, a correctly sized WS write buffer and compiled domain routes.
Explicit member-only authentication can additionally save one greeting RTT on
applicable new tunnels. Bounded TLS session reuse preserves trust checks.
DNS caching and PGO were evaluated and left disabled without sufficient benefit.

See the [changelog](../../CHANGELOG.md#unreleased), [evidence and limitations](../reports/performance-implementation-2026-09-22.md)
and [reproduction guide](../performance-validation.md). These are lab and ARM
loopback results, not production WAN acceptance or a completed canary. Older
measurements below retain their original workloads and are not directly comparable.

A subsequent [raw / released 2.0.0 / current WAN comparison](wan-2026-09-22/README.md)
tested the ARM router and VPS with commit `9e0eb39`. Obfs download improved
in all six paired rounds, with median throughput 44.84 -> 51.54 MiB/s
(about +15%). Upload and WSS median gains were not statistically stable across
the six rounds; short-request latency was essentially unchanged. The report
includes separate raw controls, CPU/RSS, TCP evidence and limitations. Working
services were not upgraded.

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
> [docs/benchmarks/argon2-cost.md](argon2-cost.md).

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
this local TCP fixture detects large unmeasured setup gaps. It does not measure HTTPS response TTFB; the newer `dns` phase measures domain lookups separately.

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
[docs/benchmarks/relay-profile.md](relay-profile.md).

```bash
PROFILE_CONNS=8 PROFILE_MB=1024 go test -tags loadtest -run TestObfsRelayProfile ./pkg/s5server/
go tool pprof -list='Read$' -sample_index=alloc_space bench/profiles/obfs-relay.alloc
```

#### On ARM: measured on a router, 19.09.2026

Most numbers above come from an x86 desktop, but the machine that matters for a
client is a router. That one is now measured rather than extrapolated: a
three-core aarch64 router with hardware AES, 1 GB of RAM and a gigabit port,
with the client cross-compiled to a static binary. Full write-up:
[docs/benchmarks/arm-router.md](arm-router.md).

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
| Share of channel bandwidth available through the tunnel | ≥ 85% of the `iperf3` baseline | `iperf3` + same transfer through the tunnel | measured 19.09.2026 on a deployed VPS: **80.3% down, 73.3% up** through the obfuscated tunnel, 89.9%/83.2% through plain SOCKS5. The threshold is met by the plain listener and missed by the obfuscated one; the gap is framing and encryption, not a bottleneck in the code - CPU stays at 5-6.5% of one core. On a short path the same obfuscated listener does meet it: 87.1% on the ARM router bench, where a plain control on the same path reaches 98.3%. That control splits the shortfall: framing costs 9.6-11.2 points on either path, while RTT and the TCP window cost 1.7 points on the short one and 10.1 on the long one. Verdict and full numbers in [docs/gates/README.md](../gates/README.md) and [docs/benchmarks/arm-router.md](arm-router.md) |
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

[Documentation index](../README.md) · [Project home](../../README.md)
