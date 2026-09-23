# What the relay's scheduling point costs

The latency work in 2.1.0 (PERF-01) added `runtime.Gosched()` after every
obfs `Read` and `Write` that moved more than one frame. The code quality audit
of 22.09.2026 (`docs/reports/code-quality-audit-2026-09-22.html`) found its
price: +50-57% per 4 KiB write in microbenchmarks and +57% CPU per GiB on the
in-process relay benchmark, with no latency benefit visible there. The
in-process benchmark could not see the benefit, because one runtime schedules
both ends of the tunnel. This file is the process A/B that decided it.

## What it is now

`yieldDue` in `pkg/obfs/conn.go`: a direction yields only after a batch longer
than one frame, and at most once per `yieldInterval` (100 µs). The scheduling
point stays; its cost becomes a share of time instead of a price per write.

## Why a yield is needed at all

A bulk copy whose socket never blocks never parks its goroutine. The runtime
then takes a long time to notice that another tunnel's socket has become
readable, and a small request queued behind a download waits for the next
preemption. Without any yield, the p99 of small requests running alongside a
parallel 8 MiB download grows 4.7-66 times (first table below). Small requests
on an idle proxy do not change, so this is purely a cost of sharing the
process with bulk traffic.

## The stand

- 11th Gen Intel Core i7-11700K (8C/16T), Linux 7.0.0-31, Go 1.26.6, loopback.
- `scripts/performance-ab.py` with `cmd/httpsprobe` as the probe: a real
  `s5core` and `s5client` process pair, an HTTPS origin, HTTP/1.1, new and
  reused connections, obfs and WSS transports.
- Cases: `small` (1700 requests per run, 25-byte body), `large` and `upload`
  (15 x 8 MiB), `mixed` (1700 small requests while a parallel connection
  downloads 8 MiB in a loop).
- 6 rounds in `before, after, after, before` order, 12 process runs per
  comparison. `S5_PERF_PROCS` (proxy `GOMAXPROCS`) 8 or 2, generator
  `GOMAXPROCS=8`, everything pinned with `taskset -c 0-5,8-13`; builds ran on
  the other cores.
- p50 and p99 are over all pooled observations. The interval is the bootstrap
  95% CI of the change in median-run p99. CPU is server plus client seconds per
  GiB moved, read from `/proc`.
- Variants of the same tree were built with `go build -overlay` replacing only
  `yieldInterval`: `0` yields after every batch, `1<<62` never yields.

## Same tree, no yield against 100 µs (`S5_PERF_PROCS=8`)

| Scenario | p99 none, ms | p99 100µs, ms | Median-run p99 change, 95% CI |
|---|---:|---:|---:|
| `obfs/mixed/new` | 29.15 | 6.21 | [-81%, -76%] |
| `obfs/mixed/reuse` | 10.26 | 0.45 | [-96%, -94%] |
| `wss/mixed/new` | 36.35 | 4.58 | [-89%, -84%] |
| `wss/mixed/reuse` | 17.73 | 0.27 | [-99%, -98%] |
| `obfs/small/new` | 2.70 | 1.76 | [-48%, +26%] |
| `obfs/small/reuse` | 0.16 | 0.14 | [-22%, -2%] |
| `wss/small/new` | 3.02 | 2.60 | [-23%, +8%] |
| `wss/small/reuse` | 0.21 | 0.17 | [-21%, +14%] |

| Scenario | p50 none, ms | p50 100µs, ms | Change | CPU none, s/GiB | CPU 100µs, s/GiB | Change |
|---|---:|---:|---:|---:|---:|---:|
| `obfs/large/new` | 10.09 | 10.34 | +2% | 1.93 | 2.13 | +10% |
| `obfs/large/reuse` | 7.93 | 8.43 | +6% | 1.68 | 2.12 | +26% |
| `obfs/upload/new` | 10.52 | 10.25 | -3% | 2.01 | 2.15 | +7% |
| `obfs/upload/reuse` | 8.34 | 8.63 | +3% | 1.79 | 2.09 | +17% |
| `wss/large/new` | 20.59 | 21.25 | +3% | 4.37 | 4.68 | +7% |
| `wss/large/reuse` | 19.24 | 19.98 | +4% | 4.17 | 5.30 | +27% |
| `wss/upload/new` | 24.41 | 25.31 | +4% | 4.81 | 5.12 | +7% |
| `wss/upload/reuse` | 22.41 | 23.83 | +6% | 4.69 | 5.26 | +12% |

The bound costs 7-27% of bulk CPU per GiB and 2-6% of bulk p50 against never
yielding, and buys a 4.7-66 times lower p99 for everything that shares the
process with a download.

## Same tree, yield after every batch against 100 µs (`S5_PERF_PROCS=8`)

| Scenario | p99 every, ms | p99 100µs, ms | Median-run p99 change, 95% CI |
|---|---:|---:|---:|
| `obfs/mixed/new` | 6.46 | 6.51 | [-9%, +6%] |
| `obfs/mixed/reuse` | 1.01 | 0.55 | [-70%, +0%] |
| `wss/mixed/new` | 4.53 | 4.50 | [-14%, +17%] |
| `wss/mixed/reuse` | 0.31 | 0.31 | [-16%, +25%] |
| `obfs/small/new` | 1.75 | 1.61 | [-15%, +8%] |
| `obfs/small/reuse` | 0.18 | 0.19 | [-19%, +29%] |
| `wss/small/new` | 2.68 | 2.63 | [-9%, +5%] |
| `wss/small/reuse` | 0.21 | 0.22 | [-9%, +27%] |

| Scenario | p50 every, ms | p50 100µs, ms | Change | CPU every, s/GiB | CPU 100µs, s/GiB | Change |
|---|---:|---:|---:|---:|---:|---:|
| `obfs/large/new` | 10.62 | 10.57 | -1% | 2.65 | 2.23 | -16% |
| `obfs/large/reuse` | 9.19 | 8.35 | -9% | 2.55 | 2.08 | -18% |
| `obfs/upload/new` | 11.18 | 10.14 | -9% | 2.72 | 2.13 | -21% |
| `obfs/upload/reuse` | 9.59 | 8.69 | -9% | 2.52 | 2.09 | -17% |
| `wss/large/new` | 24.81 | 20.77 | -16% | 5.75 | 4.61 | -20% |
| `wss/large/reuse` | 23.27 | 20.00 | -14% | 5.87 | 5.11 | -13% |
| `wss/upload/new` | 29.42 | 24.96 | -15% | 6.43 | 5.21 | -19% |
| `wss/upload/reuse` | 27.19 | 23.38 | -14% | 6.34 | 5.16 | -19% |

Every p99 interval contains zero: the bound keeps the latency of yielding
after every batch. It takes 13-21% off bulk CPU per GiB and 1-16% off bulk p50.
Yielding after every batch, as 2.1.0 does, cost 35-59% more CPU per GiB than
never yielding (the `none` row of the next table, measured in the audit tree).

## Choosing the interval

Each interval was compared with 2.1.0 in its own ABBA run; the first row is the
2.1.0 side of the `every`/`none` run, and each interval is shown against its
own 2.1.0 runs. These builds came from the audit tree before the other changes
of the release, so compare rows with each other, not with the tables above.

| Interval | `obfs/mixed/new` p99, ms (CI) | `obfs/mixed/reuse` p99, ms (CI) | `wss/mixed/new` p99, ms (CI) | `wss/mixed/reuse` p99, ms (CI) | Bulk CPU/GiB vs every batch |
|---|---:|---:|---:|---:|---:|
| every batch (2.1.0) | 6.64 | 1.02 | 4.12 | 0.23 | - |
| 25 µs | 6.26 [-13%, +2%] | 0.52 [-70%, +18%] | 4.81 [-9%, +36%] | 0.33 [-3%, +190%] | -16% ... -10% |
| 100 µs | 6.80 [-13%, +16%] | 0.50 [-68%, -20%] | 4.85 [-7%, +23%] | 0.27 [-6%, +42%] | -22% ... -14% |
| 400 µs | 7.00 [-10%, +23%] | 0.99 [-46%, +123%] | 4.65 [-5%, +22%] | 0.41 [+2%, +250%] | -22% ... -15% |
| none | 28.49 [+301%, +353%] | 9.64 [+587%, +1506%] | 36.49 [+739%, +819%] | 17.67 [+6989%, +8118%] | -37% ... -26% |

25 µs saves less CPU than 100 µs. 400 µs saves no more CPU than 100 µs, and
its `wss/mixed/reuse` interval lies wholly above zero. 100 µs is the longest
interval that did not make any mixed p99 significantly worse.

## The release against 2.1.0

The whole working tree (the bound plus the WebSocket write buffer, the client
relay pool and the dial and resolver changes of the same release) against
2.1.0.

| Scenario | P=8 bulk p50 | P=8 bulk CPU/GiB | P=2 bulk p50 | P=2 bulk CPU/GiB |
|---|---:|---:|---:|---:|
| `obfs/large/new` | +2% | -11% | -3% | -16% |
| `obfs/large/reuse` | -11% | -16% | -2% | -15% |
| `obfs/upload/new` | -7% | -18% | -8% | -15% |
| `obfs/upload/reuse` | -5% | -13% | -7% | -15% |
| `wss/large/new` | -16% | -16% | -16% | -21% |
| `wss/large/reuse` | -9% | -12% | -15% | -14% |
| `wss/upload/new` | -10% | -14% | -14% | -17% |
| `wss/upload/reuse` | -9% | -13% | -12% | -13% |

No `mixed` or `small` p99 interval lies wholly above zero at either
`GOMAXPROCS`. At P=2 the tails are tight (`obfs/mixed/new` 6.40 against
6.28 ms, CI [-11%, +10%]). At P=8 the same comparison is wide
(`wss/mixed/reuse` [-34%, +320%]): Chrome was running on the host during that
run (load average around 8), and the P=8 runs of the same tree against its own
variants above are the cleaner evidence.

## The ARM router

The same three variants on the client's target hardware (22.09.2026): the
router from `docs/benchmarks/arm-router.md` (aarch64, 3 cores with hardware
AES, 1 GB RAM, Linux 4.9), binaries cross-compiled with `CGO_ENABLED=0`, the
probe as `go test -c`. Server and client `GOMAXPROCS=1` each
(`S5_PERF_PROCS=1`), generator `GOMAXPROCS=3`, obfs with a member key,
HTTP/1.1, `small` 500 requests, `large` and `upload` 10 x 8 MiB. 12 runs in
`cur, every, none, none, every, cur` order twice, 4 per variant. The stand ran
in its own directory under `/opt/tmp` on its own ports and was removed after
the run; the production clients on the router were not touched.

| Scenario | p99 none, ms | p99 every, ms | p99 100µs, ms | 100µs vs none, CI | 100µs vs every, CI |
|---|---:|---:|---:|---:|---:|
| `obfs/mixed/new` | 145.0 | 109.2 | 105.2 | [-31%, -25%] | [-8%, +4%] |
| `obfs/mixed/reuse` | 54.5 | 42.7 | 43.0 | [-26%, -16%] | [-6%, +7%] |
| `obfs/small/new` | 14.2 | 14.4 | 16.1 | [-1%, +28%] | [+1%, +28%] |
| `obfs/small/reuse` | 1.30 | 1.16 | 2.24 | [-4%, +148%] | [+5%, +169%] |

| Scenario | CPU none, s/GiB | CPU every, s/GiB | CPU 100µs, s/GiB | p50 100µs vs every |
|---|---:|---:|---:|---:|
| `obfs/large/new` | 10.37 | 10.43 | 10.50 | +2% |
| `obfs/large/reuse` | 10.05 | 10.11 | 10.24 | +3% |
| `obfs/upload/new` | 10.72 | 11.17 | 10.75 | -4% |
| `obfs/upload/reuse` | 10.72 | 10.82 | 10.82 | +2% |

- The yield is needed on the router too: against never yielding, the bound
  takes 16-31% off the p99 of small requests beside a download, both intervals
  wholly below zero.
- On the router the bound and a yield after every batch are the same thing,
  in latency and in CPU (within 4% either way). A batch is 16 frames of up to
  1400 bytes, and at about 5 s of server CPU per GiB one batch costs about
  110 µs, longer than the interval: the bound expires on nearly every batch.
  On the desktop a batch is several times shorter, which is where the 13-21%
  saving above comes from. The bound costs the router nothing and saves it
  nothing.
- `small` is not an effect of the variant. A write or read of at most one
  frame never calls `yieldDue` (`len(b) > c.maxFrame` is checked first), so
  the three builds run the same code there. The `cur` side's p99 is 1.2, 3.0,
  1.8 and 1.5 ms across its four runs against 0.8-1.4 ms for the others: that
  spread is the stand's noise floor for a 1 ms p99 over 500 samples per run,
  not a regression.

Raw runs: `bench/arm/out/` (not committed), summaries
`bench/arm/cmp-every-cur.summary.json` and `bench/arm/cmp-none-cur.summary.json`.

## Limits

- One host, loopback. There is no WAN in these numbers: on a path with 25-43 ms
  RTT the channel dominates (`docs/field/nodes.md`), and the CPU saving shows
  as density per core, not as bandwidth.
- On the router the saving is zero (section above), so the reason to keep the
  bound there is the latency it shares with every-batch yielding, not CPU.
- `pkg/obfs/relay_bench_test.go` is not a latency test for this: in one
  process the yield looked like pure cost. Use the process stand.
