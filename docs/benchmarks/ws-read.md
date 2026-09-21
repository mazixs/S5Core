# What buffering a WebSocket message cost

Audit finding F05 in
[`../reports/code-quality-audit-2026-09-20.md`](../reports/code-quality-audit-2026-09-20.md).
The finding is about memory an unauthenticated peer could make the server
allocate; this file is the other half of the answer - what the fix did to the
read path, measured, because the read path is hot.

## What it was

`ws.Conn.Read` called gorilla's `ReadMessage`, which assembles the whole
message in memory and returns it as one slice. The adapter then copied as much
as the caller asked for and kept the remainder in a `readBuf` field of the
connection. Two consequences, one per half of this file:

- the peer chose the allocation, and nothing above this layer had
  authenticated it yet - the obfuscation check runs on the bytes `Read`
  returns;
- every byte of the tunnel was copied twice and allocated once, on the path
  that carries all traffic.

## What it is

`Read` holds the current message as an `io.Reader` and copies straight into
the caller's buffer, taking the next message only when the current one runs
out. Nothing is retained between calls. `SetReadLimit` (`DefaultReadLimit`,
1 MiB) is the second line: the largest message this protocol sends is one
batch of obfuscated frames - 32 KiB by `maxWriteBatchBytes`, and some 128 KiB
where a jumbo MTU raises the floor of the write buffer - so a message an order
of magnitude past that is not this protocol.

## The stand

`go test -run XXX -bench='BenchmarkThroughput|BenchmarkWriteLatency' -benchmem
-count=6 -benchtime=300ms ./pkg/transport/ws/`, 11th Gen Intel Core i7-11700K
@ 3.60 GHz, linux/amd64, Go 1.26.6, loopback. `benchstat` over six runs of
each; the two benchmarks are the package's own (`bench_test.go`), unchanged.

## What changed

| Benchmark | Before | After | Change |
|---|---|---|---|
| `Throughput_PlainWS` | 526.9 µs ± 7% | 125.2 µs ± 21% | -76.2% (p=0.002) |
| `Throughput_ShapedWS` | 880.0 µs ± 10% | 836.8 µs ± 3% | -4.9% (p=0.009) |
| `WriteLatency_PlainWS` | 3.320 µs ± 42% | 3.342 µs ± 2% | no change (p=1.000) |
| `WriteLatency_ShapedWS` | 9.576 µs ± 6% | 9.225 µs ± 3% | -3.7% (p=0.026) |

Allocation, which is where the buffering actually showed:

| Benchmark | Before | After | Change |
|---|---|---|---|
| `Throughput_PlainWS` | 3 223 517 B/op, 27 allocs | 80 B/op, 3 allocs | -100% / -88.9% |
| `Throughput_ShapedWS` | 2 475 KiB/op, 2713 allocs | 11.5 KiB/op, 527 allocs | -99.5% / -80.6% |
| `WriteLatency_PlainWS` | 3319 B/op, 6.5 allocs | 56 B/op, 2 allocs | -98.3% / -69.2% |
| `WriteLatency_ShapedWS` | 3033 B/op, 11 allocs | 164.5 B/op, 5 allocs | -94.6% / -54.6% |

The throughput benchmark writes large messages, so the old path allocated one
message-sized slice per operation; that is the 3.2 MB. The write latency
benchmark writes small ones, and the 3.3 KB there is gorilla's per-message
slice rather than anything this adapter held - it disappears for the same
reason.

Read this as "the fix is not a tax", not as "reading got four times faster in
the field": the benchmark runs over loopback with no network in the way, so it
measures copying and allocation and little else. On a real path the win is the
allocation, which is what the relay profile
([`relay-profile.md`](relay-profile.md)) spends its time on.

## What holds it

`pkg/transport/ws/readlimit_test.go`:

- `TestAReaderDoesNotHoldAMessageItHasNotBeenAskedFor` - 24 connections read
  one byte each out of a 512 KiB message and the live heap stays under 2 MiB.
  Buffering held 12.4 MiB, which is the 12 MiB of messages.
- `TestAMessageOverTheLimitIsRefusedAndNotAssembled` - past the limit the read
  fails with `websocket.ErrReadLimit` and the heap does not grow.
- `TestTheDefaultLimitPassesTheLargestBatchWeSend` - 256 KiB in one message,
  twice the largest batch we send, still passes.
- `TestReadingAMessageInPiecesYieldsTheWholeMessage`,
  `TestAnEmptyMessageDoesNotEndTheStream`, `TestATextMessageIsNotPayload` -
  streaming did not change what the stream contains.
