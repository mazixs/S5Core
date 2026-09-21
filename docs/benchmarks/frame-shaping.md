# What WebSocket frame shaping costs

Plan task Ф4-7. The gate asks for two things: the histogram of frame lengths
must not show the obfuscated frames inside, and the overhead must stay under
10% in bandwidth and latency - otherwise shaping is to be limited to the
handshake. This is what was measured and what it means.

## What was wrong

`ShapedConn.Write` had a fast path: a write no larger than `maxFrame` went out
as one frame. With the old band (512-4096) and an obfuscated frame of
1400-1700 bytes, that path took every write. Shaping never ran, and every TLS
record on the wire was one obfuscated frame, at its exact length.

That is worse than not shaping at all. A bare obfuscated stream tells an
observer "some encrypted protocol". A WebSocket stream whose records are all
1400-1700 bytes tells them "a tunnel with a 1400-byte MTU inside it". Nesting
the protocol identified it more precisely than leaving it naked would have.

## The histogram, after

`TestTheWebSocketFramesDoNotShowTheFramesInside` drives 200 connections,
writing the frame sizes the obfuscation layer actually produces, and counts
what the receiving side sees:

```
5487 frames over 200 connections, 1634 distinct lengths, most common 4096 in 2.5%
```

Nothing lands in 1400-1700 bytes, no length covers more than 5% of the frames,
and no frame is a copy of the write that produced it. For a single repeated
inner size the outer lengths have a standard deviation of about 200 bytes
around a mean of 505 - the spread comes from the cut count varying, not from
the jitter, which is why one cut per write would not have been enough even
though it also produces no 1422-byte frames.

## The upper bound

The band is documented as bounds, and for a while only its lower edge was one.
`plan` draws each piece around the mean with a normal jitter, and the mean sits
close to `maxFrame` whenever the cut count lands on its floor - which is where
the count is biased to land. Half the draws therefore came out above the
maximum and went on the wire that way (review finding R09):

| write | pieces over the maximum | largest piece seen |
| --- | --- | --- |
| 8 KiB | 8.4% | 5877 |
| 16 KiB | 15.5% | 5958 |
| 64 KiB | 31.6% | 5867 |
| 1 MiB | 48.5% | 6757 |

With the default band that is a frame 65% above the configured maximum, which
makes both `WS_MAX_FRAME` and the histogram above false statements.
`TestNoPieceIsLargerThanTheConfiguredMaximum` and
`TestTheMaximumHoldsOverManyDraws` hold the bound now.

**The bound is not the maximum itself.** A draw above the bound has to land
somewhere, and putting every one of them on `maxFrame` exactly replaces one
defect with another: a single length that stands out. Measured as the share of
pieces landing on the most common length:

| | no bound | clamped onto the bound | spread over the top 1/16 |
| --- | --- | --- | --- |
| the corpus above | 1.7% | 4.3% | 2.5% |
| one batched write (22752 B) | 5.4% | 17.0% | 9.5% |
| one 64 KiB write | 10.1% | 62.8% | 56.4% |

The clamp took the corpus from 1.7% to 4.3% against the 5% the histogram test
allows - a defect waiting for a different payload size. Spreading the same
mass over the top sixteenth of the band costs nothing (the bytes taken off a
piece go to the pieces after it: same cut count, same frame count, same
bandwidth overhead of 7.3% / 1.1% / 0.93%) and halves the share.
`TestTheBoundDoesNotMakeOneLengthTheShape` fails at 13% and so fails on the
plain clamp.

What is left after that belongs to the floor rule, not to the bound. When the
cut count lands on its floor, `k = ceil(n/maxFrame)`, the pieces *must* average
`maxFrame` - k pieces bounded by `maxFrame` can only sum to n if almost all of
them sit at the bound. That is arithmetic, not a choice of distribution, and
the last column shows what it does to a write that is an exact multiple of the
maximum. The only lever is a higher cut count: `k >= n/(0.8*maxFrame)` would
keep the mean off the bound and costs 25% more frames, so 25% more syscalls,
against a 10% budget. It is not taken. A mode at the top of the band is also
the ordinary shape of a TLS application with a fixed write buffer, which is
what this transport is pretending to be.

### What the bound costs

Nothing in time, something in garbage, and only on writes far larger than the
tunnel makes. `go test -bench 'Throughput_ShapedWS|WriteLatency_ShapedWS'
-benchmem -count 6`, i7-11700K, benchstat against the same code without the
bound:

| | sec/op | B/op | allocs/op |
| --- | --- | --- | --- |
| 1 MiB write | ~ (783 µs, -6% in the noise) | 11.50 KiB -> 19.14 KiB | 526 -> 743 |
| one 1422-byte write | ~ (8.77 µs) | 164 -> 164 | 5 -> 5 |

The megabyte figure is a boundary artefact and it names itself: with the bound
in place the pieces of that write are all 4096 bytes, and gorilla's write
buffer is 4096 bytes *including* the frame header it has to fit in front of
them - so every piece misses the buffered path by 14 bytes and goes out through
`net.Buffers`, at two allocations each. The tunnel does not write megabytes:
`pkg/obfs` batches sixteen frames at the MTU, so a bulk write is about 22 KiB
and roughly a tenth of its pieces land on the bound. The interactive write,
which is what latency is measured on, is unchanged.

## The cost

Measured on an i7-11700K over loopback, `go test -bench Throughput|WriteLatency
-benchtime 2s -count 3`:

| | plain | shaped |
| --- | --- | --- |
| bulk throughput, 1 MiB writes | ~1450 MB/s | ~930 MB/s |
| one 1422-byte write | ~1.56 µs | ~11.5 µs |

Split into its parts:

| | ns/op | allocs |
| --- | --- | --- |
| the cut plan alone | 31.6 | 0 |
| one WebSocket frame | 1898 | 6 |
| three WebSocket frames | 11133 | 9 |

The shaper itself is free. Everything above the plain number is the frames it
asks for: one syscall each.

**That cost cannot be optimised away.** Batching the frames of one write into a
single write to the socket would put them in one TLS record, of the original
length, and there would be nothing left hidden. The syscall per frame *is* the
disguise. `TestPlanningAFrameCostsNothing` guards the part that can regress -
the plan staying allocation-free - and the comment on `Write` says why the
rest must not be "fixed".

## Against the 10% budget

The budget is met on what a user of the tunnel sees, and missed on a number
that does not reach them:

- **Bandwidth on the wire: 0.9-7.4%.** This is the real cost, because the
  shaper adds no payload bytes - it can only cut a stream, never pad it - so
  the entire cost is frame headers. `TestShapingCostsLessThanATenthOfTheBandwidth`
  charges 36 bytes per frame (a maximal WebSocket header plus a TLS record
  header and tag) and measures 7.4% for single obfuscated frames, 1.1% for
  batched traffic and 0.9% for 64 KiB writes. Bulk traffic, where the bytes
  actually are, costs about 1%.
- **Latency: +9.2 µs per write.** Over any real path, where the round trip is
  milliseconds, that is under 1%. It would matter only on a link whose latency
  is comparable to a syscall, and no such link exists between a client and a
  VPS.
- **Single-connection CPU ceiling: -36%.** 1450 MB/s becomes 930 MB/s. This is
  the one number outside the budget, and it is a loopback artefact: the
  benchmark charges nothing for the network, so the syscall is the whole cost.
  930 MB/s is 7.4 Gbit/s on one core on one connection, well above any link
  this tunnel runs over, so the ceiling does not become the limit.

Shaping therefore stays on for the whole connection rather than the handshake
only. The fallback in the plan exists for the case where the cost reaches the
user, and it does not: shaping the handshake alone would leave every byte of
the session carrying the inner frame length, which is the defect this task was
opened for.

## The band

`WS_MIN_FRAME` moved from 512 to 256, and the meaning changed with it. It is
the lower edge of the range the shaper cuts to, not a size frames are padded
up to; a write below two minimum pieces still goes out whole, because this
layer carries a byte stream and cannot add bytes. Closing that last gap needs
cover traffic (Ф4-8) or padding inside the obfuscation format, which already
has it.

512 was too high to cut with: an obfuscated frame only fits two pieces of that
size, so every write became exactly two halves and the outer lengths tracked
the inner ones perfectly, at n/2. At 256 the same frame can be cut two to five
ways, and it is that varying count that produces the spread.

## The empty write

`io.Writer` allows a write of no bytes, and the shaper used to answer one with
a plan of a single zero-length piece - a zero-length binary WebSocket frame on
the wire (review finding R10). That is a shape nothing else on this connection
produces, at a position an observer picks out by looking for it, which is the
one thing this file is about. Nothing reaches it today, because `pkg/obfs`
never writes an empty frame, so this was a defect of the contract rather than
of the measured wire; it is closed at the plan, where the decision is, and
`TestAnEmptyWritePutsNothingOnTheWire` checks the wire as well, because the
plan is not the only way a frame could get out.
