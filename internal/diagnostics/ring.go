package diagnostics

import (
	"runtime/metrics"
	"time"

	"github.com/mazixs/S5Core/internal/tcptune"
)

const (
	// ringRecords is the capacity of the ring, allocated when the recorder
	// starts.
	ringRecords = 32768
	// historyWindow is how far back the ring reaches: the part of an
	// incident before its trigger.
	historyWindow = 2 * time.Minute
	// copyChunk is how many records the worker copies out of the ring under
	// one lock.
	copyChunk = 512
)

// kind is what a record says.
type kind uint8

const (
	kindStage       kind = iota + 1 // one read or write of a sampled socket, or the setup of its tunnel
	kindSocket                      // the kernel's counters of a sampled socket
	kindFlowOpen                    // a socket is sampled from now on
	kindFlowClose                   // a sampled socket was closed
	kindRuntime                     // the Go runtime's metrics
	kindSpike                       // the detector or a lost native path started an incident
	kindQueue                       // the queue in front of a selected socket
	kindNativePath                  // the native UDP path beside a selected socket changed
	kindNativeProbe                 // a probe of that path answered
)

// The what of a stage record.
const (
	stageRead uint8 = iota + 1
	stageWrite
	stageSetup // the setup of the tunnel on the socket (Flow.TunnelSetup)
)

// The flags of a stage record.
const (
	flagPeriodic uint8 = 1 << iota // the call was one of every transportSampleEvery
	flagSlow                       // a write that took slowWrite or longer
	flagError                      // the call, or the setup, failed
	flagSpare                      // a setup on a spare transport
	flagDeferred                   // a setup that left the greeting's answer to its caller
)

// The what of a native path record.
const (
	pathVerified uint8 = iota + 1
	pathLost
	pathRestored
)

// The what of a socket record.
const (
	sampleTick uint8 = iota + 1
	sampleOpen
	sampleClose
)

// The what of a spike record.
const (
	spikeRTT        uint8 = iota + 1 // the round trip time stayed far above its floor
	spikeRTO                         // the retransmit timer fired
	spikeNativeLost                  // the native UDP path beside the socket was lost
)

// record is one entry of the ring: 64 bytes on 64-bit platforms. What is the
// same for the process or the incident (schema, run, boot, incident) goes
// into the manifest, what is the same for a flow is in its flowInfo.
type record struct {
	seq  uint64
	mono int64 // nanoseconds since the recorder started, by the monotonic clock
	wall int64 // Unix nanoseconds: the clock of a router without RTC jumps at NTP
	// dur, in nanoseconds: how long a stage's call or setup took, a native
	// probe's round trip.
	dur int64
	// payload is *tcpSample, *runtimeSample, *flowTotals, *QueueState,
	// *pathAddrs for a verified native path or, for a spike, the incident ID;
	// nil otherwise.
	payload any
	flow    *flowInfo // nil for the process
	n       uint32    // stage: bytes; a lost native path: the probes unanswered
	kind    kind
	what    uint8
	flags   uint8
}

// pathAddrs are the addresses of the client's UDP socket of a native path.
type pathAddrs struct{ local, remote string }

// flowInfo is what stays the same for a sampled socket.
type flowInfo struct {
	id             uint32 // counted from 1 since the recorder started
	outer          uint32 // the flow a related socket belongs to; 0 for a selected one
	leg, transport string
	local, remote  string
}

type tcpSample struct {
	counters  tcptune.Counters
	available bool
	// readWait is the longest read since the sample before: how long the
	// peer kept the socket waiting. Periodic samples only.
	readWait time.Duration
}

// flowTotals ends a flow. evicted says the socket was found closed under a
// wrapper nobody closed.
type flowTotals struct {
	reads, writes uint64
	evicted       bool
}

// The runtime metrics read every tick. A scalar is a uint64 or a float64 in
// the Go version the binary is built with, a histogram keeps its counts; the
// bucket bounds go into the manifest.
var (
	runtimeScalars = [...]string{
		"/gc/cycles/total:gc-cycles", "/gc/cycles/forced:gc-cycles",
		"/cpu/classes/gc/total:cpu-seconds", "/cpu/classes/gc/mark/assist:cpu-seconds",
		"/cpu/classes/gc/mark/idle:cpu-seconds", "/cpu/classes/total:cpu-seconds",
		"/gc/heap/live:bytes", "/gc/limiter/last-enabled:gc-cycle",
		"/sync/mutex/wait/total:seconds", "/sched/gomaxprocs:threads",
		"/sched/goroutines:goroutines", "/memory/classes/heap/stacks:bytes",
		"/gc/heap/allocs:bytes", "/gc/heap/allocs:objects",
	}
	runtimeHistograms = [...]string{"/sched/pauses/total/gc:seconds", "/sched/latencies:seconds"}
)

type runtimeSample struct {
	scalars [len(runtimeScalars)]metrics.Value
	// counts holds the counts of every histogram, one after another; ends
	// says where each one stops.
	counts []uint64
	ends   [len(runtimeHistograms)]int
}

// ring keeps the latest records, at most ringRecords of them and none older
// than historyWindow. The recorder's mutex guards it.
type ring struct {
	recs        []record
	head, count int
	seq         uint64 // of the newest record
	// overwritten counts the records pushed out by a full ring before their
	// age: history an incident would have had.
	overwritten uint64
}

func newRing(n int) ring { return ring{recs: make([]record, n)} }

// push adds rec and drops what is older than historyWindow by rec's time.
// A dropped entry is cleared, so its payload can go.
func (g *ring) push(rec record) {
	if g.count == len(g.recs) {
		g.drop()
		g.overwritten++
	}
	g.seq++
	rec.seq = g.seq
	g.recs[(g.head+g.count)%len(g.recs)] = rec
	g.count++
	for g.count > 1 && rec.mono-g.recs[g.head].mono > int64(historyWindow) {
		g.drop()
	}
}

func (g *ring) drop() {
	g.recs[g.head] = record{}
	g.head = (g.head + 1) % len(g.recs)
	g.count--
}

// copyAfter appends to dst[:0], up to its capacity, the records after seq,
// oldest first. lost is how many of those were already gone.
func (g *ring) copyAfter(seq uint64, dst []record) (_ []record, lost uint64) {
	dst = dst[:0]
	if g.count == 0 {
		return dst, g.seq - seq
	}
	if first := g.recs[g.head].seq; seq+1 < first {
		lost, seq = first-seq-1, first-1
	}
	from := int(seq + 1 - g.recs[g.head].seq)
	for i := from; i < g.count && len(dst) < cap(dst); i++ {
		dst = append(dst, g.recs[(g.head+i)%len(g.recs)])
	}
	return dst, lost
}
