package tcptune

import "golang.org/x/sys/unix"

// Not in golang.org/x/sys yet.
const (
	tcpRTOMaxMS = 44 // TCP_RTO_MAX_MS
	tcpRTOMinUS = 45 // TCP_RTO_MIN_US
)

type option struct {
	name  string
	opt   int
	value int
}

// Options is what a tunnel socket gets. Thin linear timeouts keep the first
// six timer retransmissions from doubling while fewer than four segments
// are in flight. A 64 Hz game at RTT 50 ms is below that most of the time on
// the client and about half of it on the server; wss, which sends every
// datagram as two segments, half of it on both sides
// (docs/benchmarks/game-tuning.md). The floor of the timer is what makes
// those retransmissions early.
//
// The cap of the timer (TCP_RTO_MAX_MS) is left alone on purpose. Linux
// derives from it how long a connection may retransmit before it gives up,
// and counts that time from the first retransmission of an episode that it
// does not always forget once the episode is over. A 1 s cap turned the
// kernel's 924 s into 14.4 s, and a tunnel died with ETIMEDOUT on the second
// retransmission of a 200 ms fade (docs/benchmarks/game-tuning.md).
var options = []option{
	{"TCP_THIN_LINEAR_TIMEOUTS", unix.TCP_THIN_LINEAR_TIMEOUTS, 1},
	{"TCP_RTO_MIN_US", tcpRTOMinUS, 20_000},
}

func apply(fd uintptr, skipped Skipped) {
	for _, o := range options {
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, o.opt, o.value); err != nil {
			skipped[o.name] = err
		}
	}
}
