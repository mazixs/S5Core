package diagnostics

import (
	"time"

	"github.com/mazixs/S5Core/internal/tcptune"
)

const (
	// spikeExcess and spikeStreak: the round trip time stays at least this
	// far, and half again, above the floor of its socket for this many
	// samples of a socket that moves data.
	spikeExcess = 20 * time.Millisecond
	spikeStreak = 3
	// spikeCooldown is the least time between two spikes of one socket.
	spikeCooldown = 2 * time.Minute
)

// spikeDetector watches the samples of one socket against its own floor,
// never another socket's. Only the worker uses it.
type spikeDetector struct {
	seen     bool
	floor    time.Duration // the lowest round trip time of a moving sample
	activity uint64        // the byte counters of the last sample, summed
	timeouts uint32
	streak   int
	last     time.Time // of the last spike
}

// observe takes the next sample and returns the reason of a spike, or zero.
// The retransmit timer counts where the kernel says it fired: on Linux a
// sample taken while it keeps firing, on Windows a timeout episode more than
// the sample before.
func (d *spikeDetector) observe(now time.Time, c *tcptune.Counters) uint8 {
	var activity uint64
	for _, f := range [...]struct {
		f tcptune.CounterField
		n uint64
	}{{tcptune.CounterBytesAcked, c.BytesAcked}, {tcptune.CounterBytesSent, c.BytesSent}, {tcptune.CounterBytesReceived, c.BytesReceived}} {
		if c.Known(f.f) {
			activity += f.n
		}
	}
	moving := !d.seen || activity != d.activity
	rto := c.Known(tcptune.CounterRetransmits) && c.Retransmits > 0 ||
		c.Known(tcptune.CounterTimeoutEpisodes) && d.seen && c.TimeoutEpisodes > d.timeouts
	d.seen, d.activity, d.timeouts = true, activity, c.TimeoutEpisodes
	cooling := d.cooling(now)
	if rto && !cooling {
		d.last, d.streak = now, 0
		return spikeRTO
	}
	if !c.Known(tcptune.CounterRTT) || c.RTT <= 0 || !moving {
		d.streak = 0
		return 0
	}
	if d.floor == 0 {
		d.floor = c.RTT
		return 0
	}
	d.floor = min(d.floor, c.RTT)
	if c.RTT-d.floor >= spikeExcess && c.RTT >= d.floor+d.floor/2 {
		d.streak++
	} else {
		d.streak = 0
	}
	if d.streak >= spikeStreak && !cooling {
		d.last, d.streak = now, 0
		return spikeRTT
	}
	return 0
}

func (d *spikeDetector) cooling(now time.Time) bool {
	return !d.last.IsZero() && now.Sub(d.last) < spikeCooldown
}

// claim takes a spike the socket's owner reported, unless the socket is
// cooling down from one.
func (d *spikeDetector) claim(now time.Time) bool {
	if d.cooling(now) {
		return false
	}
	d.last, d.streak = now, 0
	return true
}
