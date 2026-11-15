package diagnostics

import (
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/tcptune"
)

func linuxSample(rtt time.Duration, acked uint64, retransmits uint8) *tcptune.Counters {
	return &tcptune.Counters{
		Has: tcptune.CounterRTT | tcptune.CounterRetransmits | tcptune.CounterBytesAcked,
		RTT: rtt, BytesAcked: acked, Retransmits: retransmits,
	}
}

// Three moving samples far above the socket's own floor make a spike; a
// sample that moves nothing breaks the streak and does not move the floor.
func TestTheRTTSpikeIsAgainstTheSocketsOwnFloor(t *testing.T) {
	var d spikeDetector
	now := time.Unix(1000, 0)
	step := func(rtt time.Duration, acked uint64) uint8 {
		now = now.Add(sampleInterval)
		return d.observe(now, linuxSample(rtt, acked, 0))
	}
	for i, s := range []struct {
		rtt   time.Duration
		acked uint64
		want  uint8
	}{
		{100 * time.Millisecond, 1, 0}, // the first sample sets the floor
		{80 * time.Millisecond, 2, 0},  // a lower one moves it
		{200 * time.Millisecond, 3, 0},
		{200 * time.Millisecond, 4, 0},
		{200 * time.Millisecond, 4, 0}, // idle: no streak
		{10 * time.Millisecond, 4, 0},  // idle: no floor either
		{200 * time.Millisecond, 5, 0},
		{200 * time.Millisecond, 6, 0},
		{200 * time.Millisecond, 7, spikeRTT},
		{200 * time.Millisecond, 8, 0}, // the cooldown
		{200 * time.Millisecond, 9, 0},
		{200 * time.Millisecond, 10, 0},
	} {
		if got := step(s.rtt, s.acked); got != s.want {
			t.Fatalf("sample %d: %d, want %d", i, got, s.want)
		}
	}
	if d.floor != 80*time.Millisecond {
		t.Fatalf("floor %v", d.floor)
	}
	now = now.Add(spikeCooldown)
	if got := step(200*time.Millisecond, 11); got != spikeRTT {
		t.Fatalf("after the cooldown the streak gave %d", got)
	}
	// 15 ms above the floor is no spike, however long it lasts.
	var small spikeDetector
	for i, rtt := range []time.Duration{80, 95, 95, 95, 95} {
		if got := small.observe(now.Add(time.Duration(i)*time.Second), linuxSample(rtt*time.Millisecond, uint64(i+1), 0)); got != 0 {
			t.Fatal("15 ms over the floor is a spike")
		}
	}
	var unknown spikeDetector
	for i := range 10 {
		if got := unknown.observe(now, &tcptune.Counters{Has: tcptune.CounterBytesSent, BytesSent: uint64(i)}); got != 0 {
			t.Fatal("a spike without a round trip time")
		}
	}
}

// The retransmit timer: on Linux a sample taken while it fires, on Windows
// one more timeout episode than the sample before. The cooldown holds.
func TestTheRetransmitTimerMakesASpike(t *testing.T) {
	now := time.Unix(1000, 0)
	var linux spikeDetector
	if got := linux.observe(now, linuxSample(10*time.Millisecond, 1, 1)); got != spikeRTO {
		t.Fatalf("Linux: %d", got)
	}
	if got := linux.observe(now.Add(spikeCooldown-time.Second), linuxSample(10*time.Millisecond, 1, 2)); got != 0 {
		t.Fatal("Linux: a spike inside the cooldown")
	}
	if got := linux.observe(now.Add(spikeCooldown), linuxSample(10*time.Millisecond, 1, 3)); got != spikeRTO {
		t.Fatal("Linux: no spike after the cooldown")
	}
	windows := func(episodes uint32) *tcptune.Counters {
		return &tcptune.Counters{Has: tcptune.CounterRTT | tcptune.CounterTimeoutEpisodes | tcptune.CounterBytesSent,
			RTT: 10 * time.Millisecond, TimeoutEpisodes: episodes}
	}
	var w spikeDetector
	for i, s := range []struct {
		episodes uint32
		want     uint8
	}{{5, 0}, {5, 0}, {6, spikeRTO}, {7, 0}} {
		if got := w.observe(now.Add(time.Duration(i)*time.Second), windows(s.episodes)); got != s.want {
			t.Fatalf("Windows sample %d: %d, want %d", i, got, s.want)
		}
	}
}
