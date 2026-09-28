package main

import (
	"net"
	"slices"
	"testing"
	"time"
)

func TestAnAskSurvivesTheWire(t *testing.T) {
	a := burstAsk{id: 7, size: 928, wave: 450, waveFor: 5 * time.Millisecond, tail: 450, tailEvery: 500 * time.Microsecond}
	got, ok := parseBurstAsk(a.marshal())
	if !ok || got != a {
		t.Fatalf("parsed %+v, %v from %+v", got, ok, a)
	}
	if _, ok := parseBurstAsk(append(a.marshal(), 0)); ok {
		t.Fatal("a longer datagram parsed as an ask")
	}
}

// The wave fills millisecond slots evenly and ends inside waveFor; the tail
// starts after it.
func TestTheWaveIsSentInMillisecondSlots(t *testing.T) {
	a := burstAsk{wave: 450, waveFor: 5 * time.Millisecond, tail: 2, tailEvery: time.Millisecond}
	perSlot := map[time.Duration]int{}
	for i := range a.wave {
		perSlot[a.due(i)]++
	}
	if len(perSlot) != 5 || perSlot[0] != 90 || perSlot[4*time.Millisecond] != 90 {
		t.Fatalf("slots %v", perSlot)
	}
	if a.due(a.wave) != 6*time.Millisecond || a.due(a.wave+1) != 7*time.Millisecond {
		t.Fatalf("tail at %v and %v", a.due(a.wave), a.due(a.wave+1))
	}
}

func TestABurstArrivesWholeOnLoopback(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if ask, ok := parseBurstAsk(buf[:n]); ok {
				go func() { _ = sendBurst(pc, from, ask) }()
			}
		}
	}()
	rep, err := runBursts(burstSettings{
		settings: settings{target: pc.LocalAddr().String(), timeout: time.Second},
		ask:      burstAsk{size: 200, wave: 50, waveFor: 2 * time.Millisecond, tail: 10, tailEvery: time.Millisecond},
		bursts:   2,
		gap:      10 * time.Millisecond,
	}, "loopback")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Sent != 120 || rep.Lost != 0 || len(rep.Bursts) != 2 {
		t.Fatalf("%+v", rep)
	}
}

func TestTheReportNamesOnlyTheSocketsThatDroppedDuringIt(t *testing.T) {
	before := map[string]socketDrops{
		"10": {Local: "127.0.0.1:53", Drops: 7},
		"11": {Local: "0.0.0.0:1443", Drops: 2},
	}
	after := map[string]socketDrops{
		"10": {Local: "127.0.0.1:53", Drops: 7},
		"11": {Local: "0.0.0.0:1443", Drops: 42},
		"12": {Local: "127.0.0.1:40000", Drops: 3},
		"13": {Local: "127.0.0.1:40001"},
	}
	got := dropsSince(before, after)
	want := []socketDrops{
		{Local: "0.0.0.0:1443", Drops: 40, inode: "11"},
		{Local: "127.0.0.1:40000", Drops: 3, inode: "12"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
