package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"time"
)

// A game server answers in bursts. At the node where a match lost 5% of its
// answers, a burst came as some 450 datagrams of 928 bytes within 5-10 ms,
// up to 138 in one millisecond, and then a tail of about 2000 a second for a
// few hundred milliseconds (docs/field/nodes.md, "Узел B для игры"). A socket
// on the way that holds fewer than the wave loses the rest however fast it is
// read, and a steady probe never shows it. In burst mode the probe asks the
// echo side for such bursts and counts what arrives.

var burstMagic = [4]byte{'U', 'B', 'S', 'T'}

const burstAskLen = 4 + 4*6

// burstAsk is what the probe sends to start one burst: wave datagrams of
// size bytes spread over waveFor, then tail more at tailEvery apart.
type burstAsk struct {
	id        uint32
	size      int
	wave      int
	waveFor   time.Duration
	tail      int
	tailEvery time.Duration
}

func (a burstAsk) total() int { return a.wave + a.tail }

func (a burstAsk) marshal() []byte {
	b := append([]byte{}, burstMagic[:]...)
	for _, v := range []uint32{a.id, uint32(a.size), uint32(a.wave), uint32(a.waveFor.Microseconds()),
		uint32(a.tail), uint32(a.tailEvery.Microseconds())} {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	return b
}

func parseBurstAsk(b []byte) (burstAsk, bool) {
	if len(b) != burstAskLen || [4]byte(b[:4]) != burstMagic {
		return burstAsk{}, false
	}
	u := func(i int) uint32 { return binary.BigEndian.Uint32(b[4+4*i:]) }
	a := burstAsk{
		id: u(0), size: int(u(1)), wave: int(u(2)), waveFor: time.Duration(u(3)) * time.Microsecond,
		tail: int(u(4)), tailEvery: time.Duration(u(5)) * time.Microsecond,
	}
	if a.size < 8 || a.size > 65000 || a.total() > 100000 {
		return burstAsk{}, false
	}
	return a, true
}

// due is when the i-th datagram of the burst leaves, from the ask. The wave
// goes out in millisecond slots, each sent back to back, which is how the
// captured waves arrived: a sender cannot space 138 datagrams a millisecond
// by sleeping between them, and neither did the game server.
func (a burstAsk) due(i int) time.Duration {
	if i < a.wave {
		slots := max(1, int(a.waveFor/time.Millisecond))
		per := (a.wave + slots - 1) / slots
		return time.Duration(i/per) * time.Millisecond
	}
	return a.waveFor + time.Duration(i-a.wave+1)*a.tailEvery
}

// sendBurst answers an ask. Every datagram carries the burst and its index,
// so the probe counts what came and not merely how much.
func sendBurst(pc net.PacketConn, to net.Addr, a burstAsk) error {
	payload := make([]byte, a.size)
	binary.BigEndian.PutUint32(payload[4:8], a.id)
	start := time.Now()
	for i := range a.total() {
		if wait := time.Until(start.Add(a.due(i))); wait > 0 {
			time.Sleep(wait)
		}
		binary.BigEndian.PutUint32(payload[0:4], uint32(i))
		if _, err := pc.WriteTo(payload, to); err != nil {
			return err
		}
	}
	return nil
}

type burstSettings struct {
	settings
	ask    burstAsk
	bursts int
	gap    time.Duration
}

type burstResult struct {
	ID       uint32  `json:"id"`
	Received int     `json:"received"`
	Lost     int     `json:"lost"`
	WaveLost int     `json:"wave_lost"`
	LastMs   float64 `json:"last_ms"`
}

// socketDrops is a UDP socket and the datagrams the kernel dropped on it
// because its receive buffer was full.
type socketDrops struct {
	Local string `json:"local"`
	Owner string `json:"owner,omitempty"`
	Drops uint64 `json:"drops"`
	inode string
}

// dropsSince keeps the sockets, by inode, that dropped datagrams between the
// two reads, with the drops of that span: the report names what lost this
// measurement, not every socket of the machine and its owner.
func dropsSince(before, after map[string]socketDrops) []socketDrops {
	var out []socketDrops
	for inode, s := range after {
		if was := before[inode].Drops; s.Drops > was {
			s.Drops -= was
			s.inode = inode
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b socketDrops) int { return strings.Compare(a.Local, b.Local) })
	return out
}

type burstReport struct {
	Label    string        `json:"label"`
	Size     int           `json:"size"`
	Wave     int           `json:"wave"`
	WaveMs   float64       `json:"wave_ms"`
	Tail     int           `json:"tail"`
	Bursts   []burstResult `json:"bursts"`
	Sent     int           `json:"sent"`
	Lost     int           `json:"lost"`
	Sockets  []socketDrops `json:"sockets,omitempty"`
	Unmapped string        `json:"sockets_error,omitempty"`
}

// runBursts asks for one burst at a time and waits gap between them, so that
// every burst meets empty buffers, as the ones of a match did.
func runBursts(s burstSettings, label string) (burstReport, error) {
	dst, err := net.ResolveUDPAddr("udp", s.target)
	if err != nil {
		return burstReport{}, fmt.Errorf("resolve %s: %w", s.target, err)
	}
	send, recv, cleanup, err := openPath(s.settings, dst)
	if err != nil {
		return burstReport{}, err
	}
	defer cleanup()
	// After the path is open, so that the sockets of the association are
	// in the first read too.
	before, beforeErr := udpSockets()

	type arrival struct {
		id, index uint32
		at        time.Time
	}
	// The reader only reads: a probe that counted on the reading goroutine
	// would be the socket that overflows.
	arrivals := make(chan arrival, 1<<16)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := recv(buf)
			if err != nil {
				close(arrivals)
				return
			}
			if n >= 8 {
				arrivals <- arrival{binary.BigEndian.Uint32(buf[4:8]), binary.BigEndian.Uint32(buf[0:4]), time.Now()}
			}
		}
	}()

	rep := burstReport{Label: label, Size: s.ask.size, Wave: s.ask.wave,
		WaveMs: float64(s.ask.waveFor.Microseconds()) / 1000, Tail: s.ask.tail}
	base := uint32(time.Now().UnixNano())
	want := s.ask.total()
	for b := range s.bursts {
		ask := s.ask
		ask.id = base + uint32(b)
		asked := time.Now()
		if _, err := send(ask.marshal()); err != nil {
			return rep, fmt.Errorf("ask %d: %w", b, err)
		}
		seen := make([]bool, want)
		got, last := 0, time.Duration(0)
		until := time.NewTimer(ask.due(want-1) + s.timeout)
	collect:
		for got < want {
			select {
			case a, ok := <-arrivals:
				if !ok {
					until.Stop()
					return rep, errors.New("the path closed")
				}
				if a.id != ask.id || int(a.index) >= want || seen[a.index] {
					continue
				}
				seen[a.index] = true
				got++
				last = a.at.Sub(asked)
			case <-until.C:
				break collect
			}
		}
		until.Stop()
		r := burstResult{ID: ask.id, Received: got, Lost: want - got, LastMs: float64(last.Microseconds()) / 1000}
		for i := range ask.wave {
			if !seen[i] {
				r.WaveLost++
			}
		}
		rep.Bursts = append(rep.Bursts, r)
		rep.Sent += want
		rep.Lost += r.Lost
		if b != s.bursts-1 {
			time.Sleep(s.gap)
		}
	}
	// Read while every socket of the path is still open: the counts belong
	// to the sockets, and they go when the association does.
	if err := beforeErr; err != nil {
		rep.Unmapped = err.Error()
	} else if rep.Sockets, err = socketsThatDropped(before); err != nil {
		rep.Unmapped = err.Error()
	}
	return rep, nil
}

func (r burstReport) print(path string) error {
	lost := make([]int, 0, len(r.Bursts))
	for _, b := range r.Bursts {
		lost = append(lost, b.Lost)
	}
	slices.Sort(lost)
	pct := 0.0
	if r.Sent > 0 {
		pct = 100 * float64(r.Lost) / float64(r.Sent)
	}
	fmt.Printf("%s\tbursts=%d\twave=%d/%.0fms tail=%d size=%d\tsent=%d\tlost=%d (%.2f%%)\tper burst min/p50/max=%d/%d/%d\n",
		r.Label, len(r.Bursts), r.Wave, r.WaveMs, r.Tail, r.Size, r.Sent, r.Lost, pct,
		pick(lost, 0), pick(lost, len(lost)/2), pick(lost, len(lost)-1))
	for _, s := range r.Sockets {
		fmt.Printf("%s\tsocket %s (%s) dropped %d\n", r.Label, s.Local, s.Owner, s.Drops)
	}
	if r.Unmapped != "" {
		fmt.Printf("%s\tsocket drops unknown: %s\n", r.Label, r.Unmapped)
	}
	if path == "" {
		return nil
	}
	b, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func pick(sorted []int, i int) int {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[max(0, min(i, len(sorted)-1))]
}
