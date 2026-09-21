package ws

import (
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// Plan task Ф4-7, the gate: over 200 connections the histogram of WebSocket
// frame lengths must have no peak where the obfuscated frames are (1400-1700
// bytes) and must not track the length of the frame that produced it.
//
// The observer this models is one who records TLS record lengths: each
// WebSocket frame is written separately, so each becomes a record of its own.
// The lengths are therefore taken from the library's own message reader and
// not from ws.Conn.Read: Read is a stream, it hands out as much of the
// current message as the caller asks for and its return values are the
// caller's buffer sizes, not the wire's. Measuring the wire through it would
// be measuring this test's buffer.

// innerFrameSizes is the traffic the shaper actually carries: obfuscated
// frames at the default MTU, single ones for interactive traffic and batches
// for bulk. The exact values were sampled from a run and are not tied to the
// frame format - what matters is that they are a handful of lengths repeated
// endlessly, which is what a tunnel produces. These are the lengths that must
// not show through.
var innerFrameSizes = []int{1422, 1422, 1422, 1680, 1422, 22752, 1422, 1422}

func shapedFrameLengths(t *testing.T, conns, writesPerConn int, minFrame, maxFrame int) (outer []int, inner []int) {
	t.Helper()

	up := NewUpgrader(UpgraderOpts{Path: "/ws"})
	serverConnCh := make(chan *Conn, conns)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		serverConnCh <- c
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	wsURL := strings.Replace(srv.URL, "http", "ws", 1) + "/ws"

	payload := make([]byte, 64*1024)

	for i := 0; i < conns; i++ {
		client, err := Dial(DialOpts{URL: wsURL})
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		server := <-serverConnCh

		lengths := make(chan []int, 1)
		go func() {
			var got []int
			for {
				_, r, err := server.ws.NextReader()
				if err != nil {
					lengths <- got
					return
				}
				n, err := io.Copy(io.Discard, r)
				if n > 0 {
					got = append(got, int(n))
				}
				if err != nil {
					lengths <- got
					return
				}
			}
		}()

		shaped := NewShapedConn(client, minFrame, maxFrame, 0)
		for w := 0; w < writesPerConn; w++ {
			size := innerFrameSizes[w%len(innerFrameSizes)]
			if _, err := shaped.Write(payload[:size]); err != nil {
				t.Fatalf("write: %v", err)
			}
			inner = append(inner, size)
		}
		_ = client.Close()
		outer = append(outer, <-lengths...)
		_ = server.Close()
	}
	return outer, inner
}

func TestTheWebSocketFramesDoNotShowTheFramesInside(t *testing.T) {
	if testing.Short() {
		t.Skip("200 connections")
	}

	const conns = 200
	outer, inner := shapedFrameLengths(t, conns, len(innerFrameSizes), 256, 4096)
	if len(outer) < 1000 {
		t.Fatalf("only %d frames were observed, too few to say anything", len(outer))
	}

	// Nothing may sit where the obfuscated frames are.
	var inBand int
	for _, n := range outer {
		if n >= 1400 && n <= 1700 {
			inBand++
		}
	}
	if share := float64(inBand) / float64(len(outer)); share > 0.01 {
		t.Fatalf("%.1f%% of the frames are 1400-1700 bytes - the inner frame size is visible in the histogram",
			share*100)
	}

	// No single length may dominate either: a peak anywhere is a signature,
	// it just names a different number.
	counts := make(map[int]int, len(outer))
	for _, n := range outer {
		counts[n]++
	}
	top, topLen := 0, 0
	for n, c := range counts {
		if c > top {
			top, topLen = c, n
		}
	}
	if share := float64(top) / float64(len(outer)); share > 0.05 {
		t.Errorf("the most common frame length %d covers %.1f%% of the frames, want under 5%%", topLen, share*100)
	}

	// And no write may leave as a single frame: the shaper cuts every write
	// at least once, so the number of frames is at least twice the number of
	// writes.
	//
	// This used to be written as "no outer length may equal any inner one",
	// which is a stronger claim and a false one. The cuts are drawn at
	// random over 256-4096 bytes, so a piece landing on exactly 1422 is
	// bound to happen in a few thousand frames and says nothing about the
	// write it came from - while a shaper that avoided two particular
	// numbers would be carrying a signature of its own. What actually
	// matters is that a write never survives whole, and the band check above
	// is what would catch it if one did.
	if len(outer) < 2*len(inner) {
		t.Fatalf("%d frames for %d writes - fewer than two per write, so a write went out whole",
			len(outer), len(inner))
	}

	t.Logf("%d frames over %d connections, %d distinct lengths, most common %d in %.1f%%",
		len(outer), conns, len(counts), topLen, float64(top)/float64(len(outer))*100)
}

// The spread is what makes the length of a single frame uninformative. With
// one cut per write - which is what a band starting at 512 forces on a
// 1422-byte frame - every outer frame is exactly half an inner one, and the
// correlation is perfect even though no frame is 1422 bytes long.
func TestOneInnerFrameSizeProducesASpreadOfOuterSizes(t *testing.T) {
	if testing.Short() {
		t.Skip("uses real connections")
	}

	outer, _ := shapedFrameLengths(t, 40, 4, 256, 4096)

	sorted := append([]int(nil), outer...)
	sort.Ints(sorted)
	var sum float64
	for _, n := range sorted {
		sum += float64(n)
	}
	mean := sum / float64(len(sorted))
	var variance float64
	for _, n := range sorted {
		variance += (float64(n) - mean) * (float64(n) - mean)
	}
	spread := math.Sqrt(variance / float64(len(sorted)))

	// Half of 1422 with a little jitter would be a standard deviation of a few
	// dozen bytes. A varying number of cuts is worth hundreds.
	if spread < 100 {
		t.Fatalf("frame lengths have a standard deviation of %.0f bytes around %.0f - too tight to hide how many pieces a frame was cut into",
			spread, mean)
	}
	t.Logf("frame lengths: mean %.0f, standard deviation %.0f, from %d to %d", mean, spread, sorted[0], sorted[len(sorted)-1])
}

// The cut plan is arithmetic, and it has to hold for every size: the pieces
// add up to the write, none is empty, and no write leaves as a single frame
// unless it is too small to cut.
func TestEveryCutPlanAddsUp(t *testing.T) {
	shaped := NewShapedConn(nil, 256, 4096, 0)

	for n := 1; n <= 70000; n += 7 {
		plan := shaped.plan(n)
		sum := 0
		for _, size := range plan {
			if size <= 0 {
				t.Fatalf("n=%d: plan %v has an empty frame", n, plan)
			}
			sum += size
		}
		if sum != n {
			t.Fatalf("n=%d: the plan %v sums to %d", n, plan, sum)
		}
		if len(plan) == 1 && n > 2*minPiece {
			t.Fatalf("n=%d went out as one frame: the inner boundary reaches the wire", n)
		}
	}
}

// Shaping costs bandwidth, because every extra frame carries a header. The
// plan allows 10%; the bias towards fewer, larger frames keeps it far below
// that for bulk traffic, which is where the bytes are.
func TestShapingCostsLessThanATenthOfTheBandwidth(t *testing.T) {
	shaped := NewShapedConn(nil, 256, 4096, 0)

	// A WebSocket header is 2-14 bytes and a TLS record adds about 22 more.
	const perFrameOverhead = 14 + 22

	for _, size := range []int{1422, 22752, 65536} {
		var frames, bytes int
		for i := 0; i < 2000; i++ {
			frames += len(shaped.plan(size))
			bytes += size
		}
		overhead := float64(frames*perFrameOverhead) / float64(bytes)
		if overhead > 0.10 {
			t.Errorf("writes of %d bytes become %.1f frames each, costing %.1f%% in headers alone",
				size, float64(frames)/2000, overhead*100)
		}
		t.Logf("writes of %d bytes: %.1f frames each, %.2f%% bandwidth overhead", size, float64(frames)/2000, overhead*100)
	}
}

var _ io.Writer = (*ShapedConn)(nil)

// The plan itself has to be free, so that the only thing shaping costs is the
// frames it asks for. It runs on every write on every connection.
func TestPlanningAFrameCostsNothing(t *testing.T) {
	shaped := NewShapedConn(nil, DefaultMinFrame, DefaultMaxFrame, 0)
	if allocs := testing.AllocsPerRun(1000, func() { _ = shaped.plan(1422) }); allocs > 0 {
		t.Errorf("planning one write allocates %.1f times", allocs)
	}
	if allocs := testing.AllocsPerRun(1000, func() { _ = shaped.plan(64 * 1024) }); allocs > 0 {
		t.Errorf("planning a large write allocates %.1f times", allocs)
	}
}
