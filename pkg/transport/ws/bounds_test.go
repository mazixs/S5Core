package ws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The band the operator configures is what the wire is supposed to show:
// WS_MIN_FRAME and WS_MAX_FRAME are documented as bounds, and the numbers in
// docs/benchmarks/frame-shaping.md describe the shape they produce. A piece
// drawn above the maximum makes both of those statements false (review
// finding R09).

func TestNoPieceIsLargerThanTheConfiguredMaximum(t *testing.T) {
	// Several bands, because the defect depends on where the cut count
	// lands: with a mean close to the maximum, half the draws exceed it.
	for _, band := range []struct{ min, max int }{
		{256, 4096},
		{512, 2048},
		{1024, 8192},
		{64, 128},
	} {
		shaped := NewShapedConn(nil, band.min, band.max, 0)

		var worst, worstN int
		for n := 1; n <= 70000; n += 7 {
			sum := 0
			for _, size := range shaped.plan(n) {
				sum += size
				// A write smaller than two minimum pieces is not cut at all,
				// and it cannot be padded down: that one is the documented
				// exception, and it is bounded by the write, not by the band.
				if size > shaped.maxFrame && n > shaped.maxFrame {
					if size > worst {
						worst, worstN = size, n
					}
				}
			}
			if sum != n {
				t.Fatalf("band %d-%d, n=%d: the pieces sum to %d", band.min, band.max, n, sum)
			}
		}
		if worst > 0 {
			t.Errorf("band %d-%d: a write of %d bytes produced a frame of %d, %.1f%% over the configured maximum",
				band.min, band.max, worstN, worst, float64(worst-band.max)/float64(band.max)*100)
		}
	}
}

// The same statement over repeated draws of one size: the defect was a
// property of the distribution, so a single plan could come out clean by
// chance.
func TestTheMaximumHoldsOverManyDraws(t *testing.T) {
	const (
		minFrame = 4096
		maxFrame = 8192
		writeLen = 16000 // two frames at the maximum, so the mean sits near it
		rounds   = 2000
	)
	shaped := NewShapedConn(nil, minFrame, maxFrame, 0)

	over := 0
	for i := 0; i < rounds; i++ {
		sum := 0
		for _, size := range shaped.plan(writeLen) {
			if size > maxFrame {
				over++
			}
			sum += size
		}
		if sum != writeLen {
			t.Fatalf("round %d: the pieces sum to %d, want %d", i, sum, writeLen)
		}
	}
	if over > 0 {
		t.Errorf("%d of the pieces over %d writes are larger than the configured maximum of %d",
			over, rounds, maxFrame)
	}
}

// An empty write is allowed by io.Writer and used to become a zero-length
// binary WebSocket frame: a shape nothing else on this connection produces,
// and one an observer can find because it is the only frame of its size
// (review finding R10). The plan is checked first, and then the wire, because
// the plan is where the decision is and the wire is what an observer sees.
func TestAnEmptyWriteProducesNoFrame(t *testing.T) {
	shaped := NewShapedConn(nil, DefaultMinFrame, DefaultMaxFrame, 0)
	if plan := shaped.plan(0); len(plan) != 0 {
		t.Fatalf("a write of no bytes was planned as %v, want no frames at all", plan)
	}
}

func TestAnEmptyWritePutsNothingOnTheWire(t *testing.T) {
	up := NewUpgrader(UpgraderOpts{Path: "/ws"})
	serverConnCh := make(chan *Conn, 1)

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

	client, err := Dial(DialOpts{URL: strings.Replace(srv.URL, "http", "ws", 1) + "/ws"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server := <-serverConnCh
	defer func() { _ = server.Close() }()

	frames := make(chan []int, 1)
	go func() {
		var got []int
		for {
			_, r, err := server.ws.NextReader()
			if err != nil {
				frames <- got
				return
			}
			n, _ := io.Copy(io.Discard, r)
			got = append(got, int(n))
		}
	}()

	shaped := NewShapedConn(client, DefaultMinFrame, DefaultMaxFrame, 0)
	if n, err := shaped.Write(nil); err != nil || n != 0 {
		t.Fatalf("an empty write returned (%d, %v), want (0, nil)", n, err)
	}
	if n, err := shaped.Write([]byte("something to follow it")); err != nil || n != 22 {
		t.Fatalf("the write after it returned (%d, %v)", n, err)
	}
	_ = client.Close()

	got := <-frames
	for i, n := range got {
		if n == 0 {
			t.Fatalf("frame %d of %v is empty: an empty write reached the wire as a frame", i, got)
		}
	}
	if len(got) == 0 {
		t.Fatal("nothing reached the server at all, so this test is measuring a broken connection")
	}
}

// Holding the maximum is one statement; how it is held is another. A draw
// above the bound has to land somewhere, and putting every such draw on the
// bound itself makes maxFrame the single most common length on the wire -
// the shaper's whole job is to keep one length from standing out like that.
// The write size here is what the obfuscation layer actually hands the
// transport under load: sixteen frames at the default MTU, batched
// (framesPerBatch in pkg/obfs).
func TestTheBoundDoesNotMakeOneLengthTheShape(t *testing.T) {
	const (
		batchWrite = 22752
		rounds     = 1000
		// Measured: 9.3-9.8% of the pieces land on 4096 with the bound
		// spread over the top sixteenth, against 17% when every draw above
		// the bound is clamped onto it and 5.4% with no bound at all - the
		// residue belongs to the floor rule, which cannot be spread without
		// paying for more frames per write (docs/benchmarks/frame-shaping.md).
		limit = 0.13
	)
	shaped := NewShapedConn(nil, DefaultMinFrame, DefaultMaxFrame, 0)

	hist := map[int]int{}
	total := 0
	for i := 0; i < rounds; i++ {
		for _, size := range shaped.plan(batchWrite) {
			hist[size]++
			total++
		}
	}

	worstLen, worst := 0, 0
	for size, count := range hist {
		if count > worst {
			worst, worstLen = count, size
		}
	}
	if share := float64(worst) / float64(total); share > limit {
		t.Errorf("length %d is %.1f%% of the %d pieces a batched write is cut into, over the %.0f%% this shape allows",
			worstLen, share*100, total, limit*100)
	}
}
