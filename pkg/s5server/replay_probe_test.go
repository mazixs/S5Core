package s5server

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/obfs"
)

// Plan task Ф4-4, the gate. The task is stated as a probe rather than as a
// unit test on purpose: record the first flight of a working connection, send
// it again on a fresh socket, and check that the server's reaction cannot be
// told apart from its reaction to bytes that do not authenticate - not by how
// long it takes to close, and not by how much it says before closing.
//
// Since task Ф5-6 the server does not close either of them itself: it holds
// the connection, reads and discards, and lets the handshake budget end it -
// the same budget that ends a client which connected and then went quiet.
// That is what this test now measures, and the reason it configures a short
// budget rather than waiting fifteen seconds a round.
//
// The control is the recorded flight with a single ciphertext byte flipped. It
// is the strongest control available: it arrives with the same length, the
// same salt and the same frame boundary, so the server walks the identical
// code path and parts company only at the AEAD tag. Anything a prober could
// measure between the two would be a signal that the replay check leaks.

// recordingConn keeps every write as its own record, so the first flight can
// be extracted exactly as it went on the wire.
type recordingConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *recordingConn) firstWrite(t *testing.T) []byte {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.writes) == 0 {
		t.Fatal("the client wrote nothing to the wire")
	}
	return c.writes[0]
}

// recordFirstFlight makes one genuine tunnelled connection - handshake,
// authentication and an echo round trip - and returns the bytes its very first
// write put on the wire: the session salt followed by one frame.
func recordFirstFlight(t *testing.T, obfsPort, echoAddr string) []byte {
	t.Helper()

	raw, err := net.DialTimeout("tcp", "127.0.0.1:"+obfsPort, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = raw.Close() }()
	if err := raw.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	rec := &recordingConn{Conn: raw}
	tunnel, err := obfs.NewClientConn(rec, obfs.Config{
		PSK:        []byte(testPSK),
		MaxPadding: 256,
		MTU:        1400,
	})
	if err != nil {
		t.Fatalf("obfs client: %v", err)
	}

	if err := socks5Connect(tunnel, "alice", "secret1", echoAddr); err != nil {
		t.Fatalf("the connection being recorded was not a working one: %v", err)
	}
	if _, err := tunnel.Write([]byte("ping")); err != nil {
		t.Fatalf("write through the tunnel: %v", err)
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(tunnel, echo); err != nil {
		t.Fatalf("read through the tunnel: %v", err)
	}
	if string(echo) != "ping" {
		t.Fatalf("the tunnel echoed %q", echo)
	}

	return rec.firstWrite(t)
}

// probeResult is everything a prober can observe from one attempt.
type probeResult struct {
	elapsed  time.Duration
	answered int
	timedOut bool
}

// probe opens a connection, sends the given bytes and waits for the server to
// close, measuring how long that takes and how much came back.
func probe(t *testing.T, obfsPort string, payload []byte) probeResult {
	t.Helper()

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+obfsPort, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("probe write: %v", err)
	}

	var back bytes.Buffer
	buf := make([]byte, 512)
	for {
		n, err := conn.Read(buf)
		back.Write(buf[:n])
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return probeResult{elapsed: time.Since(start), answered: back.Len(), timedOut: true}
			}
			return probeResult{elapsed: time.Since(start), answered: back.Len()}
		}
	}
}

func median(samples []time.Duration) time.Duration {
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

func TestAReplayedFirstFlightIsAnsweredLikeGarbage(t *testing.T) {
	echoAddr := startEchoServer(t)
	usersPath := testUsersFile(t)

	const plainPort = "19081"
	const obfsPort = "19444"

	// The handshake budget is short here because it is also what closes a
	// refused connection (plan task Ф5-6): the server holds it, says
	// nothing and lets the budget end it, so this is the number the probe
	// below is measuring. In production it is DefaultHandshakeTimeout.
	const handshakeBudget = 500 * time.Millisecond

	startServer(t, Config{
		Port:             plainPort,
		ListenIP:         "127.0.0.1",
		RequireAuth:      true,
		UsersFile:        usersPath,
		Fail2BanRetries:  1000,
		Fail2BanTime:     time.Minute,
		HandshakeTimeout: handshakeBudget,
		ObfsEnabled:      true,
		ObfsPort:         obfsPort,
		ObfsPSK:          testPSK,
		ObfsMaxPadding:   256,
		ObfsMTU:          1400,
		ObfsReplayWindow: obfs.DefaultSaltHistory,
	})

	flight := recordFirstFlight(t, obfsPort, echoAddr)
	if len(flight) < 40 {
		t.Fatalf("the recorded flight is %d bytes, too short to be a salt and a frame", len(flight))
	}

	garbage := append([]byte(nil), flight...)
	garbage[len(garbage)-1] ^= 0x01

	// Interleaved, so that anything drifting on this machine - CPU frequency,
	// a noisy neighbour - moves both series together instead of one of them.
	const rounds = 7
	replayTimes := make([]time.Duration, 0, rounds)
	garbageTimes := make([]time.Duration, 0, rounds)

	for i := 0; i < rounds; i++ {
		r := probe(t, obfsPort, flight)
		g := probe(t, obfsPort, garbage)

		if r.timedOut {
			t.Fatalf("round %d: the server never closed the replayed connection", i)
		}
		if g.timedOut {
			t.Fatalf("round %d: the server never closed the garbage connection", i)
		}
		if r.answered != 0 || g.answered != 0 {
			t.Fatalf("round %d: the server answered %d bytes to the replay and %d to the garbage; want silence from both",
				i, r.answered, g.answered)
		}
		// Neither may be closed before the budget: a refusal that arrives
		// early is a refusal a probe can time.
		if r.elapsed < handshakeBudget/2 || g.elapsed < handshakeBudget/2 {
			t.Fatalf("round %d: closed after %v (replay) and %v (garbage), well inside the %v budget - the server answered the probe by hanging up",
				i, r.elapsed, g.elapsed, handshakeBudget)
		}
		replayTimes = append(replayTimes, r.elapsed)
		garbageTimes = append(garbageTimes, g.elapsed)
	}

	replayMedian := median(replayTimes)
	garbageMedian := median(garbageTimes)
	gap := replayMedian - garbageMedian
	if gap < 0 {
		gap = -gap
	}

	// Both are now closed by the same handshake budget rather than by the
	// code path that refused them, so the gap should be the scheduling
	// noise of two timers. Half the slower median, with a floor for fast
	// machines, is loose enough not to flake and tight enough that a real
	// difference - an early refusal at the salt, before the frame is even
	// read - would fail it.
	slower := replayMedian
	if garbageMedian > slower {
		slower = garbageMedian
	}
	tolerance := slower / 2
	if tolerance < 2*time.Millisecond {
		tolerance = 2 * time.Millisecond
	}
	if gap > tolerance {
		t.Fatalf("time to close: %v for the replay, %v for the garbage, gap %v exceeds %v - a prober can measure that",
			replayMedian, garbageMedian, gap, tolerance)
	}
	t.Logf("time to close: replay %v, garbage %v, gap %v (tolerance %v), no bytes returned by either",
		replayMedian, garbageMedian, gap, tolerance)
}

// The history has to span listeners as well as connections: a flight recorded
// on the obfuscated port is the same flight when it arrives wrapped in
// WebSocket frames. That sharing is what makes one history per server the
// right shape, and this pins it.
func TestTheSaltHistoryIsSharedByEveryObfuscatedListener(t *testing.T) {
	srv, err := NewServer(Config{
		Port:             "19082",
		ListenIP:         "127.0.0.1",
		RequireAuth:      false,
		ObfsEnabled:      true,
		ObfsPort:         "19445",
		ObfsPSK:          testPSK,
		ObfsMTU:          1400,
		ObfsReplayWindow: 128,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv.obfsConfig(TransportObfs).History == nil {
		t.Fatal("the obfuscated listener got no salt history")
	}
	if srv.obfsConfig(TransportObfs).History != srv.obfsConfig(TransportWS).History {
		t.Fatal("the two obfuscated transports keep separate histories")
	}
}

func TestZeroDisablesTheSaltHistory(t *testing.T) {
	srv, err := NewServer(Config{
		Port:             "19083",
		ListenIP:         "127.0.0.1",
		RequireAuth:      false,
		ObfsEnabled:      true,
		ObfsPort:         "19446",
		ObfsPSK:          testPSK,
		ObfsMTU:          1400,
		ObfsReplayWindow: 0,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv.obfsConfig(TransportObfs).History != nil {
		t.Fatal("OBFS_REPLAY_WINDOW=0 still built a history")
	}
}
