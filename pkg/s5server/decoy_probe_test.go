package s5server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/testcert"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/transport/ws"
)

// Plan task Ф5-6, the gate: "time to close and volume of the answer for
// garbage, for a replayed frame and for a valid connection are
// indistinguishable". Ф4-4 established that on the obfuscated port
// (replay_probe_test.go); this is the same probe against the transport that
// actually faces the open internet, where the cover story is a mirrored
// site rather than silence.
//
// Two different questions live here, and a probe asks both:
//
//  1. Over HTTP - what a scanner does first - every path must answer the way
//     the mirrored site answers it, including the tunnel's own path.
//  2. Inside an established WebSocket - what a probe does after recording a
//     real client - garbage and a replayed flight must be answered alike.

// decoyHandshakeBudget is how long this server gives a connection to finish
// its setup - and therefore how long it holds one that never authenticated
// before letting the budget close it. Short here so the probe below takes
// seconds rather than minutes; DefaultHandshakeTimeout in production.
const decoyHandshakeBudget = 500 * time.Millisecond

// decoyServerStand starts a server whose WS listener mirrors a small site,
// and returns the WS address and that site.
func decoyServerStand(t *testing.T) (string, *httptest.Server) {
	t.Helper()

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = io.WriteString(w, "<html><body>a perfectly ordinary site</body></html>")
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "not found\n")
	}))
	t.Cleanup(site.Close)

	dir := t.TempDir()
	certFile, keyFile, err := testcert.Generate(dir)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := NewServer(Config{
		Port:             "0",
		ListenIP:         "127.0.0.1",
		RequireAuth:      false,
		ReadTimeout:      30 * time.Second,
		WriteTimeout:     30 * time.Second,
		HandshakeTimeout: decoyHandshakeBudget,
		ObfsEnabled:      true,
		ObfsPSK:          testPSK,
		ObfsMaxPadding:   256,
		ObfsMTU:          1400,
		ObfsReplayWindow: obfs.DefaultSaltHistory,
		WSEnabled:        true,
		WSAddr:           "127.0.0.1:0",
		WSCertFile:       certFile,
		WSKeyFile:        keyFile,
		WSPath:           "/ws",
		WSDecoyUpstream:  site.URL,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		srv.Stop()
	})
	go func() {
		if err := srv.Start(ctx); err != nil && ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("server error: %v", err)
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if addr := srv.WSAddr(); addr != "" {
			return addr, site
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the WS listener never became ready")
	return "", nil
}

func TestTheMirroredSiteAnswersForTheTunnelsPath(t *testing.T) {
	wsAddr, site := decoyServerStand(t)

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // self-signed test certificate
		Timeout:   5 * time.Second,
	}
	get := func(url string) (int, string) {
		t.Helper()
		resp, err := client.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read %s: %v", url, err)
		}
		return resp.StatusCode, string(body)
	}

	rootStatus, rootBody := get("https://" + wsAddr + "/")
	_, siteBody := get(site.URL + "/")
	if rootStatus != http.StatusOK || rootBody != siteBody {
		t.Errorf("the front page is %d %q, the mirrored site's own is %q", rootStatus, rootBody, siteBody)
	}

	tunnelStatus, tunnelBody := get("https://" + wsAddr + "/ws")
	unknownStatus, unknownBody := get("https://" + wsAddr + "/nothing-here")
	if tunnelStatus != unknownStatus || tunnelBody != unknownBody {
		t.Errorf("the tunnel path answers %d %q, an unknown path answers %d %q",
			tunnelStatus, tunnelBody, unknownStatus, unknownBody)
	}
}

// wsProbe opens a WebSocket to the tunnel's path, sends payload inside it,
// and measures how long the server takes to close and how much it says
// first. The upgrade itself is genuine: a probe that recorded a client has
// the path and the headers, and this is what it would do with them.
func wsProbe(t *testing.T, wsAddr string, payload []byte) probeResult {
	t.Helper()

	conn, err := ws.Dial(ws.DialOpts{
		URL:       "wss://" + wsAddr + "/ws",
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed test certificate
	})
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("probe write: %v", err)
	}

	answered := 0
	buf := make([]byte, 512)
	for {
		n, err := conn.Read(buf)
		answered += n
		if err != nil {
			var netErr net.Error
			timedOut := errors.As(err, &netErr) && netErr.Timeout()
			return probeResult{elapsed: time.Since(start), answered: answered, timedOut: timedOut}
		}
	}
}

// recordWSFirstFlight makes one genuine tunnelled connection over WebSocket
// and returns the first bytes its obfuscation layer put inside the tunnel.
func recordWSFirstFlight(t *testing.T, wsAddr, echoAddr string) []byte {
	t.Helper()

	conn, err := ws.Dial(ws.DialOpts{
		URL:       "wss://" + wsAddr + "/ws",
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed test certificate
	})
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	recorder := &recordingConn{Conn: conn}
	tunnel, err := obfs.NewClientConn(recorder, obfs.Config{
		PSK:        []byte(testPSK),
		MaxPadding: 256,
		MTU:        1400,
	})
	if err != nil {
		t.Fatalf("obfs wrap: %v", err)
	}
	defer func() { _ = tunnel.Close() }()
	_ = tunnel.SetDeadline(time.Now().Add(5 * time.Second))

	if err := socks5ConnectNoAuth(tunnel, echoAddr); err != nil {
		t.Fatalf("the recording connection did not establish: %v", err)
	}
	if _, err := tunnel.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	back := make([]byte, 5)
	if _, err := io.ReadFull(tunnel, back); err != nil {
		t.Fatalf("read: %v", err)
	}
	return recorder.firstWrite(t)
}

func TestInsideTheTunnelAReplayIsAnsweredLikeGarbage(t *testing.T) {
	wsAddr, _ := decoyServerStand(t)
	echoAddr := startEchoServer(t)

	flight := recordWSFirstFlight(t, wsAddr, echoAddr)
	if len(flight) < 40 {
		t.Fatalf("the recorded flight is %d bytes, too short to be a prologue and a frame", len(flight))
	}

	// The control is the same flight with random bytes of the same length:
	// same frame boundary, same volume, different ciphertext.
	garbage := make([]byte, len(flight))
	if _, err := rand.Read(garbage); err != nil {
		t.Fatal(err)
	}

	const rounds = 7
	replayTimes := make([]time.Duration, 0, rounds)
	garbageTimes := make([]time.Duration, 0, rounds)
	for i := range rounds {
		r := wsProbe(t, wsAddr, flight)
		g := wsProbe(t, wsAddr, garbage)
		if r.answered != 0 || g.answered != 0 {
			t.Fatalf("round %d: the server answered %d bytes to the replay and %d to the garbage; want silence from both",
				i, r.answered, g.answered)
		}
		if r.timedOut {
			t.Fatalf("round %d: the server never closed the replayed connection", i)
		}
		if g.timedOut {
			t.Fatalf("round %d: the server never closed the garbage connection", i)
		}
		// Neither may be closed early: the whole point is that the budget
		// closes them, not the code that refused them.
		if r.elapsed < decoyHandshakeBudget/2 || g.elapsed < decoyHandshakeBudget/2 {
			t.Fatalf("round %d: closed after %v (replay) and %v (garbage), well inside the %v budget - the server answered the probe by hanging up",
				i, r.elapsed, g.elapsed, decoyHandshakeBudget)
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
