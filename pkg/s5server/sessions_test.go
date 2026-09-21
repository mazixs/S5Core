package s5server

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/mazixs/S5Core/internal/session"
)

// The connection state machine of plan task Ф6-1 exists to be looked at, and
// these tests are about the looking: what the metrics say, and whether it
// matches what the connections are actually doing.

// sessionCounts reads the s5core_sessions gauge into "region/state" keys. The
// gauge is observable, so Collect is what runs the registry snapshot.
func sessionCounts(t *testing.T, reader sdkmetric.Reader) map[string]int64 {
	t.Helper()
	counts := map[string]int64{}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "s5core_sessions" {
				continue
			}
			g, ok := m.Data.(metricdata.Gauge[int64])
			if !ok {
				t.Fatalf("%s: unexpected data type %T", m.Name, m.Data)
			}
			for _, dp := range g.DataPoints {
				region, _ := dp.Attributes.Value("region")
				state, _ := dp.Attributes.Value("state")
				transport, _ := dp.Attributes.Value("transport")
				// Three labels, all from closed sets in the code. A fourth
				// would mean something the traffic chooses got in; see
				// docs/design/observability-policy.md.
				if dp.Attributes.Len() != 3 {
					t.Errorf("%s: want exactly 3 labels, got %d", m.Name, dp.Attributes.Len())
				}
				if transport.Emit() == "" {
					t.Errorf("%s: a data point has no transport", m.Name)
				}
				counts[region.Emit()+"/"+state.Emit()] += dp.Value
			}
		}
	}
	return counts
}

// sessionTransitions reads s5core_session_transitions_total into
// "region/from->to" keys, prefixing an illegal move with "illegal/".
func sessionTransitions(t *testing.T, reader sdkmetric.Reader) map[string]int64 {
	t.Helper()
	moves := map[string]int64{}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "s5core_session_transitions_total" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s: unexpected data type %T", m.Name, m.Data)
			}
			for _, dp := range sum.DataPoints {
				region, _ := dp.Attributes.Value("region")
				from, _ := dp.Attributes.Value("from")
				to, _ := dp.Attributes.Value("to")
				illegal, _ := dp.Attributes.Value("illegal")
				if dp.Attributes.Len() != 5 {
					t.Errorf("%s: want exactly 5 labels, got %d", m.Name, dp.Attributes.Len())
				}
				key := region.Emit() + "/" + from.Emit() + "->" + to.Emit()
				if illegal.AsBool() {
					key = "illegal/" + key
				}
				moves[key] += dp.Value
			}
		}
	}
	return moves
}

// waitForSessionState polls the gauge until one cell reaches n, and fails
// with the whole picture when it does not. Polling beats a fixed sleep here:
// the assertion is about a state connections reach on their own schedule,
// not about how long they take to reach it.
func waitForSessionState(t *testing.T, reader sdkmetric.Reader, key string, n int64) map[string]int64 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var counts map[string]int64
	for time.Now().Before(deadline) {
		counts = sessionCounts(t, reader)
		if counts[key] == n {
			return counts
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s never reached %d; the gauge says %v", key, n, counts)
	return nil
}

// greetAndRequest performs the no-auth greeting and sends a CONNECT without
// waiting for the reply. That is exactly the client of bug 1: it has asked,
// and the server has not answered.
func greetAndRequest(t *testing.T, conn net.Conn, host string, port int) {
	t.Helper()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("connect request: %v", err)
	}
}

// This is the gate of plan task Ф6-1 and the reason the state machine was
// made explicit at all. Bug 1 of the bug report is a share of connections
// parked waiting for the reply to CONNECT while the relay looks healthy.
// That used to be invisible: connections_active counted every session the
// same, so a server with an unreachable destination and a busy server
// produced the same number.
//
// Here one destination never answers and another echoes. The gauge has to
// separate the two populations by itself: the stalled ones in the protocol
// region's dialing state, the working ones in relay.
func TestSessionsByStateShowTheBugReport(t *testing.T) {
	const (
		stalled = 3
		working = 2
	)

	echoAddr := startEchoServer(t)

	// The destination answers for the working connections and never answers
	// for the stalled ones, told apart by the port they ask for.
	release := make(chan struct{})
	var releaseOnce func()
	releaseOnce = func() { close(release); releaseOnce = func() {} }
	t.Cleanup(func() { releaseOnce() })
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if _, port, _ := net.SplitHostPort(addr); port == "9" {
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil, errors.New("this destination never answers")
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	reader := sdkmetric.NewManualReader()
	telemetry, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatalf("InitTelemetry: %v", err)
	}

	const port = "19085"
	startServer(t, Config{
		Port:        port,
		ListenIP:    "127.0.0.1",
		RequireAuth: false,
		// Long enough that nothing expires while the gauge is read: the
		// stalled connections have to still be stalled when it is, rather
		// than cut by a budget of their own.
		ReadTimeout:      30 * time.Second,
		WriteTimeout:     30 * time.Second,
		HandshakeTimeout: 30 * time.Second,
		DialTimeout:      30 * time.Second,
		Dial:             dial,
		Telemetry:        telemetry,
	})
	proxyAddr := net.JoinHostPort("127.0.0.1", port)

	for i := range working {
		conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("working dial %d: %v", i, err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if err := socks5ConnectNoAuth(conn, echoAddr); err != nil {
			t.Fatalf("working connect %d: %v", i, err)
		}
	}

	for i := range stalled {
		conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("stalled dial %d: %v", i, err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		greetAndRequest(t, conn, "127.0.0.1", 9)
	}

	counts := waitForSessionState(t, reader, "protocol/dialing", stalled)

	if got := counts["protocol/relay"]; got != working {
		t.Errorf("the gauge says %d sessions are relaying, want %d; full picture %v",
			got, working, counts)
	}
	// Nothing is metered here, so every account region is clean - which is
	// what makes the pile a destination problem and not an account problem.
	if got := counts["account/within_quota"]; got != stalled+working {
		t.Errorf("account region says %d sessions are within quota, want %d; full picture %v",
			got, stalled+working, counts)
	}
	// The plain listener has no frames, so that region must not be reported
	// for it at all: an absent region is not a region at rest.
	for key, n := range counts {
		if strings.HasPrefix(key, "frames/") && n != 0 {
			t.Errorf("the plain listener reported a frames region: %s=%d", key, n)
		}
	}

	// Letting the dial go has to drain the pile, otherwise the gauge is
	// reporting a state sessions never leave rather than one they sit in.
	releaseOnce()
	waitForSessionState(t, reader, "protocol/dialing", 0)
}

// The transitions counter is the other half of the picture: the gauge says
// where connections are, the counter says how they got there.
func TestSessionTransitionsAreCountedWithClosedLabels(t *testing.T) {
	echoAddr := startEchoServer(t)

	reader := sdkmetric.NewManualReader()
	telemetry, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatalf("InitTelemetry: %v", err)
	}

	const port = "19086"
	startServer(t, Config{
		Port:             port,
		ListenIP:         "127.0.0.1",
		RequireAuth:      false,
		ReadTimeout:      5 * time.Second,
		WriteTimeout:     5 * time.Second,
		HandshakeTimeout: 5 * time.Second,
		Telemetry:        telemetry,
	})

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := socks5ConnectNoAuth(conn, echoAddr); err != nil {
		t.Fatalf("connect: %v", err)
	}
	// Close the client so the session reaches its terminal state, putting the
	// whole path from accept to close on the counter.
	_ = conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	var moves map[string]int64
	for time.Now().Before(deadline) {
		moves = sessionTransitions(t, reader)
		if moves["protocol/relay->closed"]+moves["protocol/half_closed->closed"] > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The path a plain CONNECT takes. Each of these is one edge of the
	// protocol region's table, and each is worth an alert of its own one day.
	for _, want := range []string{
		"protocol/accepted->handshake",
		"protocol/handshake->dialing",
		"protocol/dialing->relay",
	} {
		if moves[want] == 0 {
			t.Errorf("no %s transition was counted; counter says %v", want, moves)
		}
	}
	if moves["protocol/relay->closed"]+moves["protocol/half_closed->closed"] == 0 {
		t.Errorf("the session never reached closed; counter says %v", moves)
	}

	// An illegal transition is a bug in whatever drove the session. None can
	// happen on the ordinary path, and this label is how the day one does
	// gets noticed.
	for key, n := range moves {
		if strings.HasPrefix(key, "illegal/") && n != 0 {
			t.Errorf("an illegal transition was made on the ordinary path: %s=%d", key, n)
		}
	}
}

// The states have to keep the names the metric publishes, because an
// operator's dashboards and alerts are written against those strings: a
// rename that looks harmless in Go is a silently broken alert in the field.
// This also pins which regions exist per transport.
func TestTheSessionLabelVocabularyIsStable(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	telemetry, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatalf("InitTelemetry: %v", err)
	}

	reg := session.NewRegistry(sessionTransitionObserver(telemetry))
	registration, err := registerSessionGauge(telemetry, reg)
	if err != nil {
		t.Fatalf("registerSessionGauge: %v", err)
	}
	t.Cleanup(func() { _ = registration.Unregister() })

	// One session per transport, opened straight on the registry: this is
	// about the names, not about how a connection reaches a state.
	// A grace window, because without one the account region ends the session
	// where the quota is noticed instead of draining it - a choice, not an
	// omission, and the half-closed path is what this test is about.
	plain := reg.Open(TransportPlain, false, session.SLA{Grace: time.Second})
	reg.Open(TransportObfs, true, session.SLA{})
	reg.Open(TransportWS, true, session.SLA{})

	counts := sessionCounts(t, reader)
	// Freshly opened sessions: protocol accepted, account within quota, and a
	// frames region only where the transport has one.
	if got := counts["protocol/accepted"]; got != 3 {
		t.Errorf("protocol/accepted is %d, want 3; full picture %v", got, counts)
	}
	if got := counts["account/within_quota"]; got != 3 {
		t.Errorf("account/within_quota is %d, want 3; full picture %v", got, counts)
	}
	if got := counts["frames/await_header"]; got != 2 {
		t.Errorf("frames/await_header is %d, want 2 (obfs and ws, not plain); full picture %v",
			got, counts)
	}
	if counts["frames/unframed"] != 0 {
		t.Errorf("the unframed state was published as a cell; it is the absence of a region: %v", counts)
	}

	// Walking one session through the regions publishes the rest of the
	// vocabulary, and closing it takes its cells away entirely.
	plain.Become(session.Stream)
	if !plain.Enter(session.Handshake) || !plain.Enter(session.Dialing) || !plain.Enter(session.Relay) {
		t.Fatalf("the session refused the ordinary path, it is in %s", plain.Protocol())
	}
	plain.Exhaust(session.Grace)
	counts = sessionCounts(t, reader)
	if counts["protocol/half_closed"] != 1 {
		t.Errorf("an account event did not move the protocol region to half_closed: %v", counts)
	}
	if counts["account/grace"] != 1 {
		t.Errorf("account/grace was not published: %v", counts)
	}

	plain.Close()
	counts = sessionCounts(t, reader)
	if counts["protocol/half_closed"] != 0 || counts["account/grace"] != 0 {
		t.Errorf("a closed session is still counted: %v", counts)
	}

	moves := sessionTransitions(t, reader)
	// The one cross-region coupling of the design: an account event is what
	// moved the protocol region. Quota takes effect in flight, not at the
	// next connection.
	if moves["account/within_quota->grace"] == 0 || moves["protocol/relay->half_closed"] == 0 {
		t.Errorf("the account-to-protocol coupling was not counted: %v", moves)
	}
}
