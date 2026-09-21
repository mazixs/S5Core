package s5server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/session"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// countingHandler records how many records of a level were written, which is
// what a rate limit has to be measured in.
type countingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *countingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countingHandler) WithGroup(string) slog.Handler      { return h }

func (h *countingHandler) warnings() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []slog.Record
	for _, r := range h.records {
		if r.Level >= slog.LevelWarn {
			out = append(out, r)
		}
	}
	return out
}

// rejectedFor sums s5core_connections_rejected_total for one reason. The
// reason label is the whole point of the metric here: "the server is full"
// and "this server refuses everything it accepts" are different incidents
// and must not add up into one number.
func rejectedFor(t *testing.T, reader sdkmetric.Reader, transport, reason string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "s5core_connections_rejected_total" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("unexpected data type %T", m.Data)
			}
			for _, dp := range sum.DataPoints {
				gotTransport, _ := dp.Attributes.Value("transport")
				gotReason, _ := dp.Attributes.Value("reason")
				if gotTransport.AsString() == transport && gotReason.AsString() == reason {
					total += dp.Value
				}
			}
		}
	}
	return total
}

// failingWrapPipeline builds a pipeline whose transport wrapper fails for the
// first failures connections and succeeds afterwards, the way a broken
// obfuscation configuration does.
func failingWrapPipeline(t *testing.T, failures int) (*listenerPipeline, *pipeListener, sdkmetric.Reader, *countingHandler) {
	t.Helper()

	reader := sdkmetric.NewManualReader()
	telemetry, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatalf("InitTelemetry: %v", err)
	}

	pl := newPipeListener()
	t.Cleanup(func() { _ = pl.Close() })

	handler := &countingHandler{}
	l := newListenerPipeline(pl, TransportObfs, Config{Logger: slog.New(handler)},
		telemetry, newConnLimiter(0), session.NewRegistry(nil))

	var mu sync.Mutex
	left := failures
	l.wrap = func(c net.Conn, _ *session.Session) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if left > 0 {
			left--
			return nil, errors.New("obfs: cannot derive session keys")
		}
		return c, nil
	}
	return l, pl, reader, handler
}

// A connection that cannot be wrapped is one connection's problem. Accept
// used to return the error, and every caller of Accept - ours included -
// reads an error as the end of the listener, so a single unwrappable
// connection shut the port for everybody. The wrapper is rebuilt per
// connection from configuration SIGHUP can change, so the moment this fires
// is a reload, which is the worst moment to lose a port.
func TestAConnectionThatCannotBeWrappedDoesNotCloseTheListener(t *testing.T) {
	l, pl, reader, _ := failingWrapPipeline(t, 1)

	doomed := pl.dial(t)
	good := pl.dial(t)

	accepted := make(chan net.Conn, 1)
	failed := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			failed <- err
			return
		}
		accepted <- c
	}()

	var served net.Conn
	select {
	case err := <-failed:
		t.Fatalf("one unwrappable connection closed the listener: %v", err)
	case served = <-accepted:
		t.Cleanup(func() { _ = served.Close() })
	case <-time.After(5 * time.Second):
		t.Fatal("Accept never returned the connection that follows the failure")
	}

	// The connection that failed is closed rather than left dangling.
	_ = doomed.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := doomed.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection that could not be wrapped is still open")
	}

	// And the one behind it is the one that came back: a byte written on it
	// arrives at the accepted end.
	go func() {
		_ = good.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = good.Write([]byte("x"))
	}()
	_ = served.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := served.Read(buf); err != nil || buf[0] != 'x' {
		t.Fatalf("the accepted connection is not the one behind the failure: %v", err)
	}

	if got := rejectedFor(t, reader, TransportObfs, rejectSetupFailed); got != 1 {
		t.Errorf("setup_failed counted %d times, want 1", got)
	}
	if got := rejectedFor(t, reader, TransportObfs, rejectAtLimit); got != 0 {
		t.Errorf("a setup failure was counted as the connection limit %d times", got)
	}
}

// The session of a refused connection has to end with it. It is opened at
// accept time - before anything can fail - so a failure that forgets it
// leaves a session in the registry that no connection will ever close, and
// s5core_sessions counts up forever on a server that is doing nothing.
func TestARefusedConnectionClosesItsSession(t *testing.T) {
	l, pl, _, _ := failingWrapPipeline(t, 1)
	registry := l.sessions

	pl.dial(t)
	good := pl.dial(t)
	_ = good

	c, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	// One live session: the connection that was accepted. The refused one is
	// gone.
	if got := registry.Len(); got != 1 {
		t.Fatalf("%d sessions are live, want 1 - the refused connection leaked its session", got)
	}
}

// The cause of a setup failure is the same for every connection behind it, so
// the line is rate limited: counted every time, written once per interval.
// Without that a misconfigured node writes a line per connection and buries
// its own log under whatever is scanning it.
func TestRepeatedSetupFailuresAreCountedButLoggedOnce(t *testing.T) {
	const failures = 5
	l, pl, reader, handler := failingWrapPipeline(t, failures)

	for i := 0; i < failures; i++ {
		pl.dial(t)
	}
	good := pl.dial(t)
	_ = good

	c, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	if got := rejectedFor(t, reader, TransportObfs, rejectSetupFailed); got != failures {
		t.Errorf("setup_failed counted %d times, want %d - the metric is what makes this visible", got, failures)
	}

	warnings := handler.warnings()
	if len(warnings) != 1 {
		t.Fatalf("%d warnings for %d failures, want exactly 1 per interval", len(warnings), failures)
	}
	if !hasAttr(warnings[0], "transport", TransportObfs) {
		t.Errorf("the warning does not say which transport refused: %q", warnings[0].Message)
	}
}

func hasAttr(r slog.Record, key, want string) bool {
	found := false
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key && a.Value.String() == want {
			found = true
			return false
		}
		return true
	})
	return found
}
