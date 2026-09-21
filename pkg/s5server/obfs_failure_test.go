package s5server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/obfs"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// captureConn is a net.Conn whose writes land in a buffer, so that a real
// obfs frame can be recorded and replayed byte for byte.
type captureConn struct {
	buf bytes.Buffer
}

func (c *captureConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Write(p []byte) (int, error)      { return c.buf.Write(p) }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *captureConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "test" }
func (dummyAddr) String() string  { return "test" }

// wireFrame returns the exact bytes a client with the given PSK puts on the
// wire for one payload.
func wireFrame(t *testing.T, psk, payload string) []byte {
	t.Helper()
	cc := &captureConn{}
	c, err := obfs.NewClientConn(cc, obfs.Config{PSK: []byte(psk), MTU: obfs.DefaultMTU})
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return bytes.Clone(cc.buf.Bytes())
}

// feed pushes raw bytes at a server-side obfs connection and drains it until
// it errors out, which is exactly what the accept loop does in production.
// The history is shared with the caller so that a replay can be staged across
// two connections - the only place a replay can happen.
func feed(t *testing.T, onFailure obfs.FailureObserver, history *obfs.SaltHistory, raw []byte) {
	t.Helper()
	clientEnd, serverEnd := net.Pipe()

	srv, err := obfs.NewServerConn(serverEnd, obfs.Config{
		PSK:       []byte(testPSK),
		MTU:       obfs.DefaultMTU,
		History:   history,
		OnFailure: onFailure,
	})
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if len(raw) > 0 {
			_, _ = clientEnd.Write(raw)
		}
		_ = clientEnd.Close()
	}()

	buf := make([]byte, 4096)
	for {
		if _, err := srv.Read(buf); err != nil {
			break
		}
	}
	_ = srv.Close()
	<-done
}

// prime delivers a flight once so that its salt enters the history, and
// reports nothing: it is the working connection a prober would have recorded,
// not one of the failures under test.
func prime(t *testing.T, history *obfs.SaltHistory, flight []byte) {
	t.Helper()
	clientEnd, serverEnd := net.Pipe()

	srv, err := obfs.NewServerConn(serverEnd, obfs.Config{
		PSK:     []byte(testPSK),
		MTU:     obfs.DefaultMTU,
		History: history,
	})
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = clientEnd.Write(flight)
	}()

	if _, err := srv.Read(make([]byte, 4096)); err != nil {
		t.Fatalf("the connection being recorded was not a working one: %v", err)
	}
	_ = srv.Close()
	_ = clientEnd.Close()
	<-done
}

// TestObfsFailuresAreDistinguishable is the acceptance check for plan task
// Ф1-2: the events that used to look identical in the logs must be tellable
// apart from the metrics alone, and the labels must not carry the source
// address.
//
// Two cases that used to be here are gone with the frame header. "oversize"
// cannot happen any more - the length is two masked bytes, so it can never
// exceed 65535. A client with a typo in its PSK cannot be recognised either:
// it derives a different length mask, so it does not produce a frame boundary
// the server can find, and it ends up in the same bucket as a scanner. That is
// a property worth having, not a gap - the port answers a wrong key exactly as
// it answers a probe. "short_frame" needs a length forged under the derived
// key, which only a test inside pkg/obfs can do; it is pinned there.
func TestObfsFailuresAreDistinguishable(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	telemetry, err := InitTelemetry(provider)
	if err != nil {
		t.Fatalf("InitTelemetry: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	observe := obfsFailureObserver(telemetry, logger, "obfs")

	history := obfs.NewSaltHistory(obfs.DefaultSaltHistory)
	valid := wireFrame(t, testPSK, "hello")

	// 1. Записанное соединение, переигранное на новом сокете.
	prime(t, history, valid)
	feed(t, observe, history, valid)

	// 2. Подмена байта в шифротексте: кадр найден, но подпись не сходится.
	tampered := bytes.Clone(valid)
	tampered[len(tampered)-1] ^= 0x01
	feed(t, observe, obfs.NewSaltHistory(16), tampered)

	// 3. Обычный обрыв: соединение закрыто, не начав кадр.
	feed(t, observe, nil, nil)

	// 4. Зондирование открытым текстом: длина кадра разбирается в мусор, и
	//    кадр не приходит до конца потока.
	probe := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	feed(t, observe, nil, probe)

	counts, buckets := collectObfsFailures(t, reader)

	want := map[string]int64{
		string(obfs.ReasonReplay):         1,
		string(obfs.ReasonDecryptFail):    1,
		string(obfs.ReasonEOFBeforeFrame): 2,
	}
	for reason, n := range want {
		if counts[reason] != n {
			t.Errorf("reason %q: got %d events, want %d (all counts: %v)", reason, counts[reason], n, counts)
		}
	}
	if len(counts) != len(want) {
		t.Errorf("unexpected reasons reported: %v", counts)
	}

	// Объем до отказа разделяет обрыв на нулевом байте и пира, успевшего
	// прислать данные: обе записи eof_before_frame складываются в длину
	// зонда, потому что чистое закрытие принесло ноль.
	if got, want := buckets[string(obfs.ReasonEOFBeforeFrame)], int64(len(probe)); got != want {
		t.Errorf("bytes before an end of stream: got %d, want %d (a clean close contributes 0, the probe its length)", got, want)
	}
	if got, want := buckets[string(obfs.ReasonReplay)], int64(len(valid)); got != want {
		t.Errorf("replay should report the whole flight (%d bytes), got %d", want, got)
	}
	if got, want := buckets[string(obfs.ReasonDecryptFail)], int64(len(tampered)); got != want {
		t.Errorf("a tampered frame should report the bytes it sent (%d), got %d", want, got)
	}
}

// collectObfsFailures reads the counter and the histogram back out of the SDK
// and fails the test if any label could identify a peer.
func collectObfsFailures(t *testing.T, reader sdkmetric.Reader) (counts map[string]int64, bytesBefore map[string]int64) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	counts = make(map[string]int64)
	bytesBefore = make(map[string]int64)
	seenCounter, seenHistogram := false, false

	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch m.Name {
			case "s5core_obfs_handshake_failures_total":
				seenCounter = true
				sum, ok := m.Data.(metricdata.Sum[int64])
				if !ok {
					t.Fatalf("%s: unexpected data type %T", m.Name, m.Data)
				}
				for _, dp := range sum.DataPoints {
					counts[requireCleanLabels(t, m.Name, dp.Attributes)] += dp.Value
				}
			case "s5core_obfs_bytes_before_failure":
				seenHistogram = true
				hist, ok := m.Data.(metricdata.Histogram[int64])
				if !ok {
					t.Fatalf("%s: unexpected data type %T", m.Name, m.Data)
				}
				for _, dp := range hist.DataPoints {
					bytesBefore[requireCleanLabels(t, m.Name, dp.Attributes)] += dp.Sum
				}
			}
		}
	}

	if !seenCounter {
		t.Fatal("s5core_obfs_handshake_failures_total was never exported")
	}
	if !seenHistogram {
		t.Fatal("s5core_obfs_bytes_before_failure was never exported")
	}
	return counts, bytesBefore
}

// requireCleanLabels asserts the policy from docs/design/observability-policy.md:
// reason and transport only, both from a closed set. It returns the reason.
func requireCleanLabels(t *testing.T, metricName string, set attribute.Set) string {
	t.Helper()
	var reason string
	iter := set.Iter()
	n := 0
	for iter.Next() {
		kv := iter.Attribute()
		n++
		key, value := string(kv.Key), kv.Value.Emit()
		switch key {
		case "reason":
			reason = value
		case "transport":
			if value != "obfs" && value != "ws" {
				t.Errorf("%s: unexpected transport label %q", metricName, value)
			}
		default:
			t.Errorf("%s: label %q=%q is not allowed - only reason and transport are", metricName, key, value)
		}
		if strings.ContainsAny(value, ":/") || net.ParseIP(value) != nil {
			t.Errorf("%s: label %q=%q looks like an address", metricName, key, value)
		}
	}
	if n != 2 {
		t.Errorf("%s: expected exactly 2 labels, got %d", metricName, n)
	}
	if reason == "" {
		t.Errorf("%s: missing reason label", metricName)
	}
	return reason
}

// TestFrameErrorCarriesReason checks that callers can classify a failure from
// the error alone, without the observer.
func TestFrameErrorCarriesReason(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	srv, err := obfs.NewServerConn(serverEnd, obfs.Config{PSK: []byte(testPSK), MTU: obfs.DefaultMTU})
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	tampered := wireFrame(t, testPSK, "hello")
	tampered[len(tampered)-1] ^= 0x01
	go func() {
		_, _ = clientEnd.Write(tampered)
		_ = clientEnd.Close()
	}()

	_, err = srv.Read(make([]byte, 1024))
	if err == nil {
		t.Fatal("expected a decryption failure")
	}
	reason, ok := obfs.ReasonOf(err)
	if !ok || reason != obfs.ReasonDecryptFail {
		t.Fatalf("ReasonOf(%v) = %q, %v; want %q, true", err, reason, ok, obfs.ReasonDecryptFail)
	}
	_ = srv.Close()
}

// TestCleanEOFStaysEOF guards the relay: io.Copy compares with == against
// io.EOF, so a wrapped end-of-stream would surface as a transfer error.
func TestCleanEOFStaysEOF(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	var seen []obfs.FailureReason
	srv, err := obfs.NewServerConn(serverEnd, obfs.Config{
		PSK: []byte(testPSK), MTU: obfs.DefaultMTU,
		OnFailure: func(fe *obfs.FrameError) { seen = append(seen, fe.Reason) },
	})
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	go func() { _ = clientEnd.Close() }()

	n, err := io.Copy(io.Discard, srv)
	if err != nil {
		t.Fatalf("io.Copy over a cleanly closed connection returned %v, want nil", err)
	}
	if n != 0 {
		t.Fatalf("io.Copy copied %d bytes, want 0", n)
	}
	if _, err := srv.Read(make([]byte, 16)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read after EOF = %v, want io.EOF", err)
	}
	if len(seen) != 1 || seen[0] != obfs.ReasonEOFBeforeFrame {
		t.Fatalf("observer saw %v, want exactly [%s]", seen, obfs.ReasonEOFBeforeFrame)
	}
	_ = srv.Close()
}
