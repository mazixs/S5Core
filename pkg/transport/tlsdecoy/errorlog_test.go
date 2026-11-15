package tlsdecoy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"maps"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/testcert"
)

// capture is a slog.Handler that keeps every record and wakes a waiter, so a
// test can wait for a record that arrives from another goroutine.
type capture struct {
	mu      sync.Mutex
	records []slog.Record
	arrived chan struct{}
}

func newCapture() *capture { return &capture{arrived: make(chan struct{}, 1)} }

func (c *capture) Enabled(context.Context, slog.Level) bool { return true }

func (c *capture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	c.records = append(c.records, r.Clone())
	c.mu.Unlock()
	select {
	case c.arrived <- struct{}{}:
	default:
	}
	return nil
}

func (c *capture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capture) WithGroup(string) slog.Handler      { return c }

func (c *capture) snapshot() []slog.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]slog.Record(nil), c.records...)
}

func (c *capture) waitFor(t *testing.T, match func(slog.Record) bool) slog.Record {
	t.Helper()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		for _, r := range c.snapshot() {
			if match(r) {
				return r
			}
		}
		select {
		case <-c.arrived:
		case <-timeout.C:
			t.Fatal("the expected record did not reach the Logger")
		}
	}
}

func attrsOf(r slog.Record) map[string]string {
	attrs := map[string]string{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	return attrs
}

// recordText is everything a handler could print for the record.
func recordText(r slog.Record) string {
	var b strings.Builder
	b.WriteString(r.Message)
	for k, v := range attrsOf(r) {
		b.WriteString(" " + k + "=" + v)
	}
	return b.String()
}

func TestServerErrorWriter(t *testing.T) {
	const stack = "goroutine 7 [running]:\nnet/http.(*conn).serve.func1()\n\t/go/src/net/http/server.go:1\n"
	tests := []struct {
		name  string
		line  string
		level slog.Level
		msg   string
		attrs map[string]string
		// absent are the addresses the record must not mention.
		absent []string
	}{
		{
			name:   "ipv4 remote alert",
			line:   "http: TLS handshake error from 192.0.2.1:4000: remote error: tls: bad certificate\n",
			level:  slog.LevelDebug,
			msg:    "TLS handshake failed",
			attrs:  map[string]string{"reason": "remote error: tls: bad certificate"},
			absent: []string{"192.0.2.1", "4000"},
		},
		{
			name:   "ipv6 remote alert",
			line:   "http: TLS handshake error from [2001:db8::1]:4000: remote error: tls: bad certificate\n",
			level:  slog.LevelDebug,
			msg:    "TLS handshake failed",
			attrs:  map[string]string{"reason": "remote error: tls: bad certificate"},
			absent: []string{"2001:db8", "4000"},
		},
		{
			name:   "ipv6 with a zone",
			line:   "http: TLS handshake error from [fe80::1%eth0]:4000: EOF\n",
			level:  slog.LevelDebug,
			msg:    "TLS handshake failed",
			attrs:  map[string]string{"reason": "EOF"},
			absent: []string{"fe80", "eth0", "4000"},
		},
		{
			name:   "local tls error",
			line:   "http: TLS handshake error from 192.0.2.1:4000: tls: first record does not look like a TLS handshake\n",
			level:  slog.LevelDebug,
			msg:    "TLS handshake failed",
			attrs:  map[string]string{"reason": "tls: first record does not look like a TLS handshake"},
			absent: []string{"192.0.2.1", "4000"},
		},
		{
			name:   "eof",
			line:   "http: TLS handshake error from 192.0.2.1:4000: EOF\n",
			level:  slog.LevelDebug,
			msg:    "TLS handshake failed",
			attrs:  map[string]string{"reason": "EOF"},
			absent: []string{"192.0.2.1", "4000"},
		},
		{
			name:   "read timeout",
			line:   "http: TLS handshake error from 192.0.2.1:4000: read tcp 192.0.2.10:443->192.0.2.1:4000: i/o timeout\n",
			level:  slog.LevelDebug,
			msg:    "TLS handshake failed",
			attrs:  map[string]string{"reason": "read: i/o timeout"},
			absent: []string{"192.0.2.1", "192.0.2.10", "4000", "443", "tcp"},
		},
		{
			name:   "read reset on ipv6",
			line:   "http: TLS handshake error from [2001:db8::1]:4000: read tcp [2001:db8::10]:443->[2001:db8::1]:4000: read: connection reset by peer\n",
			level:  slog.LevelDebug,
			msg:    "TLS handshake failed",
			attrs:  map[string]string{"reason": "read: connection reset by peer"},
			absent: []string{"2001:db8", "4000", "443", "tcp"},
		},
		{
			name:   "write error",
			line:   "http: TLS handshake error from 192.0.2.1:4000: write tcp 192.0.2.10:443->192.0.2.1:4000: write: broken pipe\n",
			level:  slog.LevelDebug,
			msg:    "TLS handshake failed",
			attrs:  map[string]string{"reason": "write: broken pipe"},
			absent: []string{"192.0.2.1", "192.0.2.10", "4000", "443", "tcp"},
		},
		{
			name:   "cause of an unknown shape is dropped",
			line:   "http: TLS handshake error from 192.0.2.1:4000: dial 192.0.2.99:80: refused\n",
			level:  slog.LevelDebug,
			msg:    "TLS handshake failed",
			attrs:  map[string]string{},
			absent: []string{"192.0.2", "4000", "refused"},
		},
		{
			name:   "line that does not fit the shape",
			line:   "http: TLS handshake error\n",
			level:  slog.LevelDebug,
			msg:    "TLS handshake failed",
			attrs:  map[string]string{},
			absent: []string{"http:"},
		},
		{
			name:   "address without its colon",
			line:   "http: TLS handshake error from 192.0.2.1:4000 EOF\n",
			level:  slog.LevelDebug,
			msg:    "TLS handshake failed",
			attrs:  map[string]string{},
			absent: []string{"192.0.2.1", "4000"},
		},
		{
			name:   "panic with a stack",
			line:   "http: panic serving 192.0.2.1:4000: boom\n" + stack,
			level:  slog.LevelWarn,
			msg:    "http: panic serving: boom\n" + strings.TrimSuffix(stack, "\n"),
			attrs:  map[string]string{},
			absent: []string{"192.0.2.1", "4000"},
		},
		{
			name:   "panic on ipv6",
			line:   "http: panic serving [2001:db8::1]:4000: runtime error: index out of range\n" + stack,
			level:  slog.LevelWarn,
			msg:    "http: panic serving: runtime error: index out of range\n" + strings.TrimSuffix(stack, "\n"),
			attrs:  map[string]string{},
			absent: []string{"2001:db8", "4000"},
		},
		{
			name:   "panic line that does not fit the shape",
			line:   "http: panic serving 192.0.2.1:4000\n",
			level:  slog.LevelWarn,
			msg:    "http: panic serving",
			attrs:  map[string]string{},
			absent: []string{"192.0.2.1", "4000"},
		},
		{
			name:  "accept error",
			line:  "http: Accept error: too many open files; retrying in 5ms\n",
			level: slog.LevelWarn,
			msg:   "http: Accept error: too many open files; retrying in 5ms",
			attrs: map[string]string{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := newCapture()
			n, err := serverErrorWriter{slog.New(rec)}.Write([]byte(tc.line))
			if err != nil || n != len(tc.line) {
				t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(tc.line))
			}

			got := rec.snapshot()
			if len(got) != 1 {
				t.Fatalf("records = %d, want 1", len(got))
			}
			r := got[0]
			if r.Level != tc.level {
				t.Errorf("level = %v, want %v", r.Level, tc.level)
			}
			if r.Message != tc.msg {
				t.Errorf("message = %q, want %q", r.Message, tc.msg)
			}
			if attrs := attrsOf(r); !maps.Equal(attrs, tc.attrs) {
				t.Errorf("attrs = %v, want %v", attrs, tc.attrs)
			}
			for _, a := range tc.absent {
				if strings.Contains(recordText(r), a) {
					t.Errorf("record %q mentions %q", recordText(r), a)
				}
			}
		})
	}
}

// A nil Logger means slog.Default, as it does for the decoy proxy. The default
// handler drops DEBUG, so this only has to not panic.
func TestServerErrorLog_NilLogger(t *testing.T) {
	newServerErrorLog(nil).Print("http: TLS handshake error from 192.0.2.1:4000: EOF")
}

// A client that does not trust the certificate abandons the handshake. The
// server's line about it must reach Config.Logger at DEBUG, without the
// address of the client, and nothing may reach INFO or above.
func TestListener_RejectedCertificateLogsAtDebug(t *testing.T) {
	certFile, keyFile, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	rec := newCapture()
	l, err := NewListener(Config{
		Addr:     "127.0.0.1:0",
		CertFile: certFile,
		KeyFile:  keyFile,
		WSPath:   "/ws",
		Logger:   slog.New(rec),
	})
	if err != nil {
		t.Fatalf("new listener: %v", err)
	}
	defer l.Close()

	raw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	_, clientPort, err := net.SplitHostPort(raw.LocalAddr().String())
	if err != nil {
		t.Fatalf("client address: %v", err)
	}

	// An empty pool trusts nothing, whatever roots the machine has.
	err = tls.Client(raw, &tls.Config{
		RootCAs:    x509.NewCertPool(),
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS13,
	}).Handshake()
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("client error = %v, want an unknown authority", err)
	}

	r := rec.waitFor(t, func(r slog.Record) bool { return strings.Contains(r.Message, "TLS handshake") })
	if r.Level != slog.LevelDebug {
		t.Errorf("handshake error logged at %v, want DEBUG", r.Level)
	}
	if r.Message != "TLS handshake failed" {
		t.Errorf("message = %q, want a fixed one", r.Message)
	}
	// Both ends are on loopback, so the host and the client's port cover
	// the client's address and the local one.
	for _, addr := range []string{"127.0.0.1", ":" + clientPort} {
		if strings.Contains(recordText(r), addr) {
			t.Errorf("record %q mentions %q", recordText(r), addr)
		}
	}
	for _, r := range rec.snapshot() {
		if r.Level >= slog.LevelInfo {
			t.Errorf("record at %v: %q", r.Level, r.Message)
		}
	}
}
