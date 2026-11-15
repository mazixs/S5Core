package tlsdecoy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
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
	c.records = append(c.records, r)
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

func (c *capture) waitFor(t *testing.T, prefix string) slog.Record {
	t.Helper()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		for _, r := range c.snapshot() {
			if strings.HasPrefix(r.Message, prefix) {
				return r
			}
		}
		select {
		case <-c.arrived:
		case <-timeout.C:
			t.Fatalf("no record starting with %q reached the Logger", prefix)
		}
	}
}

func TestServerErrorWriter_Classification(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		level slog.Level
		msg   string
	}{
		{
			name:  "handshake error",
			line:  "http: TLS handshake error from 192.0.2.1:4000: remote error: tls: bad certificate\n",
			level: slog.LevelDebug,
			msg:   "http: TLS handshake error from 192.0.2.1:4000: remote error: tls: bad certificate",
		},
		{
			name:  "handler panic",
			line:  "http: panic serving 192.0.2.1:4000: boom\n",
			level: slog.LevelWarn,
			msg:   "http: panic serving 192.0.2.1:4000: boom",
		},
		{
			name:  "accept error",
			line:  "http: Accept error: too many open files; retrying in 5ms\n",
			level: slog.LevelWarn,
			msg:   "http: Accept error: too many open files; retrying in 5ms",
		},
		{
			name:  "multi-line message keeps inner breaks",
			line:  "http: panic serving 192.0.2.1:4000: boom\ngoroutine 1 [running]:\n",
			level: slog.LevelWarn,
			msg:   "http: panic serving 192.0.2.1:4000: boom\ngoroutine 1 [running]:",
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
			if got[0].Level != tc.level {
				t.Errorf("level = %v, want %v", got[0].Level, tc.level)
			}
			if got[0].Message != tc.msg {
				t.Errorf("message = %q, want %q", got[0].Message, tc.msg)
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
// server's line about it must reach Config.Logger at DEBUG and nothing may
// reach INFO or above.
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

	// An empty pool trusts nothing, whatever roots the machine has.
	conn, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{
		RootCAs:    x509.NewCertPool(),
		MinVersion: tls.VersionTLS13,
	})
	if err == nil {
		conn.Close()
		t.Fatal("handshake succeeded, want the client to reject the certificate")
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("client error = %v, want an unknown authority", err)
	}

	r := rec.waitFor(t, tlsHandshakeErrorPrefix)
	if r.Level != slog.LevelDebug {
		t.Errorf("handshake error logged at %v, want DEBUG", r.Level)
	}
	for _, r := range rec.snapshot() {
		if r.Level >= slog.LevelInfo {
			t.Errorf("record at %v: %q", r.Level, r.Message)
		}
	}
}
