package obfs

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/stealth"
)

// A connection that half-closes before it ever writes data still has to open,
// because the peer cannot derive the keys the FIN is sealed with without the
// prologue. That opening is the first packet of the connection, so it is
// subject to the same rule as any other first packet - and it used to be the
// one place that wrote the raw prologue while every other path wrote the
// encoded one (review finding R04).

// halfCloseCorpusSize is smaller than the checklist's: this test is about one
// branch of the write path, not about the distribution of the format, and the
// pad is uniform over 0..20 so a few hundred streams already show the spread.
const halfCloseCorpusSize = 300

// captureHalfCloseWire returns the raw bytes a client puts on the wire when
// the first thing it does is close its write half.
func captureHalfCloseWire(t *testing.T, cfg Config) []byte {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	client, err := NewClientConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	closer, ok := client.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("an obfuscated connection no longer half-closes")
	}

	wireCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 65536)
		n, _ := serverConn.Read(buf) // raw bytes, no obfs wrapper
		wireCh <- append([]byte(nil), buf[:n]...)
	}()

	if err := closer.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	select {
	case wire := <-wireCh:
		return wire
	case <-time.After(2 * time.Second):
		t.Fatal("timeout capturing the wire bytes of a half-close")
		return nil
	}
}

func TestAHalfCloseBeforeTheFirstWriteOpensLikeEverythingElse(t *testing.T) {
	cfg := testConfig()

	corpus := make([][]byte, halfCloseCorpusSize)
	for i := range corpus {
		corpus[i] = captureHalfCloseWire(t, cfg)
	}
	report := stealth.Analyze(corpus, 64)

	// Level 1: the reason the opening is encoded at all. A raw prologue is
	// 32 bytes of high-entropy binary and matches no exemption, so a policy
	// that blocks fully encrypted traffic drops the packet.
	if share := report.Level1.BlockedShare(); share < blockedShareLow || share > blockedShareHigh {
		t.Errorf("%.1f%% of the first packets of a half-closing connection match no exemption, recorded band is %.0f%%-%.0f%%",
			share*100, blockedShareLow*100, blockedShareHigh*100)
	}

	// Level 2: the opening is there, and it is as long and as varied as the
	// one the data path writes.
	op := report.Openings
	if op.WithOpening != halfCloseCorpusSize {
		t.Errorf("%d of %d half-closing connections open with printable characters, want all of them: %s",
			op.WithOpening, halfCloseCorpusSize, op)
	}
	if op.Min < openingLenLow || op.Max > openingLenHigh {
		t.Errorf("opening lengths span [%d, %d], recorded band is [%d, %d]: %s",
			op.Min, op.Max, openingLenLow, openingLenHigh, op)
	}
	if op.Distinct < openingLenDistinct {
		t.Errorf("only %d distinct opening lengths over %d connections - the boundary between the opening "+
			"and the FIN frame is a constant: %s", op.Distinct, halfCloseCorpusSize, op)
	}
}

// The encoding is only worth anything if the server still reads what comes
// out of it: an opening the peer cannot decode is a connection that hangs,
// which is worse than one that is filtered.
func TestAHalfCloseBeforeTheFirstWriteIsStillReadByTheServer(t *testing.T) {
	for _, split := range []bool{false, true} {
		name := "one record"
		if split {
			name = "opening in a record of its own"
		}
		t.Run(name, func(t *testing.T) {
			cfg := testConfig()
			cfg.SplitOpening = split

			clientConn, serverConn := net.Pipe()
			defer func() { _ = clientConn.Close() }()
			defer func() { _ = serverConn.Close() }()

			client, err := NewClientConn(clientConn, cfg)
			if err != nil {
				t.Fatalf("NewClientConn: %v", err)
			}
			server, err := NewServerConn(serverConn, cfg)
			if err != nil {
				t.Fatalf("NewServerConn: %v", err)
			}

			go func() {
				closer, ok := client.(interface{ CloseWrite() error })
				if !ok {
					return
				}
				_ = closer.CloseWrite()
			}()

			done := make(chan error, 1)
			go func() {
				buf := make([]byte, 1024)
				_, err := server.Read(buf)
				done <- err
			}()

			select {
			case err := <-done:
				if !errors.Is(err, io.EOF) {
					t.Fatalf("the server read %v from a half-closed connection, want io.EOF", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("the server never made sense of the opening in front of the FIN")
			}
		})
	}
}
