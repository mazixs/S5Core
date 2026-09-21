package obfs

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/pkg/veil"
)

// A refused connection is held, read and discarded until the handshake budget
// runs out, so that the moment of closing carries no information about why it
// was refused (plan task Ф5-6). That guarantee is only as good as its weakest
// exit: a refusal that returns its error directly closes the socket at once,
// and a prober who can produce it has a stopwatch that answers "is there a
// server here". Three refusals in readOpening used to return directly (review
// finding R08).
//
// The schemes wired in today never take that path - an unknown client is given
// a wrong secret, not an error - so the test supplies a scheme that does, which
// is the case the invariant exists for.

var errSchemeRefusesEverything = errors.New("veil: this scheme refuses every prologue")

// refusingScheme answers with an error instead of a secret. It is the shape a
// future scheme could take, and the reason the invariant is about all
// refusals rather than about the schemes that ship today.
type refusingScheme struct{}

func (refusingScheme) Name() string { return "refusing" }
func (refusingScheme) Size() int    { return saltSize }

func (refusingScheme) Offer(psk, dst []byte) (veil.Result, error) {
	return veil.Result{}, errSchemeRefusesEverything
}

func (refusingScheme) Accept(psk, prologue []byte) (veil.Result, error) {
	return veil.Result{}, errSchemeRefusesEverything
}

// heldFor runs one server connection that is going to be refused and reports
// how long the server held it and why it gave up. The client writes what the
// test gives it and then falls silent without closing, which is what a prober
// measuring the refusal would do.
func heldFor(t *testing.T, cfg Config, flight []byte) (time.Duration, error) {
	t.Helper()

	var held time.Duration
	var refusal error

	synctest.Test(t, func(t *testing.T) {
		clientSide, serverSide := net.Pipe()
		server, err := NewServerConn(serverSide, cfg)
		if err != nil {
			t.Fatalf("server conn: %v", err)
		}

		quiet := make(chan struct{})
		sent := make(chan struct{})
		go func() {
			defer close(sent)
			if _, err := clientSide.Write(flight); err != nil {
				return
			}
			// Silent, but still connected: a peer that hangs up ends the
			// drain early, and that is the peer's choice, not the server's.
			<-quiet
			_ = clientSide.Close()
		}()

		start := time.Now()
		buf := make([]byte, 1024)
		_, refusal = server.Read(buf)
		held = time.Since(start)

		close(quiet)
		_ = server.Close()
		<-sent
	})

	return held, refusal
}

func TestASchemeThatRefusesIsHeldAsLongAsAnyOtherRefusal(t *testing.T) {
	const budget = 7 * time.Second
	psk := bytes.Repeat([]byte("k"), 32)

	// Both encodings, because they are two branches with two calls to the
	// scheme: the raw one asks about the 32 bytes as they arrive, the
	// printable one decodes first and asks after.
	prologue := bytes.Repeat([]byte{0x00}, saltSize)
	printable := make([]byte, encodedPrologueSize)
	if _, err := encodeWirePrologue(printable, prologue, 0); err != nil {
		t.Fatalf("encoding an opening: %v", err)
	}
	if looksEncoded(prologue) || !looksEncoded(printable[:saltSize]) {
		t.Fatal("the two openings do not take the two branches this test is about")
	}

	for _, tc := range []struct {
		name    string
		opening []byte
	}{
		{"a raw opening", prologue},
		{"a printable opening", printable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refused, err := heldFor(t, Config{
				PSK:          psk,
				Scheme:       refusingScheme{},
				RefuseLinger: budget,
				MaxPadding:   256,
				MTU:          1400,
			}, tc.opening)

			if refused != budget {
				t.Fatalf("%s the scheme refused was dropped after %v, want the whole %v budget", tc.name, refused, budget)
			}
			reason, ok := ReasonOf(err)
			if !ok {
				t.Fatalf("the refusal was reported as %v, not as a frame failure", err)
			}
			if reason != ReasonBadOpening {
				t.Fatalf("the refusal was classified as %q, want %q", reason, ReasonBadOpening)
			}

			// The control: the same server, the scheme it ships with, and a
			// client holding the wrong key. This is the refusal the timing of
			// every other refusal has to match, and it is reached a whole
			// frame later.
			if wrongKey := heldForAWrongKey(t, budget); wrongKey != refused {
				t.Fatalf("a refused opening was held for %v and a wrong key for %v; a prober can tell them apart", refused, wrongKey)
			}
		})
	}
}

// heldForAWrongKey is the control: a client whose PSK does not match sends a
// full opening and a frame's worth of bytes, and the server refuses somewhere
// inside the frame. What it is refused for is not the point - how long it is
// held is.
func heldForAWrongKey(t *testing.T, budget time.Duration) time.Duration {
	t.Helper()

	serverPSK := bytes.Repeat([]byte("k"), 32)
	clientPSK := bytes.Repeat([]byte("j"), 32)

	// The client's own opening, made the way a client makes it, followed by
	// enough bytes that any length the server reads under its own mask is
	// covered - otherwise the server waits for a frame that never completes,
	// which is a different refusal with a different clock.
	var flight []byte
	func() {
		clientSide, serverSide := net.Pipe()
		defer func() { _ = clientSide.Close() }()

		var wire bytes.Buffer
		collected := make(chan struct{})
		go func() {
			defer close(collected)
			buf := make([]byte, 4096)
			for {
				n, err := serverSide.Read(buf)
				wire.Write(buf[:n])
				if err != nil {
					return
				}
			}
		}()

		client, err := NewClientConn(clientSide, Config{PSK: clientPSK, MaxPadding: 256, MTU: 1400})
		if err != nil {
			t.Fatalf("client conn: %v", err)
		}
		if _, err := client.Write(bytes.Repeat([]byte("x"), 70000)); err != nil {
			t.Fatalf("client write: %v", err)
		}
		_ = clientSide.Close()
		_ = serverSide.Close()
		<-collected
		flight = wire.Bytes()
	}()

	held, err := heldFor(t, Config{
		PSK:          serverPSK,
		RefuseLinger: budget,
		MaxPadding:   256,
		MTU:          1400,
	}, flight)
	if err == nil {
		t.Fatal("the server accepted a connection made with the wrong key")
	}
	return held
}
