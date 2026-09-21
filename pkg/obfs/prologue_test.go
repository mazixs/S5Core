package obfs

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/stealth"
	"github.com/mazixs/S5Core/pkg/veil"
)

// The encoded opening is the answer to the level 1 rule: a first packet that
// looks fully encrypted is dropped, and a prologue is uniformly random by
// construction. These tests hold the properties that make the encoding worth
// its eleven bytes - it round-trips, it is printable, its length moves, a
// server understands both encodings without being told, and none of it
// changes when a connection is refused.

func TestAnEncodedPrologueDecodesToWhatWasEncoded(t *testing.T) {
	prologue := bytes.Repeat([]byte{0xAB}, saltSize)
	for _, pad := range []int{0, 1, openingPadMax} {
		wire := make([]byte, encodedPrologueSize+pad)
		n, err := encodeWirePrologue(wire, prologue, pad)
		if err != nil {
			t.Fatalf("pad %d: %v", pad, err)
		}
		if n != encodedPrologueSize+pad {
			t.Fatalf("pad %d: opening is %d bytes, expected %d", pad, n, encodedPrologueSize+pad)
		}
		if !looksEncoded(wire[:n]) {
			t.Fatalf("pad %d: the opening is not printable: %q", pad, wire[:n])
		}

		back := make([]byte, saltSize)
		if err := decodeWirePrologue(back, wire[:encodedPrologueSize]); err != nil {
			t.Fatalf("pad %d: decode: %v", pad, err)
		}
		if !bytes.Equal(back, prologue) {
			t.Fatalf("pad %d: decoded %x, encoded %x", pad, back, prologue)
		}
	}
}

// The two spare bits of the last base64 character are filled with noise, not
// zeroes. Left at zero they would confine that character to sixteen of the
// sixty-four values on every connection - a bias at a fixed offset, which is
// what level 2 of the checklist exists to find.
func TestTheLastCharacterOfTheEncodedPrologueIsNotBiased(t *testing.T) {
	const samples = 4000
	var seen [256]int
	for range samples {
		var prologue [saltSize]byte
		scheme := veil.Symmetric{}
		if _, err := scheme.Offer(nil, prologue[:]); err != nil {
			t.Fatal(err)
		}
		wire := make([]byte, encodedPrologueSize)
		if _, err := encodeWirePrologue(wire, prologue[:], 0); err != nil {
			t.Fatal(err)
		}
		seen[wire[encodedPrologueSize-1]]++
	}

	distinct := 0
	for _, c := range seen {
		if c > 0 {
			distinct++
		}
	}
	if distinct != 64 {
		t.Errorf("the last character took %d of the 64 values over %d samples; "+
			"if it is 16, the spare bits went out as zeroes", distinct, samples)
	}
}

// A server is told nothing about which encoding a client uses: it decides
// from the bytes. Both directions of that decision have to work, because a
// fleet is not updated in one step.
func TestAServerAcceptsBothPrologueEncodings(t *testing.T) {
	for _, enc := range []PrologueEncoding{ProloguePrintable, PrologueRaw, ""} {
		t.Run(string("encoding="+enc), func(t *testing.T) {
			psk := bytes.Repeat([]byte("k"), 32)
			clientRaw, serverRaw := net.Pipe()
			defer clientRaw.Close()
			defer serverRaw.Close()

			client, err := NewClientConn(clientRaw, Config{PSK: psk, MaxPadding: 64, PrologueEncoding: enc})
			if err != nil {
				t.Fatalf("client: %v", err)
			}
			server, err := NewServerConn(serverRaw, Config{PSK: psk, MaxPadding: 64})
			if err != nil {
				t.Fatalf("server: %v", err)
			}

			go func() {
				_, _ = client.Write([]byte("payload through the tunnel"))
			}()

			_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 64)
			n, err := server.Read(buf)
			if err != nil {
				t.Fatalf("server read: %v", err)
			}
			if got := string(buf[:n]); got != "payload through the tunnel" {
				t.Fatalf("server read %q", got)
			}
		})
	}
}

// What the printable encoding buys, measured the way the checklist measures
// it: the first packet of a connection is exempt from the level 1 rule, and
// the raw encoding is not.
func TestThePrintableOpeningExemptsTheFirstPacket(t *testing.T) {
	const streams = 200
	for _, tc := range []struct {
		enc  PrologueEncoding
		want bool // blocked
	}{
		{ProloguePrintable, false},
		{PrologueRaw, true},
	} {
		cfg := testConfig()
		cfg.PrologueEncoding = tc.enc
		corpus := make([][]byte, streams)
		for i := range corpus {
			corpus[i] = captureWireBytes(t, cfg, socks5Greeting)
		}
		blocked := stealth.RunLevel1(corpus).BlockedShare()
		if tc.want && blocked < 0.9 {
			t.Errorf("encoding %q: only %.1f%% of first packets are blocked; the raw opening is "+
				"supposed to be the case the rule catches", tc.enc, blocked*100)
		}
		if !tc.want && blocked > 0 {
			t.Errorf("encoding %q: %.1f%% of first packets match no exemption", tc.enc, blocked*100)
		}
	}
}

// The pad comes from the session secret, so its length is different on every
// connection and unknown to anyone without the PSK. A constant length would
// hand an observer the alignment of every frame behind it.
func TestTheOpeningLengthMovesBetweenConnections(t *testing.T) {
	const streams = 300
	lengths := map[int]int{}
	for range streams {
		wire := captureWireBytes(t, testConfig(), socks5Greeting)
		lengths[stealth.OpeningLength(wire)]++
	}
	if len(lengths) < 10 {
		t.Errorf("only %d distinct opening lengths over %d connections: %v", len(lengths), streams, lengths)
	}
}

// A wrong PSK must fail where every wrong PSK fails - on the tag of the first
// frame, after the refusal drain - and not earlier because the opening gave
// the server something to check. The prologue decodes for anyone; only the
// frame behind it does not open.
func TestAWrongKeyBehindAPrintableOpeningStillFailsOnTheFrame(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	client, err := NewClientConn(clientRaw, Config{PSK: bytes.Repeat([]byte("k"), 32), MaxPadding: 64})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	server, err := NewServerConn(serverRaw, Config{PSK: bytes.Repeat([]byte("j"), 32), MaxPadding: 64})
	if err != nil {
		t.Fatalf("server: %v", err)
	}

	go func() {
		_, _ = client.Write([]byte("hello"))
	}()

	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	if _, err := server.Read(buf); err == nil {
		t.Fatal("a frame opened under the wrong PSK")
	} else if errors.Is(err, io.EOF) {
		t.Fatalf("the server gave up at the opening rather than at the frame: %v", err)
	}
}

// What the encoding costs, measured where it is paid: once per connection,
// on the client, before the first frame. The data path is untouched - the
// frames behind the opening are byte-for-byte what they were - so this is
// the whole bill.
func BenchmarkEncodeOpening(b *testing.B) {
	psk := bytes.Repeat([]byte("k"), 32)
	scheme := veil.NewClocked()
	prologue := make([]byte, saltSize)
	offered, err := scheme.Offer(psk, prologue)
	if err != nil {
		b.Fatal(err)
	}
	c := &conn{cfg: Config{PSK: psk}, prologue: prologue, resolved: offered}

	b.ReportAllocs()
	for b.Loop() {
		if err := c.encodeOpening(); err != nil {
			b.Fatal(err)
		}
	}
}

// A path may classify the first packet only above a length of its own: the
// filter measured in docs/field/stealth.md lets through anything shorter than
// 100 bytes and the client's first write is 125 and up. SplitOpening is the
// answer to that path, and what it has to produce is the opening alone in the
// first write - not the opening plus whatever frames were ready.
func TestASplitOpeningLeavesOnItsOwn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		split bool
	}{
		{"together", false},
		{"split", true},
	} {
		cfg := testConfig()
		cfg.Hello = &Hello{Version: "1.4.4", Transport: "obfs"}
		cfg.SplitOpening = tc.split

		const streams = 100
		short, longest := 0, 0
		for range streams {
			first := firstWrite(t, cfg, socks5Greeting)
			if len(first) < 100 {
				short++
			}
			longest = max(longest, len(first))
		}
		switch {
		case tc.split && short != streams:
			t.Errorf("split opening: only %d of %d first packets are below 100 bytes (longest %d); "+
				"the opening is 43-72 bytes, so every one of them has to be", short, streams, longest)
		case !tc.split && short != 0:
			t.Errorf("opening in the same write: %d of %d first packets are below 100 bytes; "+
				"the write carries the opening, a hello frame and a data frame", short, streams)
		}
	}
}

// Splitting the write must not split the protocol: the server reads the
// opening from the stream and cannot tell, nor care, how many packets it
// arrived in.
func TestAServerReadsASplitOpeningLikeAnyOther(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	cfg := testConfig()
	cfg.SplitOpening = true
	client, err := NewClientConn(clientRaw, cfg)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	server, err := NewServerConn(serverRaw, testConfig())
	if err != nil {
		t.Fatalf("server: %v", err)
	}

	payload := bytes.Repeat([]byte("payload"), 100)
	go func() {
		_, _ = client.Write(payload)
		_, _ = client.Write(payload)
	}()

	got := make([]byte, len(payload))
	for range 2 {
		if _, err := io.ReadFull(server, got); err != nil {
			t.Fatalf("server read: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("server read %d bytes that are not what the client wrote", len(got))
		}
	}
}

// firstWrite is captureWireBytes for a client that writes more than once: it
// takes the first write and lets the rest go nowhere, which a pipe cannot do
// (the second write there waits for a reader forever).
func firstWrite(t *testing.T, cfg Config, payload []byte) []byte {
	t.Helper()
	rec := &recordingConn{}
	client, err := NewClientConn(rec, cfg)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(rec.writes) == 0 {
		t.Fatal("the client wrote nothing")
	}
	return rec.writes[0]
}

// recordingConn keeps the boundaries of the writes it is given. Everything
// else is what a connection that goes nowhere does.
type recordingConn struct {
	writes [][]byte
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}

func (c *recordingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *recordingConn) LocalAddr() net.Addr              { return nil }
func (c *recordingConn) RemoteAddr() net.Addr             { return nil }
