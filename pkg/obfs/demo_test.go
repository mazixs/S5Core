package obfs

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/stealth"
)

// What this file measures, and why it no longer measures entropy.
//
// The test that used to live here computed Shannon entropy over one frame and
// failed below 5.0 bits per byte. Every encrypted or compressed stream clears
// that bar, so the check was green precisely when the product was easiest to
// detect: the policy this transport actually meets - block anything that looks
// fully encrypted unless it looks like something recognisable - treats a
// high-entropy packet with no plausible prefix as the thing to block. Maximum
// entropy is the signature, not the defence.
//
// The checklist in internal/stealth replaces it. Level 1 asks whether a
// censor's first-packet policy would block the stream; level 2 asks what the
// protocol tells about itself across a thousand connections. The numbers below
// are recorded, not aspirational: they say what the format does today, and the
// tasks that change the format have to change them.

// corpusSize is the checklist's number for level-2 checks.
const corpusSize = 1000

// The first packet a client sends is the obfuscated SOCKS5 greeting - three
// bytes of payload inside one frame. That, not a bulk transfer, is what a
// first-packet policy sees.
var socks5Greeting = []byte{0x05, 0x01, 0x00}

func testConfig() Config {
	return Config{PSK: bytes.Repeat([]byte("K"), 32), MaxPadding: 256}
}

// buildCorpus collects the first packet of many independent connections.
//
// Setting S5CORE_STEALTH_CORPUS writes the corpus to that directory, which is
// what cmd/stealthcheck reads: the same pipeline then runs over a capture from
// a real deployment.
func buildCorpus(t *testing.T, cfg Config, payload []byte, streams int) [][]byte {
	t.Helper()

	corpus := make([][]byte, streams)
	for i := range corpus {
		corpus[i] = captureWireBytes(t, cfg, payload)
	}

	dir := os.Getenv("S5CORE_STEALTH_CORPUS")
	if dir == "" {
		return corpus
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("corpus directory: %v", err)
	}
	for i, p := range corpus {
		name := filepath.Join(dir, fmt.Sprintf("%05d.bin", i))
		if err := os.WriteFile(name, p, 0o644); err != nil {
			t.Fatalf("write corpus: %v", err)
		}
	}
	t.Logf("corpus written to %s", dir)
	return corpus
}

// The recorded state of the current wire format.
//
//   - blockedShare* : the share of first packets that match no exemption, and
//     therefore the share a fully-encrypted-traffic policy drops. It was
//     0.95-1.00 until the prologue went out encoded (phase 5): the opening is
//     printable now, so every first packet is exempt under Ex2 and Ex4 and
//     the band is zero. A packet that is blocked again means the encoding
//     stopped reaching the wire.
//   - openingLen* : how long that printable opening is. The band is the
//     encoded prologue plus the pad derived from the session secret, and both
//     ends of it matter: too short stops buying the exemption (a live path
//     dropped 16-byte openings in 0% and passed them in 100%, which is a
//     narrow margin), and a single fixed length would put the body back at a
//     constant offset.
//   - constantHeaderOffsets: offsets in the body that always carry the same
//     value. Empty, and that is the point.
//
// The bounds are wide enough to absorb sampling noise over 1000 streams and
// narrow enough that a format change lands here as a failure.
const (
	blockedShareLow  = 0.00
	blockedShareHigh = 0.00

	openingLenLow = 43
	// The upper bound is the encoded prologue plus the largest pad (63) plus
	// the measurement's own overshoot: the observer walks the alphabet and
	// cannot see where the pad ends, so a body byte that happens to land in
	// the 64-character set extends the run. A quarter of bytes do, which puts
	// a run of nine extra bytes past a thousand streams.
	openingLenHigh = 72
	// openingLenDistinct is how many different opening lengths the corpus
	// must show. The pad is uniform over 0..20, so 1000 streams produce all
	// 21; the floor leaves room for sampling noise but not for a constant.
	openingLenDistinct = 15
)

// constantHeaderOffsets is empty, and that is the point. Until plan task Ф4-3
// the frame began with a 4-byte plaintext length whose two high bytes were
// always zero and whose third took two values, so offsets 0-2 were a fixed
// field an analyser could lock onto. The length is masked now and the frame
// carries no nonce, so nothing on the wire sits at a fixed offset.
//
// If a future format brings a constant byte back, list it here with the task
// that introduced it - the entry is a record of a leak, not permission for it.
var constantHeaderOffsets = []int{}

func TestTheStealthChecklist(t *testing.T) {
	corpus := buildCorpus(t, testConfig(), socks5Greeting, corpusSize)
	report := stealth.Analyze(corpus, 64)
	t.Log("\n" + report.String())

	// Level 1.
	share := report.Level1.BlockedShare()
	if share < blockedShareLow || share > blockedShareHigh {
		t.Errorf("level 1: %.1f%% of first packets match no exemption, recorded band is %.0f%%-%.0f%%.\n"+
			"If the wire format changed, update the recorded band and name the task that changed it.",
			share*100, blockedShareLow*100, blockedShareHigh*100)
	}
	if share > 0 {
		t.Logf("level 1: recorded - %.1f%% of first packets are blocked by the policy.", share*100)
	}

	// Level 2: the printable opening that buys the exemption above. Its
	// length has to vary, or the body behind it sits at a fixed offset and
	// the positional check below is measuring an alignment it was handed.
	op := report.Openings
	if op.WithOpening != corpusSize {
		t.Errorf("level 2: %d of %d streams open with printable characters; the encoded prologue "+
			"is what makes the first packet exempt, so every stream must have one: %s",
			op.WithOpening, corpusSize, op)
	}
	if op.Min < openingLenLow || op.Max > openingLenHigh {
		t.Errorf("level 2: opening lengths span [%d, %d], recorded band is [%d, %d]: %s",
			op.Min, op.Max, openingLenLow, openingLenHigh, op)
	}
	if op.Distinct < openingLenDistinct {
		t.Errorf("level 2: only %d distinct opening lengths over %d streams - the boundary between "+
			"the opening and the frames is a constant: %s", op.Distinct, corpusSize, op)
	}

	// Level 2: positional uniformity over the first 64 bytes past the opening.
	found := map[int]stealth.PositionFinding{}
	for _, f := range report.Positions {
		found[f.Offset] = f
	}
	for _, off := range constantHeaderOffsets {
		f, ok := found[off]
		if !ok {
			t.Errorf("level 2: offset %d is no longer a constant field. If the frame header changed, "+
				"update constantHeaderOffsets - this test records what the format leaks, and the "+
				"record has to follow the format.", off)
			continue
		}
		delete(found, off)
		t.Logf("level 2: recorded - %s (plaintext frame length)", f)
	}

	// Everything else is the session salt and ciphertext: no offset may carry
	// a repeated value. This is the half of the check that has to stay green,
	// and the one a new constant would break.
	for off, f := range found {
		t.Errorf("level 2: unexpected structure at offset %d: %s", off, f)
	}

	// Level 2: frame lengths. Padding is what spreads them; a single peak
	// means the wire length is a function of the payload length alone.
	lengths := report.Lengths
	if lengths.Distinct < 200 {
		t.Errorf("level 2: only %d distinct first-packet lengths over %d streams: %s",
			lengths.Distinct, corpusSize, lengths)
	}
	if lengths.TopShare > 0.05 {
		t.Errorf("level 2: one length covers %.1f%% of streams: %s", lengths.TopShare*100, lengths)
	}
}

// The signature check the old file did assert, kept because it is a real
// regression test: a plaintext marker on the wire is a defect regardless of
// what any policy does with entropy.
func TestNoPlaintextMarkersReachTheWire(t *testing.T) {
	cfg := testConfig()

	socks5Connect := []byte{0x05, 0x01, 0x00, 0x03, 0x0b}
	socks5Connect = append(socks5Connect, []byte("example.com")...)
	socks5Connect = append(socks5Connect, 0x01, 0xBB)
	httpPayload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	wireGreeting := captureWireBytes(t, cfg, socks5Greeting)
	wireConnect := captureWireBytes(t, cfg, socks5Connect)
	wireHTTP := captureWireBytes(t, cfg, httpPayload)

	t.Logf("SOCKS5 greeting %2d bytes plain -> %3d bytes obfuscated: %s",
		len(socks5Greeting), len(wireGreeting), hex.EncodeToString(wireGreeting[:16]))
	t.Logf("SOCKS5 CONNECT  %2d bytes plain -> %3d bytes obfuscated", len(socks5Connect), len(wireConnect))
	t.Logf("HTTP request    %2d bytes plain -> %3d bytes obfuscated", len(httpPayload), len(wireHTTP))

	markers := []struct {
		name string
		in   []byte
		want []byte
	}{
		{"SOCKS5 greeting bytes", wireGreeting, socks5Greeting},
		{"the destination name", wireConnect, []byte("example.com")},
		{"the HTTP keyword", wireHTTP, []byte("HTTP")},
	}
	for _, m := range markers {
		if bytes.Contains(m.in, m.want) {
			t.Errorf("%s survived onto the wire", m.name)
		}
	}
}

func TestPayloadsSurviveTheRoundTrip(t *testing.T) {
	cfg := testConfig()
	for _, payload := range [][]byte{
		socks5Greeting,
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		bytes.Repeat([]byte{0xA5}, 8192),
	} {
		verifyRoundTrip(t, cfg, payload, fmt.Sprintf("%d bytes", len(payload)))
	}
}

// captureWireBytes writes one payload through obfs and returns the raw bytes
// that reached the socket.
func captureWireBytes(t *testing.T, cfg Config, payload []byte) []byte {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	obfsClient, err := NewClientConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}

	wireCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 65536)
		n, _ := serverConn.Read(buf) // raw bytes, no obfs wrapper
		wireCh <- append([]byte(nil), buf[:n]...)
	}()

	if _, err := obfsClient.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	select {
	case wire := <-wireCh:
		return wire
	case <-time.After(2 * time.Second):
		t.Fatal("timeout capturing wire bytes")
		return nil
	}
}

// verifyRoundTrip confirms data survives encryption and decryption.
func verifyRoundTrip(t *testing.T, cfg Config, payload []byte, name string) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	obfsClient, err := NewClientConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("%s: client: %v", name, err)
	}
	obfsServer, err := NewServerConn(serverConn, cfg)
	if err != nil {
		t.Fatalf("%s: server: %v", name, err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		got := make([]byte, 0, len(payload))
		buf := make([]byte, 4096)
		for len(got) < len(payload) {
			n, err := obfsServer.Read(buf)
			if err != nil {
				t.Errorf("%s: read: %v", name, err)
				return
			}
			got = append(got, buf[:n]...)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("%s: payload changed in transit", name)
		}
	}()

	if _, err := obfsClient.Write(payload); err != nil {
		t.Fatalf("%s: write: %v", name, err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: roundtrip timeout", name)
	}
}
