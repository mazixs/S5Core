package obfs

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// Plan task Ф4-4. The old defence was a nonce window inside each connection.
// It cost about 82 KiB per connection and caught the one replay that cannot
// happen anyway - a frame repeated inside a session, which counter nonces rule
// out by construction. The replay an active prober actually performs is the
// one it could never see: record the first frame of a working connection and
// send it again on a fresh socket. These tests pin the new behaviour - the
// history lives on the server and spans connections - and, just as important,
// that catching the replay does not make the server answer it any differently
// than it answers bytes that simply fail to authenticate.

// scriptConn hands out a fixed script of bytes and keeps what is written back,
// which is the whole observable surface of a probe: what it can send, what it
// gets back, and where the stream ends.
type scriptConn struct {
	in  *bytes.Reader
	out bytes.Buffer
}

func newScriptConn(script []byte) *scriptConn {
	return &scriptConn{in: bytes.NewReader(script)}
}

func (c *scriptConn) Read(p []byte) (int, error)       { return c.in.Read(p) }
func (c *scriptConn) Write(p []byte) (int, error)      { return c.out.Write(p) }
func (c *scriptConn) Close() error                     { return nil }
func (c *scriptConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptConn) SetWriteDeadline(time.Time) error { return nil }
func (c *scriptConn) LocalAddr() net.Addr              { return benchAddr{} }
func (c *scriptConn) RemoteAddr() net.Addr             { return benchAddr{} }
func (c *scriptConn) consumed() int                    { return int(c.in.Size()) - c.in.Len() }
func (c *scriptConn) answered() int                    { return c.out.Len() }

// firstFlight produces the bytes a client puts on the wire for one payload:
// the session salt followed by a single frame. This is what a prober records.
func firstFlight(t *testing.T, cfg Config, payload []byte) []byte {
	t.Helper()
	wire := &countingConn{}
	client, err := NewClientConn(wire, cfg)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	return wire.bytes()
}

// feedServer runs one probe: a fresh server connection reads the script once.
// It returns the failure classification (empty if the read succeeded), what the
// server sent back, and how much of the script it consumed.
func feedServer(t *testing.T, cfg Config, script []byte) (FailureReason, int, int) {
	t.Helper()
	wire := newScriptConn(script)
	server, err := NewServerConn(wire, cfg)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	buf := make([]byte, 4096)
	_, readErr := server.Read(buf)
	reason, _ := ReasonOf(readErr)
	return reason, wire.answered(), wire.consumed()
}

func TestARecordedConnectionCannotBeReplayedIntoANewOne(t *testing.T) {
	psk := bytes.Repeat([]byte("k"), 32)
	client := Config{PSK: psk, MaxPadding: 0}
	server := Config{PSK: psk, MaxPadding: 0, History: NewSaltHistory(DefaultSaltHistory)}

	flight := firstFlight(t, client, []byte("the payload a prober records"))

	// First delivery: an ordinary connection.
	if reason, _, _ := feedServer(t, server, flight); reason != "" {
		t.Fatalf("the original connection failed with %q", reason)
	}

	// Same bytes, new connection. Counter nonces make them decrypt perfectly;
	// only the history knows they have been seen.
	reason, _, _ := feedServer(t, server, flight)
	if reason != ReasonReplay {
		t.Fatalf("the replay was classified as %q, want %q", reason, ReasonReplay)
	}

	// A second, genuine connection must still get through - the history
	// rejects repeated salts, not repeated peers.
	fresh := firstFlight(t, client, []byte("the payload a prober records"))
	if bytes.Equal(fresh[:saltSize], flight[:saltSize]) {
		t.Fatal("two connections drew the same salt")
	}
	if reason, _, _ := feedServer(t, server, fresh); reason != "" {
		t.Fatalf("a fresh connection was refused with %q", reason)
	}
}

// The point of Ф4-4 is not only to notice the replay but to answer it with
// nothing a prober can measure. The control is the same flight with one
// ciphertext byte flipped: bytes that reached the server looking exactly as
// plausible and failed to authenticate. Server and control must consume the
// same input, send back the same nothing, and stop at the same place.
func TestAReplayAnswersLikeBytesThatDoNotAuthenticate(t *testing.T) {
	psk := bytes.Repeat([]byte("k"), 32)
	client := Config{PSK: psk, MaxPadding: 0}
	server := Config{PSK: psk, MaxPadding: 0, History: NewSaltHistory(DefaultSaltHistory)}

	flight := firstFlight(t, client, []byte("indistinguishable, please"))
	if reason, _, _ := feedServer(t, server, flight); reason != "" {
		t.Fatalf("the original connection failed with %q", reason)
	}

	corrupt := append([]byte(nil), flight...)
	corrupt[len(corrupt)-1] ^= 0x01

	replayReason, replayBack, replayRead := feedServer(t, server, flight)
	garbageReason, garbageBack, garbageRead := feedServer(t, server, corrupt)

	if replayReason != ReasonReplay {
		t.Fatalf("replay classified as %q", replayReason)
	}
	if garbageReason != ReasonDecryptFail {
		t.Fatalf("the corrupted flight classified as %q, want %q", garbageReason, ReasonDecryptFail)
	}
	if replayBack != 0 || garbageBack != 0 {
		t.Fatalf("the server answered: %d bytes to the replay, %d to the garbage; want silence from both",
			replayBack, garbageBack)
	}
	if replayRead != garbageRead {
		t.Fatalf("the server read %d bytes of the replay and %d of the garbage - a prober can time that difference",
			replayRead, garbageRead)
	}
}

func TestTheHistoryForgetsInOrderAndOnlyWhenFull(t *testing.T) {
	h := NewSaltHistory(3)

	salts := [][]byte{
		bytes.Repeat([]byte{1}, saltSize),
		bytes.Repeat([]byte{2}, saltSize),
		bytes.Repeat([]byte{3}, saltSize),
		bytes.Repeat([]byte{4}, saltSize),
	}

	for i, s := range salts[:3] {
		if !h.Accept(s) {
			t.Fatalf("salt %d was refused on its first use", i)
		}
		if h.Accept(s) {
			t.Fatalf("salt %d was accepted twice", i)
		}
	}
	if h.Len() != 3 {
		t.Fatalf("the history holds %d salts, want 3", h.Len())
	}

	// The fourth entry evicts the first, and only the first.
	if !h.Accept(salts[3]) {
		t.Fatal("a new salt was refused by a full history")
	}
	if h.Accept(salts[1]) || h.Accept(salts[2]) {
		t.Fatal("a salt younger than the oldest one was evicted")
	}
	if !h.Accept(salts[0]) {
		t.Fatal("the oldest salt was still remembered after eviction")
	}
	if h.Len() != 3 {
		t.Fatalf("the history grew to %d salts beyond its limit of 3", h.Len())
	}
}

func TestAHistoryThatIsNotThereAcceptsEverything(t *testing.T) {
	var h *SaltHistory
	salt := bytes.Repeat([]byte{7}, saltSize)
	if !h.Accept(salt) {
		t.Fatal("a nil history refused a salt; the client side has no history and must never be blocked by one")
	}
	if !h.Accept(salt) {
		t.Fatal("a nil history refused a salt it had already seen; it remembers nothing, by design")
	}
	if h.Len() != 0 {
		t.Fatalf("a nil history reports %d entries", h.Len())
	}
	if sized := NewSaltHistory(0); sized != nil {
		t.Fatal("a history of size zero should be nil, so the check costs nothing when it is switched off")
	}
}

// A truncated salt cannot be checked, so it is refused rather than waved
// through. It cannot come from this protocol at all.
func TestATruncatedSaltIsRefused(t *testing.T) {
	h := NewSaltHistory(4)
	if h.Accept(bytes.Repeat([]byte{9}, saltPrefix-1)) {
		t.Fatal("a salt shorter than the stored prefix was accepted")
	}
}

var _ io.Reader = (*scriptConn)(nil)
