package obfs

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/veil"
)

// Plan task Ф5-2 puts one requirement on the format: the scheme that turns a
// connection's prologue into a session secret must be replaceable without
// rewriting the framing around it. That is the only thing protecting the
// project from having picked the wrong scheme at gate G4.
//
// These tests hold the seam open. pkg/veil proves a scheme can be swapped at
// its own interface; what is proved here is that the swap reaches the wire -
// that this layer really asks the scheme for the prologue it sends and for
// the secret it derives from, instead of drawing 32 random bytes itself.

// markedScheme is a second scheme, unrelated to the symmetric one. Its
// prologue starts with a recognisable mark so a test can point at bytes on
// the wire and say they came from the scheme; its secret is a different
// function of the same inputs, so keys derived through it differ too.
type markedScheme struct{ mark string }

func (markedScheme) Name() string { return "marked" }
func (markedScheme) Size() int    { return veil.SaltSize }

func (s markedScheme) Offer(psk, dst []byte) (veil.Result, error) {
	if len(dst) < veil.SaltSize {
		return veil.Result{}, errors.New("marked: buffer too small")
	}
	copy(dst, s.mark)
	if _, err := rand.Read(dst[len(s.mark):veil.SaltSize]); err != nil {
		return veil.Result{}, err
	}
	return s.Accept(psk, dst[:veil.SaltSize])
}

func (markedScheme) Accept(psk, prologue []byte) (veil.Result, error) {
	sum := sha256.Sum256(append(append([]byte{}, psk...), prologue...))
	return veil.Result{Secret: sum[:]}, nil
}

// oddScheme wants a prologue this framing cannot carry.
type oddScheme struct{}

func (oddScheme) Name() string { return "odd" }
func (oddScheme) Size() int    { return 48 }

func (oddScheme) Offer(_, dst []byte) (veil.Result, error) {
	return veil.Result{Secret: dst}, nil
}

func (oddScheme) Accept(_, _ []byte) (veil.Result, error) {
	return veil.Result{Secret: make([]byte, 32)}, nil
}

func TestASwappedSchemeCarriesATunnel(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	cfg := Config{
		PSK:        bytes.Repeat([]byte("k"), 32),
		MaxPadding: 64,
		Scheme:     markedScheme{mark: "MARK"},
	}

	client, err := NewClientConn(clientConn, cfg)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	server, err := NewServerConn(serverConn, cfg)
	if err != nil {
		t.Fatalf("server: %v", err)
	}

	msg := []byte("a scheme the framing has never heard of")
	go func() {
		if _, writeErr := client.Write(msg); writeErr != nil {
			t.Errorf("write: %v", writeErr)
		}
	}()

	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("read %q, want %q", buf[:n], msg)
	}
}

func TestThePrologueOnTheWireIsTheSchemesOwn(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	client, err := NewClientConn(clientConn, Config{
		PSK:        bytes.Repeat([]byte("k"), 32),
		MaxPadding: 64,
		Scheme:     markedScheme{mark: "MARK"},
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	go func() {
		_, _ = client.Write([]byte("hello"))
	}()

	// Read the raw bytes the client put on the wire, not what an obfs server
	// would make of them. The prologue goes out encoded, so what is checked
	// is that decoding it gives back exactly what the scheme produced -
	// the encoding is a rendering of the prologue, not a second prologue.
	_ = serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	wire := make([]byte, encodedPrologueSize)
	if _, err := readFull(serverConn, wire); err != nil {
		t.Fatalf("wire: %v", err)
	}
	prologue := make([]byte, veil.SaltSize)
	if err := decodeWirePrologue(prologue, wire); err != nil {
		t.Fatalf("the opening on the wire is not an encoded prologue: %v", err)
	}
	if !bytes.HasPrefix(prologue, []byte("MARK")) {
		t.Fatalf("the prologue on the wire is %x, which the scheme did not produce", prologue)
	}
}

func TestASchemeThisFramingCannotCarryIsRefused(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	_, err := NewClientConn(clientConn, Config{
		PSK:    bytes.Repeat([]byte("k"), 32),
		Scheme: oddScheme{},
	})
	if err == nil {
		t.Fatal("a 48-byte prologue was accepted by a framing that reserves 32 bytes for it")
	}
}

// The context is not on the wire, so a mismatch cannot be negotiated away: it
// has to fail like a wrong PSK. That is what makes veil.Context usable for
// per-node keys (task Ф5-4) - an observer learns nothing from the failure.
func TestAContextMismatchFailsLikeAWrongKey(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	psk := bytes.Repeat([]byte("k"), 32)
	client, err := NewClientConn(clientConn, Config{
		PSK:    psk,
		Scheme: veil.Symmetric{Context: veil.Context{NodeID: "edge"}},
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	server, err := NewServerConn(serverConn, Config{PSK: psk, Scheme: veil.Symmetric{}})
	if err != nil {
		t.Fatalf("server: %v", err)
	}

	go func() {
		_, _ = client.Write([]byte("hello"))
	}()

	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := server.Read(make([]byte, 64)); err == nil {
		t.Fatal("a server read a frame encrypted under a context it does not have")
	}
}

// readFull is io.ReadFull, spelled out to keep the import list of this file
// about schemes.
func readFull(c net.Conn, buf []byte) (int, error) {
	off := 0
	for off < len(buf) {
		n, err := c.Read(buf[off:])
		off += n
		if err != nil {
			return off, err
		}
	}
	return off, nil
}
