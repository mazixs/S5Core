package ws

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/stealth"
	"github.com/mazixs/S5Core/internal/utls"
)

const extPreSharedKey = 41

// helloTap sits in front of a server and keeps the first bytes each client
// sent, which is where its ClientHello is.
type helloTap struct {
	addr   string
	mu     sync.Mutex
	hellos []*bytes.Buffer
}

func tapHellos(t *testing.T, upstream string) *helloTap {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	tap := &helloTap{addr: l.Addr().String()}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", upstream)
			if err != nil {
				_ = c.Close()
				continue
			}
			rec := &bytes.Buffer{}
			tap.mu.Lock()
			tap.hellos = append(tap.hellos, rec)
			tap.mu.Unlock()
			go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
			go func() {
				_, _ = io.Copy(up, io.TeeReader(c, lockedWriter{&tap.mu, rec}))
				_ = up.Close()
			}()
		}
	}()
	return tap
}

type lockedWriter struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

// hello returns the i-th client's first TLS record and its parse.
func (tap *helloTap) hello(t *testing.T, i int) ([]byte, *stealth.ClientHello) {
	t.Helper()
	tap.mu.Lock()
	raw := append([]byte(nil), tap.hellos[i].Bytes()...)
	tap.mu.Unlock()
	if len(raw) < 5 {
		t.Fatalf("client %d sent %d bytes", i, len(raw))
	}
	record := raw[:5+int(binary.BigEndian.Uint16(raw[3:5]))]
	h, err := stealth.ParseClientHello(record)
	if err != nil {
		t.Fatalf("client %d: %v", i, err)
	}
	return record, h
}

// pskIdentity returns the first identity of the pre_shared_key extension,
// nil when the hello offers none.
func pskIdentity(t *testing.T, record []byte) []byte {
	t.Helper()
	b := record[5+4:]         // record and handshake headers
	b = b[2+32:]              // legacy version, random
	b = b[1+int(b[0]):]       // session id
	b = b[2+int(be16(b)):]    // cipher suites
	b = b[1+int(b[0]):]       // compression methods
	b = b[2 : 2+int(be16(b))] // extensions
	for len(b) >= 4 {
		typ, n := be16(b), int(be16(b[2:]))
		body := b[4 : 4+n]
		b = b[4+n:]
		if typ == extPreSharedKey {
			ids := body[2:]
			return ids[2 : 2+int(be16(ids))]
		}
	}
	return nil
}

func be16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }

// roundTrip reads the echo, which is also how a TLS 1.3 client gets to the
// session ticket the server sent after the handshake.
func roundTrip(t *testing.T, c *Conn) {
	t.Helper()
	msg := []byte("ticket, please")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, make([]byte, len(msg))); err != nil {
		t.Fatal(err)
	}
}

// A browser preset has no resumption extension, and uTLS is told not to add
// one, so the cache a Dialer keeps changes nothing on the wire: the second
// connection is a full handshake with the same JA4 as the first, after the
// first had a ticket to offer.
func TestABrowserFingerprintNeverResumes(t *testing.T) {
	url, pool, _, certAsks := wssEcho(t)
	tap := tapHellos(t, strings.TrimSuffix(strings.TrimPrefix(url, "wss://"), "/ws"))
	d := NewDialer(DialOpts{URL: "wss://" + tap.addr + "/ws", RootCAs: pool, TLSFingerprint: utls.FPChrome})

	for i := 0; i < 2; i++ {
		c, err := d.DialContext(t.Context())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		roundTrip(t, c)
		_ = c.Close()
	}
	first, h1 := tap.hello(t, 0)
	second, h2 := tap.hello(t, 1)
	if h1.JA4() != h2.JA4() {
		t.Errorf("JA4 moved on the second connection: %s, then %s", h1.JA4(), h2.JA4())
	}
	if pskIdentity(t, first) != nil || pskIdentity(t, second) != nil {
		t.Error("a chrome hello offered a session ticket")
	}
	if got := certAsks.Load(); got != 2 {
		t.Errorf("the server was asked for a certificate %d times, want 2 full handshakes", got)
	}
}

// Without TLS_FINGERPRINT crypto/tls resumes, and it does not spend a TLS 1.3
// ticket: connections opened before a fresh ticket arrives offer the same
// one, so an observer can link them by the PSK identity in clear text.
// Recorded rather than fixed, like the rest of the fallback's shape.
func TestWithoutAFingerprintParallelConnectionsShareATicket(t *testing.T) {
	url, pool, _, certAsks := wssEcho(t)
	tap := tapHellos(t, strings.TrimSuffix(strings.TrimPrefix(url, "wss://"), "/ws"))
	d := NewDialer(DialOpts{URL: "wss://" + tap.addr + "/ws", RootCAs: pool, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}})

	c, err := d.DialContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c)
	_ = c.Close()

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Go(func() {
			c, err := d.DialContext(t.Context())
			if err != nil {
				t.Error(err)
				return
			}
			_ = c.Close()
		})
	}
	wg.Wait()

	a, _ := tap.hello(t, 1)
	b, _ := tap.hello(t, 2)
	idA, idB := pskIdentity(t, a), pskIdentity(t, b)
	if idA == nil || idB == nil {
		t.Fatalf("the parallel connections did not resume (identities %d and %d bytes)", len(idA), len(idB))
	}
	if !bytes.Equal(idA, idB) {
		t.Error("the two connections offered different tickets; crypto/tls now spends them, update this record and the NewDialer comment")
	}
	if got := certAsks.Load(); got != 1 {
		t.Errorf("certificate asked %d times, want only the first full handshake", got)
	}
}
