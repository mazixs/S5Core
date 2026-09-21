package obfs

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// Plan task Ф5-7. A client on a router nobody logs in to has to be able to
// tell the server which build it is, and the server has to be able to tell
// it which transport to use next - inside the tunnel, authenticated by the
// session keys, and without a round trip or a packet of its own. These
// tests pin those three properties.

// writeRecorder records every Write that reaches the connection underneath,
// so a test can say "this went out in one packet" about bytes it cannot
// otherwise see.
type writeRecorder struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (c *writeRecorder) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, bytes.Clone(b))
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *writeRecorder) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.writes)
}

// controlPair builds a client and a server over a pipe with the given
// configurations, and hands back the counting wrappers underneath each, so
// the test can see how many writes each end made.
func controlPair(t *testing.T, clientCfg, serverCfg Config) (client, server net.Conn, clientRaw, serverRaw *writeRecorder) {
	t.Helper()
	psk := bytes.Repeat([]byte{7}, 32)
	c, s := net.Pipe()
	clientRaw = &writeRecorder{Conn: c}
	serverRaw = &writeRecorder{Conn: s}

	clientCfg.PSK = psk
	serverCfg.PSK = psk

	var err error
	client, err = NewClientConn(clientRaw, clientCfg)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	server, err = NewServerConn(serverRaw, serverCfg)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server, clientRaw, serverRaw
}

// relayOnce reads until it has got want bytes or fails.
func relayOnce(t *testing.T, r io.Reader, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("read %q, want %q", got, want)
	}
}

func TestAHelloRidesInTheClientsFirstWrite(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []Hello
	)
	client, server, clientRaw, _ := controlPair(t,
		Config{Hello: &Hello{Version: "v9.8.7", Transport: "ws"}},
		Config{OnHello: func(h Hello) {
			mu.Lock()
			seen = append(seen, h)
			mu.Unlock()
		}},
	)

	payload := []byte("GET / HTTP/1.1\r\n\r\n")
	go func() {
		_, _ = client.Write(payload)
	}()
	relayOnce(t, server, payload)

	// The hello arrived, once, with what the client put in it.
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 {
		t.Fatalf("server saw %d hellos, want 1", len(seen))
	}
	if seen[0] != (Hello{Version: "v9.8.7", Transport: "ws"}) {
		t.Fatalf("server saw %+v", seen[0])
	}

	// And it cost no packet of its own: prologue, hello and data went to
	// the socket in a single write.
	if n := clientRaw.writeCount(); n != 1 {
		t.Fatalf("the client made %d writes for its first frame, want 1 (prologue + hello + data together)", n)
	}
}

func TestAnAdviceRidesInTheServersFirstWrite(t *testing.T) {
	want := Advice{
		Transport:     "ws",
		WSMinFrame:    512,
		WSMaxFrame:    2048,
		WSMaxJitterMs: 7,
		MaxPadding:    128,
		KeepaliveMin:  12 * time.Second,
		KeepaliveMax:  25 * time.Second,
	}
	got := make(chan Advice, 1)
	client, server, _, serverRaw := controlPair(t,
		Config{OnAdvice: func(a Advice) { got <- a }},
		Config{Advice: &want},
	)

	// The server cannot speak first; the client opens as usual.
	go func() { _, _ = client.Write([]byte("hello")) }()
	relayOnce(t, server, []byte("hello"))

	reply := []byte{0x05, 0x00}
	go func() { _, _ = server.Write(reply) }()
	relayOnce(t, client, reply)

	select {
	case a := <-got:
		if a != want {
			t.Fatalf("client got %+v, want %+v", a, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the advice never reached the client")
	}
	if n := serverRaw.writeCount(); n != 1 {
		t.Fatalf("the server made %d writes for its first frame, want 1 (advice + data together)", n)
	}
}

func TestControlFramesAreOptional(t *testing.T) {
	helloCalled := false
	client, server, _, _ := controlPair(t,
		Config{},
		Config{OnHello: func(Hello) { helloCalled = true }},
	)
	go func() { _, _ = client.Write([]byte("x")) }()
	relayOnce(t, server, []byte("x"))
	if helloCalled {
		t.Fatal("a client with no Hello configured sent one")
	}
}

func TestAControlFrameIsDeliveredOnce(t *testing.T) {
	calls := 0
	c := &conn{cfg: Config{Role: RoleServer, OnHello: func(Hello) { calls++ }}}
	payload := encodeHello(Hello{Version: "v1"})
	for range 3 {
		if err := c.deliverControl(kindHello, payload); err != nil {
			t.Fatalf("deliver: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("OnHello ran %d times, want 1: a peer repeating itself must not drive the counter", calls)
	}
}

func TestAControlFrameForTheOtherRoleIsDropped(t *testing.T) {
	// A hello arriving at a client, an advice arriving at a server: authentic,
	// harmless, ignored.
	helloAtClient := &conn{cfg: Config{Role: RoleClient, OnHello: func(Hello) { t.Fatal("a client delivered a hello") }}}
	if err := helloAtClient.deliverControl(kindHello, encodeHello(Hello{Version: "v1"})); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	adviceAtServer := &conn{cfg: Config{Role: RoleServer, OnAdvice: func(Advice) { t.Fatal("a server delivered an advice") }}}
	if err := adviceAtServer.deliverControl(kindAdvice, encodeAdvice(Advice{Transport: "ws"})); err != nil {
		t.Fatalf("deliver: %v", err)
	}
}

func TestABadControlPayloadIsRefused(t *testing.T) {
	var got *FrameError
	client, server, _, _ := controlPair(t,
		Config{},
		Config{OnFailure: func(fe *FrameError) { got = fe }},
	)

	// A hello whose one field claims more bytes than the payload has.
	cc := client.(*conn)
	cc.writeMu.Lock()
	cc.pending = &pendingControl{kind: kindHello, payload: []byte{helloVersion, 9, 'v'}}
	cc.writeMu.Unlock()

	go func() { _, _ = client.Write([]byte("data")) }()
	_, err := server.Read(make([]byte, 16))
	if err == nil {
		t.Fatal("the server accepted a control frame it could not parse")
	}
	if got == nil || got.Reason != ReasonBadControl {
		t.Fatalf("failure reported as %+v, want %s", got, ReasonBadControl)
	}
}

func TestAHelloThatDoesNotFitTheMTUIsRefusedAtSetup(t *testing.T) {
	c, _ := net.Pipe()
	defer c.Close()
	// frameOverhead+17 leaves a 17-byte budget; the hello below needs more.
	_, err := NewClientConn(c, Config{
		PSK:   bytes.Repeat([]byte{1}, 32),
		MTU:   frameOverhead + 17,
		Hello: &Hello{Version: "v1.2.3-verylongbuildid", Transport: "obfs"},
	})
	if err == nil {
		t.Fatal("a hello larger than the payload budget was accepted")
	}
	if !strings.Contains(err.Error(), "MTU") {
		t.Fatalf("the error does not name the MTU: %v", err)
	}
}

func TestTLVRoundTrips(t *testing.T) {
	t.Run("hello", func(t *testing.T) {
		in := Hello{Version: "abc123-dirty", Transport: "obfs"}
		out, err := decodeHello(encodeHello(in))
		if err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Fatalf("got %+v, want %+v", out, in)
		}
	})
	t.Run("advice with every field", func(t *testing.T) {
		in := Advice{Transport: "ws", WSMinFrame: 1, WSMaxFrame: 65535, WSMaxJitterMs: 3, MaxPadding: 4, KeepaliveMin: 5 * time.Second, KeepaliveMax: 6 * time.Second}
		out, err := decodeAdvice(encodeAdvice(in))
		if err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Fatalf("got %+v, want %+v", out, in)
		}
	})
	t.Run("zero advice is empty on the wire", func(t *testing.T) {
		if got := encodeAdvice(Advice{}); len(got) != 0 {
			t.Fatalf("a zero advice encoded to %d bytes, want 0", len(got))
		}
		out, err := decodeAdvice(nil)
		if err != nil || out != (Advice{}) {
			t.Fatalf("decoding nothing gave %+v, %v", out, err)
		}
	})
	t.Run("a long version is cut, not refused", func(t *testing.T) {
		long := strings.Repeat("v", maxControlString+10)
		out, err := decodeHello(encodeHello(Hello{Version: long}))
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Version) != maxControlString {
			t.Fatalf("version came back %d bytes, want %d", len(out.Version), maxControlString)
		}
	})
	t.Run("an unknown field is skipped", func(t *testing.T) {
		payload := append([]byte{0x7f, 3, 1, 2, 3}, encodeHello(Hello{Version: "v2"})...)
		out, err := decodeHello(payload)
		if err != nil {
			t.Fatal(err)
		}
		if out.Version != "v2" {
			t.Fatalf("got %+v", out)
		}
	})
	t.Run("a truncated field is an error", func(t *testing.T) {
		if _, err := decodeHello([]byte{helloVersion, 5, 'v'}); !errors.Is(err, errControlTruncated) {
			t.Fatalf("got %v, want %v", err, errControlTruncated)
		}
		if _, err := decodeHello([]byte{helloVersion}); !errors.Is(err, errControlTruncated) {
			t.Fatalf("got %v, want %v", err, errControlTruncated)
		}
	})
	t.Run("a numeric field of the wrong width is an error", func(t *testing.T) {
		if _, err := decodeAdvice([]byte{adviceWSMinFrame, 1, 9}); err == nil {
			t.Fatal("a one-byte frame size was accepted")
		}
	})
	t.Run("a value past the 16-bit range is clamped", func(t *testing.T) {
		out, err := decodeAdvice(encodeAdvice(Advice{WSMaxFrame: 1 << 20}))
		if err != nil {
			t.Fatal(err)
		}
		if out.WSMaxFrame != 0xFFFF {
			t.Fatalf("got %d, want 65535", out.WSMaxFrame)
		}
	})
}
