package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

// tcpmuxRecorder admits the 0x83 command and refuses every datagram, keeping
// the destination it was asked about. Refusing is what keeps the fuzzer off
// the network: a refused datagram is never resolved and never sent, while
// the frame reader, the header parser and the rule question all still run.
type tcpmuxRecorder struct {
	mu    sync.Mutex
	asked []string
}

func (r *tcpmuxRecorder) Allow(ctx context.Context, req *Request) (context.Context, bool) {
	if !req.Datagram {
		return ctx, req.Command == UDPTunnelCommand
	}
	r.mu.Lock()
	r.asked = append(r.asked, tcpmuxDestination(req.DestAddr))
	r.mu.Unlock()
	return ctx, false
}

func (r *tcpmuxRecorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	asked := r.asked
	r.asked = nil
	return asked
}

func tcpmuxDestination(a *AddrSpec) string {
	return a.FQDN + "|" + a.IP.String() + "|" + itoa(a.Port)
}

// tcpmuxExpected is what the frame loop must ask the rules about, worked out
// from the stream without the server: every complete frame with a length
// other than zero whose header ParseUDPHeader accepts, in order.
func tcpmuxExpected(stream []byte) []string {
	var want []string
	for len(stream) >= 2 {
		n := int(binary.BigEndian.Uint16(stream))
		stream = stream[2:]
		if n == 0 {
			continue
		}
		if len(stream) < n {
			break
		}
		if _, dst, err := ParseUDPHeader(stream[:n]); err == nil {
			want = append(want, tcpmuxDestination(dst))
		}
		stream = stream[n:]
	}
	return want
}

// tcpmuxConn is one end of an in-memory connection that can be half-closed.
// net.Pipe cannot: the client could then only end the stream by closing
// outright, and what the server sends after that would be lost unread.
type tcpmuxConn struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func tcpmuxPipe() (client, server *tcpmuxConn) {
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	return &tcpmuxConn{r: cr, w: cw}, &tcpmuxConn{r: sr, w: sw}
}

func (c *tcpmuxConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *tcpmuxConn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *tcpmuxConn) CloseWrite() error           { return c.w.Close() }
func (c *tcpmuxConn) Close() error {
	_ = c.w.Close()
	return c.r.Close()
}
func (c *tcpmuxConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}
}
func (c *tcpmuxConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
}
func (c *tcpmuxConn) SetDeadline(time.Time) error      { return nil }
func (c *tcpmuxConn) SetReadDeadline(time.Time) error  { return nil }
func (c *tcpmuxConn) SetWriteDeadline(time.Time) error { return nil }

func tcpmuxFrame(payload []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(payload))), payload...)
}

// tcpmuxOpening is the client side of the handshake: no authentication and
// the tunnel command. Everything after it is the fuzzer's.
var tcpmuxOpening = []byte{
	Socks5Version, 1, NoAuth,
	Socks5Version, UDPTunnelCommand, 0, ipv4Address, 127, 0, 0, 1, 0, 0,
}

// tcpmuxReplies is everything the server may send when no datagram leaves:
// the method selection and the success reply to 0x83.
var tcpmuxReplies = []byte{
	Socks5Version, NoAuth,
	Socks5Version, successReply, 0, ipv4Address, 0, 0, 0, 0, 0, 0,
}

// FuzzUDPTunnelFrames feeds arbitrary frame streams to the server side of
// command 0x83 (handleUDPTcpmux) after a successful handshake. It asserts:
//   - the handler returns once the client closes, whatever it was sent;
//   - the rules are asked about exactly the frames the format defines, in
//     order: a length prefix, a header ParseUDPHeader accepts, and zero-length
//     frames skipped as keepalives - so a malformed frame neither stops the
//     loop nor desynchronises the frames behind it;
//   - nothing but the two handshake replies comes back through the tunnel.
func FuzzUDPTunnelFrames(f *testing.F) {
	v4 := BuildUDPHeader(&AddrSpec{IP: net.IPv4(192, 0, 2, 1), Port: 53}, []byte("query"))
	v6 := BuildUDPHeader(&AddrSpec{IP: net.ParseIP("2001:db8::1"), Port: 443}, []byte("quic"))
	name := BuildUDPHeader(&AddrSpec{FQDN: "example.com", Port: 3478}, []byte("stun"))
	f.Add(tcpmuxFrame(v4))
	f.Add(append(append(tcpmuxFrame(v4), tcpmuxFrame(v6)...), tcpmuxFrame(name)...))
	f.Add(append(append([]byte{0, 0}, tcpmuxFrame([]byte{0, 0, 1, 1, 2, 3, 4, 5})...), tcpmuxFrame(v4)...))
	f.Add(append(tcpmuxFrame([]byte{0, 0, 0, 9}), tcpmuxFrame(name)...))
	f.Add(tcpmuxFrame(bytes.Repeat([]byte{0}, 300)))
	f.Add([]byte{0xff, 0xff, 0, 0, 0, 1})
	f.Add([]byte{0})
	f.Add([]byte{})

	rules := &tcpmuxRecorder{}
	srv, err := New(&Config{
		Rules:  rules,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		f.Fatalf("New: %v", err)
	}

	f.Fuzz(func(t *testing.T, stream []byte) {
		clientEnd, serverEnd := tcpmuxPipe()

		served := make(chan struct{})
		go func() {
			defer close(served)
			_ = srv.ServeConnContext(context.Background(), serverEnd)
		}()

		var answer bytes.Buffer
		read := make(chan struct{})
		go func() {
			defer close(read)
			_, _ = io.Copy(&answer, clientEnd)
		}()

		// The client ends its direction and keeps reading: the server sees
		// the end of the stream, and whatever it sends until it closes is
		// collected.
		_, writeErr := clientEnd.Write(append(append([]byte(nil), tcpmuxOpening...), stream...))
		_ = clientEnd.CloseWrite()

		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Fatalf("the 0x83 handler did not return after the client closed, on %d bytes: %x", len(stream), stream)
		}
		<-read
		_ = clientEnd.Close()

		asked := rules.take()
		if writeErr != nil {
			t.Fatalf("the server stopped reading the stream: %v", writeErr)
		}
		want := tcpmuxExpected(stream)
		if len(asked) != len(want) {
			t.Fatalf("the rules were asked about %d datagrams, the stream holds %d:\nasked %q\nwant  %q", len(asked), len(want), asked, want)
		}
		for i := range want {
			if asked[i] != want[i] {
				t.Fatalf("datagram %d: the rules were asked about %q, the frame names %q", i, asked[i], want[i])
			}
		}
		if !bytes.Equal(answer.Bytes(), tcpmuxReplies) {
			t.Fatalf("the tunnel answered %x, want only the handshake replies %x", answer.Bytes(), tcpmuxReplies)
		}
	})
}
