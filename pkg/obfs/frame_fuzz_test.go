package obfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/veil"
)

// fuzzPSK is the key every frame target shares, so that seeds built by a real
// client stay authentic for the server under test.
var fuzzPSK = bytes.Repeat([]byte{0x5c}, 32)

// fuzzWire is one end of a connection that exists only as bytes: a client
// writes into w, a server reads from r. Neither end ever waits, so a target
// needs no goroutine and a refusal drain ends at the end of the input.
type fuzzWire struct {
	r *bytes.Reader
	w bytes.Buffer
}

func (c *fuzzWire) Read(p []byte) (int, error) {
	if c.r == nil {
		return 0, io.EOF
	}
	return c.r.Read(p)
}
func (c *fuzzWire) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *fuzzWire) Close() error                { return nil }
func (c *fuzzWire) LocalAddr() net.Addr         { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1443} }
func (c *fuzzWire) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
}
func (c *fuzzWire) SetDeadline(time.Time) error      { return nil }
func (c *fuzzWire) SetReadDeadline(time.Time) error  { return nil }
func (c *fuzzWire) SetWriteDeadline(time.Time) error { return nil }

// fuzzMember and fuzzDirectory are the one roster member the targets know.
var (
	fuzzMember    = veil.Member{ID: "fuzz-member", Key: bytes.Repeat([]byte{0x3a}, veil.MemberKeySize)}
	fuzzDirectory = func() *veil.Directory {
		d, err := veil.NewDirectory([]veil.Member{fuzzMember})
		if err != nil {
			panic(err)
		}
		return d
	}()
)

// fuzzSchemes is a client scheme and the server scheme that accepts it:
// the default, ChaCha20 against a server that takes both ciphers, the bare
// symmetric scheme, a roster member, and a roster server with the shared
// account as fallback.
func fuzzSchemes(pick uint8) (client, server veil.Scheme, identity string) {
	both := []veil.Context{{}, {Cipher: veil.CipherChaCha}}
	switch pick % 5 {
	case 1:
		return &veil.Clocked{Context: veil.Context{Cipher: veil.CipherChaCha}}, &veil.Clocked{Accepts: both}, ""
	case 2:
		return veil.Symmetric{}, veil.Symmetric{}, ""
	case 3:
		return &veil.Roster{Member: fuzzMember}, &veil.Roster{Members: fuzzDirectory}, fuzzMember.ID
	case 4:
		return veil.NewClocked(), &veil.Roster{Members: fuzzDirectory, Anonymous: veil.NewClocked()}, ""
	}
	return nil, nil, ""
}

// fuzzServer is a server connection over wire with counters on its
// callbacks, the way a listener configures one, and the refusal drain on.
type fuzzServer struct {
	conn     *conn
	src      *bytes.Reader
	failures []*FrameError
	hellos   []Hello
}

func newFuzzServer(t *testing.T, wire []byte, scheme veil.Scheme, mtu int, history *SaltHistory) *fuzzServer {
	s := &fuzzServer{src: bytes.NewReader(wire)}
	c, err := NewServerConn(&fuzzWire{r: s.src}, Config{
		PSK:          fuzzPSK,
		MTU:          mtu,
		Scheme:       scheme,
		History:      history,
		RefuseLinger: time.Hour,
		OnFailure:    func(e *FrameError) { s.failures = append(s.failures, e) },
		OnHello:      func(h Hello) { s.hellos = append(s.hellos, h) },
	})
	if err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}
	s.conn = c.(*conn)
	return s
}

// readAll reads until the first error and checks what every server read
// must hold whatever it was sent: each Read returns bytes or an error, a
// failure is reported once, an error other than a timeout stays, the read
// buffer never grows past the largest frame the length field can name, and
// a connection that never authenticated has been drained to the end.
func (s *fuzzServer) readAll(t *testing.T, limit int) ([]byte, error) {
	var got []byte
	buf := make([]byte, 4096)
	var err error
	for i := 0; ; i++ {
		if i > limit {
			t.Fatalf("%d reads did not end the stream", i)
		}
		var n int
		n, err = s.conn.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			break
		}
		if n == 0 {
			t.Fatalf("a Read returned neither bytes nor an error")
		}
	}
	if n, again := s.conn.Read(buf); n != 0 || !errors.Is(again, err) {
		t.Fatalf("after %v a second Read gave %d bytes and %v", err, n, again)
	}
	if !errors.Is(err, io.EOF) {
		var fe *FrameError
		if !errors.As(err, &fe) {
			t.Fatalf("a read failed with %T %v, want io.EOF or a FrameError", err, err)
		}
	}
	if len(s.failures) > 1 {
		t.Fatalf("one connection reported %d failures", len(s.failures))
	}
	for _, fe := range s.failures {
		if fe.BytesBefore < 0 || fe.BytesBefore > s.src.Size() {
			t.Fatalf("a failure after %d bytes of a %d-byte stream", fe.BytesBefore, s.src.Size())
		}
	}
	if len(s.hellos) > 1 {
		t.Fatalf("%d hellos delivered on one connection", len(s.hellos))
	}
	if len(s.conn.readBuf) > 2+0xFFFF {
		t.Fatalf("the read buffer grew to %d bytes", len(s.conn.readBuf))
	}
	if (len(got) > 0 || len(s.hellos) > 0) && !s.conn.authenticated {
		t.Fatalf("delivered %d bytes and %d hellos without authenticating", len(got), len(s.hellos))
	}
	if !s.conn.authenticated && s.src.Len() != 0 {
		t.Fatalf("a refused connection was left with %d bytes undrained", s.src.Len())
	}
	return got, err
}

// clientStream is what a real client puts on the wire for payload: the
// opening, the frames and the FIN.
func clientStream(tb testing.TB, cfg Config, chunks ...[]byte) ([]byte, *conn) {
	wire := &fuzzWire{}
	c, err := NewClientConn(wire, cfg)
	if err != nil {
		tb.Fatalf("NewClientConn: %v", err)
	}
	for _, chunk := range chunks {
		if n, err := c.Write(chunk); err != nil || n != len(chunk) {
			tb.Fatalf("Write of %d bytes: %d, %v", len(chunk), n, err)
		}
	}
	if err := c.(*conn).CloseWrite(); err != nil {
		tb.Fatalf("CloseWrite: %v", err)
	}
	return wire.w.Bytes(), c.(*conn)
}

// splitBySizes cuts payload into chunks whose sizes are read, two bytes at a
// time, from sizes; what is left goes in a final chunk.
func splitBySizes(payload, sizes []byte) [][]byte {
	var chunks [][]byte
	for len(sizes) >= 2 {
		n := min(int(binary.BigEndian.Uint16(sizes)), len(payload))
		sizes = sizes[2:]
		chunks = append(chunks, payload[:n])
		payload = payload[n:]
	}
	return append(chunks, payload)
}

// FuzzFrameRoundTrip writes a payload through a real client, cut into writes
// by a pattern, with an MTU, a padding cap, a scheme, an opening encoding and
// a hello all chosen by the fuzzer, and reads it back on a server with an MTU
// of its own. It asserts:
//   - the client refuses exactly the configurations that cannot work: an MTU
//     with no room for payload, a hello that does not fit one frame;
//   - the server delivers the very bytes that were written, then io.EOF on
//     the FIN, with no failure reported;
//   - the server gets the hello once, cut to 32 bytes, and the member name
//     the scheme carries;
//   - no frame on the wire is longer than the client's MTU allows;
//   - the same bytes sent again to a server with the same salt history are
//     refused as a replay and deliver nothing.
func FuzzFrameRoundTrip(f *testing.F) {
	f.Add([]byte("hello, tunnel"), []byte{}, uint8(0), uint32(0), int16(256), uint16(0), uint8(0), false, "v2.2.0", "obfs", uint8(0))
	f.Add(bytes.Repeat([]byte{0xa5}, 3000), []byte{0, 1, 0, 0, 5, 0xdc}, uint8(3), uint32(200), int16(64), uint16(9000), uint8(1), true, "", "", uint8(1))
	f.Add([]byte("x"), []byte{0xff, 0xff}, uint8(0), uint32(frameOverhead+1), int16(0), uint16(frameOverhead+1), uint8(2), false, "v", "ws", uint8(2))
	f.Add([]byte{}, []byte{0, 0, 0, 0}, uint8(0), uint32(70000), int16(-1), uint16(1400), uint8(3), true, "", "", uint8(3))
	f.Add([]byte("jumbo"), []byte{}, uint8(40), uint32(70000), int16(30000), uint16(0), uint8(0), false, "", "", uint8(4))
	f.Add([]byte("tiny mtu, big hello"), []byte{}, uint8(0), uint32(frameOverhead+8), int16(0), uint16(0), uint8(0), true, "a-version-longer-than-the-cut-of-32", "obfs", uint8(0))
	f.Add([]byte("bad mtu"), []byte{}, uint8(0), uint32(frameOverhead), int16(0), uint16(0), uint8(0), false, "", "", uint8(0))

	history := NewSaltHistory(1024)

	f.Fuzz(func(t *testing.T, data, sizes []byte, grow uint8, mtuRaw uint32, maxPadding int16, serverMTU uint16,
		encoding uint8, withHello bool, version, transport string, schemePick uint8) {
		payload := bytes.Repeat(data, 1+int(grow)%32)
		clientScheme, serverScheme, identity := fuzzSchemes(schemePick)
		cfg := Config{
			PSK:          fuzzPSK,
			MTU:          int(mtuRaw % 140000),
			MaxPadding:   int(maxPadding),
			Scheme:       clientScheme,
			SplitOpening: encoding&2 != 0,
		}
		if encoding&1 != 0 {
			cfg.PrologueEncoding = PrologueRaw
		}
		var hello Hello
		if withHello {
			hello = Hello{Version: version, Transport: transport}
			cfg.Hello = &hello
		}

		budget := cfg.MTU - frameOverhead
		if cfg.MTU == 0 {
			budget = DefaultMTU - frameOverhead
		}
		budget = min(budget, 65535-(minCiphertext-16))
		wantRefusal := (cfg.MTU > 0 && cfg.MTU <= frameOverhead) || (withHello && len(encodeHello(hello)) > budget)
		if _, err := NewClientConn(&fuzzWire{}, cfg); (err != nil) != wantRefusal {
			t.Fatalf("MTU %d, hello of %d bytes: NewClientConn err=%v, want refusal=%v", cfg.MTU, len(encodeHello(hello)), err, wantRefusal)
		}
		if wantRefusal {
			return
		}

		wire, client := clientStream(t, cfg, splitBySizes(payload, sizes)...)

		// The server's MTU sizes only its own frames and buffers; one with no
		// room for a payload is refused where it is configured.
		smtu := int(serverMTU)
		if smtu <= frameOverhead {
			smtu = 0
		}
		srv := newFuzzServer(t, wire, serverScheme, smtu, history)
		got, err := srv.readAll(t, len(wire)+2)
		if !errors.Is(err, io.EOF) || !srv.conn.readClosed {
			t.Fatalf("the stream ended with %v (FIN seen: %v), want io.EOF on the FIN", err, srv.conn.readClosed)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("delivered %d bytes, wrote %d, and they differ", len(got), len(payload))
		}
		if len(srv.failures) != 0 {
			t.Fatalf("a clean stream reported %v", srv.failures[0])
		}
		if withHello {
			want := Hello{Version: cutControlString(version), Transport: cutControlString(transport)}
			if len(srv.hellos) != 1 || srv.hellos[0] != want {
				t.Fatalf("hellos %+v, want one %+v", srv.hellos, want)
			}
		} else if len(srv.hellos) != 0 {
			t.Fatalf("hellos %+v from a client that sent none", srv.hellos)
		}
		if srv.conn.Identity() != identity {
			t.Fatalf("identity %q, want %q", srv.conn.Identity(), identity)
		}

		pos, counter := len(client.wirePrologue), uint64(0)
		for pos < len(wire) {
			size := int(binary.BigEndian.Uint16(wire[pos:]) ^ srv.conn.maskRecv.Mask(counter))
			if 2+size > client.maxFrame || (cfg.MTU > 0 && 2+size > cfg.MTU) {
				t.Fatalf("frame %d is %d bytes on the wire, MTU %d", counter, 2+size, cfg.MTU)
			}
			pos += 2 + size
			counter++
		}
		if pos != len(wire) {
			t.Fatalf("the frames end at %d, the stream at %d", pos, len(wire))
		}

		replay := newFuzzServer(t, wire, serverScheme, smtu, history)
		got, err = replay.readAll(t, len(wire)+2)
		if reason, _ := ReasonOf(err); reason != ReasonReplay || len(got) != 0 || len(replay.hellos) != 0 {
			t.Fatalf("a replayed stream gave %d bytes, %d hellos and %v, want a replay refusal", len(got), len(replay.hellos), err)
		}
	})
}

// FuzzServerReadsArbitraryWire gives a server connection arbitrary bytes,
// with the refusal drain on as a listener sets it, and seeds that real
// clients produced under every scheme. Beyond what readAll checks for every
// stream, a server whose scheme has no members names nobody.
func FuzzServerReadsArbitraryWire(f *testing.F) {
	for pick := range uint8(5) {
		client, _, _ := fuzzSchemes(pick)
		cfg := Config{PSK: fuzzPSK, Scheme: client, Hello: &Hello{Version: "v2.2.0", Transport: "obfs"}}
		wire, _ := clientStream(f, cfg, []byte("GET / HTTP/1.1\r\n\r\n"))
		f.Add(wire, pick)
		f.Add(wire[:len(wire)-1], pick)
		f.Add(wire[:60], pick)
		cfg.PrologueEncoding = PrologueRaw
		cfg.Hello = nil
		wire, _ = clientStream(f, cfg)
		f.Add(wire, pick)
	}
	f.Add(bytes.Repeat([]byte("A"), 100), uint8(0))
	f.Add(bytes.Repeat([]byte{0}, 100), uint8(0))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05}, uint8(0))
	f.Add([]byte{}, uint8(0))

	f.Fuzz(func(t *testing.T, wire []byte, pick uint8) {
		_, scheme, _ := fuzzSchemes(pick)
		srv := newFuzzServer(t, wire, scheme, 0, NewSaltHistory(8))
		if _, err := srv.readAll(t, len(wire)+2); err == nil {
			t.Fatal("the stream ended without an error")
		}
		if pick%5 < 3 && srv.conn.Identity() != "" {
			t.Fatalf("a scheme without members named %q", srv.conn.Identity())
		}
	})
}

// FuzzTamperedStream takes a real client stream and flips one byte of it or
// cuts it short. Whatever the change, the server delivers a prefix of what
// was written and never different bytes; it reaches the FIN only when the
// stream is complete and the change fell where nothing is authenticated -
// the two noise bits of the last base64 character and the opening pad.
func FuzzTamperedStream(f *testing.F) {
	f.Add([]byte("one frame"), uint16(0), byte(1), uint16(0), false)
	f.Add([]byte("the last prologue character"), uint16(encodedPrologueSize-1), byte(3), uint16(0), false)
	f.Add(bytes.Repeat([]byte("several frames "), 300), uint16(2000), byte(0x80), uint16(0), false)
	f.Add(bytes.Repeat([]byte("cut "), 1000), uint16(0), byte(0), uint16(1500), true)
	f.Add([]byte{}, uint16(0), byte(0), uint16(0), true)

	f.Fuzz(func(t *testing.T, payload []byte, at uint16, flip byte, cut uint16, truncate bool) {
		wire, client := clientStream(t, Config{PSK: fuzzPSK, MaxPadding: 64}, payload)
		wire = append([]byte(nil), wire...)
		full, opening := len(wire), len(client.wirePrologue)
		idx, cutAt := int(at)%full, int(cut)%(full+1)
		if truncate {
			wire = wire[:cutAt]
		} else {
			wire[idx] ^= flip
		}

		srv := newFuzzServer(t, wire, nil, 0, nil)
		got, _ := srv.readAll(t, len(wire)+2)
		if !bytes.HasPrefix(payload, got) {
			t.Fatalf("delivered bytes that were never written")
		}
		if !srv.conn.readClosed {
			return
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("reached the FIN with %d of %d bytes", len(got), len(payload))
		}
		if truncate && cutAt < full {
			t.Fatalf("a stream cut to %d of %d bytes reached the FIN", cutAt, full)
		}
		if !truncate && flip != 0 && (idx < encodedPrologueSize-1 || idx >= opening) {
			t.Fatalf("a flip of %#x at %d (opening %d bytes) went unnoticed", flip, idx, opening)
		}
	})
}
