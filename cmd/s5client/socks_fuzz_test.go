package main

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"testing/iotest"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
)

// The client parses two peers it does not control: the server through the
// tunnel (the reply to 0x83, the answer to the credentials) and the local
// application (its greeting and request, and every datagram it sends).

func replySeeds() [][]byte {
	v4 := socks5.AppendAddr([]byte{socks5Ver, 0, 0}, &socks5.AddrSpec{IP: net.IPv4zero, Port: 0})
	v6 := socks5.AppendAddr([]byte{socks5Ver, 1, 0}, &socks5.AddrSpec{IP: net.ParseIP("2001:db8::1"), Port: 443})
	name := socks5.AppendAddr([]byte{socks5Ver, 0, 0}, &socks5.AddrSpec{FQDN: "example.com", Port: 53})
	long := socks5.AppendAddr([]byte{socks5Ver, 0, 0}, &socks5.AddrSpec{FQDN: string(bytes.Repeat([]byte("n"), 255)), Port: 65535})
	return [][]byte{
		v4,
		append(append([]byte(nil), v4...), 0, 7, 'f', 'r', 'a', 'm', 'e', 0, 0),
		v6, name, long,
		{socks5Ver, 0, 0, addrFQDN, 0, 0, 0},
		{socks5Ver, 0, 1, addrIPv4, 0, 0, 0, 0, 0, 0},
		{4, 0, 0, addrIPv4, 0, 0, 0, 0, 0, 0},
		{socks5Ver, 0, 0, 2},
		{socks5Ver},
		{},
	}
}

// FuzzReadSOCKSReply holds the reader of the server's reply to 0x83 to the
// format (review finding F14):
//   - an accepted reply is VER=5, RSV=0, a known ATYP and a named address that
//     is not empty, and it is exactly the bytes it was read from;
//   - it consumes the reply and nothing else, so the frames behind it stay in
//     the stream, and it does so however the bytes are split into reads;
//   - it takes the same length the server's own address parser does, so the
//     two ends agree on where the reply ends.
func FuzzReadSOCKSReply(f *testing.F) {
	for _, s := range replySeeds() {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		reply, err := readSOCKSReply(r)
		consumed := len(data) - r.Len()

		slow := bytes.NewReader(data)
		reply2, err2 := readSOCKSReply(iotest.OneByteReader(slow))
		if (err == nil) != (err2 == nil) || !bytes.Equal(reply, reply2) || slow.Len() != r.Len() {
			t.Fatalf("the reply depends on how it is split into reads: %x/%v against %x/%v", reply, err, reply2, err2)
		}

		// RSV, RSV, FRAG and then the address: the same bytes behind the
		// datagram header ParseUDPHeader reads.
		var udpLen int
		var udpAddr *socks5.AddrSpec
		udpErr := errors.New("too short")
		if len(data) >= 3 {
			udpLen, udpAddr, udpErr = socks5.ParseUDPHeader(append([]byte{0, 0, 0}, data[3:]...))
		}
		fits := udpErr == nil && data[0] == socks5Ver && data[2] == 0 &&
			(data[3] != addrFQDN || udpAddr.FQDN != "")

		if err != nil {
			if reply != nil {
				t.Fatalf("a refusal returned %x", reply)
			}
			if fits {
				t.Fatalf("refused a reply the format allows: %x: %v", data, err)
			}
			return
		}
		if !fits {
			t.Fatalf("accepted %x, which the format does not allow", reply)
		}
		if consumed != len(reply) || !bytes.Equal(reply, data[:consumed]) {
			t.Fatalf("consumed %d bytes and returned %x, want the bytes it read", consumed, reply)
		}
		if len(reply) != udpLen {
			t.Fatalf("the reply is %d bytes, the address parser says %d", len(reply), udpLen)
		}
	})
}

// FuzzSocksUDPHeader holds the client's per-datagram check to the server's
// parser: it must accept exactly the datagrams socks5.ParseUDPHeader accepts,
// or the client either forwards what the server drops or takes the answer
// port from a datagram that was not the application speaking.
func FuzzSocksUDPHeader(f *testing.F) {
	for _, s := range replySeeds() {
		if len(s) >= 3 {
			f.Add(append([]byte{0, 0, 0}, s[3:]...))
		}
	}
	f.Add([]byte{0, 0, 1, addrIPv4, 1, 2, 3, 4, 0, 53})
	f.Add([]byte{0, 0, 0, addrFQDN})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, d []byte) {
		_, _, err := socks5.ParseUDPHeader(d)
		if got := socksUDPHeader(d); got != (err == nil) {
			t.Fatalf("socksUDPHeader(%x) = %v, ParseUDPHeader err = %v", d, got, err)
		}
	})
}

// FuzzReadUserPassAuthResponse: RFC 1929 status 0 is the only success, any
// other status is a rejection (errAuthRejected, which leaves the transport
// alone), and a short answer is a failure of the path, not a rejection. The
// reader takes the two bytes of the answer and nothing behind them.
func FuzzReadUserPassAuthResponse(f *testing.F) {
	f.Add([]byte{0x01, 0x00})
	f.Add([]byte{0x01, 0x01})
	f.Add([]byte{0x01, 0x00, socks5Ver, 0})
	f.Add([]byte{0x01})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		err := readUserPassAuthResponse(r)
		if consumed := len(data) - r.Len(); consumed != min(2, len(data)) {
			t.Fatalf("consumed %d bytes of %d", consumed, len(data))
		}
		switch {
		case len(data) < 2:
			if err == nil || errors.Is(err, errAuthRejected) {
				t.Fatalf("a short answer %x gave %v, want a read failure", data, err)
			}
		case data[1] == 0:
			if err != nil {
				t.Fatalf("status 0 gave %v", err)
			}
		default:
			if !errors.Is(err, errAuthRejected) {
				t.Fatalf("status %#x gave %v, want a rejection", data[1], err)
			}
		}
	})
}

// fuzzAppConn is the local application: it says what the fuzzer wrote and
// records what the client answers.
type fuzzAppConn struct {
	r *bytes.Reader
	w bytes.Buffer
}

func (c *fuzzAppConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *fuzzAppConn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *fuzzAppConn) Close() error                { return nil }
func (c *fuzzAppConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}
}
func (c *fuzzAppConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
}
func (c *fuzzAppConn) SetDeadline(time.Time) error      { return nil }
func (c *fuzzAppConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fuzzAppConn) SetWriteDeadline(time.Time) error { return nil }

// FuzzApplicationHandshake feeds arbitrary bytes to the client as the local
// application's greeting and request. The request is forwarded to the server
// verbatim, so the invariant is that the client and the server read it alike:
//   - an accepted request is CONNECT or UDP ASSOCIATE and is exactly the bytes
//     behind the greeting, with nothing read past it;
//   - socks5.NewRequest accepts the same bytes, takes the same length and
//     reads the same command and destination name;
//   - the application gets the method reply once the greeting is read, and a
//     command-not-supported reply for any other command.
func FuzzApplicationHandshake(f *testing.F) {
	greeting := []byte{socks5Ver, 1, socks5NoAuth}
	for _, s := range replySeeds() {
		if len(s) >= 3 {
			f.Add(append(append(append([]byte(nil), greeting...), socks5Ver, socks5.ConnectCommand, 0), s[3:]...))
		}
	}
	f.Add(append(append([]byte(nil), greeting...), socks5Ver, socks5.AssociateCommand, 0, addrIPv4, 0, 0, 0, 0, 0, 0))
	f.Add(append(append([]byte(nil), greeting...), socks5Ver, socks5.BindCommand, 0, addrIPv4, 0, 0, 0, 0, 0, 0))
	f.Add(append([]byte{socks5Ver, 3, 0, 1, 2}, socks5Ver, socks5.ConnectCommand, 0, addrFQDN, 0, 0, 80))
	f.Add([]byte{socks5Ver, 0})
	f.Add([]byte{socks5Ver})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		app := &fuzzAppConn{r: bytes.NewReader(data)}
		req, cmd, fqdn, err := socks5Handshake(app)
		consumed := len(data) - app.r.Len()
		answer := app.w.Bytes()

		greetingOK := len(data) >= 2 && data[0] == socks5Ver && data[1] > 0 && len(data) >= 2+int(data[1])
		if greetingOK != bytes.HasPrefix(answer, []byte{socks5Ver, socks5Success}) {
			t.Fatalf("greeting %x answered with %x", data[:min(len(data), 2)], answer)
		}
		if !greetingOK {
			if err == nil || len(answer) != 0 {
				t.Fatalf("a bad greeting gave err=%v and answer %x", err, answer)
			}
			return
		}

		body := data[2+int(data[1]):]
		want, wantErr := socks5.NewRequest(bytes.NewReader(body))

		if err != nil {
			if req != nil {
				t.Fatalf("a refusal returned the request %x", req)
			}
			if wantErr == nil && (want.Command == socks5.ConnectCommand || want.Command == socks5.AssociateCommand) {
				t.Fatalf("refused a request the server accepts: %x: %v", body, err)
			}
			if wantErr == nil && !bytes.Equal(answer[2:], []byte{socks5Ver, socks5CmdNotSup, 0, addrIPv4, 0, 0, 0, 0, 0, 0}) {
				t.Fatalf("command %#x was answered with %x", want.Command, answer[2:])
			}
			return
		}
		if wantErr != nil {
			t.Fatalf("forwarded %x, which the server refuses: %v", req, wantErr)
		}
		if cmd != socks5.ConnectCommand && cmd != socks5.AssociateCommand {
			t.Fatalf("accepted command %#x", cmd)
		}
		if len(answer) != 2 {
			t.Fatalf("an accepted request was answered with %x", answer)
		}
		if consumed != 2+int(data[1])+len(req) || !bytes.Equal(req, body[:len(req)]) {
			t.Fatalf("the request %x is not the %d bytes behind the greeting", req, consumed)
		}
		if want.Command != cmd || want.DestAddr.FQDN != fqdn {
			t.Fatalf("the server reads command %#x and name %q, the client %#x and %q", want.Command, want.DestAddr.FQDN, cmd, fqdn)
		}
		if n := len(body) - len(req); n != bodyLeft(t, body) {
			t.Fatalf("the client and the server end the request at different bytes")
		}
	})
}

// bodyLeft is how many bytes socks5.NewRequest leaves unread behind the
// request in body.
func bodyLeft(t *testing.T, body []byte) int {
	r := bytes.NewReader(body)
	if _, err := socks5.NewRequest(r); err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return r.Len()
}
