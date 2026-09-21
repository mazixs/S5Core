package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// The server's answer to the 0x83 command is the last thing the tunnel carries
// before it carries frames, and the two are read by different loops. Where the
// reply ends is therefore not a detail of parsing: a byte counted as part of
// the reply is a byte the frame loop never sees, and a byte left behind is read
// as a frame length (audit finding F14).

// udpTunnelReply is a well-formed answer to 0x83: success, bound to
// 127.0.0.1:1080.
var udpTunnelReply = []byte{socks5Ver, 0x00, 0x00, addrIPv4, 127, 0, 0, 1, 0x04, 0x38}

// startUDPAssociate runs the client's UDP handler against two ends the test
// drives: the application's SOCKS5 connection and the server's end of the
// tunnel.
func startUDPAssociate(t testing.TB) (app, tunnel net.Conn, done chan struct{}) {
	t.Helper()
	app, clientSide := tcpPair(t)
	tunnel, obfsSide := tcpPair(t)

	done = make(chan struct{})
	go func() {
		defer close(done)
		handleUDPAssociate(clientSide, obfsSide, "example.com", clientParams{})
	}()
	return app, tunnel, done
}

// readAppReply reads the one SOCKS5 reply the client sends its application.
func readAppReply(t testing.TB, app net.Conn) []byte {
	t.Helper()
	_ = app.SetReadDeadline(time.Now().Add(5 * time.Second))

	head := make([]byte, 4, 4+net.IPv6len+2)
	if _, err := io.ReadFull(app, head); err != nil {
		t.Fatalf("the application got no reply from the client: %v", err)
	}
	var addrLen int
	switch head[3] {
	case addrIPv4:
		addrLen = net.IPv4len
	case addrIPv6:
		addrLen = net.IPv6len
	default:
		t.Fatalf("the client told its application about address type %#x", head[3])
	}
	rest := make([]byte, addrLen+2)
	if _, err := io.ReadFull(app, rest); err != nil {
		t.Fatalf("the reply to the application stopped after its header: %v", err)
	}
	return append(head, rest...)
}

// boundUDPPort reads the address a SOCKS5 reply carries.
func boundUDPPort(t testing.TB, reply []byte) *net.UDPAddr {
	t.Helper()
	if reply[3] != addrIPv4 {
		t.Fatalf("expected the client to bind an IPv4 socket, got address type %#x", reply[3])
	}
	return &net.UDPAddr{
		IP:   net.IPv4(reply[4], reply[5], reply[6], reply[7]),
		Port: int(binary.BigEndian.Uint16(reply[8:10])),
	}
}

// datagram is one SOCKS5 UDP request: header naming 198.51.100.7:53 and a
// payload. The client tunnels it verbatim, so the bytes are the assertion.
func datagram(payload string) []byte {
	return append([]byte{0, 0, 0, addrIPv4, 198, 51, 100, 7, 0, 53}, payload...)
}

// tunnelFrame wraps a datagram in the length prefix the tunnel uses.
func tunnelFrame(inner []byte) []byte {
	frame := make([]byte, 2+len(inner))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(inner)))
	copy(frame[2:], inner)
	return frame
}

func TestHalfAReplyIsNotAWorkingTunnel(t *testing.T) {
	app, tunnel, done := startUDPAssociate(t)

	// The server sends the version byte and stops - a connection cut in the
	// middle of the answer, or a server that never meant to finish it.
	if _, err := tunnel.Write([]byte{socks5Ver}); err != nil {
		t.Fatalf("writing the first byte of the reply: %v", err)
	}
	if err := tunnel.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("closing the server's half: %v", err)
	}

	reply := readAppReply(t, app)
	if reply[1] == 0x00 {
		t.Fatalf("the client told its application the UDP tunnel is up after one byte from the server: % x", reply)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler is still running on a tunnel that answered with one byte")
	}
}

func TestAReplyThatArrivesInPiecesIsStillOneReply(t *testing.T) {
	app, tunnel, _ := startUDPAssociate(t)

	// The reply is split where a real connection would split it: the first
	// byte in one segment, the rest in the next.
	if _, err := tunnel.Write(udpTunnelReply[:1]); err != nil {
		t.Fatalf("writing the first byte of the reply: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := tunnel.Write(udpTunnelReply[1:]); err != nil {
		t.Fatalf("writing the rest of the reply: %v", err)
	}

	reply := readAppReply(t, app)
	if reply[1] != 0x00 {
		t.Fatalf("the client refused a tunnel the server accepted: reply % x", reply)
	}
	local := boundUDPPort(t, reply)

	// The application sends one datagram, which is also how the client
	// learns where to send answers.
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("application socket: %v", err)
	}
	defer func() { _ = sender.Close() }()
	outbound := datagram("question")
	if _, err := sender.WriteToUDP(outbound, local); err != nil {
		t.Fatalf("sending a datagram: %v", err)
	}

	// What comes out of the tunnel is the datagram and nothing else: had the
	// tail of the reply been left in the stream, it would be read here as a
	// frame length instead.
	_ = tunnel.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(outbound)+2)
	if _, err := io.ReadFull(tunnel, got); err != nil {
		t.Fatalf("the datagram never reached the server: %v", err)
	}
	if want := tunnelFrame(outbound); !bytes.Equal(got, want) {
		t.Fatalf("the server got % x, want the framed datagram % x", got, want)
	}

	// And the answer comes back, which is the direction the leftover bytes
	// of the reply used to be parsed in.
	inbound := datagram("answer")
	if _, err := tunnel.Write(tunnelFrame(inbound)); err != nil {
		t.Fatalf("answering through the tunnel: %v", err)
	}
	_ = sender.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := sender.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the answer never reached the application: %v", err)
	}
	if !bytes.Equal(buf[:n], inbound) {
		t.Fatalf("the application got % x, want % x", buf[:n], inbound)
	}
}

func TestAReplyTheClientCannotParseIsNotASuccess(t *testing.T) {
	cases := []struct {
		name  string
		reply []byte
	}{
		{"a version that is not 5", []byte{0x04, 0x00, 0x00, addrIPv4, 127, 0, 0, 1, 0x04, 0x38}},
		{"a reserved byte that is not zero", []byte{socks5Ver, 0x00, 0x01, addrIPv4, 127, 0, 0, 1, 0x04, 0x38}},
		{"an address type nobody defines", []byte{socks5Ver, 0x00, 0x00, 0x07, 127, 0, 0, 1, 0x04, 0x38}},
		{"a bound name of zero length", []byte{socks5Ver, 0x00, 0x00, addrFQDN, 0x00, 0x04, 0x38}},
		{"an address that stops short", []byte{socks5Ver, 0x00, 0x00, addrIPv4, 127, 0}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, tunnel, done := startUDPAssociate(t)

			if _, err := tunnel.Write(tc.reply); err != nil {
				t.Fatalf("writing the reply: %v", err)
			}
			if err := tunnel.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatalf("closing the server's half: %v", err)
			}

			reply := readAppReply(t, app)
			if reply[1] == 0x00 {
				t.Fatalf("the client accepted %s and told its application the tunnel is up", tc.name)
			}

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("the handler is still running after %s", tc.name)
			}
		})
	}
}

func TestARefusalFromTheServerReachesTheApplication(t *testing.T) {
	app, tunnel, done := startUDPAssociate(t)

	// Connection not allowed by ruleset, bound to nothing.
	refusal := []byte{socks5Ver, 0x02, 0x00, addrIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := tunnel.Write(refusal); err != nil {
		t.Fatalf("writing the refusal: %v", err)
	}

	reply := readAppReply(t, app)
	if !bytes.Equal(reply, refusal) {
		t.Fatalf("the application got % x, want the server's own refusal % x", reply, refusal)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler is still running after the server refused the tunnel")
	}
}
