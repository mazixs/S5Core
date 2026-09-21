package socks5

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// udpAssociate opens an association and returns the client's UDP socket, the
// address the server advertised, and the TCP connection that keeps the
// association alive.
func udpAssociate(t *testing.T, bindIP string) (*net.UDPConn, *net.UDPAddr, net.Conn) {
	t.Helper()

	server, err := New(&Config{BindIP: net.ParseIP(bindIP)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(bindIP, "0"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = server.ServeContext(context.Background(), ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if _, err := conn.Read(make([]byte, 2)); err != nil {
		t.Fatalf("method reply: %v", err)
	}
	if _, err := conn.Write([]byte{0x05, AssociateCommand, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		t.Fatalf("associate: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := conn.Read(reply); err != nil {
		t.Fatalf("associate reply: %v", err)
	}
	if reply[1] != 0 {
		t.Fatalf("associate refused: %v", reply[1])
	}
	advertised := &net.UDPAddr{
		IP:   net.IPv4(reply[4], reply[5], reply[6], reply[7]),
		Port: int(reply[8])<<8 | int(reply[9]),
	}

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(bindIP), Port: 0})
	if err != nil {
		t.Fatalf("client udp socket: %v", err)
	}
	t.Cleanup(func() { _ = clientUDP.Close() })
	if err := clientUDP.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	return clientUDP, advertised, conn
}

// udpEchoServer answers every datagram with its payload and reports the
// address each one came from.
func udpEchoServer(t *testing.T) (*net.UDPAddr, <-chan *net.UDPAddr) {
	t.Helper()
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("echo server: %v", err)
	}
	t.Cleanup(func() { _ = echo.Close() })

	seen := make(chan *net.UDPAddr, 8)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			select {
			case seen <- addr:
			default:
			}
			_, _ = echo.WriteToUDP(buf[:n], addr)
		}
	}()
	return echo.LocalAddr().(*net.UDPAddr), seen
}

// The association now has two sockets, and this is the difference an operator
// could see on the wire: the port the client was told to use is not the port
// the internet is answered from. One socket meant the advertised port was
// also the egress port, so every target learned the address the client talks
// to (plan task Ф6-5).
func TestTheUDPEgressPortIsNotTheAdvertisedPort(t *testing.T) {
	clientUDP, advertised, _ := udpAssociate(t, "127.0.0.1")
	target, seen := udpEchoServer(t)

	payload := []byte("who am I talking to?")
	request := BuildUDPHeader(&AddrSpec{IP: target.IP, Port: target.Port}, payload)
	if _, err := clientUDP.WriteToUDP(request, advertised); err != nil {
		t.Fatalf("write to relay: %v", err)
	}

	var from *net.UDPAddr
	select {
	case from = <-seen:
	case <-time.After(3 * time.Second):
		t.Fatal("the target never received the datagram")
	}
	if from.Port == advertised.Port {
		t.Fatalf("the relay sent to the target from its advertised port %d: one socket serves both sides", from.Port)
	}

	// And the reply still finds its way home, which is the other half of the
	// claim: two sockets, one association.
	buf := make([]byte, 2048)
	n, _, err := clientUDP.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read the echo: %v", err)
	}
	hdrLen, _, err := ParseUDPHeader(buf[:n])
	if err != nil {
		t.Fatalf("parse the reply header: %v", err)
	}
	if !bytes.Equal(buf[hdrLen:n], payload) {
		t.Fatalf("the echo came back as %q, want %q", buf[hdrLen:n], payload)
	}
}

// A stranger who finds the advertised port used to be able to put datagrams
// into the client's stream: with one socket, anything arriving from an address
// that was not the client's was taken for a target's reply and forwarded. The
// client-facing socket now speaks to the client and to nobody else.
func TestAStrangerCannotInjectIntoTheUDPAssociation(t *testing.T) {
	clientUDP, advertised, _ := udpAssociate(t, "127.0.0.1")
	target, _ := udpEchoServer(t)

	// First a real datagram, so the relay knows the client's UDP address -
	// without it nothing would be forwarded to the client at all and the test
	// would pass for the wrong reason.
	hello := []byte("hello")
	if _, err := clientUDP.WriteToUDP(BuildUDPHeader(&AddrSpec{IP: target.IP, Port: target.Port}, hello), advertised); err != nil {
		t.Fatalf("write to relay: %v", err)
	}
	buf := make([]byte, 2048)
	if _, _, err := clientUDP.ReadFromUDP(buf); err != nil {
		t.Fatalf("the echo never came back: %v", err)
	}

	// 127.0.0.2 is the whole of the attacker: another address on this host,
	// which is all "not the client" has to mean.
	stranger, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 0})
	if err != nil {
		t.Skipf("no second loopback address to send from: %v", err)
	}
	defer func() { _ = stranger.Close() }()
	if _, err := stranger.WriteToUDP([]byte("injected"), advertised); err != nil {
		t.Fatalf("the stranger could not send: %v", err)
	}

	_ = clientUDP.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	n, from, err := clientUDP.ReadFromUDP(buf)
	if err == nil {
		t.Fatalf("the client received %d bytes from %s that no target sent: %q", n, from, buf[:n])
	}
	if !isTimeout(err) {
		t.Fatalf("unexpected error waiting for silence: %v", err)
	}
}
