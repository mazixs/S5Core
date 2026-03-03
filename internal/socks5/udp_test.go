package socks5

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestUDPAssociate(t *testing.T) {
	// Create a local UDP echo server to act as our target on the internet
	echoAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve echo addr: %v", err)
	}
	echoServer, err := net.ListenUDP("udp", echoAddr)
	if err != nil {
		t.Fatalf("Failed to start echo server: %v", err)
	}
	defer echoServer.Close()

	targetPort := echoServer.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := echoServer.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// The proxy sends us pure UDP payload without the SOCKS5 header.
			// The proxy has stripped it. We just echo the raw payload back.
			echoServer.WriteToUDP(buf[:n], addr)
		}
	}()

	// Create a SOCKS5 server with BindIP explicitly set
	conf := &Config{
		BindIP: net.ParseIP("127.0.0.1"),
	}
	server, err := New(conf)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()
	go server.Serve(ln)

	// Connect to SOCKS5 server
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// 1. SOCKS5 handshake
	req := []byte{0x05, 0x01, 0x00}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	// 2. Send UDP ASSOCIATE command (0x03)
	// We tell the server our IP is 127.0.0.1, port 0 (standard SOCKS5 doesn't enforce this strictly)
	req = []byte{0x05, AssociateCommand, 0x00, 0x01, 127, 0, 0, 1, 0, 0}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Server reply
	resp = make([]byte, 10)
	if _, err := conn.Read(resp); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if resp[1] != 0 {
		t.Fatalf("Expected success, got: %v", resp[1])
	}

	// Extract the BND.ADDR and BND.PORT to know where to send our UDP packets
	proxyIP := net.IPv4(resp[4], resp[5], resp[6], resp[7])
	proxyPort := (int(resp[8]) << 8) | int(resp[9])
	proxyUDPAddr := &net.UDPAddr{IP: proxyIP, Port: proxyPort}

	// 3. Create our local UDP client socket
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to start local UDP client: %v", err)
	}
	defer clientUDP.Close()
	clientUDP.SetDeadline(time.Now().Add(2 * time.Second))

	// 4. Send a UDP packet through the SOCKS5 proxy to the Echo server
	msg := []byte("Hello UDP over SOCKS5!")

	// The packet sent to the SOCKS5 proxy must have the SOCKS5 UDP header!
	destSpec := &AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: targetPort}
	pkt := BuildUDPHeader(destSpec, msg)

	if _, err := clientUDP.WriteToUDP(pkt, proxyUDPAddr); err != nil {
		t.Fatalf("Failed to send UDP packet to proxy: %v", err)
	}

	// 5. Receive the echoed UDP packet from the SOCKS5 proxy
	resBuf := make([]byte, 1024)
	n, _, err := clientUDP.ReadFromUDP(resBuf)
	if err != nil {
		t.Fatalf("Failed to read from proxy: %v", err)
	}

	// 6. Verify payload
	// The client UDP socket receives the SOCKS5 UDP header from the proxy!
	hdrLen, srcAddr, err := ParseUDPHeader(resBuf[:n])
	if err != nil {
		t.Fatalf("Failed to parse response UDP header: %v, raw: %x", err, resBuf[:n])
	}

	if srcAddr.Port != targetPort {
		t.Fatalf("Expected response from target port %d, got %d", targetPort, srcAddr.Port)
	}

	payload := resBuf[hdrLen:n]
	if !bytes.Equal(payload, msg) {
		t.Fatalf("Expected payload %q, got %q", msg, payload)
	}
}

func TestUDPTcpmux(t *testing.T) {
	// Create a local UDP echo server to act as our target on the internet
	echoAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve echo addr: %v", err)
	}
	echoServer, err := net.ListenUDP("udp", echoAddr)
	if err != nil {
		t.Fatalf("Failed to start echo server: %v", err)
	}
	defer echoServer.Close()

	targetPort := echoServer.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := echoServer.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echoServer.WriteToUDP(buf[:n], addr)
		}
	}()

	// Create a SOCKS5 server with BindIP explicitly set
	conf := &Config{
		BindIP: net.ParseIP("127.0.0.1"),
	}
	server, err := New(conf)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()
	go server.Serve(ln)

	// Connect to SOCKS5 server via TCP
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 1. SOCKS5 handshake
	req := []byte{0x05, 0x01, 0x00}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	// 2. Send Custom UDPTunnelCommand (0x83)
	req = []byte{0x05, UDPTunnelCommand, 0x00, 0x01, 127, 0, 0, 1, 0, 0}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Server reply
	resp = make([]byte, 10)
	if _, err := conn.Read(resp); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if resp[1] != 0 {
		t.Fatalf("Expected success, got: %v", resp[1])
	}

	// 3. Send a UDP packet encapsulated in TCP framing [LEN(2)] [SOCKS_UDP_HDR] [DATA]
	msg := []byte("Hello Muxed UDP!")
	destSpec := &AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: targetPort}
	socksHdr := BuildUDPHeader(destSpec, msg)

	frame := make([]byte, 2+len(socksHdr))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(socksHdr)))
	copy(frame[2:], socksHdr)

	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("Failed to write to tcp tunnel: %v", err)
	}

	// 4. Read the encapsulated UDP reply from the TCP stream
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		t.Fatalf("Failed to read reply length: %v", err)
	}
	replyLen := binary.BigEndian.Uint16(lenBuf)

	replyFrame := make([]byte, replyLen)
	if _, err := io.ReadFull(conn, replyFrame); err != nil {
		t.Fatalf("Failed to read reply frame: %v", err)
	}

	// 5. Verify payload
	hdrLen, srcAddr, err := ParseUDPHeader(replyFrame)
	if err != nil {
		t.Fatalf("Failed to parse response UDP header: %v, raw: %x", err, replyFrame)
	}

	if srcAddr.Port != targetPort {
		t.Fatalf("Expected response from target port %d, got %d", targetPort, srcAddr.Port)
	}

	payload := replyFrame[hdrLen:]
	if !bytes.Equal(payload, msg) {
		t.Fatalf("Expected payload %q, got %q", msg, payload)
	}
}
