package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// exclusiveWriteConn reports a second concurrent writer by being deliberately
// unsynchronised: inWrite is a plain field, so two goroutines inside Write at
// once is a data race and the race detector says so by name.
//
// This is the guard for plan task Ф6-5, which removed the mutex that used to
// serialise these writes. The mutex was protecting against a writer that does
// not exist; if one is ever added, this test is what notices.
type exclusiveWriteConn struct {
	net.Conn
	inWrite bool
	writes  int
}

func (c *exclusiveWriteConn) Write(b []byte) (int, error) {
	c.inWrite = true
	c.writes++
	n, err := c.Conn.Write(b)
	c.inWrite = false
	return n, err
}

// TestOnlyOneGoroutineWritesToTheTunnel drives datagrams through the UDP-over-TCP
// tunnel in both directions at once and fails - under -race - if more than one
// goroutine writes to the TCP connection.
func TestOnlyOneGoroutineWritesToTheTunnel(t *testing.T) {
	// A UDP echo, so every datagram sent produces one coming back and the two
	// directions are busy at the same time.
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = echo.Close() }()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(buf[:n], addr)
		}
	}()
	targetPort := echo.LocalAddr().(*net.UDPAddr).Port

	server, err := New(&Config{
		BindIP: net.ParseIP("127.0.0.1"),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	clientSide, serverSide := net.Pipe()
	counted := &exclusiveWriteConn{Conn: serverSide}
	go func() { _ = server.ServeConnContext(context.Background(), counted) }()

	if err := clientSide.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	// Greeting and the tunnel command, then the reply.
	if _, err := clientSide.Write([]byte{Socks5Version, 1, NoAuth}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if _, err := io.ReadFull(clientSide, make([]byte, 2)); err != nil {
		t.Fatalf("method reply: %v", err)
	}
	if _, err := clientSide.Write([]byte{Socks5Version, UDPTunnelCommand, 0, ipv4Address, 127, 0, 0, 1, 0, 0}); err != nil {
		t.Fatalf("tunnel command: %v", err)
	}
	if _, err := io.ReadFull(clientSide, make([]byte, 10)); err != nil {
		t.Fatalf("tunnel reply: %v", err)
	}

	const datagrams = 64
	dest := &AddrSpec{IP: net.ParseIP("127.0.0.1").To4(), Port: targetPort}

	sendErr := make(chan error, 1)
	go func() {
		for i := 0; i < datagrams; i++ {
			payload := BuildUDPHeader(dest, []byte("datagram"))
			frame := make([]byte, 2+len(payload))
			binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
			copy(frame[2:], payload)
			if _, err := clientSide.Write(frame); err != nil {
				sendErr <- err
				return
			}
		}
		sendErr <- nil
	}()

	// Read back as many as arrive. UDP may drop, so the test does not insist
	// on all of them - what it is watching is who writes, not how many.
	received := 0
	deadline := time.After(15 * time.Second)
	for received < datagrams {
		type frame struct {
			data []byte
			err  error
		}
		got := make(chan frame, 1)
		go func() {
			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(clientSide, lenBuf); err != nil {
				got <- frame{err: err}
				return
			}
			body := make([]byte, binary.BigEndian.Uint16(lenBuf))
			if _, err := io.ReadFull(clientSide, body); err != nil {
				got <- frame{err: err}
				return
			}
			got <- frame{data: body}
		}()
		select {
		case f := <-got:
			if f.err != nil {
				t.Fatalf("read a tunnel frame: %v", f.err)
			}
			hdr, _, err := ParseUDPHeader(f.data)
			if err != nil {
				t.Fatalf("parse a tunnel frame: %v", err)
			}
			if string(f.data[hdr:]) != "datagram" {
				t.Fatalf("the tunnel carried %q", f.data[hdr:])
			}
			received++
		case <-deadline:
			// Enough came back to have exercised both directions at once.
			if received == 0 {
				t.Fatal("nothing came back through the tunnel")
			}
			t.Logf("%d of %d datagrams came back; UDP is allowed to drop", received, datagrams)
			received = datagrams
		}
	}

	if err := <-sendErr; err != nil {
		t.Fatalf("sending through the tunnel: %v", err)
	}
	_ = clientSide.Close()
}
