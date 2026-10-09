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

// A client that does not wait for the reply to its association writes the
// first datagrams right behind the request (docs/veil-spec.md, 10.2). They
// arrive with the request and end up in the handshake buffer, and the server
// must hand them to the association rather than read past them.
func TestDatagramsBehindTheRequestReachTheTarget(t *testing.T) {
	cases := []struct {
		name    string
		command byte
		native  func(net.Conn) (NativeAssociation, error)
	}{
		{"0x83", UDPTunnelCommand, nil},
		{"0x84 without a native path", UDPNativeCommand, func(net.Conn) (NativeAssociation, error) { return nil, nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = target.Close() }()

			server, err := New(&Config{
				BindIP:    net.ParseIP("127.0.0.1"),
				Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
				NativeUDP: tc.native,
			})
			if err != nil {
				t.Fatal(err)
			}
			client, serverSide := net.Pipe()
			served := make(chan struct{})
			go func() {
				defer close(served)
				_ = server.ServeConnContext(context.Background(), serverSide)
			}()
			defer func() {
				_ = client.Close()
				<-served
			}()
			_ = client.SetDeadline(time.Now().Add(10 * time.Second))

			// Greeting, request and three datagrams in one write, the way a
			// member's client sends them when the application is quick.
			dest := &AddrSpec{IP: net.ParseIP("127.0.0.1").To4(), Port: target.LocalAddr().(*net.UDPAddr).Port}
			wire := []byte{Socks5Version, 1, NoAuth, Socks5Version, tc.command, 0, ipv4Address, 0, 0, 0, 0, 0, 0}
			payloads := []string{"first", "second", "third"}
			for _, p := range payloads {
				body := BuildUDPHeader(dest, []byte(p))
				wire = binary.BigEndian.AppendUint16(wire, uint16(len(body)))
				wire = append(wire, body...)
			}
			written := make(chan error, 1)
			go func() {
				_, err := client.Write(wire)
				written <- err
			}()

			// The method reply and the reply to the request come after all of
			// it was read.
			reply := make([]byte, 2+10)
			if _, err := io.ReadFull(client, reply); err != nil {
				t.Fatalf("the replies: %v", err)
			}
			if reply[3] != successReply {
				t.Fatalf("reply % x, want success", reply[2:])
			}
			if err := <-written; err != nil {
				t.Fatalf("writing the request and the datagrams: %v", err)
			}

			_ = target.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 2048)
			for _, want := range payloads {
				n, _, err := target.ReadFromUDP(buf)
				if err != nil {
					t.Fatalf("datagram %q never reached the target: %v", want, err)
				}
				if got := string(buf[:n]); got != want {
					t.Fatalf("the target got %q, want %q", got, want)
				}
			}
		})
	}
}
