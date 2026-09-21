package socks5

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/session"
)

// A UDP association names its destination once per datagram. Historically it
// resolved every name synchronously on the client socket reader.
// A lookup with no deadline there does not delay a datagram, it stops the
// association: every other datagram waits behind it, including the ones for
// destinations that need no lookup at all (audit finding F12).

const datagramLookupBudget = 250 * time.Millisecond

// serveOverTCPWithSession runs one connection through the server over a real
// TCP socket, carrying a session the test controls. A UDP association needs
// the real thing: it only accepts datagrams from the address its TCP
// connection came from, and net.Pipe has no address to compare against.
func serveOverTCPWithSession(t *testing.T, conf *Config, sla session.SLA) net.Conn {
	t.Helper()
	server, err := New(conf)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		sess := session.NewRegistry(nil).Open("plain", false, sla)
		_ = server.ServeConnContext(context.Background(), &sessionConn{Conn: c, sess: sess})
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = ln.Close()
		<-done
	})
	return client
}

// udpHeaderFor builds a SOCKS5 UDP request header naming a destination.
func udpHeaderForIP(addr *net.UDPAddr) []byte {
	ip := addr.IP.To4()
	return []byte{0, 0, 0, ipv4Address, ip[0], ip[1], ip[2], ip[3], byte(addr.Port >> 8), byte(addr.Port)}
}

func udpHeaderForName(name string, port int) []byte {
	hdr := []byte{0, 0, 0, fqdnAddress, byte(len(name))}
	hdr = append(hdr, name...)
	return append(hdr, byte(port>>8), byte(port))
}

func TestALookupForOneDatagramDoesNotStopTheAssociation(t *testing.T) {
	sink := newUDPSink(t, true)
	resolver := &haltingResolver{
		failsafe: 30 * time.Second,
		deadline: make(chan time.Time, 1),
		started:  make(chan struct{}, 1),
	}

	conf := &Config{BindIP: net.ParseIP("127.0.0.1"), Resolver: resolver}
	client := serveOverTCPWithSession(t, conf, session.SLA{Dial: datagramLookupBudget})

	greet(t, client)
	if _, err := client.Write([]byte{5, AssociateCommand, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		t.Fatalf("associate request: %v", err)
	}
	reply := readConnectReply(t, client)
	if reply[1] != successReply {
		t.Fatalf("associate refused with reply %#x", reply[1])
	}
	proxy := &net.UDPAddr{
		IP:   net.IPv4(reply[4], reply[5], reply[6], reply[7]),
		Port: int(reply[8])<<8 | int(reply[9]),
	}

	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	defer func() { _ = sender.Close() }()

	// One datagram for a name that will never resolve.
	stuck := append(udpHeaderForName("never.answers.example", 443), []byte("first")...)
	if _, err := sender.WriteToUDP(stuck, proxy); err != nil {
		t.Fatalf("sending the datagram that hangs: %v", err)
	}
	select {
	case <-resolver.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the association never got as far as the lookup")
	}

	// The lookup is under way and must have been given a deadline: without
	// one there is nothing to end it, and this association is over.
	select {
	case d := <-resolver.deadline:
		if left := time.Until(d); left > datagramLookupBudget {
			t.Fatalf("the lookup was given %s, want no more than the budget of %s", left, datagramLookupBudget)
		}
	case <-time.After(time.Second):
		t.Fatal("the lookup ran with no deadline: one slow name ends the association")
	}

	// A second datagram, for a destination that needs no lookup at all.
	echoed := append(udpHeaderForIP(sink.addr()), []byte("second")...)
	if _, err := sender.WriteToUDP(echoed, proxy); err != nil {
		t.Fatalf("sending the second datagram: %v", err)
	}

	_ = sender.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := sender.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the datagram behind the slow lookup never came back: %v", err)
	}
	if got := string(buf[len(udpHeaderForIP(sink.addr())):n]); got != "second" {
		t.Fatalf("the association answered with %q, want the echo of the second datagram", got)
	}
}

type cancellationOnlyResolver struct{ started, cancelled chan struct{} }

func (r *cancellationOnlyResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	close(r.started)
	<-ctx.Done()
	close(r.cancelled)
	return ctx, nil, ctx.Err()
}

// Exercise both actual handlers: DNS remains blocked until connection teardown,
// so an echo arriving first proves absence of head-of-line DNS blocking.
func TestBothUDPHandlersDeliverIPWhileDNSWaits(t *testing.T) {
	for _, command := range []byte{AssociateCommand, UDPTunnelCommand} {
		t.Run(fmt.Sprintf("command-%x", command), func(t *testing.T) {
			resolver := &cancellationOnlyResolver{started: make(chan struct{}), cancelled: make(chan struct{})}
			sink := newUDPSink(t, true)
			client := serveOverTCPWithSession(t, &Config{BindIP: net.ParseIP("127.0.0.1"), Resolver: resolver}, session.SLA{Dial: time.Minute})
			greet(t, client)
			if _, err := client.Write([]byte{5, command, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
				t.Fatal(err)
			}
			reply := readConnectReply(t, client)
			if reply[1] != successReply {
				t.Fatalf("reply: %x", reply)
			}
			sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			proxy := &net.UDPAddr{IP: net.IPv4(reply[4], reply[5], reply[6], reply[7]), Port: int(reply[8])<<8 | int(reply[9])}
			send := func(body []byte) {
				t.Helper()
				var err error
				if command == AssociateCommand {
					_, err = sender.WriteToUDP(body, proxy)
				} else {
					frame := binary.BigEndian.AppendUint16(nil, uint16(len(body)))
					frame = append(frame, body...)
					_, err = client.Write(frame)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			send(append(udpHeaderForName("blocked.example", 53), []byte("first")...))
			select {
			case <-resolver.started:
			case <-time.After(time.Second):
				t.Fatal("DNS did not start")
			}
			send(append(udpHeaderForIP(sink.addr()), []byte("ip-echo")...))
			var body []byte
			if command == AssociateCommand {
				sender.SetReadDeadline(time.Now().Add(time.Second))
				buf := make([]byte, 2048)
				n, _, err := sender.ReadFromUDP(buf)
				if err != nil {
					t.Fatal(err)
				}
				body = buf[:n]
			} else {
				client.SetReadDeadline(time.Now().Add(time.Second))
				var size [2]byte
				if _, err := io.ReadFull(client, size[:]); err != nil {
					t.Fatal(err)
				}
				body = make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := io.ReadFull(client, body); err != nil {
					t.Fatal(err)
				}
			}
			h, _, err := ParseUDPHeader(body)
			if err != nil || string(body[h:]) != "ip-echo" {
				t.Fatalf("echo: %x, %v", body, err)
			}
			select {
			case <-resolver.cancelled:
				t.Fatal("DNS completed before IP echo")
			default:
			}
			client.Close()
			select {
			case <-resolver.cancelled:
			case <-time.After(time.Second):
				t.Fatal("DNS survived association shutdown")
			}
		})
	}
}
