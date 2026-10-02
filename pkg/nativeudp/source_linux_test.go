package nativeudp

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// Finding 4 of the 2.3 review. A hub on a wildcard address must answer from
// the address the client wrote to. The kernel picks the source by the route
// back to the client, and on a host with a second address that is the other
// one: the client's connected socket drops the answer, and so does a NAT in
// front of it. On loopback, 127.0.0.2 is that second address, and the route
// back to 127.0.0.1 has 127.0.0.1 as its source.
func TestAWildcardHubAnswersFromTheAddressItWasAsked(t *testing.T) {
	listen := map[string]func() (*Hub, error){
		"0.0.0.0:0": func() (*Hub, error) { return Listen("0.0.0.0:0", nil) },
		"[::]:0":    func() (*Hub, error) { return Listen("[::]:0", nil) },
		// A host without IPv6 gives the hub a socket that is IPv4 only.
		"udp4 0.0.0.0:0": func() (*Hub, error) {
			c, err := net.ListenUDP("udp4", &net.UDPAddr{})
			if err != nil {
				return nil, err
			}
			return serve(c, true, nil), nil
		},
	}
	for name, open := range listen {
		t.Run(name, func(t *testing.T) {
			client, server := pair(t)
			hub, err := open()
			if err != nil {
				t.Skipf("cannot listen on %s: %v", name, err)
			}
			defer hub.Close()
			registered := hub.Register(server.keys)
			defer hub.Remove(registered)
			c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: hub.Port()})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			wire, _ := client.Seal(nil, KindProbe, nil)
			if _, err := c.Write(wire); err != nil {
				t.Fatal(err)
			}
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			var b [MaxWire]byte
			n, err := c.Read(b[:])
			if err != nil {
				t.Fatalf("no answer on the address the client wrote to: %v", err)
			}
			if p, err := client.Open(b[:n]); err != nil || p.Kind != KindProbeAck {
				t.Fatalf("probe: %v %+v", err, p)
			}
			// The hub's own answers carry the source as well, not only the
			// answer to a probe.
			if err := hub.Send(registered, KindData, []byte("reply")); err != nil {
				t.Fatal(err)
			}
			n, err = c.Read(b[:])
			if err != nil {
				t.Fatalf("data from the hub: %v", err)
			}
			if p, err := client.Open(b[:n]); err != nil || string(p.Data) != "reply" {
				t.Fatalf("reply: %v %+v", err, p)
			}
		})
	}
}

// The hub's address the client wrote to is part of where the answers go, and
// moves only by the rule the client's address moves by: two newest datagrams
// in a row. It used to move with any datagram, so one copy sent to another
// address of the host moved the source of every answer, and the client's
// connected socket dropped them all.
func TestTheSourceOfTheAnswersMovesOnlyWhenTheNewAddressLeads(t *testing.T) {
	client, server := pair(t)
	hub, err := Listen("0.0.0.0:0", nil)
	if err != nil {
		t.Skipf("cannot listen on the wildcard address: %v", err)
	}
	defer hub.Close()
	registered := hub.Register(server.keys)
	defer hub.Remove(registered)
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	accepted := uint64(0)
	to := func(ip string) {
		t.Helper()
		wire, _ := client.Seal(nil, KindData, []byte("tick"))
		if _, err := c.WriteToUDPAddrPort(wire, netip.AddrPortFrom(netip.MustParseAddr(ip), uint16(hub.Port()))); err != nil {
			t.Fatal(err)
		}
		accepted++
		waitFor(t, hub, func(s Stats) bool { return s.Accepted == accepted })
	}
	answersFrom := func(want, why string) {
		t.Helper()
		if err := hub.Send(registered, KindData, []byte("reply")); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		var b [MaxWire]byte
		_, from, err := c.ReadFromUDPAddrPort(b[:])
		if err != nil {
			t.Fatalf("%s: no answer: %v", why, err)
		}
		if got := from.Addr().Unmap().String(); got != want {
			t.Fatalf("%s: the answer came from %s, want %s", why, got, want)
		}
	}
	to("127.0.0.2")
	answersFrom("127.0.0.2", "the first datagram")
	to("127.0.0.1")
	answersFrom("127.0.0.2", "one datagram to another address")
	to("127.0.0.2")
	to("127.0.0.1")
	to("127.0.0.1")
	answersFrom("127.0.0.1", "two newest datagrams to the new address")
}
