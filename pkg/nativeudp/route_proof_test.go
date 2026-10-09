package nativeudp

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"
)

func proveReturnPath(t *testing.T, client *Session, c *net.UDPConn, write func([]byte) error) {
	t.Helper()
	var requestBytes int
	if err := client.SealWriteProbe(Probe{RouteProof: true}, func(wire []byte) error { requestBytes = len(wire); return write(wire) }); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var b [MaxWire]byte
	n, err := c.Read(b[:])
	if err != nil {
		t.Fatal(err)
	}
	if n > requestBytes {
		t.Fatalf("challenge amplified %d to %d", requestBytes, n)
	}
	p, err := client.Open(b[:n])
	if err != nil {
		t.Fatal(err)
	}
	a, _ := ParseAnswer(p.Data)
	if !a.RouteChallenge || a.RouteToken == [16]byte{} {
		t.Fatal("candidate was not challenged")
	}
	if err := client.SealWriteProbe(Probe{RouteProof: true, RouteEcho: true, RouteToken: a.RouteToken}, write); err != nil {
		t.Fatal(err)
	}
	n, err = c.Read(b[:])
	if err != nil {
		t.Fatal(err)
	}
	p, err = client.Open(b[:n])
	if err != nil {
		t.Fatal(err)
	}
	a, _ = ParseAnswer(p.Data)
	if p.Kind != KindProbeAck || a.RouteChallenge {
		t.Fatal("proof did not establish a normal route")
	}
}

func TestAnUnknownPeerNeedsProofBeforeAnyApplicationDatagram(t *testing.T) {
	client, server := pair(t)
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	s := hub.Register(server.keys)
	defer hub.Remove(s)
	c := dialHub(t, hub)
	for i := 0; i < 4; i++ {
		if err := client.SealWrite(KindData, []byte("spoofed"), func(wire []byte) error { _, err := c.Write(wire); return err }); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, hub, func(st Stats) bool { return st.Accepted == 4 })
	if _, ok := s.Peer(); ok {
		t.Fatal("data authenticated an unverified route")
	}
	if len(s.Packets()) != 0 || hub.Send(s, KindData, bytes.Repeat([]byte{1}, 1000)) == nil {
		t.Fatal("unverified route carried application data")
	}
	proveReturnPath(t, client, c, func(wire []byte) error { _, err := c.Write(wire); return err })
	if err := client.SealWrite(KindData, []byte("verified"), func(wire []byte) error { _, err := c.Write(wire); return err }); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-s.Packets():
		defer p.Release()
		if string(p.Data) != "verified" {
			t.Fatal("wrong data")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("verified route did not deliver")
	}
}

func TestRouteProofExpiresAndIsBoundedToTheAddressAndAssociation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, s := pair(t)
		_, other := pairOf(t, 10)
		h := &Hub{acks: make(chan ackRequest, ackQueue)}
		peer := netip.MustParseAddrPort("127.0.0.1:12000")
		wrong := netip.MustParseAddrPort("127.0.0.1:12001")
		p := Probe{RouteProof: true}
		if s.follow(h, peer, netip.Addr{}, p, true, 100) {
			t.Fatal("proposal became a route")
		}
		a := <-h.acks
		p.RouteEcho, p.RouteToken = true, a.token
		if s.follow(h, wrong, netip.Addr{}, p, true, 100) || other.follow(h, peer, netip.Addr{}, p, true, 100) {
			t.Fatal("token accepted at another route or association")
		}
		time.Sleep(6 * time.Second)
		if s.follow(h, peer, netip.Addr{}, p, true, 100) {
			t.Fatal("expired token accepted")
		}
		p.RouteEcho = false
		for i := 0; i < 1000; i++ {
			s.follow(h, netip.AddrPortFrom(peer.Addr(), uint16(13000+i)), netip.Addr{}, p, true, 100)
		}
		if len(h.acks) != 1 {
			t.Fatalf("challenge count %d, want one", len(h.acks))
		}
		a = <-h.acks
		p.RouteEcho, p.RouteToken = true, a.token
		if !s.follow(h, a.route.peer, netip.Addr{}, p, true, 100) {
			t.Fatal("valid current proof refused")
		}
	})
}

func TestALegacyInitialRouteMustMatchTheAuthenticatedTCPPeer(t *testing.T) {
	_, s := pair(t)
	s.legacyPeer = netip.MustParseAddr("127.0.0.1")
	h := &Hub{acks: make(chan ackRequest, ackQueue)}
	if s.follow(h, netip.MustParseAddrPort("127.0.0.2:9000"), netip.Addr{}, Probe{}, true, 60) {
		t.Fatal("legacy route redirected outside the TCP peer")
	}
	if !s.follow(h, netip.MustParseAddrPort("127.0.0.1:9000"), netip.Addr{}, Probe{}, true, 60) {
		t.Fatal("compatible initial route refused")
	}
	if s.follow(h, netip.MustParseAddrPort("127.0.0.1:9001"), netip.Addr{}, Probe{}, true, 60) {
		t.Fatal("legacy route migrated without proof")
	}
}
