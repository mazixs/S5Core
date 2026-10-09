package nativeudp

import (
	"net/netip"
	"testing"
	"time"
)

func TestRecoveryProposalsAreOrderedAndIdempotent(t *testing.T) {
	s, _ := pair(t)
	for _, p := range []Probe{{Generation: 1, Limit: 1210}, {Generation: 2, Limit: 1392}, {Generation: 1, Limit: 1200}, {Generation: 2, Limit: 1200}, {Generation: 0, Limit: 1220}} {
		s.ApplyProbeLimit(p)
	}
	gen, limit := s.NegotiatedLimit()
	if gen != 2 || limit != 1392 || s.Limit() != 1392 {
		t.Fatalf("generation %d limit %d", gen, limit)
	}
	if !s.ApplyProbeLimit(Probe{Generation: 2, Limit: 1392}) {
		t.Fatal("duplicate proposal is not idempotent")
	}
	for _, limit := range []int{1, BaseWire - 1, MaxWire + 1, 65535} {
		if s.ApplyProbeLimit(Probe{Generation: 3, Limit: limit}) {
			t.Fatal("out-of-range proposal accepted")
		}
	}
}

func TestRecoveryAnswerEchoesOnlyTheAppliedProposal(t *testing.T) {
	client, server := pair(t)
	for _, p := range []Probe{{Generation: 1}, {Generation: 1, Limit: 1210}, {Generation: 2, Limit: 1392}, {Generation: 1, Limit: 1210}} {
		wire := sealed(t, func(w func([]byte) error) error { return client.SealWriteProbe(p, w) })
		packet, n := open(t, server, wire)
		probe, extended := ParseProbe(packet.Data)
		server.ApplyProbeLimit(probe)
		reply := sealed(t, func(w func([]byte) error) error { return server.SealWriteAnswer(probe, extended, n, w) })
		if len(reply) > len(wire) {
			t.Fatal("recovery answer amplifies")
		}
		packet, _ = open(t, client, reply)
		a, ok := ParseAnswer(packet.Data)
		if !ok {
			t.Fatal("missing answer")
		}
		if p.Limit == 0 {
			if a.Generation != p.Generation || a.Limit != 0 {
				t.Fatal("capability answer claims a proposal")
			}
		} else {
			gen, limit := server.NegotiatedLimit()
			if a.Generation != gen || a.Limit != limit {
				t.Fatal("answer claims an unapplied proposal")
			}
		}
	}
}

func TestLegacyProbeStillGetsALegacyAnswer(t *testing.T) {
	client, server := pair(t)
	wire := sealed(t, func(w func([]byte) error) error { return client.SealWriteProbe(Probe{Limit: 1250}, w) })
	packet, n := open(t, server, wire)
	p, ext := ParseProbe(packet.Data)
	server.ApplyProbeLimit(p)
	reply := sealed(t, func(w func([]byte) error) error { return server.SealWriteAnswer(p, ext, n, w) })
	packet, _ = open(t, client, reply)
	a, _ := ParseAnswer(packet.Data)
	if a.Generation != 0 || server.Limit() != 1250 {
		t.Fatal("legacy peer was upgraded implicitly")
	}
}

func TestHubAppliesRecoveryBeforeAcknowledging(t *testing.T) {
	client, server := pair(t)
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	registered := hub.RegisterPeer(server.keys, netip.MustParseAddr("127.0.0.1"))
	defer hub.Remove(registered)
	c := dialHub(t, hub)
	var b [MaxWire + 1]byte
	for _, p := range []Probe{{Generation: 1, Limit: 1210}, {Generation: 2, Limit: 1392}, {Generation: 1, Limit: 1210}} {
		if err := client.SealWriteProbe(p, func(w []byte) error { _, e := c.Write(w); return e }); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		n, err := c.Read(b[:])
		if err != nil {
			t.Fatal(err)
		}
		packet, err := client.Open(b[:n])
		if err != nil {
			t.Fatal(err)
		}
		a, _ := ParseAnswer(packet.Data)
		gen, limit := registered.NegotiatedLimit()
		if a.Generation != gen || a.Limit != limit || registered.Limit() != limit {
			t.Fatal("hub acknowledged an unapplied generation")
		}
	}
	if registered.Limit() != 1392 {
		t.Fatal("late proposal replaced the recovered limit")
	}
}
