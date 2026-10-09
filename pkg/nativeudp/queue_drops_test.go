package nativeudp

import (
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func TestProbeACKWriteFailuresAreCountedAndWriterRecovers(t *testing.T) {
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	write := hub.write
	failed := 0
	hub.write = func(wire, oob []byte, to netip.AddrPort) error {
		if failed < 2 {
			failed++
			return syscall.ENOBUFS
		}
		return write(wire, oob, to)
	}
	client, server := pair(t)
	s := hub.RegisterPeer(server.keys, netip.MustParseAddr("127.0.0.1"))
	defer hub.Remove(s)
	c := dialHub(t, hub)
	for range 2 {
		if err := client.SealWriteProbe(Probe{}, func(wire []byte) error { _, err := c.Write(wire); return err }); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, hub, func(st Stats) bool { return st.ProbeACKWriteErrors == 2 })
	if st := hub.Stats(); st.ReadErrors != 0 || st.ProbeACKQueueDrops != 0 || st.Accepted != 2 {
		t.Fatalf("a socket write failure was attributed to another stage: %+v", st)
	}
	if err := client.SealWriteProbe(Probe{}, func(wire []byte) error { _, err := c.Write(wire); return err }); err != nil {
		t.Fatal(err)
	}
	var wire [MaxWire]byte
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	n, err := c.Read(wire[:])
	if err != nil {
		t.Fatal("ACK writer did not recover:", err)
	}
	if p, err := client.Open(wire[:n]); err != nil || p.Kind != KindProbeAck || hub.Stats().ProbeACKWriteErrors != 2 {
		t.Fatal("recovered ACK or error accounting is incorrect")
	}
}

func TestDataQueueDropsAreCountedAndTheQueueRecovers(t *testing.T) {
	client, server := pair(t)
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	s := hub.RegisterPeer(server.keys, netip.MustParseAddr("127.0.0.1"))
	defer hub.Remove(s)
	c := dialHub(t, hub)
	send := func() {
		t.Helper()
		if err := client.SealWrite(KindData, []byte("game"), func(wire []byte) error { _, err := c.Write(wire); return err }); err != nil {
			t.Fatal(err)
		}
	}
	for range 128 {
		send()
	}
	waitFor(t, hub, func(st Stats) bool { return st.DataEnqueued+st.DataQueueDrops == 128 })
	st := hub.Stats()
	if st.Accepted != 128 || st.DataEnqueued != 64 || st.DataQueueDrops != 64 || st.ProbeACKQueueDrops != 0 || len(s.packets) != 64 {
		t.Fatalf("full queue: %+v, pending=%d", st, len(s.packets))
	}
	for range 64 {
		p := <-s.Packets()
		p.Release()
	}
	send()
	waitFor(t, hub, func(st Stats) bool { return st.DataEnqueued == 65 })
	p := <-s.Packets()
	defer p.Release()
	if string(p.Data) != "game" || hub.Stats().DataQueueDrops != 64 {
		t.Fatal("the queue did not recover after being drained")
	}
}

func TestProbeACKQueueDropsAreCountedWithoutBlockingData(t *testing.T) {
	hub, err := Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	release := make(chan struct{})
	defer close(release)
	stalled := make(chan struct{}, 1)
	write := hub.write
	hub.write = func(wire, oob []byte, to netip.AddrPort) error {
		select {
		case stalled <- struct{}{}:
		default:
		}
		<-release
		return write(wire, oob, to)
	}
	client, server := pair(t)
	s := hub.RegisterPeer(server.keys, netip.MustParseAddr("127.0.0.1"))
	defer hub.Remove(s)
	c := dialHub(t, hub)
	sendProbe := func() {
		t.Helper()
		if err := client.SealWriteProbe(Probe{}, func(wire []byte) error { _, err := c.Write(wire); return err }); err != nil {
			t.Fatal(err)
		}
	}
	sendProbe()
	select {
	case <-stalled:
	case <-time.After(time.Second):
		t.Fatal("the ACK writer did not stall")
	}
	const lost = 9
	for range ackQueue + lost {
		sendProbe()
	}
	waitFor(t, hub, func(st Stats) bool { return st.ProbeACKQueueDrops == lost })
	st := hub.Stats()
	if st.Accepted != 1+ackQueue+lost || len(hub.acks) != ackQueue || st.DataQueueDrops != 0 {
		t.Fatalf("ACK queue: %+v, pending=%d", st, len(hub.acks))
	}
	otherClient, otherServer := pairOf(t, 10)
	other := hub.RegisterPeer(otherServer.keys, netip.MustParseAddr("127.0.0.1"))
	defer hub.Remove(other)
	if err := otherClient.SealWrite(KindData, []byte("other game"), func(wire []byte) error { _, err := c.Write(wire); return err }); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-other.Packets():
		defer p.Release()
		if string(p.Data) != "other game" {
			t.Fatal("data changed")
		}
	case <-time.After(time.Second):
		t.Fatal("a full ACK queue blocked another session")
	}
}
