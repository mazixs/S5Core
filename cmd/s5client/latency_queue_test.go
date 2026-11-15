package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
)

// stallingTunnel holds the writes to the tunnel while stalled until
// released.
type stallingTunnel struct {
	net.Conn
	stalled atomic.Bool
	release chan struct{}
}

func (c *stallingTunnel) Write(p []byte) (int, error) {
	if c.stalled.Load() {
		<-c.release
	}
	return c.Conn.Write(p)
}

func (c *stallingTunnel) NetConn() net.Conn { return c.Conn }

// Both ends of a native association record the queue of its stream beside
// their outer flow. On the client a write the tunnel holds shows there
// before it returns, with the datagrams native does not carry waiting behind
// it.
func TestBothEndsRecordTheQueueOfANativeStream(t *testing.T) {
	dir, stop := startLatency(t)
	addr, cfg := startTunnelServer(t, true)
	echo := udpEcho(t)
	clientCfg := nativeParams(addr, cfg.ObfsPSK)
	t.Cleanup(func() { noNative.Delete(nativeKey(clientCfg)) })
	tunnels := make(chan *stallingTunnel, 1)
	dial := func(cfg clientParams, req []byte) (net.Conn, clientParams, error) {
		c, used, err := dialAttempt(cfg, req)
		if err != nil {
			return nil, used, err
		}
		s := &stallingTunnel{Conn: c, release: make(chan struct{})}
		tunnels <- s
		return s, used, nil
	}
	app, handlerSide := tcpPair(t)
	runUDPAssociate(t, handlerSide, "", clientCfg.attempt(), []byte{5, socks5.UDPNativeCommand, 0, 1, 0, 0, 0, 0, 0, 0}, dial)
	reply := readAppReply(t, app)
	if reply[1] != 0 {
		t.Fatalf("application refused: %x", reply)
	}
	var tunnel *stallingTunnel
	select {
	case tunnel = <-tunnels:
	case <-time.After(5 * time.Second):
		t.Fatal("the association opened no tunnel")
	}
	t.Cleanup(func() { close(tunnel.release) })
	sender, local := appSocket(t), boundUDPPort(t, reply)
	// An answer comes once the association runs, its writer with it.
	tick(t, sender, local, echo, 0)
	tunnel.stalled.Store(true)
	// Too long for native: at most nativeOversizeDrops of them are dropped,
	// the rest go by the stream.
	long := socksDatagram(&socks5.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: echo.LocalAddr().(*net.UDPAddr).Port}, make([]byte, 1500))
	for range nativeOversizeDrops + 4 {
		if _, err := sender.WriteToUDP(long, local); err != nil {
			t.Fatal(err)
		}
	}
	// Two samples at least while the first of them is held.
	time.Sleep(3 * time.Second / 2)
	events := saveIncident(t, dir, stop)

	var client, server uint32
	for _, e := range events {
		switch {
		case e.Kind != "flow_open" || e.Leg != "outer":
		case e.Data.Remote == addr:
			client = e.Flow
		case e.Data.Local == addr:
			server = e.Flow
		}
	}
	queues := map[uint32]int{}
	var longest int64
	var behind int
	for _, e := range events {
		if e.Kind != "queue" {
			continue
		}
		queues[e.Flow]++
		if e.Flow == client && e.Data.Writing && e.Data.WriteElapsedNS > longest {
			longest, behind = e.Data.WriteElapsedNS, e.Data.QueuedFrames
		}
	}
	if client == 0 || server == 0 || queues[client] < 2 || queues[server] < 2 || len(queues) != 2 {
		t.Fatalf("client flow %d, server flow %d, queue events by flow %v", client, server, queues)
	}
	t.Logf("the client's tunnel held a write for %v, %d frames behind it", time.Duration(longest), behind)
	if longest < int64(400*time.Millisecond) || behind < 3 {
		t.Fatalf("the longest write the client's tunnel held: %v, %d frames behind it", time.Duration(longest), behind)
	}
}
