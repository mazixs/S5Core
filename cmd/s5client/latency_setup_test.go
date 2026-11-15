package main

import (
	"net"
	"testing"
	"time"
)

// listenAndClose is a server that accepts and hangs up at once.
func listenAndClose(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

// Every setup of a tunnel on a selected transport is one stage of its flow,
// written before a failed setup closes the flow: on a fresh dial, with the
// answer to the greeting left to the caller, failed, on a spare, and on a
// transport that is no spare but may be set up again like one.
func TestEverySetupOfATunnelIsAStageOfItsFlow(t *testing.T) {
	dir, stop := startLatency(t)
	addr, srv := startTunnelServer(t, false)
	refuser := listenAndClose(t)
	cfg := clientParams{ServerAddr: addr, PSK: srv.ObfsPSK, MTU: 1400, MaxPadding: 32, Transport: "obfs", HandshakeTimeout: 3 * time.Second}
	req := connectTo(t, listenAndClose(t))
	setUp := func(cfg clientParams, wantErr bool) {
		t.Helper()
		c, err := dialObfsTunnel(cfg, req)
		if (err != nil) != wantErr {
			t.Fatalf("setup on %s: %v", cfg.ServerAddr, err)
		}
		if c != nil {
			_ = c.Close()
		}
	}
	setUp(cfg, false)
	deferred := cfg
	deferred.deferGreeting = true
	setUp(deferred, false)
	failing := cfg
	failing.ServerAddr = refuser
	setUp(failing, true)

	spare, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	spares.mu.Lock()
	spares.on = true
	spares.spare = &spareConn{conn: spare, key: spareKey(cfg), born: spares.stamp(), maxAge: time.Minute, expire: time.AfterFunc(time.Hour, func() {})}
	spares.mu.Unlock()
	t.Cleanup(spares.stop)
	setUp(cfg, false)

	// An early upgrade may be set up again as a spare may, but it was dialed
	// for its tunnel.
	early, onSpare, err := handshakeTunnel(cfg, req, func(clientParams) (net.Conn, bool, error) {
		c, err := net.Dial("tcp", addr)
		return c, true, err
	})
	if err != nil || !onSpare {
		t.Fatalf("setup like an early upgrade: on a spare %v, %v", onSpare, err)
	}
	_ = early.Close()

	events := saveIncident(t, dir, stop)
	remotes := map[uint32]string{}
	var got []latencyEvent
	for _, e := range events {
		switch {
		case e.Kind == "flow_open" && e.Leg == "outer":
			remotes[e.Flow] = e.Data.Remote
		case e.Kind == "stage" && e.Data.Boundary == "tunnel_setup":
			got = append(got, e)
		}
	}
	want := []struct {
		remote                string
		spare, deferred, fail bool
	}{
		{addr, false, false, false},
		{addr, false, true, false},
		{refuser, false, false, true},
		{addr, true, false, false},
		{addr, false, false, false},
	}
	if len(got) != len(want) {
		t.Fatalf("%d setups recorded, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		e := got[i]
		if remotes[e.Flow] != w.remote || e.Transport != "obfs" ||
			e.Data.Spare != w.spare || e.Data.Deferred != w.deferred || e.Data.Error != w.fail {
			t.Errorf("setup %d on flow %d to %s: %+v", i, e.Flow, remotes[e.Flow], e.Data)
		}
	}
}
