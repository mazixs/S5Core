package main

import (
	"io"
	"net"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// connectServer is a server for one tunnel: it answers the greeting and the
// CONNECT, with code, delay after the request has come. If it accepted, it
// sends "hi" and ends the stream as the server does when its target hangs up:
// a FIN frame, and the tunnel kept until the client ends its half. A tunnel
// closed under the stream without the FIN frame is a truncated answer, which
// the client passes on as a reset, and on Windows a reset discards what the
// application has not read yet.
func connectServer(t *testing.T, psk string, delay time.Duration, code byte) (addr string, done func()) {
	t.Helper()
	return startTestObfsServer(t, psk, func(t *testing.T, conn net.Conn) {
		if _, err := io.ReadFull(conn, make([]byte, 3+len(clientRequest()))); err != nil {
			t.Errorf("greeting and request: %v", err)
			return
		}
		time.Sleep(delay)
		_, _ = conn.Write([]byte{0x05, 0x00})
		_, _ = conn.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		if code == socks5Success {
			_, _ = conn.Write([]byte("hi"))
			_ = conn.(interface{ CloseWrite() error }).CloseWrite()
			_, _ = io.Copy(io.Discard, conn)
		}
	})
}

// The setup_ms and the reply, if any, of each "TCP Tunnel closed" line.
var tunnelClosedLine = regexp.MustCompile(`msg="TCP Tunnel closed" .*server=(\S+) .*setup_ms=(\d+)(?: .*reply=(\d+))?`)

// Every CONNECT the server accepts is one tunnel_setup on the flow of its
// transport, as long as the setup_ms of the connection's line, which the log
// gives in whole milliseconds: a plain and an optimistic CONNECT, each on a
// fresh dial and on a spare. A refused CONNECT has none.
func TestEveryAcceptedConnectIsAStageOfItsFlow(t *testing.T) {
	logs := captureLogs(t)
	dir, stop := startLatency(t)
	const psk = "01234567890123456789012345678901"
	t.Cleanup(spares.stop)

	type setup struct {
		optimistic, spare bool
		delay             time.Duration
		code              byte
		addr              string
	}
	setups := []*setup{
		{false, false, 20 * time.Millisecond, socks5Success, ""},
		{true, false, 30 * time.Millisecond, socks5Success, ""},
		{false, true, 40 * time.Millisecond, socks5Success, ""},
		{true, true, 50 * time.Millisecond, socks5Success, ""},
		{false, false, 0, 0x05, ""},
		{true, false, 0, 0x05, ""},
	}
	for _, s := range setups {
		var done func()
		s.addr, done = connectServer(t, psk, s.delay, s.code)
		cfg := clientParams{ServerAddr: s.addr, PSK: psk, MTU: 1400, OptimisticConnect: s.optimistic}
		if s.spare {
			c, err := net.Dial("tcp", s.addr)
			if err != nil {
				t.Fatal(err)
			}
			spares.mu.Lock()
			spares.on = true
			spares.spare = &spareConn{conn: c, key: spareKey(cfg), born: spares.stamp(), maxAge: time.Minute, expire: time.AfterFunc(time.Hour, func() {})}
			spares.mu.Unlock()
		}
		app, local := tcpPair(t)
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			handleClient(local, cfg, newDomainMatcher(nil))
		}()
		_ = app.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := app.Write(append([]byte{0x05, 0x01, 0x00}, clientRequest()...)); err != nil {
			t.Fatal(err)
		}
		want := 2 + 10
		if s.code == socks5Success {
			want += len("hi")
		}
		if _, err := io.ReadFull(app, make([]byte, want)); err != nil {
			t.Fatalf("%+v: %v", *s, err)
		}
		if s.optimistic && s.code != socks5Success {
			// The refusal of an optimistic CONNECT is the end of the connection.
			_, _ = io.Copy(io.Discard, app)
		}
		_ = app.Close()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Fatalf("%+v: the connection did not end", *s)
		}
		done()
		if s.spare {
			// A pool that is on dials a spare for the next tunnel, and the
			// next server takes one connection only.
			spares.stop()
		}
	}

	lines := map[string][]string{}
	for _, m := range tunnelClosedLine.FindAllStringSubmatch(logs.String(), -1) {
		lines[m[1]] = m[2:]
	}
	events := saveIncident(t, dir, stop)
	remotes := map[uint32]string{}
	recorded := map[string]latencyEvent{}
	for _, e := range events {
		switch {
		case e.Kind == "flow_open" && e.Leg == "outer":
			remotes[e.Flow] = e.Data.Remote
		case e.Kind == "stage" && e.Data.Boundary == "tunnel_setup":
			if _, twice := recorded[remotes[e.Flow]]; twice {
				t.Fatalf("a second setup of the tunnel to %s", remotes[e.Flow])
			}
			recorded[remotes[e.Flow]] = e
		}
	}
	for _, s := range setups {
		line, ok := lines[s.addr]
		if !ok {
			t.Fatalf("%+v: no line", *s)
		}
		e, ok := recorded[s.addr]
		if s.code != socks5Success {
			if ok || line[1] != strconv.Itoa(int(s.code)) {
				t.Errorf("%+v: refused with reply %q, recorded %v", *s, line[1], ok)
			}
			continue
		}
		setupMS, _ := strconv.ParseInt(line[0], 10, 64)
		took := time.Duration(e.Data.DurationNS)
		if !ok || e.Transport != "obfs" || e.Data.Spare != s.spare || took < s.delay || took.Milliseconds() != setupMS {
			t.Errorf("%+v: recorded %v %+v, setup_ms %d", *s, ok, e.Data, setupMS)
		}
	}
}
