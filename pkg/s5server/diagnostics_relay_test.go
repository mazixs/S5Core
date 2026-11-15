package s5server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
	"uuid"

	"github.com/mazixs/S5Core/internal/socks5"
)

// latencyEvent is what these tests read of a line of an incident.
type latencyEvent struct {
	Flow      uint32 `json:"flow"`
	Leg       string `json:"leg"`
	Transport string `json:"transport"`
	Kind      string `json:"kind"`
	Data      struct {
		Remote    string `json:"remote"`
		OuterFlow uint32 `json:"outer_flow"`
		Evicted   bool   `json:"evicted"`
	} `json:"data"`
}

// saveIncident has the recorder save what it holds - a marker, the tick that
// takes it, the stop that finishes the incident - and reads its events.
func saveIncident(t *testing.T, dir string, stop func()) []latencyEvent {
	t.Helper()
	id := uuid.New().String()
	if err := os.WriteFile(filepath.Join(dir, "trigger.json"), []byte(`{"incident_id":"`+id+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if partial, _ := filepath.Glob(filepath.Join(dir, id+".events.jsonl.*.partial")); len(partial) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the recorder did not take the marker")
		}
	}
	stop()
	data, err := os.ReadFile(filepath.Join(dir, id+".events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var events []latencyEvent
	for line := range bytes.Lines(data) {
		var e latencyEvent
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("%v: %s", err, line)
		}
		events = append(events, e)
	}
	return events
}

// relatedFlow is what an incident holds of a related flow.
type relatedFlow struct {
	open, close latencyEvent
	stages      int
}

// relatedFlows maps the remote address of each outer flow to its related
// flow.
func relatedFlows(events []latencyEvent) map[string]*relatedFlow {
	outer := map[uint32]string{}
	related := map[uint32]*relatedFlow{}
	for _, e := range events {
		switch {
		case e.Kind == "flow_open" && e.Data.OuterFlow == 0:
			outer[e.Flow] = e.Data.Remote
		case e.Kind == "flow_open":
			related[e.Flow] = &relatedFlow{open: e}
		case related[e.Flow] == nil:
		case e.Kind == "stage":
			related[e.Flow].stages++
		case e.Kind == "flow_close":
			related[e.Flow].close = e
		}
	}
	out := map[string]*relatedFlow{}
	for _, f := range related {
		out[outer[f.open.Data.OuterFlow]] = f
	}
	return out
}

// A CONNECT through a server that records its client's socket records the
// destination beside it, and the relay still passes a half-close on in both
// directions and a destination's reset on to the client as a reset.
func TestTheDestinationIsRecordedBesideTheClientsSocket(t *testing.T) {
	dir, stop := startLatency(t)
	srv := startServer(t, Config{ListenIP: "127.0.0.1", Port: anyPort, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	targets := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			targets <- c
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	connect := func() (net.Conn, net.Conn) {
		c, err := net.Dial("tcp", "127.0.0.1:"+plainPortOf(t, srv))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		_ = c.SetDeadline(time.Now().Add(answerWithin))
		if code := socksOver(t, c, socks5.ConnectCommand, []byte{0x01, 127, 0, 0, 1, byte(port >> 8), byte(port)}); code != 0 {
			t.Fatalf("CONNECT refused: %d", code)
		}
		target := <-targets
		t.Cleanup(func() { _ = target.Close() })
		_ = target.SetDeadline(time.Now().Add(answerWithin))
		return c, target
	}

	halfClosed, target := connect()
	if _, err := halfClosed.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := halfClosed.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(target); err != nil || string(got) != "ping" {
		t.Fatalf("the destination read %q, %v", got, err)
	}
	if _, err := target.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	_ = target.Close()
	if got, err := io.ReadAll(halfClosed); err != nil || string(got) != "pong" {
		t.Fatalf("the client read %q, %v", got, err)
	}

	reset, target := connect()
	if err := target.(*net.TCPConn).SetLinger(0); err != nil {
		t.Fatal(err)
	}
	_ = target.Close()
	if _, err := reset.Read(make([]byte, 1)); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("the client read %v after the destination's reset", err)
	}

	for deadline := time.Now().Add(answerWithin); srv.sessions.Len() > 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the relays did not end")
		}
	}
	flows := relatedFlows(saveIncident(t, dir, stop))
	for _, c := range []net.Conn{halfClosed, reset} {
		f, ok := flows[c.LocalAddr().String()]
		if !ok {
			t.Fatalf("no destination beside the client %s", c.LocalAddr())
		}
		if f.open.Leg != "target" || f.open.Transport != "tcp" || f.open.Data.Remote != ln.Addr().String() ||
			f.stages == 0 || f.close.Kind != "flow_close" || f.close.Data.Evicted {
			t.Errorf("the destination of %s: %+v", c.LocalAddr(), f)
		}
	}
}
