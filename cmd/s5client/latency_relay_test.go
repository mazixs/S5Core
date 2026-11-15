package main

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

	"github.com/mazixs/S5Core/internal/diagnostics"
	"github.com/mazixs/S5Core/pkg/obfs"
)

// startLatency turns the latency recorder on for the test and waits until
// it selects a socket. It returns the recorder's directory and its stop.
func startLatency(t *testing.T) (dir string, stop func()) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "diag")
	t.Setenv("S5_DIAGNOSTICS_DIR", dir)
	stop = diagnostics.StartLatency()
	t.Cleanup(stop)
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		c, _ := tcpPair(t)
		observed := diagnostics.ObserveConn(c, "probe", "tcp")
		_ = observed.Close()
		if observed != c {
			return dir, stop
		}
	}
	t.Fatal("the latency recorder did not start")
	return "", nil
}

// latencyEvent is what these tests read of a line of an incident.
type latencyEvent struct {
	Flow      uint32 `json:"flow"`
	Leg       string `json:"leg"`
	Transport string `json:"transport"`
	Kind      string `json:"kind"`
	Data      struct {
		Local          string `json:"local"`
		Remote         string `json:"remote"`
		OuterFlow      uint32 `json:"outer_flow"`
		Evicted        bool   `json:"evicted"`
		QueuedFrames   int    `json:"queued_frames"`
		Writing        bool   `json:"writing"`
		WriteElapsedNS int64  `json:"write_elapsed_ns"`
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

// tunnelTo runs one CONNECT from a new application through handleClient to a
// test server whose handler answers it, sends "hi" and then does what end
// says. It returns the application's end, the server's address and a wait
// for the handler.
func tunnelTo(t *testing.T, end func(server net.Conn)) (app net.Conn, server string, wait func()) {
	t.Helper()
	const psk = "01234567890123456789012345678901"
	addr, done := startTestObfsServer(t, psk, func(t *testing.T, conn net.Conn) {
		var greeting [3]byte
		if _, err := io.ReadFull(conn, greeting[:]); err != nil {
			t.Errorf("greeting: %v", err)
			return
		}
		if _, err := io.ReadFull(conn, make([]byte, len(clientRequest()))); err != nil {
			t.Errorf("request: %v", err)
			return
		}
		_, _ = conn.Write([]byte{0x05, 0x00})
		_, _ = conn.Write(append([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}, "hi"...))
		// The application has read the answer once its "bye" is here.
		if _, err := io.ReadFull(conn, make([]byte, 3)); err != nil {
			t.Errorf("bye: %v", err)
			return
		}
		end(conn)
	})
	app, local := tcpPair(t)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		handleClient(local, clientParams{ServerAddr: addr, PSK: psk, MTU: 1400}, newDomainMatcher(nil))
	}()
	_ = app.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := app.Write(append([]byte{0x05, 0x01, 0x00}, clientRequest()...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(app, make([]byte, 2+10+2)); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Write([]byte("bye")); err != nil {
		t.Fatal(err)
	}
	return app, addr, func() {
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Fatal("the relay did not end")
		}
		done()
	}
}

// With the tunnel recorded, the application beside it is recorded too, tied
// to the tunnel's flow, and its flow ends by its own close however the relay
// ends: cleanly, or by the tunnel's reset - which still reaches the
// application as a reset, not as the end of a complete answer.
func TestTheApplicationIsRecordedBesideItsTunnel(t *testing.T) {
	dir, stop := startLatency(t)

	clean, cleanServer, wait := tunnelTo(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("hello"))
		_ = conn.(interface{ CloseWrite() error }).CloseWrite()
		_, _ = io.Copy(io.Discard, conn)
	})
	if got, err := io.ReadAll(clean); err != nil || string(got) != "hello" {
		t.Fatalf("the application read %q, %v", got, err)
	}
	_ = clean.Close()
	wait()

	reset, resetServer, wait := tunnelTo(t, func(conn net.Conn) {
		_ = conn.(interface{ NetConn() net.Conn }).NetConn().(*net.TCPConn).SetLinger(0)
		_ = conn.Close()
	})
	if _, err := reset.Read(make([]byte, 1)); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("the application read %v after the tunnel's reset", err)
	}
	wait()

	flows := relatedFlows(saveIncident(t, dir, stop))
	for server, app := range map[string]net.Conn{cleanServer: clean, resetServer: reset} {
		f, ok := flows[server]
		if !ok {
			t.Fatalf("no application beside the tunnel to %s", server)
		}
		if f.open.Leg != "application" || f.open.Transport != "tcp" || f.open.Data.Remote != app.LocalAddr().String() ||
			f.stages == 0 || f.close.Kind != "flow_close" || f.close.Data.Evicted {
			t.Errorf("the application of the tunnel to %s: %+v", server, f)
		}
	}
}

// The walk from a tunnel that may be set up again goes through the replay
// and the obfuscation down to the recorder's wrapper of the transport.
func TestTheWalkFromAReplayedTunnelReachesItsTransport(t *testing.T) {
	startLatency(t)
	near, _ := tcpPair(t)
	outer := diagnostics.ObserveConn(near, "outer", "obfs")
	if outer == near {
		t.Fatal("the transport was not selected")
	}
	tunnel, err := obfs.NewClientConn(outer, obfs.Config{PSK: []byte("01234567890123456789012345678901"), MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	app, _ := tcpPair(t)
	related := diagnostics.ObserveRelated(newReplayConn(tunnel, clientParams{}, nil, nil), app, "application")
	defer related.Close()
	if related == app {
		t.Fatal("the walk did not reach the transport")
	}
}
