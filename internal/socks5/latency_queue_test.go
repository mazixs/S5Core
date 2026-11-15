package socks5

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/mazixs/S5Core/internal/diagnostics"
)

// stallingConn holds its writes while stalled until released.
type stallingConn struct {
	net.Conn
	stalled atomic.Bool
	release chan struct{}
}

func (c *stallingConn) Write(p []byte) (int, error) {
	if c.stalled.Load() {
		<-c.release
	}
	return c.Conn.Write(p)
}

func (c *stallingConn) NetConn() net.Conn { return c.Conn }

// incidentEvent is what these tests read of a line of an incident.
type incidentEvent struct {
	Flow      uint32         `json:"flow"`
	Leg       string         `json:"leg"`
	Transport string         `json:"transport"`
	Kind      string         `json:"kind"`
	Data      map[string]any `json:"data"`
}

// saveIncident has the recorder save what it holds - a marker, the tick that
// takes it, the stop that finishes the incident - and reads its events.
func saveIncident(t *testing.T, dir string, stop func()) []incidentEvent {
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
	var events []incidentEvent
	for line := range bytes.Lines(data) {
		var e incidentEvent
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("%v: %s", err, line)
		}
		events = append(events, e)
	}
	return events
}

// The queue of a native association's stream goes into an incident beside
// the client's socket, and a write the socket holds shows there before it
// returns, with the frames waiting behind it.
func TestTheQueueOfANativeStreamGoesIntoAnIncident(t *testing.T) {
	dir, stop := startLatency(t)
	served := make(chan *stallingConn, 1)
	native := newScriptedNative(fmt.Errorf("session removed: %w", ErrNativePathGone))
	target, relay, conn := nativeAnswersThrough(t, native, &Config{}, func(c net.Conn) net.Conn {
		observed := diagnostics.ObserveConn(c, "outer", "obfs")
		if observed == c {
			t.Error("the client's socket was not selected")
		}
		s := &stallingConn{Conn: observed, release: make(chan struct{})}
		served <- s
		return s
	})
	stalling := <-served
	t.Cleanup(func() { close(stalling.release) })
	stalling.stalled.Store(true)
	for _, word := range []string{"one", "two", "three"} {
		if _, err := target.WriteToUDPAddrPort([]byte(word), relay); err != nil {
			t.Fatal(err)
		}
	}
	// Two samples at least while the first answer is held.
	time.Sleep(3 * time.Second / 2)
	events := saveIncident(t, dir, stop)

	var flow uint32
	for _, e := range events {
		if e.Kind == "flow_open" && e.Data["remote"] == conn.LocalAddr().String() {
			flow = e.Flow
		}
	}
	if flow == 0 {
		t.Fatal("no flow of the client's socket")
	}
	var queues int
	var longest float64
	var behind any
	for _, e := range events {
		if e.Kind != "queue" {
			continue
		}
		queues++
		if e.Flow != flow || e.Leg != "outer" || e.Transport != "obfs" {
			t.Fatalf("a queue event of flow %d (%s, %s), the client's is %d", e.Flow, e.Leg, e.Transport, flow)
		}
		if elapsed, ok := e.Data["write_elapsed_ns"].(float64); ok && e.Data["writing"] == true && elapsed > longest {
			longest, behind = elapsed, e.Data["queued_frames"]
		}
	}
	if queues < 2 || longest < float64(400*time.Millisecond) || behind != 2.0 {
		t.Fatalf("%d queue events; the longest write held %v ns, %v frames behind it", queues, longest, behind)
	}
}
