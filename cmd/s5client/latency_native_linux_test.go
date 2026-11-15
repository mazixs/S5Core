package main

import (
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// An association through a real server whose native path is cut and heals:
// the loss starts the incident of the client's tunnel, whose flow holds the
// path verified with the addresses of the client's UDP socket, lost and
// restored, in that order.
func TestALostNativePathStartsTheIncidentOfItsTunnel(t *testing.T) {
	dir, stop := startLatency(t)
	r := newNativeRig(t)
	r.verified()
	r.startStream()
	r.hop.dropDown.Store(true)
	waitFor(t, "the loss starts an incident", func() bool {
		partial, _ := filepath.Glob(filepath.Join(dir, "*.events.jsonl.*.partial"))
		return len(partial) > 0
	})
	r.hop.dropDown.Store(false)
	if !r.streamNative(10 * time.Second) {
		t.Fatal("the stream did not come back native after the path healed")
	}
	stop()

	tunnel, events := automaticIncident(t, dir)
	var changes []string
	var local, remote string
	lost, probes := 0, 0
	for _, e := range events {
		if e.Flow != tunnel {
			if e.Kind == "native_path" || e.Kind == "native_probe" {
				t.Fatalf("a native event of flow %d: %+v", e.Flow, e)
			}
			continue
		}
		switch e.Kind {
		case "flow_open":
			if e.Data.Remote != r.control.RemoteAddr().String() {
				t.Fatalf("the incident is of the flow to %s, not of the client's tunnel", e.Data.Remote)
			}
		case "native_path":
			changes = append(changes, e.Data.State)
			switch e.Data.State {
			case "verified":
				local, remote = e.Data.Local, e.Data.Remote
			case "lost":
				lost = e.Data.UnansweredProbes
			}
		case "native_probe":
			probes++
			if e.Data.RTTNS <= 0 {
				t.Fatalf("a round trip of %d ns", e.Data.RTTNS)
			}
		}
	}
	if !slices.Equal(changes, []string{"verified", "lost", "restored"}) || lost < nativeMisses {
		t.Fatalf("the path's changes %v, lost after %d unanswered", changes, lost)
	}
	if local != r.hop.client.Load().String() || remote != r.hop.frontAt.String() {
		t.Fatalf("verified from %s to %s, want the client's UDP socket %s to %s", local, remote, r.hop.client.Load(), r.hop.frontAt)
	}
	if probes == 0 {
		t.Fatal("no round trip of a probe")
	}
	t.Logf("%d round trips, lost after %d unanswered", probes, lost)
}
